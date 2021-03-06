import errno
import socket

from ..glb import GLBComponent
from ..exceptions import TryAgain, InvalidPkt
from ..utils.misc import errno_from_exception
from ..pkt.general import PktProto
from ..pkt.tcp import TCPPacket
from ..proto.fn.tcp import TCPFieldNames
from ..proto.fmt.tcp import TCP_META_DATA_LEN


class TCPConnHelper():

    # Connects to a specified Unix Domain Socket file and returns the socket
    @classmethod
    def conn_to_uds(cls, socket_name, blocking=False, timeout=None):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.setblocking(blocking)

        if blocking:
            sock.connect(socket_name)
            return sock
        else:
            # In non-blocking mod, the socket object will be returned
            # immediately when the EINPROGRESS occurred, the user
            # should check if the socket is ready to be used.
            try:
                sock.connect(socket_name)
            except OSError as e:
                if errno_from_exception(e) == errno.EINPROGRESS:
                    return sock
                else:
                    raise e

    # Connects to a remote node and returns the socket
    @classmethod
    def conn_to_remote(cls, remote_sa, blocking=False, timeout=None):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
        sock.settimeout(timeout)
        sock.setblocking(blocking)

        if blocking:
            sock.connect(remote_sa)
            return sock
        else:
            # same as above
            try:
                sock.connect(remote_sa)
            except OSError as e:
                if errno_from_exception(e) == errno.EINPROGRESS:
                    return sock
                else:
                    raise e


class TCPPacketHelper():

    @classmethod
    def pop_packet(cls, aff):
        if (
            aff.next_blk_size is not None and
            aff.recv_buf_bts >= aff.next_blk_size
        ):
            pkt = aff.pop_data(aff.next_blk_size)
            aff.set_next_blk_size(None)
            return pkt
        else:
            raise TryAgain()

    @classmethod
    def wrap(cls, pkt):
        return GLBComponent.tcp_pkt_wrapper.wrap(pkt)

    @classmethod
    def unwrap(cls, pkt):
        return GLBComponent.tcp_pkt_wrapper.unwrap(pkt)

    @classmethod
    def pkt_2_bytes(cls, pkt):
        wrapped_pkt = cls.wrap(pkt)
        return wrapped_pkt.data

    @classmethod
    def bytes_2_pkt(cls, data):
        pkt = TCPPacket()
        pkt.data = data
        return cls.unwrap(pkt)

    @classmethod
    def parse_tcp_metadata(cls, data):
        metadata, _ = GLBComponent.tcp_pkt_wrapper.parse_metadata(data)
        return metadata

    # :param try_dcs: try to decrypt data with default cryptors
    #                 should only be used in handshaking
    @classmethod
    def identify_next_blk_len(cls, conn, try_dcs=False):
        if try_dcs:
            metadata = None

            for metadata_b in conn.hs_metadata_iteration:
                try:
                    metadata = cls.parse_tcp_metadata(metadata_b)
                except InvalidPkt:
                    continue
                else:
                    break

            if metadata is None:
                raise InvalidPkt('Unable to parse metadata with DIV')

            # manually choose default cryptor for efferent
            conn.sync_cryptor_from_aff()
            conn._eff._hs_dc_choosed = True
        else:
            metadata_b = conn.read_data(TCP_META_DATA_LEN)
            metadata = cls.parse_tcp_metadata(metadata_b)

        next_len = metadata.get(TCPFieldNames.LEN)
        conn.set_next_blk_size(next_len)


class NonblockingTCPIOHelper():

    def __init__(self, poller):
        self._poller = poller
        self._ev_ro = self._poller.DEFAULT_EV
        self._ev_rw = self._ev_ro | self._poller.EV_OUT

    # receives data from an afferent and keep it in afferent's buffer
    #
    # If the next_blk_size has been set in the afferent, then this method
    # will try to retrieval the block which conforms the next_blk_size
    def handle_recv(self, aff):
        # The helper doesn't handle ConnectionLost
        aff.recv()

        return TCPPacketHelper.pop_packet(aff)

    # sends data from the efferent's buffer
    # the data argument is not essential since it's not the actual data to send
    # but the data to append into the efferent's buffer.
    def handle_send(self, eff, data=b''):
        bt_sent = eff.send(data)

        if eff.send_buf_bts == 0:
            self.set_ev_ro(eff)
        else:
            self.set_ev_rw(eff)

        return bt_sent

    def handle_send_ex(self, eff, data=b'', auto_ro=True):
        bt_sent = eff.send(data)

        if eff.send_buf_bts == 0 and auto_ro:
            self.set_ev_ro(eff)
            modified_to_ro = True
        else:
            self.set_ev_rw(eff)
            modified_to_ro = False

        return bt_sent, modified_to_ro

    def append_data(self, eff, data):
        eff.append_data(data)
        self.set_ev_rw(eff)

    def append_pkt(self, eff, pkt):
        eff.append_pkt(pkt)
        self.set_ev_rw(eff)

    def set_ev_ro(self, xff):
        self._poller.modify(xff.fd, self._ev_ro)

    def set_ev_rw(self, xff):
        self._poller.modify(xff.fd, self._ev_rw)
