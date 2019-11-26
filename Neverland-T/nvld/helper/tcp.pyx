import errno
import socket

from ..exceptions import TryAgain
from ..utils.misc import errno_from_exception


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
                if errno_from_exception == errno.EINPROGRESS:
                    return sock
                else:
                    raise e


class TCPPacketHelper():

    @classmethod
    def pop_packet(cls, aff):
        if (
            aff.next_blk_size is not None and
            aff.recv_buf_len >= aff.next_blk_size
        ):
            pkt = aff.pop_data(aff.next_blk_size)
            aff.set_next_blk_size(None)
            return pkt
        else:
            raise TryAgain()


class NonblockingTCPIOHelper():

    def __init__(self, poller):
        self._poller = poller
        self._ev_ro = self._poller.EV_IN | self._poller.EV_RDHUP
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

        if eff.send_buf_len == 0:
            self._poller.modify(eff.fd, self._ev_ro)
        else:
            self._poller.modify(eff.fd, self._ev_rw)

        return bt_sent

    def append_data(self, eff, data):
        eff.append_data(data)
        self._poller.modify(eff.fd, self._ev_rw)
