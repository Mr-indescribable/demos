import os
import random
from threading import Lock

from ..glb import GLBInfo
from ..pkt.tcp import TCPPacket
from ..pkt.general import PktTypes, PktProto
from ..utils.ev import DisposableEvent
from ..utils.fifo import NLFifo
from ..utils.enumeration import MetaEnum
from ..utils.misc import errno_from_exception
from ..fdx.tcp import FDXTCPConn
from ..helper.crypto import CryptoHelper
from ..helper.tcp import (
    TCPConnHelper,
    TCPPacketHelper,
    NonblockingTCPIOHelper,
)
from ..exceptions import (
    TCPError,
    TryAgain,
    InvalidPkt,
    ConnectionLost,
    NLSChannelClosed,
)


class NLSConnState(metaclass=MetaEnum):

    INIT         = 0x00  # the initial state of connections
    CONNECTING   = 0x01  # in the the first time of establishing connection
    CONNECTED    = 0x02  # the connection is ready to use
    DISCONNECTED = 0x03  # the connection is closed
    RECONNECTING = 0x04  # re-establishing the lost connection


# When the continuity of the sn is broken and the peer is still sending
# packets without retransmitting the missing packet, we have to close the
# channel. When this threshold is reached, some of NLSwirl's functionalities
# is not working as expected.
NLS_UNCONTINUOUS_SN_THRESHOLD = 64  # (packets)


# The swirl module of Neverland
#
# The NLSwirl module provides a special method to handle TCP traffic
# between nodes. It maintains multiple TCP connection and abstract
# them into one single channel, and generates a fake data stream
# which consists of random data to fill the empty channel up to full.
# Once we have actual data to transfer, the swirl shall reduce
# same amount of fake data and insert the actual data into
# the fake data stream with high priority.
#
# It also provides in order transmission on the channel layer.
#
# TODO:
#     The current NLS protocol has a major weakness, the "unwelcomed ones"
#     can manually delay the transmission of one of TCP connections in the
#     channel, if the time is long enough, NLS_UNCONTINUOUS_SN_THRESHOLD
#     will be reached and the channel will be broken.
#
#     To counter this, we need an additional strategy to handle partial delay.
class NLSwirl():

    # Constructor
    #
    # :param remote: the socket address of a remote node to communicate
    # :param conn_cnt: the quantity of TCP connections in the channel
    # :param bandwidth: the bandwidth of the channel, bytes per sec
    # :param poller: an instance of the event poller which is in use
    def __init__(self, remote, conn_cnt, bandwidth, poller):
        self._remote = remote
        self._conn_cnt = conn_cnt
        self._bandwidth = bandwidth
        self._poller = poller

        self._io_helper = NonblockingTCPIOHelper(self._poller)
        self._conn_max_retry = GLBInfo.config.net.tcp.conn_max_retry
        self._cache_size = GLBInfo.config.net.tcp.nls_cache_size

        # determines whether the reconnecting is enabled
        #
        # When reconnecting is disabled, we will not check how many
        # connections is still available, it's pointless, all connections
        # will be disconnected for some expected reasons sooner or later.
        # And this is never supposed to be happened, so, the reconnecting
        # should always be enabled.
        self._reconn_enabled = True if self._conn_max_retry > 0 else False

        # event set
        self._evs_in  = self._poller.DEFAULT_EV
        self._evs_out = self._ev_in | self._poller.EV_OUT

        # An event for the Filler to wait, the filler should not
        # start filling the channel until receiving this event.
        self._ready_ev = DisposableEvent()
        self._ready_ev_triggered = False

        # packets that missing at the remote side
        self._missing_pkt = []

        self._pkt_send_buf_lk = Lock()
        self._pkt_send_buf = []
        self._pkt_recv_buf = []

        # This is a receive buffer as well, but this one is internal, it
        # contains all received packets in random order, and than we move
        # these packet into self._pkt_recv_buf and sort them by the sn field.
        self.__internal_recv_buf = dict()    # {sn: pkt}

        self._fds = []          # file descriptors
        self._conn_map = {}     # fd-to-conn mapping
        self._conn_lk_map = {}  # fd-to-lock mapping
        self._conn_st_map = {}  # fd-to-state mapping
        self._conn_ct_map = {}  # fd-to-CurrentlyTransmittingPkt mapping
        self._conn_retried = 0  # retried times of reconnecting
        self._avai_conns = 0    # currently available connections
        self._avai_fds = []     # currently available fds

        # corresponds to the sn field in the header of the last
        # TCP packet appended into self._pkt_recv_buf
        self._sn = 0

        # A cache which holds a set of transmitted packets; {sn: pkt}
        self._pkt_cache = {}

        # A FIFO queue that contains all SN in self._pkt_cache
        self._pkt_cache_sn_fifo = NLFifo(maxlen=self._cache_size)

    def _next_sn(self):
        try:
            return self._sn
        finally:
            self._sn += 1

    def _assign_sn(self, pkt):
        pkt.fields.sn = self._next_sn()

    def _connect_remote(self):
        try:
            conn = TCPConnHelper.conn_to_remote(self._remote)
            return FDXTCPConn(
                conn,
                src=None,
                plain_mod=False,
                cryptor=CryptoHelper.new_stream_cryptor(),
                blocking=False,
            )
        except OSError as e:
            errno = errno_from_exception(e)
            raise TCPError(os.strerror(errno))

    def _remove_conn(self, fd):
        lock = self._conn_lk_map.get(fd)

        with lock:
            self._avai_conns -= 1

            self._poller.unregister(fd)

            conn = self._conn_map.get(fd)
            conn.destroy()

            self._fds.remove(fd)
            self._conn_map.pop(fd)
            self._conn_lk_map.pop(fd)
            self._conn_st_map.pop(fd)

            if fd in self._avai_fds:
                self._avai_fds.remove(fd)

            if fd in self._conn_ct_map:
                self._conn_ct_map.pop(fd)

    def _add_conn(self, conn, state):
        fd = conn.fd
        lock = Lock()

        with lock:
            self._conn_lk_map.update( {fd: lock} )
            self._conn_st_map.update( {fd: state} )
            self._conn_map.update( {fd: conn} )
            self._fds.append(fd)

            # poll with EPOLLOUT event will notice us that the connection
            # is ready, and then, we turn it to read only after we are noticed
            # (if there is no data to send)
            self._poller.register(fd, ev=self._evs_out, obj=self)

    def _new_conn(self):
        conn = self._connect_remote()
        self._add_conn(conn, NLSConnState.CONNECTING)
        return conn.fd

    def _reconnect(self):
        fd = self._new_conn()
        self._conn_st_map[fd] = NLSConnState.RECONNECTING

    def _on_connected(self, fd):
        self._conn_retried = 0
        self._conn_st_map[fd] = NLSConnState.CONNECTED
        self._avai_fds.append(fd)
        self._avai_conns += 1

        if not self._ready_ev_triggered:
            self._ready_ev.trigger()
            self._ready_ev_triggered = True

    # when the remote node sends something incorrect
    def _on_remote_error(self):
        self.close_channel()
        raise NLSChannelClosed('Remote node does not work properly')

    def _alloc_pkt_with_lock(self, fd, pkt):
        lock = self._conn_lk_map.get(fd)
        conn = self._conn_map.get(fd)

        with lock:
            self._conn_ct_map[fd] = pkt
            self._io_helper.append_data(conn, pkt.data)

    # Move packet in self.__shift_recvd_pkt into self._pkt_recv_buf
    # and sort them by the sn field.
    #
    # The sn must be continuous, if we are missing an sn, then we should
    # simply wait its arrival and queue other received packets until
    # the packet with the missing sn has been received.
    #
    # The missing packet must be sent by the peer anyway. Because of
    # TCP's reliability, the peer can know which one is the missing packet.
    # The loss only happends when an TCP connection is disconnected for some
    # unexpected reason, at that moment, the packet which is in transmission
    # is the missing packet (if not entirely transmitted).
    #
    # If the missing packet cannot be handled properly,
    # then some of functionalities of the NLSwirl is broken.
    def __shift_recvd_pkt(self):
        while self.__internal_recv_buf:
            next_sn = self._sn + 1

            if next_sn in self.__internal_recv_buf:
                pkt = self.__internal_recv_buf.pop(next_sn)
                self._pkt_recv_buf.append(pkt)
                self._sn = next_sn
            else:
                break

    def _buff_pkt(self, pkt):
        sn = pkt.fields.sn

        if self._sn + 1 == sn:
            self._pkt_recv_buf.append(pkt)
            self._sn += 1
        else:
            self.__internal_recv_buf.update( {sn: pkt} )

        self.__shift_recvd_pkt()

    def _extract_missing_pkt(self, fd):
        pkt = self._conn_ct_map.get(fd)
        self._missing_pkt.append(pkt)

    # makes connection with other node
    def build_channel(self):
        for _ in range(self._conn_cnt):
            self._new_conn()

    # closes all connections within the channel
    def close_channel(self):
        for fd, conn in self._conn_map.items():
            lock = self._conn_lk_map.get(fd)

            with lock:
                self._remove_conn(fd)

    # adds a connection into the channel
    # used on the connection-accepting side
    #
    # :param conn: an instance of FDXTCPConn class
    # :param state: current state of the connection, choose from NLSConnState
    def add_conn(self, conn, state):
        self._add_conn(conn, state)

    # adds packet into self._pkt_send_buf
    def append_pkt(self, pkt):
        self._assign_sn(pkt)
        TCPPacketHelper.wrap(pkt)

        sn = pkt.fields.sn

        with self._pkt_send_buf_lk:
            self._pkt_send_buf.append(pkt)

        # add packet to the cache
        if self._pkt_cache_sn_fifo.maxlen_reached:
            poped_sn = self._pkt_cache_sn_fifo.append(sn)
            self._pkt_cache.pop(poped_sn)
        else:
            self._pkt_cache_sn_fifo.append(sn)

        self._pkt_cache.update({sn: pkt})

    # event handler of EV_IN
    def handle_in(self, fd):
        conn = self._conn_map.get(fd)
        state = self._conn_st_map.get(fd)

        # we use the EV_OUT to notice us that the connection is ready, but we
        # cannot ensure that the EV_IN event will not arrive before EV_OUT
        if (
            state == NLSConnState.CONNECTING or
            state == NLSConnState.RECONNECTING
        ):
            self._on_connected(fd)

        if conn.next_blk_size is None:
            try:
                conn.recv()
            except TryAgain:
                return
            except ConnectionLost:
                self._extract_missing_pkt(fd)
                self._remove_conn(fd)

                if self._reconn_enabled:
                    self._reconnect()

            if conn.recv_buf_len > 3:
                try:
                    TCPPacketHelper.identify_next_blk_len(conn)
                except InvalidPkt:
                    # This is not supposed to be happended.
                    # In this case, the only thing we can do is disconnecting.
                    self._on_remote_error()
                else:
                    # try to get next packet, the helper will help in
                    # checking if we have sufficient data
                    try:
                        pkt_bt = TCPPacketHelper.pop_packet(conn)
                    except TryAgain:
                        return
        else:
            try:
                pkt_bt = self._io_helper.handle_recv(conn)
            except TryAgain:
                return

        try:
            pkt = TCPPacketHelper.bytes_2_pkt(pkt_bt)
        except InvalidPkt:
            # same as above, we can only close the channel
            self._on_remote_error()

        if pkt.fields.sn > self._sn:
            self._buff_pkt(pkt)

        if len(self.__shift_recvd_pkt) > NLS_UNCONTINUOUS_SN_THRESHOLD:
            self._on_remote_error()

    # event hander of EV_OUT
    def handle_out(self, fd):
        conn = self._conn_map.get(fd)
        state = self._conn_st_map.get(fd)

        if (
            state == NLSConnState.CONNECTING or
            state == NLSConnState.RECONNECTING
        ):
            self._on_connected(fd)

        # while we have data to send, we don't need to wait for the
        # filler to fill the channel anyway, NLSwirl itself should
        # send the data immediately (the so-called high priority).
        if conn.send_buf_len == 0:
            if len(self._missing_pkt) > 0:
                self._alloc_pkt_with_lock(fd, self._missing_pkt.pop(0))
            elif self.pkts_to_send > 0:
                self._alloc_pkt_with_lock(fd, self._pkt_send_buf.pop(0))

        # the helper will help us to do the event-changing job
        # if there is no data to send
        self._io_helper.handle_send(conn)

    # event hander of EV_RDHUP
    #
    # Neverland will never close a channel of NLSwirl,
    # unless the program itself is exiting, so, in this case,
    # we must try to reconnect.
    def handle_rdhup(self, fd):
        self._extract_missing_pkt(fd)
        self._remove_conn(fd)

        if self._reconn_enabled:
            self._reconnect()
        else:
            raise TCPError('Connection closed by remote')

    # event hander of EV_HUP
    def handle_hup(self, fd):
        self._extract_missing_pkt(fd)
        self._remove_conn(fd)

        if self._reconn_enabled:
            self._reconnect()
        else:
            raise TCPError('Connection closed by both remote and local')

    # event hander of EV_ERR
    def handle_err(self, fd):
        # the old connection must be removed anyway,
        # and we need to get all info we need before the removal
        self._extract_missing_pkt(fd)
        conn = self._conn_map.get(fd)
        state = self._conn_st_map.get(fd)
        errmsg = conn.get_socket_errmsg()

        self._remove_conn(fd)

        if (
            state == NLSConnState.CONNECTING or
            state == NLSConnState.CONNECTED
        ):
            if self._reconn_enabled:
                self._reconnect()
            else:
                raise TCPError(errmsg)
        elif state == NLSConnState.RECONNECTING:
            self._conn_retried += 1

            if self._conn_retried < self._conn_max_retry:
                self._reconnect()
            else:
                raise TCPError(errmsg)

    def pop_pkt(self):
        if len(self._pkt_recv_buf) > 0:
            return self._pkt_recv_buf.pop(0)
        else:
            raise TryAgain('no more packets')

    @property
    def conn_cnt(self):
        return self._conn_cnt

    @property
    def fds(self):
        return self._fds

    @property
    def pkts_to_read(self):
        return len(self._pkt_recv_buf)

    @property
    def pkts_to_send(self):
        return len(self._pkt_send_buf)


# The channel filler for the NLSwirl.
#
# The filler takes the duty of filling the channel with data,
# NLSwirl doesn't fill the channel itself, it only notices the
# filler to do this.
#
# The filler instance must be run in a dedicated thread.
class NLSChannelFiller():

    def __init__(self, swirl):
        self._swirl = swirl
        self._bandwidth = self._swirl._bandwidth

        self._traffic_calc_span = GLBInfo.config.net.traffic.calc_span

        # rtbw == realtime bandwidth
        # means to be fit with aff/eff's realtime bandwidth calculation
        self._traffic_rtbw = self._bandwidth * self._traffic_calc_span

        # fd == fake packet
        self.fp_fields = {
            'type': PktTypes.DATA,
            'dest': ('0.0.0.0', 0),
            'channel_id': 0,
            'fake': 1,
            'data': None,
        }

    # generates fake data
    def _gen_fdata(self, length):
        self.fp_fields.update(data=os.urandom(length))
        pkt = TCPPacket(fields=self.fp_fields)
        return TCPPacketHelper.pkt_2_bytes(pkt)

    def _choose_conn(self):
        fds = self._swirl._avai_fds
        if len(fds) == 0:
            raise TryAgain()

        fd = random.choice(fds)
        return self._swirl._conn_map.get(fd)

    def run(self):
        self._swirl._ready_ev.wait()

        # TODO: to be continued
