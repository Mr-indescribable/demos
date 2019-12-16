import os
import time
import random
import logging
from threading import Lock

from ..glb import GLBInfo, GLBComponent
from ..pkt.tcp import TCPPacket
from ..pkt.general import PktTypes, PktProto
from ..utils.ev import DisposableEvent
from ..utils.fifo import NLFifo
from ..utils.enumeration import MetaEnum
from ..utils.misc import VerifiTools, errno_from_exception
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
    InvalidIV,
    InvalidPkt,
    ConnectionLost,
    DecryptionFailed,
    # NLSChannelClosed,
    NLSRemoteError,
    NLSHandShakeError,
)


logger = logging.getLogger('NLS')


class NLSConnState(metaclass=MetaEnum):

    INIT         = 0x00  # the initial state of connections
    RECONNECTING = 0x01  # re-establishing lost connection
    CONNECTING   = 0x02  # establishing new connection
    CONNECTED    = 0x03  # connected but not ready to be used
    HANDSHAKING  = 0x04  # performing a handshake upon the transport layer
    READY        = 0x05  # ready for transmission
    DISCONNECTED = 0x0f  # the connection is closed


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
#     could manually delay the transmission of one of TCP connections in
#     the channel, if the time is long enough, NLS_UNCONTINUOUS_SN_THRESHOLD
#     will be reached and the channel will be broken.
#
#     For this, we'll need an additional strategy to handle partial delay.
#
#     But the real question is: do we really need to concern about this?
#
#     Unlike others, Neverland is designed to be used by a very little people,
#     and it will not try to hide the trait of protocol like shadowsocks.
#
#     It will straightly show the trait against the "unwelcomed ones".
#     With its very special trait, the Neverland protocol will not be
#     identified as any known protocol, but this also means once the
#     Neverland protocol get countered, the world we were guarding for
#     will be erased in no time.
class NLSwirl():

    # Constructor
    #
    # :param poller: an instance of the event poller which is in use
    # :param is_initiator: indicate the current instance is an initiator
    #                      or receiver, if is_initiator is False, then
    #                      the argument conn_num may be None.
    # :param remote: socket address of a remote node to communicate,
    #                if is_initiator is False, then the port may be None
    # :param conn_num: the maximum of TCP connections in the channel,
    #                  only affects the initiator since the connection
    #                  number is maintained by the initiator.
    # :param bandwidth: the bandwidth of the channel, bytes per sec
    def __init__(self, poller, is_initiator, remote, conn_num, bandwidth=None):
        self._poller = poller
        self._is_initiator = is_initiator
        self._remote = remote
        self._rmt_addr = self._remote[0]
        self._conn_num = conn_num
        self._bandwidth = bandwidth or GLBInfo.config.net.traffic.nls_channel_bw

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
        self._reconn_enabled = self._conn_max_retry > 0

        # event set
        self._evs_in  = self._poller.DEFAULT_EV
        self._evs_out = self._evs_in | self._poller.EV_OUT

        # An event for the Filler to wait, the filler should not
        # start filling the channel until receiving this event.
        self._ready_ev = DisposableEvent()
        self._ready_ev_triggered = False

        # packets that missing at the remote side
        self._missing_pkt = []

        self._pkt_send_buf_lk = Lock()
        self._pkt_send_buf = []
        self._pkt_recv_buf = []

        # a buffer that stores packets that containing fake data
        self._fpkt_buf = []
        self._fpkt_lk = Lock()
        self._fpkt_total_bytes = 0

        # This is a receive buffer as well, but this one is internal, it
        # contains all received packets in random order, and than we move
        # these packet into self._pkt_recv_buf and sort them by the sn field.
        self.__internal_recv_buf = dict()    # {sn: pkt}

        self._fds = []          # file descriptors
        self._conn_map = {}     # fd-to-conn mapping
        self._conn_lk_map = {}  # fd-to-lock mapping
        self._conn_st_map = {}  # fd-to-state mapping
        self._conn_ct_map = {}  # fd-to-CurrentlyTransmittingPkt mapping
        self._conn_iv_map = {}  # fd-to-CurrentlyIV mapping
        self._conn_retried = 0  # retried times of reconnecting
        self._avai_conns = 0    # currently available connections
        self._avai_fds = []     # currently available fds
        self._awkn_fdn = 0      # number of awoken fds

        # When number of awoken connection less than this,
        # we should perform an awakening. (if there is data to be sent)
        if self._is_initiator:
            self._awk_threshold = 1 if conn_num <= 3 else conn_num // 2

        # corresponds to the sn field in the header of the last
        # TCP packet appended into self._pkt_recv_buf
        self._sn = 0

        # A cache which holds a set of transmitted packets; {sn: pkt}
        self._pkt_cache = {}

        # A FIFO queue that contains all SN in self._pkt_cache
        self._pkt_cache_sn_fifo = NLFifo(maxlen=self._cache_size)

        # fields template of handshake packet
        self._hs_pktf_temp = {
            'sn': 0,
            'type': PktTypes.IV_CTRL,
            'dest': ('0.0.0.0', 0),
            'iv': None,
        }

    def _has_pkts_to_send(self):
        return (
            len(self._missing_pkt) > 0 or
            len(self._pkt_send_buf) > 0 or
            len(self._fpkt_buf) > 0
        )

    def _randomly_awake_conn(self):
        fdn = len(self._fds)
        minimum = 1 if fdn <= 3 else fdn // 2
        n2awk = random.randint(minimum, fdn)

        fds = random.choices(self._fds, k=n2awk)

        for fd in fds:
            lock = self._conn_lk_map.get(fd)

            with lock:
                conn = self._conn_map.get(fd)
                self._io_helper.set_ev_rw(conn)

    def _awake_conns(self):
        if self._poller.get_w_fdn() <= self._awk_threshold:
            self._randomly_awake_conn()

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

    def _remove_conn_with_lock(self, fd):
        lock = self._conn_lk_map.get(fd)

        with lock:
            self._fds.remove(fd)
            self._avai_conns -= 1

            self._poller.unregister(fd)

            conn = self._conn_map.get(fd)
            conn.destroy()

            self._conn_lk_map.pop(fd)
            self._conn_st_map.pop(fd)
            self._conn_map.pop(fd)

            if fd in self._avai_fds:
                self._avai_fds.remove(fd)

            if fd in self._conn_ct_map:
                self._conn_ct_map.pop(fd)

            if fd in self._conn_iv_map:
                self._conn_iv_map.pop(fd)

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

    # the initiator initiates the handshake
    # sends a new IV to the receiver and set connection state to HANDSHAKING
    def _initiate_handshake(self, fd):
        lock = self._conn_lk_map.get(fd)

        with lock:
            new_iv = GLBComponent.div_mgr.random_stmc_div()
            conn = self._conn_map.get(fd)
            self._conn_iv_map[fd] = new_iv
            self._conn_st_map[fd] = NLSConnState.HANDSHAKING

            self._hs_pktf_temp.udpate(iv=new_iv)
            iv_pkt = TCPPacket(fields=self._hs_pktf_temp)
            TCPPacketHelper.wrap(iv_pkt)

            self._io_helper.handle_send(conn, iv_pkt.data)

    # the receiver accepts the IV from the initiator and
    # reply it with an ACK.
    #
    # the pkt should be validated by the invoker,
    # and type of the packet must be IV_CTRL.
    def _accept_handshake(self, fd, pkt):
        new_iv = pkt.fields.iv
        lock = self._conn_lk_map.get(fd)

        with lock:
            conn = self._conn_map.get(fd)
            self._conn_iv_map[fd] = new_iv

            self._hs_pktf_temp.udpate(iv=new_iv)
            iv_pkt = TCPPacket(fields=self._hs_pktf_temp)
            TCPPacketHelper.wrap(iv_pkt)

            self._io_helper.handle_send(conn, iv_pkt.data)

            try:
                conn.update_iv(new_iv)
            except InvalidIV:
                raise NLSHandShakeError('invalid IV')

            # After this, we can safely declare that the connection is ready no
            # matter if the packet has been completely sent to the other side.
            # Because the data is only encrypted when it's appended into
            # the efferent's buffer.
            self._conn_st_map[fd] = NLSConnState.READY
            self._avai_fds.append(fd)
            self._avai_conns += 1

    # the initiator receives the ACK and finishes the handshake
    #
    # the pkt should be validated by the invoker,
    # and type of the packet must be IV_CTRL.
    def _finish_handshake(self, fd, pkt):
        ack_iv = pkt.fields.iv
        iv = self._conn_iv_map.get(fd)

        if iv != ack_iv:
            raise NLSHandShakeError('IV in the handshake ACK is wrong')

        lock = self._conn_lk_map.get(fd)

        with lock:
            conn = self._conn_map.get(fd)
            conn.update_iv(iv)

            self._conn_st_map[fd] = NLSConnState.READY
            self._avai_fds.append(fd)
            self._avai_conns += 1

    def _on_connected(self, fd):
        self._conn_retried = 0
        self._conn_st_map[fd] = NLSConnState.CONNECTED

        if not self._ready_ev_triggered:
            self._ready_ev.trigger()
            self._ready_ev_triggered = True

    # when the remote node sends something incorrect
    def _on_remote_error(self):
        self.close_channel()
        raise NLSRemoteError('Remote node does not work properly')

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
        if self._conn_st_map.get(fd) != NLSConnState.READY:
            return

        pkt = self._conn_ct_map.get(fd)

        if pkt is None:
            return

        if pkt.fields.type == PktTypes.DATA and pkt.fields.fake:
            return  # this would be easier to read
        else:
            self._missing_pkt.append(pkt)
            self._awake_conns()

    # makes connection with other node
    def build_channel(self):
        if not self._is_initiator:
            raise TypeError('wrong type of NLS')

        for _ in range(self._conn_num):
            self._new_conn()

    # closes all connections within the channel
    def close_channel(self):
        # self._fds will get changed during the removal
        for fd in tuple(self._fds):
            self._remove_conn_with_lock(fd)

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
        self._awake_conns()

    def handle_ev(self, fd, ev):
        if   ev & self._poller.EV_IN:
            return self.handle_in(fd)
        elif ev & self._poller.EV_OUT:
            return self.handle_out(fd)
        elif ev & self._poller.EV_RDHUP:
            return self.handle_rdhup(fd)
        elif ev & self._poller.EV_HUP:
            return self.handle_hup(fd)
        elif ev & self._poller.EV_ERR:
            return self.handle_err(fd)
        else:
            logger.warn(f'Unregistered event {ev}')

    # event handler of EV_IN
    def handle_in(self, fd):
        got_pkt = False
        accepting_handshake = False
        expecting_hs_ack = False
        conn = self._conn_map.get(fd)
        state = self._conn_st_map.get(fd)

        # we use the EV_OUT to notice us that the connection is ready, but we
        # cannot ensure that the EV_IN event will not arrive before EV_OUT
        if (
            state == NLSConnState.CONNECTING or
            state == NLSConnState.RECONNECTING
        ):
            self._on_connected(fd)

            if self._is_initiator:
                self._initiate_handshake(fd)
                return
            else:
                accepting_handshake = True
        elif state == NLSConnState.HANDSHAKING and self._is_initiator:
            expecting_hs_ack = True
        elif state == NLSConnState.DISCONNECTED:
            return
        elif state != NLSConnState.READY:
            raise RuntimeError('connection state error')

        try:
            conn.recv()
        except TryAgain:
            return
        except ConnectionLost:
            self._extract_missing_pkt(fd)
            self._remove_conn_with_lock(fd)

            if self._is_initiator and self._reconn_enabled:
                self._reconnect()

            return
        except DecryptionFailed:
            self._on_remote_error()

        if conn.next_blk_size is None:
            if conn.recv_buf_bts > 3:
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
                        got_pkt = True
                    except TryAgain:
                        return
            else:
                return
        else:
            try:
                pkt_bt = self._io_helper.handle_recv(conn)
                got_pkt = True
            except TryAgain:
                return

        if not got_pkt:
            return

        try:
            pkt = TCPPacketHelper.bytes_2_pkt(pkt_bt)
        except InvalidPkt:
            # same as above, we can only close the channel
            self._on_remote_error()

        # check packet type for handshake logic
        #
        # in this case, the first packet must be an IV_CTRL packet,
        # otherwise, the remote node is not working properly.
        if accepting_handshake or expecting_hs_ack:
            if pkt.fields.type != PktTypes.IV_CTRL:
                logger.error(
                    f'remote node {self._rmt_addr} didn\'t perform a handshake'
                )
                self._on_remote_error()

        if accepting_handshake:
            try:
                self._accept_handshake(fd, pkt)
            except NLSHandShakeError:
                self._on_remote_error()
            return

        if expecting_hs_ack:
            try:
                self._finish_handshake(fd, pkt)
            except NLSHandShakeError:
                self._on_remote_error()
            return

        # drop fake packet
        if pkt.fields.fake:
            return

        # drop already received packet
        if pkt.fields.sn <= self._sn:
            return

        self._buff_pkt(pkt)
        self.__shift_recvd_pkt()

        if len(self.__internal_recv_buf) > NLS_UNCONTINUOUS_SN_THRESHOLD:
            logger.error(
                f'NLS_UNCONTINUOUS_SN_THRESHOLD reached, peer: {self._rmt_addr}'
            )
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

            if self._is_initiator:
                self._initiate_handshake(fd)
                return
        elif state == NLSConnState.DISCONNECTED:
            return
        elif state != NLSConnState.READY:
            raise RuntimeError('connection state error')

        # We need to check the last packet sent by the current connection,
        # if it's a fake packet, then we need to reduce self._fpkt_total_bytes.
        # We cannot simply reduce this counter when we allocate the packet
        # to a connection, because it's not totally sent out at that time.
        # Now it's the time that the transmission has been completed.
        # And we should remove the last packet by the way.
        if fd in self._conn_ct_map:
            last_pkt = self._conn_ct_map.pop(fd)
            if last_pkt.fields.type == PktTypes.DATA and last_pkt.fields.fake:
                self._fpkt_total_bytes -= last_pkt.fields.len
        else:
            last_pkt = None

        # while we have data to send, we don't need to wait for the
        # filler to fill the channel anyway, NLSwirl itself should
        # send the data immediately (the so-called high priority).
        if conn.send_buf_bts == 0:
            if len(self._missing_pkt) > 0:
                self._alloc_pkt_with_lock(fd, self._missing_pkt.pop(0))
            elif len(self._pkt_send_buf) > 0:
                self._alloc_pkt_with_lock(fd, self._pkt_send_buf.pop(0))
            elif len(self._fpkt_buf) > 0:
                with self._fpkt_lk:
                    fpkt = self._fpkt_buf.pop(0)

                self._alloc_pkt_with_lock(fd, fpkt)

        # the helper will help us to do the event-changing job
        # if there is no data to send
        auto_modify_ev = not self._has_pkts_to_send()
        self._io_helper.handle_send_ex(conn, auto_modify_ev=auto_modify_ev)

    # event hander of EV_RDHUP
    #
    # Neverland will never close a channel of NLSwirl,
    # unless the program itself is exiting, so, in this case,
    # we must try to reconnect.
    def handle_rdhup(self, fd):
        self._extract_missing_pkt(fd)
        self._remove_conn_with_lock(fd)

        if self._is_initiator:
            if self._reconn_enabled:
                self._reconnect()
            else:
                raise TCPError('Connection closed by remote')

    # event hander of EV_HUP
    def handle_hup(self, fd):
        self._extract_missing_pkt(fd)
        self._remove_conn_with_lock(fd)

        if self._is_initiator:
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

        self._remove_conn_with_lock(fd)
        logger.warn(
            f'EV_ERR encountered, errmsg: {errmsg}, remote: {self._rmt_addr}'
        )

        if self._is_initiator:
            if state == NLSConnState.RECONNECTING:
                self._conn_retried += 1

                if self._conn_retried < self._conn_max_retry:
                    self._reconnect()
                else:
                    raise TCPError(errmsg)
            else:
                if self._reconn_enabled:
                    self._reconnect()
                else:
                    raise TCPError(errmsg)

    def pop_pkt(self):
        if len(self._pkt_recv_buf) > 0:
            return self._pkt_recv_buf.pop(0)
        else:
            raise TryAgain('no more packets')

    @property
    def conn_num(self):
        return self._conn_num

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
# The filler takes the duty of filling the channel with fake data,
# NLSwirl doesn't generate fake data itself, it only notices the
# filler to do this.
#
# The filler instance must be run in a dedicated thread.
class NLSChannelFiller():

    def __init__(self, swirl):
        self._swirl = swirl
        self._bandwidth = self._swirl._bandwidth

        self._running = False

        self._fdata_len_min = GLBInfo.config.net.traffic.nls_fdata_size_min
        self._fdata_len_max = GLBInfo.config.net.traffic.nls_fdata_size_max

        self._traffic_calc_span = GLBInfo.config.net.traffic.calc_span

        # rtbw == realtime bandwidth
        # means to be fit with aff/eff's realtime bandwidth calculation
        self._traffic_rtbw = self._bandwidth * self._traffic_calc_span

        # last bandwidth calculating time
        self._last_bwc_time = time.time()

        # start of next bandwidth calculating time span
        self._next_bwc_span = self._last_bwc_time + self._traffic_calc_span

        # fd == fake packet
        self.fp_fields = {
            'type': PktTypes.DATA,
            'dest': ('0.0.0.0', 0),
            'channel_id': 0,
            'fake': 1,
            'data': None,
        }

    # generates fake data
    def _gen_fpkt(self, length):
        self.fp_fields.update(data=os.urandom(length))
        pkt = TCPPacket(fields=self.fp_fields)
        return TCPPacketHelper.wrap(pkt)

    def _get_chn_rt_traffic(self):
        total_rt_traffic = 0

        for fd in self._swirl._fds:
            conn_lock = self._swirl._conn_lk_map.get(fd)

            # This could happen in some rare situation which is kinda
            # like a race condition. But we cannot totally evade it
            # since we cannot get the reference of the lock before we
            # access swirl._fds.
            if conn_lock is None:
                continue

            with conn_lock:
                conn = self._swirl._conn_map.get(fd)
                total_rt_traffic += conn.traffic_send_realtime

        return total_rt_traffic

    # fake bytes needed in current time span
    def _fbytes_needed(self):
        rt_tfc = self._get_chn_rt_traffic()

        tfc_diff = self._traffic_rtbw - rt_tfc

        if tfc_diff < self._fdata_len_min:
            return 0
        else:
            return tfc_diff

    def _wait_for_next_span(self):
        t2s = self._next_bwc_span - time.time()

        # t2s could be <= 0 due to the time consumption of the calculation
        if t2s > 0:
            time.sleep(t2s)

    def run(self):
        self._swirl._ready_ev.wait()

        while self._running:
            fbt_appended = 0
            fbt_needed = self._fbytes_needed()

            if fbt_needed == 0:
                self._wait_for_next_span()
            else:
                while fbt_appended < fbt_needed:
                    pkt = self._gen_fpkt()

                    with self._swirl._fpkt_lk:
                        self._swirl._fpkt_buf.append(pkt)
                        self._swirl._fpkt_total_bytes += pkt.fields.len

                    fbt_appended += pkt.fields.len

                self._swirl._awake_conns()

    def shutdown(self):
        self._running = False
