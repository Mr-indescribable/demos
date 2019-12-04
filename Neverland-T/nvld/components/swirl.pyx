import os
from threading import Lock

from ..glb import GLBInfo
from ..utils.ev import DisposableEvent
from ..utils.enumeration import MetaEnum
from ..utils.misc import errno_from_exception
from ..fdx.tcp import FDXTCPConn
from ..exceptions import TCPError, TryAgain
from ..helper.crypto import CryptoHelper
from ..helper.tcp import (
    TCPConnHelper,
    TCPPacketHelper,
    NonblockingTCPIOHelper,
)


class NLSConnState(metaclass=MetaEnum):

    INIT         = 0x00  # the initial state of connections
    CONNECTING   = 0x01  # in the the first time of establishing connection
    CONNECTED    = 0x02  # the connection is ready to use
    DISCONNECTED = 0x03  # the connection is closed
    RECONNECTING = 0x04  # re-establishing the lost connection


# The swirl module of Neverland
#
# The NLSwirl module provides a special method to handle TCP traffic
# between nodes. It maintains multiple TCP connection and abstract
# them into one single channel, and generates a fake data stream
# which consists of random data to fill the empty channel up to full.
# Once we have actual data to transfer, the swirl shall reduce
# same amount of fake data and insert the actual data into
# the fake data stream with high priority.
class NLSwirl():

    # Constructor
    #
    # :param remote: the socket address of a remote node to communicate
    # :param conn_cnt: the quantity of TCP connections in the channel
    # :param poller: an instance of the event poller which is in use
    def __init__(self, remote, conn_cnt, poller):
        self._remote = remote
        self._conn_cnt = conn_cnt
        self._poller = poller
        self._io_helper = NonblockingTCPIOHelper(self._poller)
        self._conn_max_retry = GLBInfo.config.net.tcp.conn_max_retry
        self._reconn_enabled = True if self._conn_max_retry > 0 else False

        # event set
        self._evs_in  = self._poller.DEFAULT_EV
        self._evs_out = self._ev_in | self._poller.EV_OUT

        self._send_buf = b''
        self._send_buf_lk = Lock()
        self._pkt_buffer = []   # A receive buffer that stores packets

        self._fds = []          # file descriptors
        self._conn_map = {}     # fd-to-conn mapping
        self._conn_lk_map = {}  # fd-to-lock mapping
        self._conn_st_map = {}  # fd-to-state mapping
        self._conn_retried = 0  # retried times of reconnecting
        self._avai_conns = 0    # currently available connections

        # An event for the Filler to wait, the filler should not
        # start filling the channel until receiving this event.
        self._ready_ev = DisposableEvent()
        self._ready_ev_triggered = False

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
        self._conn_retried = 0

    def _on_connected(self, fd):
        self._conn_st_map[fd] = NLSConnState.CONNECTED
        self._avai_conns += 1

        if not self._ready_ev_triggered:
            self._ready_ev.trigger()
            self._ready_ev_triggered = True

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

    # adds data into self._send_buf
    def append_data(self, data):
        with self._send_buf_lk:
            self._send_buf += data

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

        try:
            pkt = self._io_helper.handle_recv(conn)
        except TryAgain:
            return

        self._pkt_buffer.append(pkt)

    # event hander of EV_OUT
    def handle_out(self, fd):
        conn = self._conn_map.get(fd)
        state = self._conn_st_map.get(fd)

        if (
            state == NLSConnState.CONNECTING or
            state == NLSConnState.RECONNECTING
        ):
            self._on_connected(fd)

        # the helper will help us to do the event-changing job
        # if there is no data to send
        self._io_helper.handle_send(conn)

    # event hander of EV_RDHUP
    #
    # Neverland will never close a channel of NLSwirl,
    # unless the program itself is exiting, so, in this case,
    # we must try to reconnect.
    def handle_rdhup(self, fd):
        if self._reconn_enabled:
            self._reconnect()
        else:
            raise TCPError('Connection closed by remote')

    # event hander of EV_HUP
    def handle_hup(self, fd):
        if self._reconn_enabled:
            self._reconnect()
        else:
            raise TCPError('Connection closed by both remote and local')

    # event hander of EV_ERR
    def handle_err(self, fd):
        # the old connection must be removed anyway,
        # and we need to get all info we need before the removal
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
        if len(self._pkt_buffer) > 0:
            return self._pkt_buffer.pop(0)
        else:
            raise TryAgain('no more packets')

    @property
    def conn_cnt(self):
        return self._conn_cnt

    @property
    def fds(self):
        return self._fds

    @property
    def pkts_to_handle(self):
        return len(self._pkt_buffer)


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

    # generates fake data
    def _gen_fdata(self, swirl):
        pass

    def run(self):
        self._swirl._ready_ev.wait()
