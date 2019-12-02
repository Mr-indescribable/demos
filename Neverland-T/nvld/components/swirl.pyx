import os
from threading import Lock

from ..glb import GLBInfo
from ..utils.ev import DisposableEvent
from ..utils.misc import errno_from_exception
from ..fdx.tcp import FDXTCPConn
from ..exceptions import TCPError
from ..helper.tcp import (
    TCPConnHelper,
    TCPPacketHelper,
    NonblockingTCPIOHelper,
)


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

        self._send_buf = b''
        self._send_buf_lk = Lock()

        self._fds = []          # file descriptors
        self._conn_map = {}     # fd-to-conn mapping
        self._conn_lk_map = {}  # fd-to-lock mapping

        # An event for the Filler to wait, the filler should not
        # start filling the channel until receiving this event.
        self._ready_ev = DisposableEvent()

    # makes connection with other node
    def build_channel(self):
        for _ in range(self._conn_cnt):
            try:
                conn = TCPConnHelper.conn_to_remote(self._remote)
            except OSError as e:
                errno = errno_from_exception(e)
                raise TCPError(os.strerror(errno))

            fd = conn.fileno()
            self._fds.append(fd)
            self._conn_map.update( {fd: conn} )
            self._conn_lk_map.update( {fd: Lock()} )

    # closes all connections within the channel
    def close_channel(self):
        for fd, conn in self._conn_map.items():
            lock = self._conn_lk_map.get(fd)

            with lock:
                conn.close()
                self._conn_map.pop(fd)
                self._conn_lk_map.pop(fd)
                self._fds.remove(fd)

    # adds data into self._send_buf
    def append_data(self, data):
        pass

    # event handler of EV_IN
    def handle_in(self, fd):
        pass

    # event hander of EV_OUT
    def handle_out(self, fd):
        pass

    # event hander of EV_RDHUP
    def handle_rdhup(self, fd):
        pass

    def handle_hup(self, fd):
        pass

    def handle_err(self, fd):
        pass

    @property
    def conn_cnt(self):
        return self._conn_cnt

    @property
    def fds(self):
        return self._fds


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

    def run(self):
        pass
