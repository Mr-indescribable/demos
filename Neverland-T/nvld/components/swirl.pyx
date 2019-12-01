from threading import Lock

from ..glb import GLBInfo
from ..fdx.tcp import FDXTCPConn
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

        self._send_buf = b''
        self._send_buf_lk = Lock()

        self._fds = []          # file descriptors
        self._conn_map = {}     # fd-to-conn mapping
        self._conn_lk_map = {}  # fd-to-lock mapping

        # a flag for the Filler to check, the filler should not
        # start filling the channel while this flag is False
        self._ready_to_fill = False

    # makes connection with other node
    def build_channel(self):
        pass

    # closes all connections within the channel
    def close_channel(self):
        pass

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

    @property
    def conn_cnt(self):
        return self._conn_cnt

    @property
    def fds(self):
        return self._fds


# The fake stream generator for the NLSwirl.
# The filler must should be run in a dedicated thread.
class NLSChannelFiller():

    def __init__(self, swirl):
        self._swirl = swirl

    def run(self):
        pass
