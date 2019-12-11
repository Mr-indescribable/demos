import os

from ..aff.tcp import TCPAff
from ..eff.tcp import TCPEff
from ..utils.misc import errno_from_socket


# A TCP connection wrapper that integrates TCPAff and TCPEff.
#
# TCP supports full-duplex natively, but for the sake of our code, we need to
# split it into two parts that work in half-duplex and reintegrate them.
#
# And the FDXTCPConn class provides all APIs that the aff and the eff has,
# thus, we can use it as if either it's an aff or an eff.
class FDXTCPConn():

    def __init__(self, conn, src, plain_mod=True, cryptor=None, blocking=False):
        self._conn = conn
        self._src = src
        self._plain_mod = plain_mod
        self._cryptor = cryptor
        self._blocking = blocking
        self._fd = conn.fileno()

        self._aff = TCPAff(conn, src, plain_mod, cryptor, blocking)
        self._eff = TCPEff(conn, src, plain_mod, cryptor, blocking)

    def settimeout(self, timeout):
        self._conn.settimeout(timeout)

    def recv(self):
        return self._aff.recv()

    def send(self, data):
        return self._eff.send(data)

    def append_data(self, data):
        return self._eff.append_data(data)

    def read_data(self, length):
        return self._aff.read_data(length)

    def pop_data(self, length):
        return self._aff.pop_data(length)

    def update_cryptor(self, cryptor):
        self._aff.update_cryptor(cryptor)
        self._eff.update_cryptor(cryptor)

    def set_next_blk_size(self, blk_size):
        self._aff.set_next_blk_size(blk_size)

    def destroy(self):
        self._conn.close()
        self._sock = None
        self._aff = None
        self._err = None

    def get_socket_errno(self):
        return errno_from_socket(self._conn)

    def get_socket_errmsg(self):
        return os.strerror( self.get_socket_errno() )

    @property
    def fd(self):
        return self._fd

    @property
    def recv_buf_bts(self):
        return self._aff.recv_buf_bts

    @property
    def send_buf_bts(self):
        return self._eff.send_buf_bts

    @property
    def next_blk_size(self):
        return self._aff.next_blk_size

    @property
    def traffic_recv_total(self):
        return self._aff.traffic_recv_total

    @property
    def traffic_recv_1sec(self):
        return self._aff.traffic_recv_1sec

    @property
    def traffic_recv_realtime(self):
        return self._aff.traffic_recv_realtime

    @property
    def traffic_recv_realtime_span(self):
        return self._aff.traffic_recv_realtime_span

    @property
    def traffic_send_total(self):
        return self._eff.traffic_send_total

    @property
    def traffic_send_1sec(self):
        return self._eff.traffic_send_1sec

    @property
    def traffic_send_realtime(self):
        return self._eff.traffic_send_realtime

    @property
    def traffic_send_realtime_span(self):
        return self._eff.traffic_send_realtime_span
