import os

from ..eff.tcp import TCPEff
from ..aff.tcp import TCPAff, TCPServerAff
from ..utils.misc import errno_from_socket


# A TCP connection wrapper that integrates TCPAff and TCPEff.
#
# TCP supports full-duplex natively, but for the sake of our code, we need to
# split it into two parts that work in half-duplex and reintegrate them.
#
# And the FDXTCPConn class provides all APIs that the aff and the eff has,
# thus, we can use it as if either it's an aff or an eff.
class FDXTCPConn():

    def __init__(self, conn, src, plain_mod=True, blocking=False, dnt_hs=False):
        self._conn = conn
        self._src = src
        self._plain_mod = plain_mod
        self._blocking = blocking
        self._fd = conn.fileno()

        self._aff = TCPAff(conn, src, plain_mod, blocking, dnt_hs)
        self._eff = TCPEff(conn, src, plain_mod, blocking, dnt_hs)

    def settimeout(self, timeout):
        self._conn.settimeout(timeout)

    def recv(self):
        return self._aff.recv()

    def send(self, data):
        return self._eff.send(data)

    def sync_cryptor_from_aff(self):
        self._eff.update_cryptor(self._aff._cryptor)

    def sync_cryptor_from_eff(self):
        self._aff.update_cryptor(self._eff._cryptor)

    def initiate_handshake(self):
        new_iv = self._eff.initiate_handshake()

        self._aff._need_handshake = False
        self.sync_cryptor_from_eff()

        return new_iv

    def finish_handshake(self, new_iv):
        self._aff.finish_handshake(new_iv)
        self._eff.finish_handshake(new_iv)

    @property
    def hs_metadata_iteration(self):
        return self._aff.hs_metadata_iteration

    def append_data(self, data):
        return self._eff.append_data(data)

    def append_pkt(self, pkt):
        return self._eff.append_pkt(pkt)

    def read_data(self, length):
        return self._aff.read_data(length)

    def pop_data(self, length):
        return self._aff.pop_data(length)

    def update_cryptor(self, cryptor):
        self._aff.update_cryptor(cryptor)
        self._eff.update_cryptor(cryptor)

    def update_iv(self, iv):
        self._aff.update_iv(iv)
        self._eff.update_iv(iv)

    def set_next_blk_size(self, blk_size):
        self._aff.set_next_blk_size(blk_size)

    def destroy(self):
        self._conn.close()
        self._sock = None

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


class FDXTCPServerAff(TCPServerAff):

    def accept_fdx(self):
        conn, src = self.accept_raw()
        return FDXTCPConn(
            conn,
            src,
            self._plain_mod,
            self._blocking,
        )
