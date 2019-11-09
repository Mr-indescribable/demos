from ..aff.tcp import TCPAff
from ..eff.tcp import TCPEff


# A TCP connection wrapper that integrates TCPAff and TCPEff.
#
# TCP supports full-duplex natively, but for the sake of our code, we need to
# split it into two parts that work in half-duplex and reintegrate them.
#
# And the FDXTCPConn class provides all APIs that the aff and the eff has,
# thus, we can use it as if either it's an aff or an eff.
class FDXTCPConn():

    def __init__(self, conn, src, plain_mod=True, cryptor=None):
        self._conn = conn
        self._src = src
        self._plain_mod = plain_mod
        self._cryptor = cryptor
        self.fd = conn.fileno()

        self._aff = TCPAff(conn, src, plain_mod, cryptor)
        self._eff = TCPEff(conn, src, plain_mod, cryptor)

    def recv(self):
        return self._aff.recv()

    def send(self, data):
        return self._eff.send(data)

    def append_data(self, data):
        return self._eff.append_data(data)

    def pop_data(self, length):
        return self._aff.pop_data(length)

    def update_cryptor(self, cryptor):
        self._aff.update_cryptor(cryptor)
        self._eff.update_cryptor(cryptor)

    @property
    def recv_buf_len(self):
        return self._aff.recv_buf_len

    @property
    def send_buf_len(self):
        return self._eff.send_buf_len

    @property
    def next_blk_size(self):
        return self._aff.next_blk_size

    def set_next_blk_size(self, blk_size):
        self._aff.set_next_blk_size(blk_size)

    def destroy(self):
        self._conn.close()
        self._sock = None
        self._aff = None
        self._err = None
