from ..aff.tcp import TCPAff
from ..eff.tcp import TCPEff


# A TCP connection wrapper that integrates TCPAff and TCPEff.
#
# TCP supports full-duplex natively, but for the sake of our code, we need to
# split it into two parts that work in half-duplex and reintegrate them.
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

    def send(data):
        return self._eff.send(data)

    def pop_data(self, length):
        return self._aff.pop_data(length)

    def recv_buf_len(self):
        return self._aff.buf_len()

    def update_cryptor(self, cryptor):
        self._aff.update_cryptor(cryptor)
        self._eff.update_cryptor(cryptor)

    def need_to_send(self):
        return self._eff.need_to_send()

    def destroy(self):
        self._conn.close()
        self._sock = None
        self._aff = None
        self._err = None
