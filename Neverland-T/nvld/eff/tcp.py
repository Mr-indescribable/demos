import errno
import socket
import struct
import logging

from ..utils.misc import errno_from_exception
from ..pkt import TCPPacket


logger = logging.getLogger('Main')


TCP_BLOCK_SIZE = 32768


# A TCP efferent is a wrapper of a TCP connection
# which connects to a remote node
class TCPEff():

    def __init__(self, conn, src, plain_mod=True, cryptor=None):
        self._send_buf = b''
        self.has_data = False

        self._sock = conn
        self.src = src
        self.plain_mod = plain_mod
        self._cryptor = cryptor

        self.fd = self._sock.fileno()
        self._sock.setblocking(False)

    def destroy(self):
        self._sock.close()
        self._sock = None

    def send(self, data):
        if self.plain_mod:
            pending = data
        else:
            pending = self._cryptor.encrypt(data)

        self._send_buf += pending
        buf_len = len(self._send_buf)

        if buf_len > TCP_BLOCK_SIZE:
            d2s = self._send_buf[:TCP_BLOCK_SIZE]
        else:
            d2s = self._send_buf

        d2s_len = len(d2s)

        try:
            bt_sent = self._sock.send(d2s)
        except OSError as e:
            if errno_from_exception(e) in (errno.EAGAIN, errno.EWOULDBLOCK):
                return -1

        # The cursor moves forward by bt_sent bytes
        self._send_buf = self._send_buf[bt_sent:]

        if len(self._send_buf) > 0:
            self.has_data = True
        else:
            self.has_data = False

        return bt_sent

    def update_cryptor(self, cryptor):
        if self.plain_mod:
            raise RuntimeError(
                "TCPAff cannot be changed from plain mode to encrypting mode"
            )

        self._cryptor = cryptor
