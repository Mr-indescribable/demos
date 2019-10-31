import errno
import socket
import struct
import logging

from ..utils.misc import errno_from_exception
from ..pkt import TCPPacket


logger = logging.getLogger('Main')


TCP_BLOCK_SIZE = 32768


# A TCP efferent is a wrapper of a TCP connection
# which connects to a remote node.
#
# TCPEff objects are always in half-duplex mode.
class TCPEff():

    def __init__(self, conn, src, plain_mod=True, cryptor=None):
        self._send_buf = b''

        self._sock = conn
        self.src = src
        self.plain_mod = plain_mod
        self._cryptor = cryptor

        self.fd = self._sock.fileno()
        self._sock.setblocking(False)

    def destroy(self):
        self._sock.close()
        self._sock = None

    # writes data into the socket and returns number of bytes that
    # has been written into the socket.
    def send(self, data=b''):
        if self.plain_mod:
            pending = data
        else:
            pending = self._cryptor.encrypt(data) if len(data) > 0 else b''

        self._send_buf += pending
        buf_len = len(self._send_buf)

        if buf_len == 0:
            return 0

        if buf_len > TCP_BLOCK_SIZE:
            d2s = self._send_buf[:TCP_BLOCK_SIZE]
        else:
            d2s = self._send_buf

        d2s_len = len(d2s)

        try:
            bt_sent = self._sock.send(d2s)
        except OSError as e:
            if errno_from_exception(e) in (errno.EAGAIN, errno.EWOULDBLOCK):
                return 0
            else:
                raise e

        # The cursor moves forward by bt_sent bytes
        self._send_buf = self._send_buf[bt_sent:]

        return bt_sent

    @property
    def send_buf_len(self):
        return len(self._send_buf)

    def update_cryptor(self, cryptor):
        if self.plain_mod:
            raise RuntimeError(
                "TCPAff cannot be changed from plain mode to encrypting mode"
            )

        self._cryptor = cryptor
