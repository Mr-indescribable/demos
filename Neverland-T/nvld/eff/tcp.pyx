import errno
import socket
import logging

from ..utils.misc import errno_from_exception


logger = logging.getLogger('Main')


TCP_BLOCK_SIZE = 32768


# A TCP efferent is a wrapper of a TCP connection
# which connects to a remote node.
#
# TCPEff objects are always in half-duplex mode.
class TCPEff():

    def __init__(self, conn, src, plain_mod=True, cryptor=None, blocking=False):
        self._send_buf = b''

        self._sock = conn
        self.src = src
        self.plain_mod = plain_mod
        self._cryptor = cryptor
        self._blocking = blocking

        self.fd = self._sock.fileno()
        self._sock.setblocking(blocking)

    def settimeout(self, timeout):
        self._sock.settimeout(timeout)

    def destroy(self):
        self._sock.close()
        self._sock = None

    def _send_blking(self, data=b''):
        # to be compatible with the non-blocking api, the zero length
        # data should be allowed here
        if len(data) == 0:
            return

        if self.plain_mod:
            d2s = data
        else:
            d2s = self._cryptor.encrypt(data) if len(data) > 0 else b''

        return self._sock.send(d2s)

    def _send_nblking(self, data=b''):
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

    # writes data into the socket and returns number of bytes that
    # has been written into the socket.
    def send(self, data=b''):
        if self._blocking:
            return self._send_blking(data)
        else:
            return self._send_nblking(data)

    def append_data(self, data):
        self._send_buf += data

    @property
    def send_buf_len(self):
        return len(self._send_buf)

    def update_cryptor(self, cryptor):
        if self.plain_mod:
            raise RuntimeError(
                "TCPAff cannot be changed from plain mode to encrypting mode"
            )

        self._cryptor = cryptor
