import errno
import socket
import struct
import logging

from ..utils.misc import errno_from_exception
from ..exceptions import ConnectionLost, NotEnoughData
from ..pkt import TCPPacket


logger = logging.getLogger('Main')


TCP_BACKLOG = 128
TCP_BUFFER_SIZE = 65536


SO_ORIGINAL_DST = 80


# A normal TCP afferent is a wrapper of an accepted TCP connection
# which connects two Neverland nodes
class TCPAff():

    def __init__(self, conn, src, plain_mod=False, cryptor=None):
        # a buffer that stores raw data (unprocessed after receiving)
        self._raw_buf = b''

        # a buffer that stores plain data (decrypted if cryptor is provided)
        # if the cryptor is not provided, then this buffer will always be empty
        self._pln_buf = b''

        # But why do we need two buffers while one of them will always be
        # empty? Imagine that there could be a day, that we are not going to
        # encrypt/decrypt data at the time we receive it. Well, maybe?

        self._sock = conn
        self.src = src
        self.plain_mod = False

        # An optional crypto.Cryptor object,
        # it will be used in encryption or decryption if provided.
        # In other words, if the cryptor is not provided,
        # the afferent will work in plain mode.
        self._cryptor = cryptor

        self.fd = self._sock.fileno()
        self._sock.setblocking(False)

    def destroy(self):
        self._sock.close()
        self._sock = None

    def recv(self):
        try:
            data = self._sock.recv(TCP_BUFFER_SIZE)
        except OSError as e:
            if errno_from_exception(e) in (errno.EAGAIN, errno.EWOULDBLOCK):
                return

        if len(data) == 0:
            raise ConnectionLost()

        if self.plain_mod:
            self._raw_buf += data
        else:
            self._pln_buf += self._cryptor.decrypt(data)

    def update_cryptor(self, cryptor):
        if self.plain_mod:
            raise RuntimeError(
                "TCPAff cannot be changed from plain mode to encrypting mode"
            )

        self._cryptor = cryptor

    def buf_len(self):
        if self.plain_mod:
            return len(self._raw_buf)
        else:
            return len(self._pln_buf)

    def pop_data(self, length):
        if length > self.buf_len():
            raise NotEnoughData()

        if self.plain_mod:
            data = self._raw_buf[:length]
            self._raw_buf = self._raw_buf[length:]
        else:
            data = self._pln_buf[:length]
            self._pln_buf = self._pln_buf[length:]

        return data


# A server afferent is a wrapper of a TCP Server socket
# which accepts connections and creates normal afferents
class TCPServerAff():

    def __init__(self, listen_addr, listen_port):
        self.listen_addr = listen_addr
        self.listen_port = listen_port

        self._sock = self.create_socket()
        self.fd = self._sock.fileno()

    def create_socket(self):
        af, type_, proto, canon, sa = socket.getaddrinfo(
                                          host=self.listen_addr,
                                          port=self.listen_port,
                                          proto=socket.SOL_TCP,
                                      )[0]
        sock = socket.socket(af, type_, proto)

        self.setsockopt(sock)
        return sock

    def setsockopt(self, sock):
        sock.setblocking(False)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def listen(self):
        self._sock.bind(
            (self.listen_addr, self.listen_port)
        )

    def destroy(self):
        self._sock.close()
        self._sock = None

    def accept(self):
        try:
            conn, src = self._sock.accept()
        except OSError as e:
            if errno_from_exception(e) in (errno.EAGAIN, errno.EWOULDBLOCK):
                return

        return TCPAff(conn, src)
