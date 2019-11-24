import errno
import socket
import logging

from ..utils.misc import errno_from_exception
from ..exceptions import ConnectionLost, NotEnoughData, TryAgain


logger = logging.getLogger('Main')


TCP_BACKLOG = 128
TCP_RECV_SIZE = 65536


SO_ORIGINAL_DST = 80


# A normal TCP afferent is a wrapper of an accepted TCP connection
# which connects to a remote node.
# TCPAff objects are always in half-duplex mode.
class TCPAff():

    def __init__(self, conn, src, plain_mod=True, cryptor=None, blocking=False):
        # A register that stores an integer (or None) which means the size of
        # the next block incoming. This is shortcut for easily avoiding
        # parsing the length field for multiple times.
        self._next_blk_size = None

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
        self._plain_mod = plain_mod

        # An optional crypto.Cryptor object,
        # it will be used in encryption or decryption if provided.
        # In other words, if the cryptor is not provided,
        # the afferent will work in plain mode.
        self._cryptor = cryptor
        self._blocking = blocking

        self.fd = self._sock.fileno()
        self._sock.setblocking(blocking)

    def destroy(self):
        self._sock.close()
        self._sock = None

    def _recv_blking(self):
        data = self._sock.recv(TCP_RECV_SIZE)

        if len(data) == 0:
            raise ConnectionLost()

        if self._plain_mod:
            self._raw_buf += data
        else:
            self._pln_buf += self._cryptor.decrypt(data)

        return len(data)

    def _recv_nblking(self):
        try:
            data = self._sock.recv(TCP_RECV_SIZE)
        except OSError as e:
            if errno_from_exception(e) in (errno.EAGAIN, errno.EWOULDBLOCK):
                raise TryAgain()
            else:
                raise e

        if len(data) == 0:
            raise ConnectionLost()

        if self._plain_mod:
            self._raw_buf += data
        else:
            self._pln_buf += self._cryptor.decrypt(data)

        return len(data)

    # receives data from the socket and put it into the buffer
    # returns the length of the received data block
    def recv(self):
        if self._blocking:
            return self._recv_blking()
        else:
            return self._recv_nblking()

    def update_cryptor(self, cryptor):
        if self._plain_mod:
            raise RuntimeError(
                "TCPAff cannot be changed from plain mode to encrypting mode"
            )

        self._cryptor = cryptor

    @property
    def recv_buf_len(self):
        if self._plain_mod:
            return len(self._raw_buf)
        else:
            return len(self._pln_buf)

    @property
    def next_blk_size(self):
        return self._next_blk_size

    def set_next_blk_size(self, blk_size):
        self._next_blk_size = blk_size

    def pop_data(self, length):
        if length > self.recv_buf_len:
            raise NotEnoughData()

        if self._plain_mod:
            data = self._raw_buf[:length]
            self._raw_buf = self._raw_buf[length:]
        else:
            data = self._pln_buf[:length]
            self._pln_buf = self._pln_buf[length:]

        return data


# A server afferent is a wrapper of a TCP Server socket
# which accepts connections and creates normal afferents
class TCPServerAff():

    # The constructor
    #
    # :param plain_mod: used in construction of TCPAff objects
    # :param cryptor:   used in construction of TCPAff objects
    def __init__(self, listen_addr, listen_port, plain_mod=True, cryptor=None):
        self.listen_addr = listen_addr
        self.listen_port = listen_port

        self._sock = self.create_socket()
        self.fd = self._sock.fileno()

        self._plain_mod = plain_mod
        self._cryptor = cryptor

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
                raise TryAgain()
            else:
                raise e

        return TCPAff(conn, src, self._plain_mod, self._cryptor)

    def accept_raw(self):
        try:
            return self._sock.accept()
        except OSError as e:
            if errno_from_exception(e) in (errno.EAGAIN, errno.EWOULDBLOCK):
                raise TryAgain()
            else:
                raise e
