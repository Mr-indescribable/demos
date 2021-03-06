import os
import time
import errno
import socket
import logging

from ..glb import GLBInfo, GLBComponent
from ..helper.crypto import CryptoHelper
from ..utils.misc import errno_from_exception, errno_from_socket
from ..proto.fmt.tcp import TCP_META_DATA_LEN
from ..exceptions import (
    ConnectionLost,
    NotEnoughData,
    TryAgain,
    TCPError,
    DecryptionFailed,
)


logger = logging.getLogger('Main')


TCP_BACKLOG = 128
TCP_MAX_RECV_SIZE = 32768


SO_ORIGINAL_DST = 80


# A normal TCP afferent is a wrapper of an accepted TCP connection
# which connects to a remote node.
# TCPAff objects are always in half-duplex mode.
class TCPAff():

    def __init__(self, conn, src, plain_mod=True, blocking=False, dnt_hs=False):
        self._sock = conn
        self.src = src
        self._plain_mod = plain_mod
        self._blocking = blocking
        self._cryptor = None

        self._sock.setblocking(blocking)
        self.fd = self._sock.fileno()

        self._handshaked = False
        self._need_handshake = False if dnt_hs else not self._plain_mod

        # self._traiffic_*: variables for the statistics of traffic
        self._traffic_total = 0

        # the time span of the real-time traffic calculation (in seconds)
        self._traffic_calc_span = GLBInfo.config.net.traffic.calc_span
        self._traffic_last_span_outset = time.time()
        self._traffic_realtime = 0

        # The last time of handling I/O event
        self._last_io_time = time.time()

        # A register that stores an integer (or None) which means the size of
        # the next block incoming. This is shortcut for easily avoiding
        # parsing the length field for multiple times.
        self._next_blk_size = None

        # a buffer that stores raw data (unprocessed after receiving)
        self._raw_buf = b''

        # a buffer that stores plain data (decrypted if cryptor is provided)
        # if the cryptor is not provided, then this buffer will always be empty
        self._pln_buf = b''

    def settimeout(self, timeout):
        self._sock.settimeout(timeout)

    def destroy(self):
        self._sock.close()
        self._sock = None

    # Unlike the TCPEff, TCPAff doesn't know about the new IV,
    # so the object which is using TCPAff should give the new IV to it.
    def finish_handshake(self, new_iv):
        self._handshaked = True
        self._need_handshake = False
        self.update_iv(new_iv)

        # once the handshake is done, all data in the self._raw_buf should
        # be decrypted and shifted into self._pln_buf
        if len(self._raw_buf) > 0:
            self._pln_buf += self._cryptor.decrypt(self._raw_buf)
            self._raw_buf = b''

    def _update_traffic_sum(self, data_len):
        self._traffic_total += data_len

        current = time.time()
        if current >= self._traffic_last_span_outset + self._traffic_calc_span:
            self._traffic_realtime = data_len
            self._traffic_last_span_outset = current
        else:
            self._traffic_realtime += data_len

    def _store_data(self, data):
        if self._plain_mod:
            self._raw_buf += data
        else:
            if self._need_handshake:
                self._raw_buf += data
            else:
                self._pln_buf += self._cryptor.decrypt(data)

        self._update_traffic_sum( len(data) )

    def _recv_blking(self):
        data = self._sock.recv(TCP_MAX_RECV_SIZE)

        if len(data) == 0:
            raise ConnectionLost()

        self._store_data(data)
        return len(data)

    def _recv_nblking(self):
        try:
            data = self._sock.recv(TCP_MAX_RECV_SIZE)
        except ConnectionResetError:
            raise ConnectionLost('Connection reset by peer')
        except OSError as e:
            if errno_from_exception(e) in (errno.EAGAIN, errno.EWOULDBLOCK):
                raise TryAgain()
            else:
                raise e

        if len(data) == 0:
            raise ConnectionLost()

        self._store_data(data)
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
            raise RuntimeError("object is in plain mode")

        self._cryptor = cryptor

    def update_iv(self, iv):
        cryptor = CryptoHelper.new_stream_cryptor(iv=iv)
        self.update_cryptor(cryptor)

    def set_next_blk_size(self, blk_size):
        self._next_blk_size = blk_size

    def read_data(self, length):
        if length > self.recv_buf_bts:
            raise NotEnoughData()

        if self._plain_mod:
            return self._raw_buf[:length]
        else:
            if self._need_handshake:
                return self._raw_buf[:length]
            else:
                return self._pln_buf[:length]

    def __decrypt_hs_metadata(self, data, cryptor):
        self._cryptor = cryptor
        self._cryptor.reset()

        try:
            return self._cryptor.decrypt(data)
        except DecryptionFailed:
            # this is impossible unless we are using an AEAD cipher
            return b''  # and returning b'' will cause an InvalidPkt
        finally:
            self._cryptor.reset()

    # trys to decrypt the first piece of metadata with all default cryptors
    # returns b'' while it encounters DecryptionFailed
    @property
    def hs_metadata_iteration(self):
        if not self._need_handshake:
            raise RuntimeError("handshake is done")

        if len(self._raw_buf) < TCP_META_DATA_LEN:
            raise NotEnoughData()

        metadata = self._raw_buf[:TCP_META_DATA_LEN]

        # generator
        return (
            self.__decrypt_hs_metadata(metadata, cryptor)
            for cryptor in GLBComponent.default_stmc_list
        )

    def pop_data(self, length):
        if length > self.recv_buf_bts:
            raise NotEnoughData()

        if self._plain_mod:
            data = self._raw_buf[:length]
            self._raw_buf = self._raw_buf[length:]
        else:
            if self._need_handshake:
                raw_data = self._raw_buf[:length]
                self._raw_buf = self._raw_buf[length:]

                try:
                    data = self._cryptor.decrypt(raw_data)
                except DecryptionFailed:
                    # this is impossible unless we are using an AEAD cipher
                    data = b''
            else:
                data = self._pln_buf[:length]
                self._pln_buf = self._pln_buf[length:]

        return data

    def get_socket_errno(self):
        return errno_from_socket(self._sock)

    def get_socket_errmsg(self):
        return os.strerror( self.get_socket_errno() )

    # bytes held by the receive buffer
    @property
    def recv_buf_bts(self):
        if self._plain_mod:
            return len(self._raw_buf)
        else:
            if self._need_handshake:
                return len(self._raw_buf) + len(self._pln_buf)
            else:
                return len(self._pln_buf)

    @property
    def next_blk_size(self):
        return self._next_blk_size

    @property
    def traffic_recv_total(self):
        return self._traffic_total

    @property
    def traffic_recv_1sec(self):
        return self._traffic_realtime / self._traffic_calc_span

    @property
    def traffic_recv_realtime(self):
        return self._traffic_realtime

    @property
    def traffic_recv_realtime_span(self):
        return self._traffic_calc_span


# A server afferent is a wrapper of a TCP Server socket
# which accepts connections and creates normal afferents
class TCPServerAff():

    def __init__(self, listen_addr, listen_port, plain_mod=False, blocking=False):
        self.listen_addr = listen_addr
        self.listen_port = listen_port
        self._plain_mod = plain_mod
        self._blocking = blocking

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
        sock.setblocking(self._blocking)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def listen(self):
        self._sock.bind(
            (self.listen_addr, self.listen_port)
        )
        self._sock.listen()

    def destroy(self):
        self._sock.close()
        self._sock = None

    # accept as raw materials, returns what socket.accept() returns
    def accept_raw(self):
        try:
            return self._sock.accept()
        except OSError as e:
            if errno_from_exception(e) in (errno.EAGAIN, errno.EWOULDBLOCK):
                raise TryAgain()
            else:
                raise e

    # accept as a help-duplex connection object (TCPAff)
    def accept_hdx(self):
        conn, src = self.accept_raw()

        return TCPAff(
            conn,
            src,
            self._plain_mod,
            self._blocking,
        )
