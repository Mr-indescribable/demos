import os
import time
import errno
import random
import socket
import logging

from ..glb import GLBInfo, GLBComponent
from ..utils.misc import errno_from_exception, errno_from_socket
from ..pkt.general import PktTypes
from ..pkt.tcp import TCPPacket
from ..proto.fn.tcp import TCPFieldNames
from ..helper.crypto import CryptoHelper
from ..helper.tcp import TCPPacketHelper


logger = logging.getLogger('Main')


TCP_BLOCK_SIZE = 32768


# A TCP efferent is a wrapper of a TCP connection
# which connects to a remote node.
#
# TCPEff objects are always in half-duplex mode.
class TCPEff():

    def __init__(self, conn, src, plain_mod=True, blocking=False):
        self._sock = conn
        self.src = src
        self._plain_mod = plain_mod
        self._blocking = blocking
        self._cryptor = None

        self._sock.setblocking(blocking)
        self.fd = self._sock.fileno()

        self._new_iv = None
        self._handshaked = False
        self._need_handshake = not self._plain_mod

        if self._need_handshake:
            self._cryptor = CryptoHelper.random_defaul_stmc()

        # self._traiffic_*: variables for the statistics of traffic
        self._traffic_total = 0

        # the time span of the real-time traffic calculation (in seconds)
        self._traffic_calc_span = GLBInfo.config.net.traffic.calc_span
        self._traffic_last_span_outset = time.time()
        self._traffic_realtime = 0

        # The last time of handling I/O event
        self._last_io_time = time.time()

        self._send_buf = b''

        # fields template of handshake packet
        self._hs_pktf_temp = {
            TCPFieldNames.SN: 0,
            TCPFieldNames.TYPE: PktTypes.IV_CTRL,
            TCPFieldNames.DEST: ('0.0.0.0', 0),
            TCPFieldNames.IV: None,
        }

    def settimeout(self, timeout):
        self._sock.settimeout(timeout)

    def destroy(self):
        self._sock.close()
        self._sock = None

    def initiate_handshake(self):
        self._new_iv = GLBComponent.div_mgr.random_stmc_div()
        self._hs_pktf_temp.udpate( {TCPFieldNames.IV: self._new_iv} )

        iv_pkt = TCPPacket(fields=self._hs_pktf_temp)
        TCPPacketHelper.wrap(iv_pkt)

        # This could be uncompleted in non-blocking mode,
        # so the invoker should keep the poller running until
        # the transmission is over.
        self.send(iv_pkt.data)

        # The method returns the new_iv to the invoker,
        # the invoker should check the ACK and determine
        # whether the handshake is finished. Once the handshake
        # is done, finish_handshake() should be invoked.
        return self._new_iv

    def finish_handshake(self):
        self._handshaked = True
        self._need_handshake = False
        self.update_iv(self._new_iv)

    def _update_traffic_sum(self, data_len):
        self._traffic_total += data_len

        current = time.time()
        if current >= self._traffic_last_span_outset + self._traffic_calc_span:
            self._traffic_realtime = data_len
            self._traffic_last_span_outset = current
        else:
            self._traffic_realtime += data_len

    def _send_blking(self, data=b''):
        # to be compatible with the non-blocking api, the zero length
        # data should be allowed here
        if len(data) == 0:
            return

        if self._plain_mod:
            d2s = data
        else:
            d2s = self._cryptor.encrypt(data) if len(data) > 0 else b''

        # blocking socket will send all data given
        self._update_traffic_sum( len(d2s) )

        return self._sock.send(d2s)

    def _send_nblking(self, data=b''):
        if self._plain_mod:
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

        self._update_traffic_sum(bt_sent)
        return bt_sent

    # writes data into the socket and returns number of bytes that
    # has been written into the socket.
    def send(self, data=b''):
        if self._blocking:
            return self._send_blking(data)
        else:
            return self._send_nblking(data)

    def _append_data_nblk(self, data):
        if self._blocking:
            raise TypeError(
                'appending data into the buffer makes no sense in blocking mode'
            )

        if self._plain_mod:
            pending = data
        else:
            pending = self._cryptor.encrypt(data) if len(data) > 0 else b''

        self._send_buf += pending

    def append_data(self, data):
        # To implement the handshake on the afferent/efferent
        # layer, the first piece of data must be an IV_CTRL packet
        # and it must be intact on the sending side, otherwise, the
        # handshake logic will make no sense.
        if self._need_handshake:
            raise RuntimeError("efferent is not ready")

        self._append_data_nblk(data)

    def append_pkt(self, pkt):
        if self._need_handshake:
            raise RuntimeError("efferent is not ready")

        self._append_data_nblk(pkt.data)

    def update_cryptor(self, cryptor):
        if self._plain_mod:
            raise RuntimeError(
                "TCPEff cannot be changed from plain mode to encrypting mode"
            )

        self._cryptor = cryptor

    def update_iv(self, iv):
        if self._plain_mod:
            raise RuntimeError(
                "TCPEff cannot be changed from plain mode to encrypting mode"
            )

        cryptor = CryptoHelper.new_stream_cryptor(iv=iv)
        self.update_cryptor(cryptor)

    def get_socket_errno(self):
        return errno_from_socket(self._sock)

    def get_socket_errmsg(self):
        return os.strerror( self.get_socket_errno() )

    # bytes held by the send buffer
    @property
    def send_buf_bts(self):
        return len(self._send_buf)

    @property
    def traffic_send_total(self):
        return self._traffic_total

    @property
    def traffic_send_1sec(self):
        return self._traffic_realtime / self._traffic_calc_span

    @property
    def traffic_send_realtime(self):
        return self._traffic_realtime

    @property
    def traffic_send_realtime_span(self):
        return self._traffic_calc_span
