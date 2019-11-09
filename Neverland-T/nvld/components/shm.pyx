import json
import select
import socket
import struct as pystruct
import logging

from ..glb import GLBInfo
from ..util.od import ODict
from ..exceptions import AddressAlreadyInUse, TryAgain, ConnectionLost
from ..fdx.tcp import FDXTCPConn
from ..aff.tcp import TCPServerAff
from ..ev.epoll import EpollPoller
from ..helper.tcp import NonblockingTCPIOHelper


logger = logging.getLogger('SHM')


class SHMServerAff(TCPServerAff):

    def __init__(self, sock_path):
        self._sock_path = sock_path
        self._sock = self.__create_sock(self._sock_path)
        self.fd = self._sock.fileno()

    def __create_sock(self, sock_path):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.setblocking(False)

        try:
            if sock_path is not None:
                logger.debug(
                    f'created socket and tring to bind on {sock_path}'
                )
                sock.bind(sock_path)
        except OSError as e:
            if e.errno == 98:
                raise AddressAlreadyInUse(
                    f'{sock_path} is already in use, cannot bind on it'
                )
            else:
                raise e

        return sock


# The Shared Memory Server
#
# The shared memory server is a simple TCP server that works with Unix sockets.
# It provides storages to store data in several Python types.
#
# We don't need any encryption or authentication for the shared memory system
# since it's mode for the local inter-process communication only.
#
# Packet format:
#
#     | 4 bytes |        Length bytes       |
#     +---------+---------------------------+
#     | Length  |          Payload          |
#     +---------+---------------------------+
#
#     Length:
#         The length field marks the length of the payload field,
#         it will be packed or parsed as an unsigned integer in little-endian.
#
#     Payload:
#         The payload contains the data we need to transfer, it's length should
#         always match the length field.
#
#         The content of payload field is a serialized JSON string.
class SHMServer():

    def __init__(self):
        self._sock_path = GLBInfo.config.shm.socket
        self._server_aff = SHMServerAff(self.sock_path)
        self._server_fd = self._server_aff.fd

        self._poller = EpollPoller()
        self._poller.register(
            self._server_fd,
            self._poller.EV_IN,
        )

        self._io_helper = NonblockingTCPIOHelper(self._poller)

    def run(self):
        evs = self._poller.poll()

        for fd, ev in evs:
            self._handle_ev(fd, ev)

    def _handle_ev(self, fd, ev):
        if fd == self._server_fd and ev & self._poller.EV_IN:
            self._accept()

        if ev & self._poller.EV_ERR | ev & self._poller.EV_RDHUP:
            pass
        elif ev & self._poller.EV_OUT:
            pass
        elif ev & self._poller.EV_IN:
            pass
        else:
            logger.debug(f"unrecognized ev code: {ev}")

    def _accept(self):
        try:
            conn, src = self.SHMServerAff.accept_raw()
        except TryAgain:
            return

        conn = FDXTCPConn(conn, src)
        self._poller.register(conn.fd, self._poller.DEFAULT_EV, conn)

    def __try_to_parse_next_blk_size(self, conn):
        if conn.next_blk_size is None and conn.recv_buf_len >= 4:
            # pop out 4 bytes of the length field, and then, we'll need to
            # receive a block that matchs the length
            length_bt = conn.pop_data(4)
            length = pystruct.unpack('<I', length_bt)
            conn.set_next_blk_size(length)

    def _handle_in(self, fd):
        conn = self._poller.get_registered_obj(fd)
        pkt_ready = False

        # We should do a recv() first, no matter what will happen next or
        # what we've got now
        try:
            pkt = self._io_helper.handle_recv(conn)
            pkt_ready = True
        except TryAgain:
            # the TryAgain raised by the helper means we've not completely
            # reveived the next packet yet or the next_blk_size is not set.
            # So, if the next_blk_size is not set, then we should try to
            # parse it here.
            if conn.next_blk_size is not None:
                # otherwise, we are waiting for the rest data of the packet.
                return

            self.__try_to_parse_next_blk_size(conn)

            # And we may try again and see if the packet is ready to be parsed.
            try:
                pkt = self._io_helper.pop_packet(conn)
                pkt_ready = True
            except TryAgain:
                # In this case, nothing we can do now,
                # we need to wait the rest data of the packet.
                return
        except ConnectionLost:
            self._handle_destroy(fd)
            return

        if pkt_ready:
            conn.set_next_blk_size(None)
            self._handle_pkt(pkt, conn)

    def _handle_out(self, fd):
        conn = self._poller.get_registered_obj(fd)
        self._io_helper.handle_send(conn)

    def _handle_destroy(self, fd):
        conn = self._poller.get_registered_obj(fd)

        self._poller.unregister(fd)
        conn.destroy()

    def _handle_pkt(self, pkt_bt, conn):
        try:
            pkt = json.loads(pkt_bt.decode())
            pkt = ODict(**pkt)
        except Exception:
            # We don't care what excetpion occurred, if the we cannot parse
            # the data, then just disconnect it.
            self._handle_destroy(conn.fd)

            logger.info(
                f'Unable to parse the data, '
                f'connection from {conn._src} has been removed.'
            )
            return

