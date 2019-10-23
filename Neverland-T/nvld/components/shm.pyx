import select
import socket

from ..glb import GLBInfo
from ..exceptions import AddressAlreadyInUse, EAgain
from ..fdx.tcp import FDXTCPConn
from ..aff.tcp import TCPServerAff
from ..ev.epoll import EpollPoller


class SHMServerAff(TCPServerAff):

    def __init__(self, sock_path):
        self._sock_path = sock_path
        self._sock = self.__create_sock()
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
                    f'{socket_path} is already in use, cannot bind on it'
                )
            else:
                raise err

        return sock


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

    def run(self):
        evs = self._poller.poll()

        for fd, ev in evts:
            self._handle_ev(fd, ev)

    def _handle_ev(self, fd, ev):
        if fd == self._server_fd and ev & self._poller.EV_IN:
            self._accept()

    def _accept(self):
        try:
            conn, src = self.SHMServerAff.accept()
        except EAgain:
            return

        conn = FDXTCPConn(conn, src)
        self._poller.register(conn.fd, None, conn)
        # TODO to be continued...
