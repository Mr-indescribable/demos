import select

from ..utils.misc import VerifiTools


class EpollPoller():

    EV_IN    = select.EPOLLIN
    EV_OUT   = select.EPOLLOUT
    EV_ERR   = select.EPOLLERR
    EV_RDHUP = select.EPOLLRDHUP

    DEFAULT_EV = EV_IN | EV_RDHUP
    DEFAULT_POLL_TIMEOUT = 2

    def __init__(self):
        self._fd_map = dict()
        self._fd_ev_map = dict()
        self._epoll = select.epoll()

    # register an object to the epoll, the object to be registered must contain
    # an attribute 'fd' which contains the value the actual fd to be registered
    def register(self, fd, ev=None, obj=None):
        if fd in self._fd_map:
            raise RuntimeError(f'fd {fd} has already been registered')

        self._epoll.register(fd, ev or self.DEFAULT_EV)
        self._fd_map.update( {fd: obj} )
        self._fd_ev_map.update( {fd: ev} )

    def unregister(self, fd):
        if fd not in self._fd_map:
            raise RuntimeError(f'fd {fd} is not registered')

        self._epoll.unregister(fd)
        self._fd_map.pop(fd)
        self._fd_ev_map.pop(fd)

    def modify(self, fd, ev):
        if fd not in self._fd_map:
            raise RuntimeError(f'fd {fd} is not registered')

        if self._fd_ev_map.get(fd) == ev:
            return

        self._epoll.modify(fd, ev)
        self._fd_ev_map.update( {fd: ev} )

    def has(self, fd):
        return fd in self._fd_map

    def get_registered_obj(self, fd):
        return self._fd_map.get(fd)

    def get_registered_ev(self, fd):
        return self._fd_ev_map.get(fd)

    def poll(self, timeout=None):
        return self._epoll.poll(timeout or self.DEFAULT_POLL_TIMEOUT)
