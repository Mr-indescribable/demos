import os
import sys
import time
import threading

from nvld.glb import GLBInfo, GLBComponent
from nvld.utils.od import ODict
from nvld.utils.ev import DisposableEvent
from nvld.exceptions import TryAgain
from nvld.components.swirl import NLSConnState, NLSwirl, NLSChannelFiller
from nvld.components.conf import JsonConfig
from nvld.components.div import DefaultIVMgr
from nvld.fdx.tcp import FDXTCPServerAff
from nvld.ev.epoll import EpollPoller


_ADDR = '127.0.0.1'
_PORT = 40000


class _NLSReceiver():

    def __init__(self, input_pkt_handler_func):
        self._input_pkt_handler_func = input_pkt_handler_func

        self._poller = EpollPoller()
        self._server = self._create_server()
        self._server_fd = self._server.fd
        self._nls = NLSwirl(
            self._poller,
            is_initiator=False,
            remote=(_ADDR, None),
            conn_num=None,
        )
        self._nls_filler = NLSChannelFiller(self._nls)
        self._nls_filler_thr = None

        self._running = False

        self.ev_ready = DisposableEvent()

    def _create_server(self):
        return FDXTCPServerAff(_ADDR, _PORT, plain_mod=False, blocking=False)

    def _start_filler(self):
        thr = threading.Thread(target=self._nls_filler.run)
        self._nls_filler_thr = thr

        thr.start()

    def _shutdow_filler(self):
        self._nls_filler.shutdown()

    def shutdown(self):
        self._shutdow_filler()
        self._running = False

    def run(self):
        self._poller.register(self._server_fd, self._poller.EV_IN, None)
        self._server.listen()
        self._start_filler()
        self._running = True

        self.ev_ready.trigger()

        while self._running:
            evs = self._poller.poll()

            for fd, ev in evs:
                if fd == self._server_fd:
                    self._handle_accept()
                    continue

                elif fd in self._nls.fds:
                    self._nls.handle_ev(fd, ev)

            self._handle_pkts()

    def _handle_accept(self):
        try:
            conn = self._server.accept_fdx()
        except TryAgain:
            return

        self._nls.add_conn(conn, NLSConnState.CONNECTING)

    def _handle_pkts(self):
        for _ in range(self._nls.pkts_to_read):
            self._input_pkt_handler_func(self._nls.pop_pkt())


def __with_glb_conf(func):

    def wrapper(gl_config, *args, **kwargs):
        try:
            gl_config.acquire()

            div_mgr = DefaultIVMgr(iv_len=32)
            div_mgr.load_as_stmc_iv( os.urandom(32 * 12) )
            div_mgr.load_as_dgmc_iv( os.urandom(32 * 12) )
            GLBComponent.div_mgr = div_mgr

            conf_dict = {
                'net': {
                    'tcp': {
                        'conn_max_retry': 4,
                        'nls_cache_size': 64,
                    },
                    'crypto': {
                        'password': 'The_P@5sw0RD',
                        'stream_cipher': 'kc-aes-256-gcm',
                        'dgram_cipher': 'aes-256-gcm',
                        'salt_len': 8,
                        'iv_len': 12,
                        'iv_duration_range': [1000, 2000],
                    },
                    'traffic': {
                        'calc_span': 0.1,
                        'nls_channel_bw': 100000,
                        'nls_fdata_size_min': 1024,
                        'nls_fdata_size_min': 10240,
                    }
                },
            }

            GLBInfo._INITED = True
            GLBInfo.config = ODict(**conf_dict)

            return func(*args, **kwargs)
        finally:
            gl_config.release()

    return wrapper


def __with_receiver(pkt_handler_func):

    def decorator(func):

        def wrapper(*args, **kwargs):
            recver = _NLSReceiver(pkt_handler_func)
            thr = threading.Thread(target=recver.run)
            thr.start()

            try:
                return func(recver, *args, **kwargs)
            finally:
                recver.shutdown()
                thr.join()

        return wrapper

    return decorator


def _pkt_dropper(pkt):
    return


def _wait_for_channel(nls, poller):
    max_poll = nls._conn_num * 4
    polled = 0

    while polled <= max_poll:
        evs = poller.poll()

        for fd, ev in evs:
            nls.handle_ev(fd, ev)

        connected = 0

        for fd, st in nls._conn_st_map.items():
            if st == NLSConnState.CONNECTED:
                connected += 1

        if connected == nls._conn_num:
            return

        polled += 1

    raise Exception('failed to establish channel')


@__with_glb_conf
@__with_receiver(_pkt_dropper)
def test_build_channel(recver):
    recver.ev_ready.wait()

    poller = EpollPoller()
    nls = NLSwirl(
        poller,
        is_initiator=True,
        remote=(_ADDR, _PORT),
        conn_num=4,
    )

    nls.build_channel()
    _wait_for_channel(nls, poller)

    fds = set()

    assert len(nls._fds) == nls._conn_num

    for fd in nls._fds:
        assert fd not in fds
        fds.add(fd)

        st = nls._conn_st_map.get(fd)
        assert st == NLSConnState.CONNECTED
        assert fd in nls._conn_map
        assert fd in nls._conn_lk_map
