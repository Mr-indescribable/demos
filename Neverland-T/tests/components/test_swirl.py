import os
import sys
import time
import threading

from nvld.glb import GLBInfo, GLBComponent
from nvld.ginit import ginit_glb_pktfmt
from nvld.utils.od import ODict
from nvld.utils.ev import DisposableEvent
from nvld.exceptions import TryAgain
from nvld.components.swirl import NLSConnState, NLSwirl, NLSChannelFiller
from nvld.components.conf import JsonConfig
from nvld.components.div import DefaultIVMgr
from nvld.components.idg import IDGenerator
from nvld.crypto.wrapper import StreamCryptor
from nvld.proto.wrapper import TCPPacketWrapper
from nvld.fdx.tcp import FDXTCPServerAff
from nvld.ev.epoll import EpollPoller
from nvld.pkt.general import PktProto, PktTypes
from nvld.pkt.tcp import TCPPacket
from nvld.proto.fn.tcp import TCPFieldNames


_ADDR = '127.0.0.1'
_PORT = 40000


class _PacketHandlers():

    _fpkt_only_handler_failed = False
    _spec_only_handler_failed = False

    @classmethod
    def pkt_dropper(cls, recver, pkt):
        recver.succeed()

    @classmethod
    def fpkt_only_handler(cls, recver, pkt):
        if _fpkt_handler_failed:
            return

        assert pkt.proto == PktProto.TCP

        if pkt.fields.type != PktTypes.DATA or not pkt.fields.fake:
            recver.fail()
            cls._fpkt_only_handler_failed = True

        recver.succeed()

    @classmethod
    def spec_pkt_only_handler(cls, recver, pkt):
        if _spec_only_handler_failed:
            return

        exp_pkt = recver._expecting_pkt

        if exp_pkt is None:
            recver.fail()
            cls._spec_only_handler_failed = True

        assert exp_pkt.proto == PktProto.TCP
        assert pkt.proto == PktProto.TCP

        for k, v in pkt.fields:
            exp_v = exp_pkt.fields.get(k)

            if exp_v != v:
                recver.fail()
                cls._spec_only_handler_failed = True
                break
        else:
            # all fields matched
            recver.succeed()


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
        self._succeeded = False

        self._expecting_pkt = None

        self.ev_ready = DisposableEvent()

    def _create_server(self):
        return FDXTCPServerAff(_ADDR, _PORT, plain_mod=False, blocking=False)

    def _start_filler(self):
        thr = threading.Thread(target=self._nls_filler.run)
        self._nls_filler_thr = thr

        thr.start()

    def _shutdow_filler(self):
        # otherwise, the filler will wait forever
        if not self._nls._ready_ev_triggered:
            self._nls._ready_ev.trigger()

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

        self._nls_filler_thr.join()

    def _handle_accept(self):
        try:
            conn = self._server.accept_fdx()
        except TryAgain:
            return

        self._nls.add_conn(conn, NLSConnState.CONNECTING)

    def _handle_pkts(self):
        for _ in range(self._nls.pkts_to_read):
            self._input_pkt_handler_func(self, self._nls.pop_pkt())

    def succeed(self):
        self._succeeded = True

    def fail(self):
        self._succeeded = False

    def expect_pkt(self, pkt):
        self._expecting_pkt = pkt

    @property
    def test_succeeded(self):
        assert self._running == False
        return self._succeeded


def __with_glb_conf(func):

    def wrapper(gl_config, *args, **kwargs):
        try:
            gl_config.acquire()

            conf_dict = {
                'net': {
                    'ipv6': False,
                    'tcp': {
                        'conn_max_retry': 4,
                        'nls_cache_size': 64,
                        'aff_listen_port': None,
                    },
                    'udp': {
                        'aff_listen_port': None,
                    },
                    'crypto': {
                        'password': 'The_P@5sw0RD',
                        'stream_cipher': 'aes-256-gcm',
                        'dgram_cipher': 'kc-aes-256-gcm',
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

            GLBInfo.config = ODict(**conf_dict)
            GLBInfo.max_iv_len = 32
            GLBInfo.local_ip = '127.0.0.1'
            GLBInfo.svr_tcp_port = 20000
            GLBInfo._INITED = True

            GLBComponent.id_generator = IDGenerator(1, 1)

            div_mgr = DefaultIVMgr(iv_len=32)
            div_mgr.load_as_stmc_iv( os.urandom(32 * 12) )
            div_mgr.load_as_dgmc_iv( os.urandom(32 * 12) )
            GLBComponent.div_mgr = div_mgr

            GLBComponent.default_stmc_list = [
                StreamCryptor(iv) for iv in GLBInfo.stmc_div_list
            ]

            ginit_glb_pktfmt()
            GLBComponent.tcp_pkt_wrapper = TCPPacketWrapper()

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


def _get_new_poller_n_nls():
    poller = EpollPoller()
    nls = NLSwirl(
        poller,
        is_initiator=True,
        remote=(_ADDR, _PORT),
        conn_num=4,
    )

    return poller, nls


def _wait_for_channel(nls, poller):
    max_poll = nls._conn_num * 4
    polled = 0

    while polled <= max_poll:
        evs = poller.poll()

        for fd, ev in evs:
            nls.handle_ev(fd, ev)

        ready = 0

        for fd, st in nls._conn_st_map.items():
            if st == NLSConnState.READY:
                ready += 1

        if ready == nls._conn_num:
            return

        polled += 1

    raise Exception('failed to establish channel')


def _wait_for_sending(nls, poller, max_poll_times):
    polled = 0

    while nls.pkts_to_send > 0 and polled <= max_poll_times:
        evs = poller.poll()

        for fd, ev in evs:
            nls.handle_ev(fd, ev)

        polled += 1

    if nls.pkts_to_send > 0:
        raise Exception(
            f'transmission not completed, packet remaining: {nls.pkts_to_send}'
        )


@__with_glb_conf
@__with_receiver(_PacketHandlers.pkt_dropper)
def test_build_n_close(recver):
    recver.ev_ready.wait()
    poller, nls = _get_new_poller_n_nls()

    nls.build_channel()
    _wait_for_channel(nls, poller)

    fds = set()

    assert len(nls._fds) == nls._conn_num

    for fd in nls._fds:
        assert fd not in fds
        fds.add(fd)

        st = nls._conn_st_map.get(fd)
        assert st == NLSConnState.READY
        assert fd in nls._conn_map
        assert fd in nls._conn_lk_map

    nls.close_channel()
    assert len(nls._fds) == 0
    assert len(nls._conn_map) == 0
    assert len(nls._conn_lk_map) == 0
    assert len(nls._conn_st_map) == 0
    assert len(nls._conn_ct_map) == 0


@__with_glb_conf
@__with_receiver(_PacketHandlers.spec_pkt_only_handler)
def _test_send(recver):
    recver.ev_ready.wait()
    poller, nls = _get_new_poller_n_nls()

    nls.build_channel()
    _wait_for_channel(nls, poller)

    pkt_fields = {
        TCPFieldNames.TYPE: PktTypes.DATA,
        TCPFieldNames.FAKE: 0,
        TCPFieldNames.CHANNEL_ID: 100,
        TCPFieldNames.DATA: os.urandom(128),
        TCPFieldNames.DEST: ('127.0.0.1', 12345),
    }
    pkt = TCPPacket(fields=pkt_fields)

    recver.expect_pkt(pkt)
    nls.append_pkt(pkt)

    _wait_for_sending(nls, poller, 8)

    assert recver.test_succeeded
