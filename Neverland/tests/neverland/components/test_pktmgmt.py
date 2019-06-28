#!/usr/bin/python3.6
#coding: utf-8

import time
import pytest

from neverland.test.utils import shm_wrapper, FakeUDPTransmitter

from neverland.pkt import UDPPacket, PktTypes
from neverland.config import JsonConfig
from neverland.utils import ObjectifiedDict
from neverland.components.pktmgmt import (
    SpecialPacketManager,
    SpecialPacketRepeater,
)


shm_config_dict = {
    'shm': {
        'socket_dir': '/tmp/nl-shm-test',
        'manager_socket_name': 'manager.socket',
    }
}

shm_config = JsonConfig(**shm_config_dict)


def with_shm_mgr(func):
    ''' Shared memory worker manager

    With this decorator, test functions will run a SHM worker automatically,
    and close it after the test is done.

    The SharedMemoryManager instance will be passed into the function as the
    first argument.
    '''

    def fixture_wrapper(pkt_2_test):
        return shm_wrapper(func, shm_config, pkt_2_test)

    return fixture_wrapper


@pytest.fixture
def pkt_2_test():
    pkt_fields = {
        'sn': 1,
        'type': PktTypes.CTRL,
        'dest': ('127.0.0.1', 40000),
        'subject': 0x01,
        'content': {'a': 1, 'b': True},
    }
    pkt = UDPPacket()
    pkt.fields = ObjectifiedDict(**pkt_fields)
    pkt.type = pkt.fields.type
    return pkt


@with_shm_mgr
def test_store_n_get(shm_mgr, pkt_2_test):
    pkt_mgr = SpecialPacketManager(shm_config)
    pkt_mgr.init_shm()

    try:
        pkt_mgr.store_pkt(pkt_2_test)
        pkt = pkt_mgr.get_pkt(pkt_2_test.fields.sn)

        assert pkt.__to_dict__() == pkt_2_test.__to_dict__()
    finally:
        pkt_mgr.close_shm()


@with_shm_mgr
def test_pop(shm_mgr, pkt_2_test):
    pkt_mgr = SpecialPacketManager(shm_config)
    pkt_mgr.init_shm()

    try:
        pkt_mgr.store_pkt(pkt_2_test)
        pkt = pkt_mgr.pop_pkt(pkt_2_test.fields.sn)
        assert pkt.__to_dict__() == pkt_2_test.__to_dict__()

        pkt = pkt_mgr.get_pkt(pkt_2_test.fields.sn)
        assert pkt is None
    finally:
        pkt_mgr.close_shm()


@with_shm_mgr
def test_repeat_n_cancle(shm_mgr, pkt_2_test):
    pkt_mgr = SpecialPacketManager(shm_config)
    pkt_mgr.init_shm()

    MAX_TIMES = 10

    try:
        pkt_mgr.repeat_pkt(pkt_2_test, max_rpt_times=MAX_TIMES)

        pkt = pkt_mgr.get_pkt(pkt_2_test.fields.sn)
        assert pkt.__to_dict__() == pkt_2_test.__to_dict__()

        rpt_list = pkt_mgr.get_repeating_sn_list()
        assert pkt_2_test.fields.sn in rpt_list

        max_rpt_times = pkt_mgr.get_pkt_max_repeat_times(pkt_2_test.fields.sn)
        assert max_rpt_times == MAX_TIMES

        rpted_times = pkt_mgr.get_pkt_repeated_times(pkt_2_test.fields.sn)
        assert rpted_times == 0

        _test_other_getter_setters(pkt_mgr, pkt_2_test.fields.sn, rpted_times)

        #################### cancle ####################
        pkt_mgr.cancel_repeat(pkt_2_test.fields.sn)

        rpt_list = pkt_mgr.get_repeating_sn_list()
        assert len(rpt_list) == 0

        r = pkt_mgr.get_pkt_last_repeat_time(pkt_2_test.fields.sn)
        assert r is None

        r = pkt_mgr.get_pkt_next_repeat_time(pkt_2_test.fields.sn)
        assert r is None

        r = pkt_mgr.get_pkt_max_repeat_times(pkt_2_test.fields.sn)
        assert r is None

        r = pkt_mgr.get_pkt_repeated_times(pkt_2_test.fields.sn)
        assert r is None
    finally:
        pkt_mgr.close_shm()


def _test_other_getter_setters(pkt_mgr, sn, rpted_times):
    for _ in range(5):
        pkt_mgr.increase_pkt_repeated_times(sn)

        rpted_times += 1
        current_times = pkt_mgr.get_pkt_repeated_times(sn)
        assert rpted_times == current_times

        now = time.time()
        pkt_mgr.set_pkt_last_repeat_time(sn, now)
        last_rpt_time = pkt_mgr.get_pkt_last_repeat_time(sn)
        assert now == last_rpt_time

        next_ = now + 0.1
        pkt_mgr.set_pkt_next_repeat_time(sn, next_)
        next_rpt_time = pkt_mgr.get_pkt_next_repeat_time(sn)
        assert next_ == next_rpt_time


@with_shm_mgr
def test_repeater(shm_mgr, pkt_2_test):
    pkt_rptr = SpecialPacketRepeater(shm_config)
