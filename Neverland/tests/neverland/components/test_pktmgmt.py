#!/usr/bin/python3.6
#coding: utf-8

import pytest

from neverland.test.utils import shm_wrapper

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
        'type': PktTypes.CTRL,
        'dest': ('127.0.0.1', 40000),
        'subject': 0x01,
        'content': {'a': 1, 'b': True},
    }
    pkt = UDPPacket()
    pkt.fields = ObjectifiedDict(**pkt_fields)
    return pkt


@with_shm_mgr
def test_shm(shm_mgr, pkt_2_test):
    pkt_mgr = SpecialPacketManager(shm_config)
    pkt_mgr.init_shm()


    pkt_mgr.close_shm()
