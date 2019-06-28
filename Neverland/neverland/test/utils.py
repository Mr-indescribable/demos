#!/usr/bin/python3.6
#coding: utf-8

import os
import time
import signal

from neverland.components.shm import SharedMemoryManager


'''Utilities for unittests
'''


SOCK_NAME = 'shm-wrapper.socket'


def shm_wrapper(func, shm_config, *args, **kwargs):
    ''' A wrapper for test functions that need to use the SHM worker

    This wrapper should be used inside a decorator.

    It will help test functions to automatically start and stop
    the SHM worker and pass the instance of the SharedMemoryManager
    into the test function as the first positional argument.

    ----------------------------------
    A simple example:

        shm_config = JsonConfig(**some_config)

        def with_shm(func):
            def wrapper(*args, **kwargs):
                return shm_wrapper(func, shm_config, *args, **kwargs)
            return wrapper

        @with_shm
        def test_something(shm_mgr, arg):
            do_something()
    ----------------------------------

    :param func: the test funcion which has decorated
    :param shm_config: an ObjectifiedDict instance that contains
                       informations needed by the SharedMemoryManager
    :param args: args should be passed into the func
    :param kwargs: same as args
    '''

    shm_sock_dir = shm_config.shm.socket_dir
    shm_mgr_sock = os.path.join(
        shm_sock_dir,
        shm_config.shm.manager_socket_name,
    )

    os.makedirs(shm_sock_dir)
    shm_mgr = SharedMemoryManager(shm_config)

    pid = os.fork()
    if pid < 0:
        raise RuntimeError('Failed to call fork()')

    if pid == 0:
        shm_mgr.run_as_worker()

        # The SHM worker process must be terminated here
        sys.exit(0)

    # wait for the SHM worker
    time.sleep(2)

    try:
        shm_mgr.connect(SOCK_NAME)
        return func(shm_mgr, *args, **kwargs)
    finally:
        shm_mgr.disconnect()

        # without any mercy :)
        os.kill(pid, signal.SIGKILL)
        os.remove(shm_mgr_sock)
        os.removedirs(shm_sock_dir)


class FakeUDPTransmitter:

    ''' A fake efferent class for testing SpecialPacketRepeater

    In these unittests we cannot let the Repeater send out those packets.
    Instead, we tamper the efferent and intercept all packet with it.
    And then we can do some assert in the transmit method.
    '''

    def __init__(self, config, shared_socket=None, expected_pkts=None):
        ''' COnstructor

        :param expected_pkts: UDPPacket instances that will be passed into the
                              transmit method. If a packet not included in it
                              has been passed into the transmit method, then
                              an AssertionError will be raised.
        '''

        self.config = config
        self.expected_pkts_raw = expected_pkts

        self.expected_pkts = [pkt.__to_dict__() for pkt in expected_pkts]

    def create_socket(self, bind_port=None):
        return None

    def setsockopt(self, sock):
        pass

    def transmit(self, pkt):
        assert pkt.__to_dict__() in sefl.expected_pkts
