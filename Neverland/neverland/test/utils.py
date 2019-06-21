#!/usr/bin/python3.6
#coding: utf-8

import os
import time
import signal

from neverland.components.shm import SharedMemoryManager


'''Utilities for unittests
'''


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
        return func(shm_mgr, *args, **kwargs)
    finally:
        # without any mercy :)
        os.kill(pid, signal.SIGKILL)
        os.remove(shm_mgr_sock)
        os.removedirs(shm_sock_dir)
