import os
import sys
import time
import signal
import threading

from nvld.components.shm import *
from nvld.utils.od import ODict
from nvld.glb import GLBInfo


def __with_glb_conf(func):

    def wrapper(gl_config, *args, **kwargs):
        try:
            gl_config.acquire()

            conf_dict = {
                'shm': {
                    'socket': '/tmp/nvld-shm.socket'
                }
            }

            GLBInfo._INITED = True
            GLBInfo.config = ODict(**conf_dict)

            return func(*args, **kwargs)
        finally:
            gl_config.release()

    return wrapper


# we run the server in a new thread and close it when the function is finished
def __with_shm_server(func):

    def wrapper(*args, **kwargs):
        server = SHMServer()

        def shm_subthread():
            server.run()

        th = threading.Thread(target=shm_subthread)
        th.start()

        try:
            return func(*args, **kwargs)
        finally:
            server.shutdown()

    return wrapper


@__with_glb_conf
def test_run_server():
    server = SHMServer()

    def term_shm_server(*_, **__):
        server.shutdown()

    def terminator(ppid):
        time.sleep(2)
        os.kill(ppid, signal.SIGUSR2)
        sys.exit(0)

    th = threading.Thread(target=terminator, args=(os.getpid(), ))
    th.start()

    signal.signal(signal.SIGUSR2, term_shm_server)
    server.run()

    assert not os.path.isfile(GLBInfo.config.shm.socket)


@__with_glb_conf
@__with_shm_server
def test_init():
    KEY_STR  = 'K0'
    KEY_INT  = 'K1'
    KEY_BOOL = 'K2'
    KEY_NULL = 'K3'
    KEY_LIST = 'K4'
    KEY_DICT = 'K5'

    # The client will check the rcode for us,
    # so we don't need to do any additional check here.
    shm = SHMClient()
    shm.init(KEY_STR,  SHM_TYPE_NC)
    shm.init(KEY_INT,  SHM_TYPE_NC)
    shm.init(KEY_BOOL, SHM_TYPE_NC)
    shm.init(KEY_NULL, SHM_TYPE_NC)
    shm.init(KEY_LIST, SHM_TYPE_ARY)
    shm.init(KEY_DICT, SHM_TYPE_OBJ)


# def test_read_all():
    # pass


# def test_get():
    # pass


# def test_set():
    # pass


# def test_put():
    # pass


# def test_remove():
    # pass


# def test_delete():
    # pass
