import os
import sys
import time
import signal

from nvld.components.shm import *
from nvld.utils.od import ODict
from nvld.glb import GLBInfo


def with_glb_conf(func):

    def wrapper(*args, **kwargs):
        conf_dict = {
            'shm': {
                'socket': '/tmp/nvld-shm.socket'
            }
        }

        GLBInfo._INITED = True
        GLBInfo.config = ODict(**conf_dict)

        return func(*args, **kwargs)

    return wrapper


def with_shm_server(func):

    def wrapper(*args, **kwargs):
        pid = os.fork()
        if pid < 0:
            raise RuntimeError('Failed to call fork()')

        if pid == 0:
            server = SHMServer()
            server.run()

            sys.exit(0)

        # the main process should wait for the server
        time.sleep(2)

        try:
            return func(*args, **kwargs)
        finally:
            # without any mercy :)
            os.kill(pid, signal.SIGKILL)

            if os.path.isfile(GLBInfo.config.shm.socket):
                os.remove(GLBInfo.config.shm.socket)

    return wrapper


@with_glb_conf
def test_run_server():
    server = SHMServer()

    def term_shm_server(*_, **__):
        server.shutdown()

    pid = os.fork()
    if pid < 0:
        raise RuntimeError('Failed to call fork()')

    if pid == 0:
        time.sleep(2)
        os.kill(os.getppid(), signal.SIGUSR2)

        sys.exit(0)
    else:
        signal.signal(signal.SIGUSR2, term_shm_server)
        server.run()


@with_glb_conf
@with_shm_server
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
