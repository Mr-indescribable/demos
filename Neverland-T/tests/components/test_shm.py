import os
import sys
import time
import signal
import threading

from nvld.exceptions import SHMError
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
            func_r = func(*args, **kwargs)
        finally:
            # We must wait for the server to shutdown,
            # otherwise the socket file is occupied.
            server.shutdown()
            th.join()

        return func_r

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

    # waiting for the terminator thread to send signal

    assert not os.path.exists(GLBInfo.config.shm.socket)


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

    try:
        shm.init(KEY_STR,  SHM_TYPE_NC)
    except SHMError as e:
        assert e.args[1] == SHM_RCODE_KEY_CONFLICTION
    else:
        raise Exception('SHM_RCODE_KEY_CONFLICTION not catched')


@__with_glb_conf
@__with_shm_server
def test_nc():
    TEST_NC_DATA = {
        'K_STR':  ('D_STR', SHM_TYPE_NC),
        'K_NUM':  (123, SHM_TYPE_NC),
        'K_BOOL': (True, SHM_TYPE_NC),
        'K_NULL': (None, SHM_TYPE_NC),
    }

    shm = SHMClient()

    for key, dnt in TEST_NC_DATA.items():
        data, type_ = dnt
        shm.init(key, type_)
        shm.set(key, data)

        got = shm.read_all(key)
        assert got == data

        shm.delete(key)
        try:
            shm.read_all(key)
        except SHMError as e:
            assert e.args[1] == SHM_RCODE_NO_SUCH_KEY
        else:
            raise Exception('SHM_RCODE_NO_SUCH_KEY not catched')


@__with_glb_conf
@__with_shm_server
def test_array():
    KEY = 'K_ARR'
    ELEMENTS = [1, 2, 'a', 'b', True, None]
    ELEMENTS_REDUCED = [1, 'a', 'b', True, None]

    shm = SHMClient()
    shm.init(KEY, SHM_TYPE_ARY)
    shm.put(KEY, ELEMENTS)

    got = shm.read_all(KEY)
    assert got == ELEMENTS

    shm.remove(KEY, 1)
    got = shm.read_all(KEY)
    assert got == ELEMENTS_REDUCED

    shm.delete(KEY)
    try:
        shm.read_all(KEY)
    except SHMError as e:
        assert e.args[1] == SHM_RCODE_NO_SUCH_KEY
    else:
        raise Exception('SHM_RCODE_NO_SUCH_KEY not catched')


@__with_glb_conf
@__with_shm_server
def test_object():
    KEY = 'K_OBJ'
    DATA = {
        'a': 1,
        'b': 2,
        'c': True,
        'd': None
    }
    DATA_REDUCED = {
        'a': 1,
        'c': True,
        'd': None
    }

    shm = SHMClient()
    shm.init(KEY, SHM_TYPE_OBJ)
    shm.put(KEY, DATA)

    got = shm.read_all(KEY)
    assert got == DATA

    shm.remove(KEY, 'b')
    got = shm.read_all(KEY)
    assert got == DATA_REDUCED

    shm.delete(KEY)
    try:
        shm.read_all(KEY)
    except SHMError as e:
        assert e.args[1] == SHM_RCODE_NO_SUCH_KEY
    else:
        raise Exception('SHM_RCODE_NO_SUCH_KEY not catched')
