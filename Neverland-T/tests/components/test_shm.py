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
                'net': {
                    'traffic': {
                        'calc_span': 0.1
                    }
                },
                'shm': {
                    'socket': '/tmp/nvld-shm.socket'
                },
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

        thr = threading.Thread(target=shm_subthread)
        thr.start()

        try:
            func_r = func(*args, **kwargs)
        finally:
            # We must wait for the server to shutdown,
            # otherwise the socket file is occupied.
            server.shutdown()
            thr.join()

        return func_r

    return wrapper


# Try to trigger an SHMError and validate its rcode
#
# :param func: a method of SHMClient
# :param func_args: arguments of func
# :param rcode: the expecting rcode in the SHMError
# :param errmsg: the error message to output when the SHMError is not catched
def __expect_err_rcode(func, func_args, rcode, errmsg):
    try:
        func(*func_args)
    except SHMError as e:
        assert e.args[1] == rcode
    else:
        raise Exception(errmsg)


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

    __expect_err_rcode(
        shm.init, ('K_ff', 0xff),
        SHM_RCODE_TYPE_ERROR, 'SHM_RCODE_TYPE_ERROR not catched',
    )

    __expect_err_rcode(
        shm.init, (KEY_STR, SHM_TYPE_NC),
        SHM_RCODE_KEY_CONFLICTION, 'SHM_RCODE_KEY_CONFLICTION not catched',
    )


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

        __expect_err_rcode(
            shm.put, (key, ['Something']),
            SHM_RCODE_TYPE_ERROR, 'SHM_RCODE_TYPE_ERROR not catched',
        )

        __expect_err_rcode(
            shm.remove, (key, 'Something'),
            SHM_RCODE_TYPE_ERROR, 'SHM_RCODE_TYPE_ERROR not catched',
        )

        shm.delete(key)
        __expect_err_rcode(
            shm.read_all, (key, ),
            SHM_RCODE_NO_SUCH_KEY, 'SHM_RCODE_NO_SUCH_KEY not catched',
        )


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

    __expect_err_rcode(
        shm.set, (KEY, 'Something'),
        SHM_RCODE_TYPE_ERROR, 'SHM_RCODE_TYPE_ERROR not catched',
    )

    shm.delete(KEY)
    __expect_err_rcode(
        shm.read_all, (KEY, ),
        SHM_RCODE_NO_SUCH_KEY, 'SHM_RCODE_NO_SUCH_KEY not catched',
    )


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

    __expect_err_rcode(
        shm.set, (KEY, 'Something'),
        SHM_RCODE_TYPE_ERROR, 'SHM_RCODE_TYPE_ERROR not catched',
    )

    shm.delete(KEY)
    __expect_err_rcode(
        shm.read_all, (KEY, ),
        SHM_RCODE_NO_SUCH_KEY, 'SHM_RCODE_NO_SUCH_KEY not catched',
    )
