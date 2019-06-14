#!/usr/bin/python3.6
#coding: utf-8

from neverland.config import JsonConfig
from neverland.utils import ObjectifiedDict
from neverland.components.shm import (
    Actions,
    ReturnCodes,
    PY_TYPE_MAPPING,
    SHMContainerTypes,
    SharedMemoryManager,
)


shm_config_entity = {
    'shm': {
        'socket_dir': '/tmp/nl-shm-test',
        'manager_socket_name': 'manager.socket',
    }
}

shm_config = JsonConfig(**shm_config_entity)
shm_mgr = SharedMemoryManager(shm_config)


# global variables
connected = False
conn_id = None


def auto_connect(func):
    ''' a decorator helps test functions to connect to the shm_mgr
    '''

    def wrapper(*args, **kwargs):
        global connected

        helped = False

        if not connected:
            resp = _connect()
            helped = True

        assert connected is True
        exec_result = func(*args, **kwargs)

        if helped:
            _disconnect(conn_id)

        assert connected is False
        return exec_result

    return wrapper


def _handle_request(method_name, data):
    ''' runs one of SharedMemoryManager's handle_* method

    :param method_name: name of the method to be tested
    :param data: data that should be received by the SharedMemoryManager worker
    '''

    method = getattr(shm_mgr, method_name)

    data = ObjectifiedDict(**data)
    resp = method(data)
    return ObjectifiedDict(**resp) if isinstance(resp, dict) else resp


def _connect(socket_name='conn-0'):
    global conn_id, connected

    data = {
        'socket': socket_name,
        'action': Actions.CONNECT,
    }
    resp =  _handle_request('handle_connect', data)

    connected = True
    conn_id = resp.conn_id

    return resp


def _disconnect(another_conn_id=None):
    global conn_id, connected

    data = {
        'conn_id': another_conn_id or conn_id,
        'action': Actions.DISCONNECT,
    }
    resp = _handle_request('handle_disconnect', data)

    connected = False
    conn_id = None

    return resp


def test_connection():
    global conn_id, connected

    resp = _connect()
    assert conn_id is not None
    assert connected is True
    assert resp.data.succeeded is True
    assert resp.data.conn_id == resp.conn_id
    assert resp.data.rcode == ReturnCodes.OK
    assert conn_id in shm_mgr.connections

    original_conn_id = resp.conn_id

    resp = _disconnect(conn_id)
    assert resp is None
    assert connected is False
    assert conn_id is None
    assert original_conn_id not in shm_mgr.connections


@auto_connect
def test_locking():
    global conn_id

    KEY = 'something'

    data = {
        'conn_id': conn_id,
        'action': Actions.LOCK,
        'key': KEY,
    }
    resp = _handle_request('handle_lock', data)

    assert resp.data.succeeded is True
    assert KEY in shm_mgr.locks
    assert shm_mgr.locks.get(KEY) == conn_id

    data = {
        'conn_id': conn_id,
        'action': Actions.UNLOCK,
        'key': KEY,
    }
    resp = _handle_request('handle_unlock', data)

    assert resp.data.succeeded is True
    assert KEY not in shm_mgr.locks


@auto_connect
def test_create():
    global conn_id

    KEY_PREFIX = 'create-'

    for tp_name, tp_value in SHMContainerTypes:
        key = KEY_PREFIX + str(tp_value)
        data = {
            'conn_id': conn_id,
            'action': Actions.CREATE,
            'key': key,
            'type': tp_value,
            'value': None,
        }
        resp = _handle_request('handle_create', data)

        assert resp.data.succeeded is True

        # all non queue types that should be stored in shm_mgr.resources
        if tp_value < SHMContainerTypes.FIFO_QUEUE:
            assert key in shm_mgr.resources
            assert isinstance(
                shm_mgr.resources.get(key),
                PY_TYPE_MAPPING.get(tp_value),
            )
        elif tp_value == SHMContainerTypes.FIFO_QUEUE:
            assert key in shm_mgr.fifo_queues

            # default size of FIFO queues
            assert shm_mgr.fifo_queues.get(key).get('size') == 1024

        # Test key confliction
        resp = _handle_request('handle_create', data)
        assert resp.data.succeeded is False
        assert resp.data.rcode == ReturnCodes.KEY_CONFLICT


@auto_connect
def _test_read(type_, key, data):
    global conn_id

    KEY_PREFIX = 'read-'
    key = KEY_PREFIX + key

    data = {
        'conn_id': conn_id,
        'action': Actions.CREATE,
        'key': key,
        'type': type_,
    }
    resp = _handle_request('handle_create', data)
    assert resp.data.succeeded is True
