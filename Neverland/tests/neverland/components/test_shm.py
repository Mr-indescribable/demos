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


shm_config_dict = {
    'shm': {
        'socket_dir': '/tmp/nl-shm-test',
        'manager_socket_name': 'manager.socket',
    }
}

shm_config = JsonConfig(**shm_config_dict)
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

    KEY = 'test-locking'

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
def test_create_normal_types():
    global conn_id

    KEY_PREFIX = 'test-normal-create-'

    for tp_name, tp_value in SHMContainerTypes:
        if tp_value >= SHMContainerTypes.FIFO_QUEUE:
            # Only test normal container types here.
            # Types after FIFO_QUEUE should be tested in other functions.
            continue

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

        assert key in shm_mgr.resources
        assert isinstance(
            shm_mgr.resources.get(key),
            PY_TYPE_MAPPING.get(tp_value),
        )

        # Test key confliction
        resp = _handle_request('handle_create', data)
        assert resp.data.succeeded is False
        assert resp.data.rcode == ReturnCodes.KEY_CONFLICT


def _test_normal_rw(type_, key, value):
    global conn_id

    KEY_PREFIX = 'rw-'
    key = KEY_PREFIX + key

    data = {
        'conn_id': conn_id,
        'action': Actions.CREATE,
        'key': key,
        'type': type_,
    }
    resp = _handle_request('handle_create', data)
    assert resp.data.succeeded is True

    # single-value containers
    if type_ <= SHMContainerTypes.BOOL:
        data = {
            'conn_id': conn_id,
            'action': Actions.SET,
            'key': key,
            'type': type_,
            'value': value,
        }
        resp = _handle_request('handle_set', data)
        assert resp.data.succeeded is True

        data = {
            'conn_id': conn_id,
            'action': Actions.READ,
            'key': key,
        }
        resp = _handle_request('handle_read', data)
        assert resp.data.succeeded is True
        assert resp.data.value == value

    # multi-value containers
    elif type_ <= SHMContainerTypes.DICT:
        data = {
            'conn_id': conn_id,
            'action': Actions.ADD,
            'key': key,
            'type': type_,
            'value': value,
        }
        resp = _handle_request('handle_add', data)
        assert resp.data.succeeded is True

        data = {
            'conn_id': conn_id,
            'action': Actions.READ,
            'key': key,
        }
        resp = _handle_request('handle_read', data)
        assert resp.data.succeeded is True

        orig_value = value
        resp_value = resp.data.value

        if type_ == SHMContainerTypes.SET:
            orig_value = list(value)
        elif type_ == SHMContainerTypes.DICT:
            resp_value = resp_value.__to_dict__()

        assert resp_value == orig_value
    else:
        raise Exception('Unexpected container type')


@auto_connect
def test_str_rw():
    _test_normal_rw(
        SHMContainerTypes.STR,
        'test-str',
        'String-value',
    )


@auto_connect
def test_int_rw():
    _test_normal_rw(
        SHMContainerTypes.INT,
        'test-int',
        1024,
    )


@auto_connect
def test_float_rw():
    _test_normal_rw(
        SHMContainerTypes.FLOAT,
        'test-float',
        0.001,
    )


@auto_connect
def test_bool_rw():
    _test_normal_rw(
        SHMContainerTypes.BOOL,
        'test-bool',
        True,
    )


@auto_connect
def test_set_rw():
    _test_normal_rw(
        SHMContainerTypes.SET,
        'test-set',
        {1, 2, 3, 4},
    )


@auto_connect
def test_list_rw():
    _test_normal_rw(
        SHMContainerTypes.LIST,
        'test-list',
        [1, 2, 3, 4],
    )


@auto_connect
def test_dict_rw():
    _test_normal_rw(
        SHMContainerTypes.DICT,
        'test-dict',
        {'a': 1, 'b': 2},
    )


@auto_connect
def test_fifo_create():
    global conn_id

    key = 'test-fifo-create'
    data = {
        'conn_id': conn_id,
        'action': Actions.CREATE,
        'key': key,
        'type': SHMContainerTypes.FIFO_QUEUE,
        # 'size': None,
    }
    resp = _handle_request('handle_create', data)

    assert resp.data.succeeded is True
    assert key in shm_mgr.fifo_queues

    # default size of fifo-queues
    assert shm_mgr.fifo_queues.get(key).get('size') == 1024

    ## Test again with a size argument
    size = 100
    key = 'test-fifo-create-with-size'
    data = {
        'conn_id': conn_id,
        'action': Actions.CREATE,
        'key': key,
        'type': SHMContainerTypes.FIFO_QUEUE,
        'size': size,
    }
    resp = _handle_request('handle_create', data)

    assert resp.data.succeeded is True
    assert key in shm_mgr.fifo_queues

    # default size of fifo-queues
    assert shm_mgr.fifo_queues.get(key).get('size') == size


@auto_connect
def test_fifo_rw():
    global conn_id

    key = 'test-fifo-rw'
    values = [1, 2, 3, 4]

    data = {
        'conn_id': conn_id,
        'action': Actions.CREATE,
        'key': key,
        'type': SHMContainerTypes.FIFO_QUEUE,
    }
    resp = _handle_request('handle_create', data)
    assert resp.data.succeeded is True

    for value in values:
        data = {
            'conn_id': conn_id,
            'action': Actions.FIFO_APPEND,
            'key': key,
            'value': value
        }
        resp = _handle_request('handle_fifo_append', data)
        assert resp.data.succeeded is True

    for value in values:
        data = {
            'conn_id': conn_id,
            'action': Actions.FIFO_POP,
            'key': key,
        }
        resp = _handle_request('handle_fifo_pop', data)
        assert resp.data.succeeded is True

        # First In First Out
        assert resp.data.value == value


def _test_rm_value(type_, key, init_value, value_2_rm, value_remaining):
    global conn_id

    KEY_PREFIX = 'rm-'
    key = KEY_PREFIX + key

    data = {
        'conn_id': conn_id,
        'action': Actions.CREATE,
        'key': key,
        'type': type_,
        'value': init_value,
    }
    resp = _handle_request('handle_create', data)
    assert resp.data.succeeded is True

    # multi-value containers
    if SHMContainerTypes.SET <= type_ <= SHMContainerTypes.DICT:
        data = {
            'conn_id': conn_id,
            'action': Actions.REMOVE,
            'key': key,
            'value': value_2_rm,
        }
        resp = _handle_request('handle_remove', data)
        assert resp.data.succeeded is True

        data = {
            'conn_id': conn_id,
            'action': Actions.READ,
            'key': key,
        }
        resp = _handle_request('handle_read', data)
        assert resp.data.succeeded is True

        resp_value = resp.data.value

        if type_ == SHMContainerTypes.SET:
            assert len(set(resp_value) - set(value_remaining)) == 0
        else:
            if type_ == SHMContainerTypes.DICT:
                resp_value = resp_value.__to_dict__()

            assert resp_value == value_remaining
    else:
        raise Exception('Unexpected container type')


@auto_connect
def test_rm_dict_value():
    _test_rm_value(
        type_           = SHMContainerTypes.DICT,
        key             = 'test-dict',
        init_value      = {'a': 1, 'b': 2, 'c': 3},
        value_2_rm      = ['a', 'b'],
        value_remaining = {'c': 3},
    )


@auto_connect
def test_rm_set_value():
    _test_rm_value(
        type_           = SHMContainerTypes.SET,
        key             = 'test-set',
        init_value      = ['a', 'b', 1, 2],
        value_2_rm      = {'a', 1},
        value_remaining = {'b', 2},
    )


@auto_connect
def test_rm_list_value():
    _test_rm_value(
        type_           = SHMContainerTypes.LIST,
        key             = 'test-list',
        init_value      = ['a', 'b', 1, 2],
        value_2_rm      = ['a', 1],
        value_remaining = ['b', 2],
    )
