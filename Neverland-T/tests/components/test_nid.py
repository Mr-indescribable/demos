import json

from nvld.components.nid import NIDMgr


data_2_test = {
    'group_0': {
        'key_0': 'value_0',
        'key_1': 'value_1',
        'key_2': 'value_2',
    },
    'group_1': {
        'key_0': 'value_3',
        'key_1': 'value_4',
        'key_2': 'value_5',
    },
    'group_2': {
        'key_0': 'value_6',
        'key_1': 'value_7',
        'key_2': 'value_8',
    },
    'group_3': {
        'key_0': 'value_9',
        'key_1': 'value_10',
        'key_2': 'value_11',
    },
    'group_4': {
        'key_0': 'value_12',
        'key_1': 'value_13',
        'key_2': 'value_14',
    },
    'group_5': {
        'key_0': 'value_15',
        'key_1': 'value_16',
        'key_2': 'value_17',
    },
    'group_6': {
        'key_0': 'value_18',
        'key_1': 'value_19',
        'key_2': 'value_20',
    },
}


def test_cross():
    nid_mgr = NIDMgr()

    byte0  = b'\xe3'     # 1 1 1 0 0 0 1 1
    byte1  = b'\x6a'     #  0 1 1 0 1 0 1 0
    result = b'\xbc\x4e' # 1011110001001110

    r = nid_mgr.bit_cross(byte0, byte1)

    assert r == result


def test_uncross():
    nid_mgr = NIDMgr()

    in_byte = b'\xbc\x4e' # 1011110001001110
    byte0   = b'\xe3'     # 1 1 1 0 0 0 1 1
    byte1   = b'\x6a'     #  0 1 1 0 1 0 1 0

    o_b0, o_b1 = nid_mgr.bit_uncross(in_byte)

    assert o_b0 == byte0
    assert o_b1 == byte1


def test_nid():
    nid_mgr = NIDMgr()

    conf_data = json.dumps(data_2_test).encode()
    nid_0, div_used_0 = nid_mgr.gen_nid_data(conf_data)

    div_0, parsed_conf_0 = nid_mgr.parse_nid_data(nid_0)

    assert div_0 == div_used_0
    assert conf_data == parsed_conf_0
    assert len(div_0) == len(conf_data)

    nid_1, div_used_1 = nid_mgr.gen_nid_data(conf_data, div_used_0)
    div_1, parsed_conf_1 = nid_mgr.parse_nid_data(nid_1)

    assert div_1 == div_used_1
    assert div_used_1 == div_used_0
    assert conf_data == parsed_conf_1
