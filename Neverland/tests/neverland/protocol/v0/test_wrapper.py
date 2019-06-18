#!/usr/bin/python3.6
#coding: utf-8

import json
import struct

import pytest

from neverland.config import JsonConfig
from neverland.pkt import UDPPacket, PktTypes, FieldTypes
from neverland.protocol.v0.wrapper import ProtocolWrapper
from neverland.protocol.v0.fmt import (
    HeaderFormat,
    DataPktFormat,
    CtrlPktFormat,
    ConnCtrlPktFormat,
    ConnCtrlAckPktFormat,
)


wrapper_config_dict = {
    'net': {
        'crypto': {
            'salt_len': 8,
            'iv_len': 12,
        }
    }
}
wrapper_config = JsonConfig(**wrapper_config_dict)

proto_wrapper = ProtocolWrapper(
    wrapper_config,
    HeaderFormat,
    DataPktFormat,
    CtrlPktFormat,
    ConnCtrlPktFormat,
    ConnCtrlAckPktFormat,
)


def _test_pack_numeral_type(type_, struct_fmt, value, v_uplimit):
    ''' do a single test with a numeral type

    :param type_: field type of the value, enumerated in FieldTypes
    :param struct_fmt: the format argument of struct.pack
    :param value: the value to pack
    :param v_uplimit: the upper limit of the value in current type
    '''

    if value <= v_uplimit:
        res = proto_wrapper._pack_field(value, type_)
        expected = struct.pack(struct_fmt, value)
        assert res == expected
    else:
        with pytest.raises(struct.error):
            proto_wrapper._pack_field(value, type_)


def test_pack_field_u_char():
    uplimit = 0xFF

    for num in range(uplimit - 100, uplimit + 10):
        _test_pack_numeral_type(
            type_      = FieldTypes.STRUCT_U_CHAR,
            struct_fmt = 'B',
            value      = num,
            v_uplimit  = uplimit,
        )


def test_pack_field_u_int():
    uplimit = 0xFFFFFFFF

    for num in range(uplimit - 100, uplimit + 10):
        _test_pack_numeral_type(
            type_      = FieldTypes.STRUCT_U_INT,
            struct_fmt = 'I',
            value      = num,
            v_uplimit  = uplimit,
        )


def test_pack_field_u_long_long():
    #              4   8   12  16
    #              |   |   |   |
    uplimit = 0xFFFFFFFFFFFFFFFF

    for num in range(uplimit - 100, uplimit + 10):
        _test_pack_numeral_type(
            type_      = FieldTypes.STRUCT_U_LONG_LONG,
            struct_fmt = 'Q',
            value      = num,
            v_uplimit  = uplimit,
        )


def test_pack_field_ipv4_sa():
    ip = '127.0.0.1'
    port = 12345

    res = proto_wrapper._pack_field(
        (ip, port), FieldTypes.STRUCT_IPV4_SA
    )

    ip_splited = [int(u) for u in ip.split('.')]
    expected = struct.pack('!BBBBH', *ip_splited, port)

    assert expected == res


def test_pack_field_ipv6_sa():
    # NotImplemented
    pass


def test_pack_field_py_bytes():
    data = 'a striiiiiiiiiiiiiiing'
    res = proto_wrapper._pack_field(data, FieldTypes.PY_BYTES)
    assert res == data.encode()

    data = b'byteeeeeeeeeeeeeeee'
    res = proto_wrapper._pack_field(data, FieldTypes.PY_BYTES)
    assert data == res


def test_pack_field_py_dict():
    data = {
        'a': 1,
        'b': None,
        'c': [1, 2, 3],
        'd': {
            'e': True,
        }
    }
    res = proto_wrapper._pack_field(data, FieldTypes.PY_DICT)

    expected = json.dumps(data).encode()
    assert res == expected


def test_unpack_field():
    pass


def test_make_pkt():
    pass


def test_parse_pkt():
    pass
