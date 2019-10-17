#!/usr/bin/python3.6
#coding: utf-8

import os
import json
import struct

import pytest

from nvld.config import JsonConfig
from nvld.utils import ODict
from nvld.components.idg import IDGenerator
from nvld.pkt.general import PktTypes, FieldTypes
from nvld.pkt.tcp import TCPPacket
from nvld.pkt.udp import UDPPacket
from nvld.proto.wrapper import PacketWrapper

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

packet_wrapper = ProtocolWrapper(wrapper_config)


def _test_pack_numeral_type(type_, struct_fmt, value, v_uplimit):
    ''' do a single test of packing with a numeral type

    :param type_: field type of the value, enumerated in FieldTypes
    :param struct_fmt: the format argument of struct.pack
    :param value: the value to pack
    :param v_uplimit: the upper limit of the value in current type
    '''

    if value <= v_uplimit:
        res = packet_wrapper._pack_field(value, type_)
        expected = struct.pack(struct_fmt, value)
        assert res == expected
    else:
        with pytest.raises(struct.error):
            packet_wrapper._pack_field(value, type_)


def test_pack_field_u_char():
    uplimit = 0xFF

    for num in range(uplimit - 100, uplimit + 10):
        _test_pack_numeral_type(
            type_      = FieldTypes.STRUCT_U_CHAR,
            struct_fmt = 'B',
            value      = num,
            v_uplimit  = uplimit,
        )


def test_pack_field_u_short():
    uplimit = 0xFFFF

    for num in range(uplimit - 100, uplimit + 10):
        _test_pack_numeral_type(
            type_      = FieldTypes.STRUCT_U_CHAR,
            struct_fmt = 'H',
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

    res = packet_wrapper._pack_field(
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
    res = packet_wrapper._pack_field(data, FieldTypes.PY_BYTES)
    assert res == data.encode()

    data = b'byteeeeeeeeeeeeeeee'
    res = packet_wrapper._pack_field(data, FieldTypes.PY_BYTES)
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
    res = packet_wrapper._pack_field(data, FieldTypes.PY_DICT)

    expected = json.dumps(data).encode()
    assert res == expected


def _test_unpack_numeral_type(type_, struct_fmt, data, length):
    ''' do a single test of unpacking with a numeral type

    :param type_: field type of the data, enumerated in FieldTypes
    :param struct_fmt: the format argument of struct.pack
    :param data: the data to unpack
    :param length: the length of current type
    '''

    if len(data) == length:
        res = packet_wrapper._unpack_field(data, type_)
        expected = struct.unpack(struct_fmt, data)[0]
        assert res == expected
    else:
        with pytest.raises(struct.error):
            packet_wrapper._unpack_field(data, type_)


def test_unpack_field_u_char():
    length = 1

    for l in range(0, length + 2):
        _test_unpack_numeral_type(
            type_      = FieldTypes.STRUCT_U_CHAR,
            struct_fmt = 'B',
            data       = os.urandom(l),
            length     = length,
        )


def test_unpack_field_u_short():
    length = 2

    for l in range(0, length + 2):
        _test_unpack_numeral_type(
            type_      = FieldTypes.STRUCT_U_SHORT,
            struct_fmt = 'H',
            data       = os.urandom(l),
            length     = length,
        )


def test_unpack_field_u_int():
    length = 4

    for l in range(0, length + 2):
        _test_unpack_numeral_type(
            type_      = FieldTypes.STRUCT_U_INT,
            struct_fmt = 'I',
            data       = os.urandom(l),
            length     = length,
        )


def test_unpack_field_u_long_long():
    length = 8

    for l in range(0, length + 2):
        _test_unpack_numeral_type(
            type_      = FieldTypes.STRUCT_U_LONG_LONG,
            struct_fmt = 'Q',
            data       = os.urandom(l),
            length     = length,
        )


def test_unpack_field_ipv4_sa():
    ip = '127.0.0.1'
    port = 12345

    packed_sa = packet_wrapper._pack_field(
        (ip, port), FieldTypes.STRUCT_IPV4_SA
    )

    res = packet_wrapper._unpack_field(
        packed_sa, FieldTypes.STRUCT_IPV4_SA
    )

    assert (ip, port) == res


def test_unpack_field_ipv6_sa():
    # NotImplemented
    pass


def test_unpack_field_py_bytes():
    data = b'byteeeeeeeeeeeeeeee'
    res = packet_wrapper._unpack_field(data, FieldTypes.PY_BYTES)
    assert data == res


def test_unpack_field_py_dict():
    data = {
        'a': 1,
        'b': None,
        'c': [1, 2, 3],
        'd': {
            'e': True,
        }
    }
    packed_dict = packet_wrapper._pack_field(data, FieldTypes.PY_DICT)
    res = packet_wrapper._unpack_field(packed_dict, FieldTypes.PY_DICT)
    assert data == res


def _init_glb():
    NodeContext.local_ip = '127.0.0.1'
    NodeContext.listen_port = 40000
    NodeContext.id_generator = IDGenerator(0x01, 0x01)


def test_make_n_parse_udp_pkt():
    _init_glb()

    # Prepare 4 types of packets
    data_pkt_fields = {
        'type': PktTypes.DATA,
        'dest': ('127.0.0.1', 40000),
        'data': os.urandom(40000),
    }
    data_pkt = UDPPacket()
    data_pkt.fields = ObjectifiedDict(**data_pkt_fields)

    ctrl_pkt_fields = {
        'type': PktTypes.CTRL,
        'dest': ('127.0.0.1', 40000),
        'subject': 0x01,
        'content': {'a': 1, 'b': True},
    }
    ctrl_pkt = UDPPacket()
    ctrl_pkt.fields = ObjectifiedDict(**ctrl_pkt_fields)

    conn_ctrl_pkt_fields = {
        'type': PktTypes.CONN_CTRL,
        'dest': ('127.0.0.1', 40000),
        'communicating': 0x01,
        'iv_changed': 0x01,
        'iv_duration': 0xFFFFFFFFF,
        'iv': os.urandom(wrapper_config.net.crypto.iv_len),
    }
    conn_ctrl_pkt = UDPPacket()
    conn_ctrl_pkt.fields = ObjectifiedDict(**conn_ctrl_pkt_fields)

    conn_ctrl_ack_pkt_fields = {
        'type': PktTypes.CONN_CTRL_ACK,
        'dest': ('127.0.0.1', 40000),
        'resp_sn': 1,
    }
    conn_ctrl_ack_pkt = UDPPacket()
    conn_ctrl_ack_pkt.fields = ObjectifiedDict(**conn_ctrl_ack_pkt_fields)

    pkts = {
        PktTypes.DATA: data_pkt,
        PktTypes.CTRL: ctrl_pkt,
        PktTypes.CONN_CTRL: conn_ctrl_pkt,
        PktTypes.CONN_CTRL_ACK: conn_ctrl_ack_pkt,
    }

    # preparation completed, now we do the test
    for pkt_type, body_fmt in packet_wrapper._body_fmt_mapping.items():
        original_pkt = pkts.get(pkt_type)
        udp_data = packet_wrapper.make_udp_pkt(original_pkt, body_fmt)

        pkt_to_parse = UDPPacket()
        pkt_to_parse.data = udp_data
        parsed_fields, parsed_byte_fields = \
                packet_wrapper.parse_udp_pkt(pkt_to_parse)

        packet_wrapper._validate_pkt(parsed_fields, parsed_byte_fields)
        assert original_pkt.fields.__to_dict__() == parsed_fields.__to_dict__()
