import os
import json
import struct

import pytest

from nvld.glb import GLBInfo, GLBComponent
from nvld.ginit import ginit_glb_pktfmt
from nvld.utils.od import ODict
from nvld.pkt.tcp import TCPPacket
from nvld.pkt.general import PktTypes, FieldTypes, PktProto
from nvld.proto.wrapper import TCPPacketWrapper
from nvld.proto.fn.tcp import TCPFieldNames
from nvld.components.conf import JsonConfig
from nvld.components.idg import IDGenerator


def _ginit():
    config_dict = {
        'net': {
            'ipv6': False,
            'crypto': {
                'salt_len': 8,
            }
        }
    }

    GLBInfo.config       = JsonConfig(**config_dict)
    GLBInfo.local_ip     = '127.0.0.1'
    GLBInfo.svr_tcp_port = 10000
    GLBInfo.svr_udp_port = 20000
    GLBInfo.svr_tcp_sa   = (GLBInfo.local_ip, GLBInfo.svr_tcp_port)
    GLBInfo.svr_udp_sa   = (GLBInfo.local_ip, GLBInfo.svr_udp_port)
    GLBInfo._INITED = True

    ginit_glb_pktfmt()

    GLBComponent.id_generator = IDGenerator(1, 1)
    GLBComponent._INITED = True


packet_wrapper = None


def __with_globals(func):

    def wrapper(gl_config, *args, **kwargs):
        global packet_wrapper

        try:
            gl_config.acquire()

            _ginit()
            packet_wrapper = TCPPacketWrapper()

            return func(*args, **kwargs)
        finally:
            gl_config.release()

    return wrapper


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


@__with_globals
def test_pack_field_u_char():
    uplimit = 0xFF

    for num in range(uplimit - 100, uplimit + 10):
        _test_pack_numeral_type(
            type_      = FieldTypes.STRUCT_U_CHAR,
            struct_fmt = 'B',
            value      = num,
            v_uplimit  = uplimit,
        )


@__with_globals
def test_pack_field_u_short():
    uplimit = 0xFFFF

    for num in range(uplimit - 100, uplimit + 10):
        _test_pack_numeral_type(
            type_      = FieldTypes.STRUCT_U_SHORT,
            struct_fmt = 'H',
            value      = num,
            v_uplimit  = uplimit,
        )


@__with_globals
def test_pack_field_u_int():
    uplimit = 0xFFFFFFFF

    for num in range(uplimit - 100, uplimit + 10):
        _test_pack_numeral_type(
            type_      = FieldTypes.STRUCT_U_INT,
            struct_fmt = 'I',
            value      = num,
            v_uplimit  = uplimit,
        )


@__with_globals
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


@__with_globals
def test_pack_field_ipv4_sa():
    ip = '127.0.0.1'
    port = 12345

    res = packet_wrapper._pack_field(
        (ip, port), FieldTypes.STRUCT_IPV4_SA
    )

    ip_splited = [int(u) for u in ip.split('.')]
    expected = struct.pack('!BBBBH', *ip_splited, port)

    assert expected == res


@__with_globals
def test_pack_field_ipv6_sa():
    # NotImplemented
    pass


@__with_globals
def test_pack_field_py_bytes():
    data = 'a striiiiiiiiiiiiiiing'
    res = packet_wrapper._pack_field(data, FieldTypes.PY_BYTES)
    assert res == data.encode()

    data = b'byteeeeeeeeeeeeeeee'
    res = packet_wrapper._pack_field(data, FieldTypes.PY_BYTES)
    assert data == res


@__with_globals
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


@__with_globals
def test_unpack_field_u_char():
    length = 1

    for l in range(0, length + 2):
        _test_unpack_numeral_type(
            type_      = FieldTypes.STRUCT_U_CHAR,
            struct_fmt = 'B',
            data       = os.urandom(l),
            length     = length,
        )


@__with_globals
def test_unpack_field_u_short():
    length = 2

    for l in range(0, length + 2):
        _test_unpack_numeral_type(
            type_      = FieldTypes.STRUCT_U_SHORT,
            struct_fmt = 'H',
            data       = os.urandom(l),
            length     = length,
        )


@__with_globals
def test_unpack_field_u_int():
    length = 4

    for l in range(0, length + 2):
        _test_unpack_numeral_type(
            type_      = FieldTypes.STRUCT_U_INT,
            struct_fmt = 'I',
            data       = os.urandom(l),
            length     = length,
        )


@__with_globals
def test_unpack_field_u_long_long():
    length = 8

    for l in range(0, length + 2):
        _test_unpack_numeral_type(
            type_      = FieldTypes.STRUCT_U_LONG_LONG,
            struct_fmt = 'Q',
            data       = os.urandom(l),
            length     = length,
        )


@__with_globals
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


@__with_globals
def test_unpack_field_ipv6_sa():
    # NotImplemented
    pass


@__with_globals
def test_unpack_field_py_bytes():
    data = b'byteeeeeeeeeeeeeeee'
    res = packet_wrapper._unpack_field(data, FieldTypes.PY_BYTES)
    assert data == res


@__with_globals
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


@__with_globals
def test_make_n_parse_tcp_pkt():
    # Prepare 4 types of packets
    data_pkt_fields = {
        TCPFieldNames.SN: 0,
        TCPFieldNames.TYPE: PktTypes.DATA,
        TCPFieldNames.DEST: ('127.0.0.1', 40000),
        TCPFieldNames.DATA: os.urandom(2000),
        TCPFieldNames.CHANNEL_ID: 1,
    }
    data_pkt = TCPPacket()
    data_pkt.type = PktTypes.DATA
    data_pkt.fields = ODict(**data_pkt_fields)

    conn_ctrl_pkt_fields = {
        TCPFieldNames.SN: 0,
        TCPFieldNames.TYPE: PktTypes.CONN_CTRL,
        TCPFieldNames.TRANSACTION: 1,
        TCPFieldNames.CHANNEL_ID: 2,
        TCPFieldNames.IS_IPV4: 1,
        TCPFieldNames.DEST: ('127.0.0.1', 40000),
        TCPFieldNames.V4ADDR: ('127.0.0.1', 100),
    }
    conn_ctrl_pkt = TCPPacket()
    conn_ctrl_pkt.type = PktTypes.CONN_CTRL
    conn_ctrl_pkt.fields = ODict(**conn_ctrl_pkt_fields)

    clst_ctrl_pkt_fields = {
        TCPFieldNames.SN: 0,
        TCPFieldNames.TYPE: PktTypes.CLST_CTRL,
        TCPFieldNames.DEST: ('127.0.0.1', 40000),
        TCPFieldNames.SUBJECT: 0x01,
        TCPFieldNames.ARGS: {'a': 1, 'b': True},
    }
    clst_ctrl_pkt = TCPPacket()
    clst_ctrl_pkt.type = PktTypes.CLST_CTRL
    clst_ctrl_pkt.fields = ODict(**clst_ctrl_pkt_fields)

    pkts = {
        PktTypes.DATA: data_pkt,
        PktTypes.CONN_CTRL: conn_ctrl_pkt,
        PktTypes.CLST_CTRL: clst_ctrl_pkt,
    }

    # preparation completed, now we do the test
    for pkt_type, pkt in pkts.items():
        fmt = packet_wrapper._find_fmt(pkt.proto, pkt_type)
        original_pkt = pkts.get(pkt_type)
        wrapped_pkt = packet_wrapper.wrap(original_pkt)

        pkt_to_parse = TCPPacket()
        pkt_to_parse.data = wrapped_pkt.data
        unwrapped_pkt = packet_wrapper.unwrap(pkt_to_parse)

        valid = packet_wrapper._validate_tcp_pkt(unwrapped_pkt.byte_fields, fmt)

        assert original_pkt.fields.__to_dict__() == \
               unwrapped_pkt.fields.__to_dict__()

        assert valid is True
