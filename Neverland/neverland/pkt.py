#!/usr/bin/python3.6
#coding: utf-8

from neverland.utils import ObjectifiedDict, MetaEnum


class PktTypes(metaclass=MetaEnum):

    # Normal data packets, used in transfering data from applications
    DATA = 0x01

    # Cluster controlling packets, used in communicating with the controller node
    CTRL = 0x02

    # Connection controlling packets, used in managing connections from other nodes
    CONN_CTRL = 0x03

    # ACK of Connection controlling packets
    CONN_CTRL_ACK = 0x04


class FieldTypes(metaclass=MetaEnum):

    STRUCT_U_CHAR = 0x11
    STRUCT_U_INT = 0x12
    STRUCT_U_LONG = 0x13
    STRUCT_U_LONG_LONG = 0x14

    STRUCT_IPV4_SA = 0x31
    STRUCT_IPV6_SA = 0x32

    PY_BYTES = 0x41
    PY_DICT = 0x42


class UDPPacket(ObjectifiedDict):

    ''' The UDP Packet

    Inner Data Structure:
        {
            valid: bool or None,
            type: int,
            data: bytes,
            fields: ObjectifiedDict,
            byte_fields: ObjectifiedDict,
            previous_hop: (ip, port)
            next_hop: (ip, port),
        }

    By default, the "valid" field is None. It should be set
    during the unpacking if the packet is from other node.

    The "data" field is bytes which is going to transmit or just received.

    The "fields" field is the data that hasn't been wrapped or has been parsed.
    The "byte_fields" fields is a duplicate of the "fields" field,
    the difference is data in this field is bytes.
    '''

    def __init__(self, **kwargs):
        for kw in ['previous_hop', 'next_hop']:
            if kw not in kwargs:
                kwargs.update(
                    {kw: (None, None)}
                )

        for kw in ['fields', 'byte_fields']:
            if kw not in kwargs:
                kwargs.update(
                    {kw: ObjectifiedDict()}
                )

        if 'valid' not in kwargs:
            kwargs.update(valid=None)

        ObjectifiedDict.__init__(self, **kwargs)
