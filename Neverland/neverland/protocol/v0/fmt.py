#!/usr/bin/python3.6
#coding: utf-8

from neverland.pkt import FieldTypes, PktTypes
from neverland.protocol.base import (
    FieldDefinition,
    BasePktFormat,
)
from neverland.protocol.v0.calculators import (
    src_calculator,
    salt_calculator,
    mac_calculator,
    sn_calculator,
    time_calculator,
)


UDP_DATA_MAX_LEN = 65507


'''
In order to normalize the packets, we simply split them into 2 pieces.

The first one is the header, it will be fixed on the head of a packet,
it shall contain some common informations that all packets shall contain.

The second one is the body, just like body field in HTTP,
it shall contain the data we need to transfer.
'''


class HeaderFormat(BasePktFormat):

    ''' The format of packet headers
    '''

    __type__ = None

    @classmethod
    def gen_fmt(cls, config):
        cls.__fmt__ = {
            # Allows users to config it in the config file.
            # This should be unified in the community.
            'salt': FieldDefinition(
                        length        = config.net.crypto.salt_len or 8,
                        type          = FieldTypes.PY_BYTES,
                        calculator    = salt_calculator,
                        calc_priority = 0x00,
                    ),

            # The Message Authentication Code.
            # In protocol v0, we use sha256 as the digest method,
            # so the length is fixed to 64
            'mac': FieldDefinition(
                       length        = 64,
                       type          = FieldTypes.PY_BYTES,
                       calculator    = mac_calculator,
                       calc_priority = 0xff,
                   ),

            # Each UDP packet shall have a serial number as its identifier.
            'sn': FieldDefinition(
                      length        = 8,
                      type          = FieldTypes.STRUCT_U_LONG_LONG,
                      calculator    = sn_calculator,
                      calc_priority = 0x00,
                  ),

            # The timestamp of the creation of the packet
            'time': FieldDefinition(
                        length        = 8,
                        type          = FieldTypes.STRUCT_U_LONG_LONG,
                        calculator    = time_calculator,
                        calc_priority = 0x00,
                    ),

            # Packet type,
            # 0x01 for data packets,
            # 0x02 for controlling packets,
            # 0x03 for connection controlling packets
            # 0x04 for connection controlling ACK
            'type': FieldDefinition(
                        length = 1,
                        type   = FieldTypes.STRUCT_U_CHAR,
                    ),

            # Whether this packet has been diverged,
            # 0x01 for True and 0x00 for False
            'diverged': FieldDefinition(
                            length  = 1,
                            type    = FieldTypes.STRUCT_U_CHAR,
                            default = 0x00,
                        ),

            # The source of the packet
            # TODO ipv6 support
            'src': FieldDefinition(
                       length = None if config.net.ipv6 else 6,
                       type   = FieldTypes.STRUCT_IPV4_SA,
                       calculator    = src_calculator,
                       calc_priority = 0x00,
                   ),

            # The destination of the packet
            # TODO ipv6 support
            'dest': FieldDefinition(
                        length = None if config.net.ipv6 else 6,
                        type   = FieldTypes.STRUCT_IPV4_SA,
                    ),
        }


class DataPktFormat(BasePktFormat):

    ''' The format of data packets' body
    '''

    __type__ = PktTypes.DATA

    @classmethod
    def gen_fmt(cls, config):
        cls.__fmt__ = {
            # just the data
            'data': FieldDefinition(
                        # This length means "Use all of these bytes remaining."
                        length = UDP_DATA_MAX_LEN,
                        type   = FieldTypes.PY_BYTES,
                    ),
        }


class CtrlPktFormat(BasePktFormat):

    ''' The format of cluster controlling packets' body
    '''

    __type__ = PktTypes.Ctrl

    @classmethod
    def gen_fmt(cls, config):
        cls.__fmt__ = {
            # Literally, the subject field means what the node wants to do.
            # Enumerated in neverland.protocol.v0.subjects
            'subject': FieldDefinition(
                           length = 4,
                           type   = FieldTypes.STRUCT_U_INT,
                       ),

            # Just like invoking a function with arguments, the content field
            # contains arguments for the selected subject.
            # The format of content field is stringified JSON.
            'content': FieldDefinition(
                           length = UDP_DATA_MAX_LEN,
                           type   = FieldTypes.PY_DICT,
                       ),
        }


class ConnCtrlPktFormat(BasePktFormat):

    ''' The format of connection controlling packets' body
    '''

    __type__ = PktTypes.CONN_CTRL

    @classmethod
    def gen_fmt(cls, config):
        cls.__fmt__ = {
            # The flag of whether a node want to keep communicating with
            # another node. 0x01 for Ture and 0x00 for False
            #
            # Actually, communicating == 0x00 means "disconnecting".
            'communicating': FieldDefinition(
                                 length = 1,
                                 type   = FieldTypes.STRUCT_U_CHAR,
                             ),

            # The flag of whether the iv should be changed
            # 0x01 for Ture and 0x00 for False
            'iv_changed': FieldDefinition(
                              length = 1,
                              type   = FieldTypes.STRUCT_U_CHAR,
                          ),

            # The amount of packets that can be encrypted by this iv
            'iv_duration': FieldDefinition(
                               length = 8,
                               type   = FieldTypes.STRUCT_U_LONG_LONG,
                           ),

            # The iv
            'iv': FieldDefinition(
                      length = config.net.crypto.iv_len,
                      type   = FieldTypes.PY_BYTES,
                  ),
        }


class ConnCtrlAckPktFormat(BasePktFormat):

    ''' The format of connection controlling ACK packets' body
    '''

    __type__ = PktTypes.CONN_CTRL_ACK

    @classmethod
    def gen_fmt(cls, config):
        cls.__fmt__ = {
            # The serial number of the received (at remote) CONN_CTRL packet
            'resp_sn': FieldDefinition(
                           length = 8,
                           type   = FieldTypes.STRUCT_U_LONG_LONG,
                       ),
        }
