from ...glb import GLBInfo
from ...pkt.general import FieldTypes, PktTypes
from ..fmt import (
    FieldDefinition,
    BasePktFormat,
)
from ..fc import (
    tcp_len_calculator,
    tcp_src_calculator,
    salt_calculator,
    mac_calculator,
    sn_calculator,
    time_calculator,
)


RESERVED_FIELD_VALUE  = b'\x00' * 4
DELIMITER_FIELD_VALUE = b'\xff' * 32


class TCPHeaderFormat(BasePktFormat):

    # The format of the header of TCP packet

    __type__ = None

    @classmethod
    def gen_fmt(cls):
        cls.__fmt__ = {
            # Reserved field, should be 0x00000000 within transmission
            'rsv': FieldDefinition(
                       length  = 4,
                       type    = FieldTypes.PY_BYTES,
                       default = RESERVED_FIELD_VALUE,
                   ),

            # Length of the packet
            'len': FieldDefinition(
                       length  = 2,
                       type    = FieldTypes.STRUCT_U_SHORT,
                       calculator    = tcp_len_calculator,
                       calc_priority = 0xfe,
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

            # The source of the packet
            # TODO ipv6 support
            'src': FieldDefinition(
                       length = None if GLBInfo.config.net.ipv6 else 6,
                       type   = FieldTypes.STRUCT_IPV4_SA,
                       calculator    = tcp_src_calculator,
                       calc_priority = 0x00,
                   ),

            # The destination of the packet
            # TODO ipv6 support
            'dest': FieldDefinition(
                        length = None if GLBInfo.config.net.ipv6 else 6,
                        type   = FieldTypes.STRUCT_IPV4_SA,
                    ),
        }


class TCPDelimiterPktFormat(BasePktFormat):

    __type__ = None

    @classmethod
    def gen_fmt(cls):
        cls.__fmt__ = {
            'delimiter': FieldDefinition(
                             length  = 32,
                             type    = FieldTypes.PY_BYTES,
                             default = DELIMITER_FIELD_VALUE,
                         )
        }


class TCPDataPktFormat(BasePktFormat):

    ''' The format of data packets' body
    '''

    __type__ = PktTypes.DATA

    @classmethod
    def gen_fmt(cls):
        cls.__fmt__ = {
            # just the data
            'data': FieldDefinition(
                        length = -1,
                        type   = FieldTypes.PY_BYTES,
                    ),
        }


class TCPConnCtrlPktFormat(BasePktFormat):

    ''' The format of connection controlling packets' body
    '''

    __type__ = PktTypes.CONN_CTRL

    @classmethod
    def gen_fmt(cls):
        cls.__fmt__ = {
            # An IPv4 address
            # this field should be set to all zero if IPv6 is in use
            'v4ip': FieldDefinition(
                        length = 4,
                        type   = FieldTypes.STRUCT_IPV4_SA,
                    ),
            # An IPv6 address
            # this fields should be set to all zero if IPv4 is in use
            'v6ip': FieldDefinition(
                        length = 16,
                        type   = FieldTypes.STRUCT_IPV6_SA,
                    ),
            # The port
            'port': FieldDefinition(
                        length = 2,
                        type   = FieldTypes.STRUCT_U_SHORT,
                    ),
            # A boolean in int type that indicates whether we are using IPv4
            'v4': FieldDefinition(
                      length = 1,
                      type   = FieldTypes.STRUCT_U_CHAR,
                  ),
        }


class TCPClstCtrlPktFormat(BasePktFormat):

    ''' The format of cluster controlling packets' body
    '''

    __type__ = PktTypes.CLST_CTRL

    @classmethod
    def gen_fmt(cls):
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
            'args': FieldDefinition(
                           length = -1,
                           type   = FieldTypes.PY_DICT,
                       ),
        }
