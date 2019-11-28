from ...glb import GLBInfo
from ...pkt.general import FieldTypes, PktTypes
from ..fmt import (
    SpecialLength,
    FieldDefinition,
    BasePktFormat,
)
from ..fc import (
    tcp_len_calculator,
    tcp_src_calculator,
    tcp_mac_calculator,
    salt_calculator,
    sn_calculator,
    time_calculator,
)


RESERVED_FIELD_LEN  = 4
DELIMITER_FIELD_LEN = 32

RESERVED_FIELD_VALUE  = b'\x00' * RESERVED_FIELD_LEN
DELIMITER_FIELD_VALUE = b'\xff' * DELIMITER_FIELD_LEN


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

            # Packet type
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
                       calculator    = tcp_mac_calculator,
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


class TCPDelimiterFormat(BasePktFormat):

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
            # indicates which TCP connection that the data belongs to
            'channel_id': FieldDefinition(
                              length = 4,
                              type   = FieldTypes.STRUCT_U_INT,
                          ),
            # just the data
            'data': FieldDefinition(
                        length = SpecialLength.TCP_EXCEPT_DELIM,
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
            # The channel ID assigned for the TCP connection
            'channel_id': FieldDefinition(
                              length = 4,
                              type   = FieldTypes.STRUCT_U_INT,
                          ),

            # An IPv4 socket address
            # this field should be set to all zero if IPv6 is in use
            'v4ip': FieldDefinition(
                        length  = 6,
                        type    = FieldTypes.STRUCT_IPV4_SA,
                        default = b'\x00' * 6,
                    ),
            # An IPv6 socket address
            # this fields should be set to all zero if IPv4 is in use
            # This field is not in use now.
            'v6ip': FieldDefinition(
                        length  = 18,
                        type    = FieldTypes.PY_BYTES,
                        default = b'\x00' * 18,
                    ),
            # A boolean in int type that indicates whether we are using IPv4
            'v4': FieldDefinition(
                      length  = 1,
                      type    = FieldTypes.STRUCT_U_CHAR,
                      default = 1,
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
                        length = SpecialLength.TCP_EXCEPT_DELIM,
                        type   = FieldTypes.PY_DICT,
                    ),
        }
