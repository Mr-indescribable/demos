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
    gid_calculator,
    time_calculator,
)


RESERVED_FIELD_LEN  = 4
DELIMITER_FIELD_LEN = 32

RESERVED_FIELD_VALUE  = b'\x00' * RESERVED_FIELD_LEN
DELIMITER_FIELD_VALUE = b'\xff' * DELIMITER_FIELD_LEN


# The format of the header of TCP packet
class TCPHeaderFormat(BasePktFormat):

    __type__ = None

    @classmethod
    def gen_fmt(cls):
        cls.__fmt__ = {
            # Reserved field, should always be 0x00000000
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

            # Here, we define that the metadata of the TCP packet
            # consists of these 3 fields above. These fields are
            # essential for parsing the whole packet.

            # The Message Authentication Code.
            # In protocol v0, we use sha256 as the digest method,
            # so the length is fixed to 64
            'mac': FieldDefinition(
                       length        = 64,
                       type          = FieldTypes.PY_BYTES,
                       calculator    = tcp_mac_calculator,
                       calc_priority = 0xff,
                   ),

            # Each packet shall have a global identifier.
            'gid': FieldDefinition(
                       length        = 8,
                       type          = FieldTypes.STRUCT_U_LONG_LONG,
                       calculator    = gid_calculator,
                       calc_priority = 0x00,
                   ),

            # Eectional identifier in a NLSwirl channel.
            # The sn fields should be managed by NLSwirl itself.
            'sn': FieldDefinition(
                      length        = 8,
                      type          = FieldTypes.STRUCT_U_LONG_LONG,
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


# The format of data packets' body
class TCPDataPktFormat(BasePktFormat):

    __type__ = PktTypes.DATA

    @classmethod
    def gen_fmt(cls):
        cls.__fmt__ = {
            # A flag that marks whether this data packet is a pad of NLSwirl,
            # in other words, a fake packet. 0/1
            'fake': FieldDefinition(
                        length  = 1,
                        type    = FieldTypes.STRUCT_U_CHAR,
                        default = 0,
                    ),
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


# The format of connection controlling packets' body
class TCPConnCtrlPktFormat(BasePktFormat):

    __type__ = PktTypes.CONN_CTRL

    @classmethod
    def gen_fmt(cls):
        cls.__fmt__ = {
            #An integer that marks what the sender wants to do
            'transaction': FieldDefinition(
                               length = 1,
                               type   = FieldTypes.STRUCT_U_CHAR,
                           ),
            # The channel ID assigned for the TCP connection
            'channel_id': FieldDefinition(
                              length = 4,
                              type   = FieldTypes.STRUCT_U_INT,
                          ),
            # A boolean in int type that indicates whether we are using IPv4
            'is_v4': FieldDefinition(
                         length  = 1,
                         type    = FieldTypes.STRUCT_U_CHAR,
                         default = 1,
                     ),
            # An IPv4 socket address used with REQ_CONNECT transaction,
            # this field should be set to all zero if IPv6 is in use
            'v4ip': FieldDefinition(
                        length  = 6,
                        type    = FieldTypes.STRUCT_IPV4_SA,
                        default = ('0.0.0.0', 0),
                    ),
            # An IPv6 socket address used with REQ_CONNECT transaction,
            # this fields should be set to all zero if IPv4 is in use.
            #
            # Currnetly, it's not in use.
            'v6ip': FieldDefinition(
                        length  = 18,
                        type    = FieldTypes.PY_BYTES,
                        default = b'\x00' * 18,
                    ),
            # just the errno, mainly used with RPT_ERROR transaction
            'errno': FieldDefinition(
                         length  = 4,
                         type    = FieldTypes.STRUCT_U_INT,
                         default = 0,
                     ),
        }


# The format of cluster controlling packets' body
class TCPClstCtrlPktFormat(BasePktFormat):

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
