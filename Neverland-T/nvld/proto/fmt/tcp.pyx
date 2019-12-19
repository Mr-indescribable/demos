from ...glb import GLBInfo
from ...pkt.general import FieldTypes, PktTypes
from ..fn.tcp import TCPFieldNames
from ..fmt import (
    SpecialLength,
    FieldDefinition,
    BasePktFormat,
)
from ..fc import (
    tcp_len_calculator,
    tcp_metacrc_calculator,
    tcp_src_calculator,
    tcp_mac_calculator,
    salt_calculator,
    gid_calculator,
    time_calculator,
)


# Though the len field is an integer, but we still need to declare
# the maximum length explicitly, we will never allow a node to receive
# a packet with 4GBs of data, but we will not want the length limitation
# like UDP as well, so we can use an integer to carry the len field
# and limit the maximum of length in a way which it can be easily
# regulated whenever we want.
TCP_LEN_MAXIMUM = 65000

TCP_META_DATA_LEN = 9

RESERVED_FIELD_LEN  = 4
DELIMITER_FIELD_LEN = 16

RESERVED_FIELD_VALUE  = b'\x00' * RESERVED_FIELD_LEN
DELIMITER_FIELD_VALUE = b'\xff' * DELIMITER_FIELD_LEN


# The format of the header of TCP packet
class TCPHeaderFormat(BasePktFormat):

    __type__ = None

    @classmethod
    def gen_fmt(cls):
        cls.__fmt__ = {
            # Reserved field, should always be 0x00000000
            TCPFieldNames.RSV: FieldDefinition(
                length  = 4,
                type    = FieldTypes.PY_BYTES,
                default = RESERVED_FIELD_VALUE,
            ),

            # Length of the packet
            TCPFieldNames.LEN: FieldDefinition(
                length        = 4,
                type          = FieldTypes.STRUCT_U_INT,
                calculator    = tcp_len_calculator,
                calc_priority = 0xfd,
            ),

            # Packet type
            TCPFieldNames.TYPE: FieldDefinition(
                length = 1,
                type   = FieldTypes.STRUCT_U_CHAR,
            ),

            # CRC-32 of metadata
            TCPFieldNames.METACRC: FieldDefinition(
                length = 4,
                type   = FieldTypes.STRUCT_U_INT,
                calculator    = tcp_metacrc_calculator,
                calc_priority = 0xfe,
            ),

            # Here, we define that the metadata of the TCP packet
            # consists of these 3 fields above. These fields are
            # essential for parsing the whole packet.

            # The Message Authentication Code.
            # In protocol v0, we use sha256 as the digest method,
            # so the length is fixed to 64
            TCPFieldNames.MAC: FieldDefinition(
                length        = 64,
                type          = FieldTypes.PY_BYTES,
                calculator    = tcp_mac_calculator,
                calc_priority = 0xff,
            ),

            # Each packet shall have a global identifier.
            TCPFieldNames.GID: FieldDefinition(
                length        = 8,
                type          = FieldTypes.STRUCT_U_LONG_LONG,
                calculator    = gid_calculator,
                calc_priority = 0x00,
            ),

            # Eectional identifier in a NLSwirl channel.
            # The sn fields should be managed by NLSwirl itself.
            TCPFieldNames.SN: FieldDefinition(
                length = 8,
                type   = FieldTypes.STRUCT_U_LONG_LONG,
            ),

            # The source of the packet
            # TODO ipv6 support
            TCPFieldNames.SRC: FieldDefinition(
                length = None if GLBInfo.config.net.ipv6 else 6,
                type   = FieldTypes.STRUCT_IPV4_SA,
                calculator    = tcp_src_calculator,
                calc_priority = 0x00,
            ),

            # The destination of the packet
            # TODO ipv6 support
            TCPFieldNames.DEST: FieldDefinition(
                length = None if GLBInfo.config.net.ipv6 else 6,
                type   = FieldTypes.STRUCT_IPV4_SA,
            ),
        }


class TCPDelimiterFormat(BasePktFormat):

    __type__ = None

    @classmethod
    def gen_fmt(cls):
        cls.__fmt__ = {
            TCPFieldNames.DELIMITER: FieldDefinition(
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
            TCPFieldNames.FAKE: FieldDefinition(
                length  = 1,
                type    = FieldTypes.STRUCT_U_CHAR,
                default = 0,
            ),
            # indicates which TCP connection that the data belongs to
            TCPFieldNames.CHANNEL_ID: FieldDefinition(
                length = 4,
                type   = FieldTypes.STRUCT_U_INT,
            ),
            # just the data
            TCPFieldNames.DATA: FieldDefinition(
                length = SpecialLength.TCP_EXCEPT_DELIM,
                type   = FieldTypes.PY_BYTES,
            ),
        }


# The format of IV control packets' body
#
# This packet is very simple, and so, the usage is very simple as well.
# One node transmits an IV to the other side and the other side reply it
# with the same IV, and then, they are using the same IV.
class TCPIVCtrlPktFormat(BasePktFormat):

    __type__ = PktTypes.IV_CTRL

    @classmethod
    def gen_fmt(cls):
        cls.__fmt__ = {
            TCPFieldNames.IV: FieldDefinition(
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
            TCPFieldNames.TRANSACTION: FieldDefinition(
                length = 1,
                type   = FieldTypes.STRUCT_U_CHAR,
            ),
            # The channel ID assigned for the TCP connection
            TCPFieldNames.CHANNEL_ID: FieldDefinition(
                length = 4,
                type   = FieldTypes.STRUCT_U_INT,
            ),
            # A boolean in int type that indicates whether we are using IPv4
            TCPFieldNames.IS_IPV4: FieldDefinition(
                length  = 1,
                type    = FieldTypes.STRUCT_U_CHAR,
                default = 1,
            ),
            # An IPv4 socket address used with REQ_CONNECT transaction,
            # this field should be set to all zero if IPv6 is in use
            TCPFieldNames.V4ADDR: FieldDefinition(
                length  = 6,
                type    = FieldTypes.STRUCT_IPV4_SA,
                default = ('0.0.0.0', 0),
            ),
            # An IPv6 socket address used with REQ_CONNECT transaction,
            # this fields should be set to all zero if IPv4 is in use.
            #
            # Currnetly, it's not in use.
            TCPFieldNames.V6ADDR: FieldDefinition(
                length  = 18,
                type    = FieldTypes.PY_BYTES,
                default = b'\x00' * 18,
            ),
            # just the errno, mainly used with RPT_ERROR transaction
            TCPFieldNames.ERRNO: FieldDefinition(
                length  = 4,
                type    = FieldTypes.STRUCT_U_INT,
                default = 0,
            ),
        }


# The format of cluster control packets' body
class TCPClstCtrlPktFormat(BasePktFormat):

    __type__ = PktTypes.CLST_CTRL

    @classmethod
    def gen_fmt(cls):
        cls.__fmt__ = {
            # Literally, the subject field means what the node wants to do.
            # Enumerated in neverland.protocol.v0.subjects
            TCPFieldNames.SUBJECT: FieldDefinition(
                length = 4,
                type   = FieldTypes.STRUCT_U_INT,
            ),

            # Just like invoking a function with arguments, the content field
            # contains arguments for the selected subject.
            # The format of content field is stringified JSON.
            TCPFieldNames.ARGS: FieldDefinition(
                length = SpecialLength.TCP_EXCEPT_DELIM,
                type   = FieldTypes.PY_DICT,
            ),
        }
