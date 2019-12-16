from ..utils.enumeration import MetaEnum


class PktProto(metaclass=MetaEnum):

    TCP = 0x01
    UDP = 0x02


class PktTypes(metaclass=MetaEnum):

    # Normal data packets, used in transfering data from applications
    DATA = 0x01

    # IV control packets, used in managing IV of TCP connections
    IV_CTRL = 0x02

    # Connection control packets, used in managing TCP connections
    CONN_CTRL = 0x03

    # Cluster control packets, used in communicating with other nodes
    CLST_CTRL = 0x04


class FieldTypes(metaclass=MetaEnum):

    STRUCT_U_CHAR      = 0x11
    STRUCT_U_SHORT     = 0x12
    STRUCT_U_INT       = 0x13
    STRUCT_U_LONG_LONG = 0x14

    STRUCT_IPV4_SA = 0x31
    STRUCT_IPV6_SA = 0x32

    PY_BYTES = 0x41
    PY_DICT = 0x42
