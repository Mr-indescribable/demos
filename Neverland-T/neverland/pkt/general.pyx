from ..utils.enumeration import MetaEnum


class PktTypes(metaclass=MetaEnum):

    # Normal data packets, used in transfering data from applications
    DATA = 0x01

    # Cluster controlling packets, used in communicating with the controller node
    CLSTR_CTRL = 0x02

    # Connection controlling packets,
    # used in managing connections between other nodes
    CONN_CTRL = 0x03


class FieldTypes(metaclass=MetaEnum):

    STRUCT_U_CHAR = 0x11
    STRUCT_U_INT = 0x12
    STRUCT_U_LONG_LONG = 0x13

    STRUCT_IPV4_SA = 0x31
    STRUCT_IPV6_SA = 0x32

    PY_BYTES = 0x41
    PY_DICT = 0x42
