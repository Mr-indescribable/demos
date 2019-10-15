from .utils.enumeration import MetaEnum


class Roles(metaclass=MetaEnum):

    CLIENT     = 0x01
    RELAY      = 0x02
    OUTLET     = 0x03
    CONTROLLER = 0x04
