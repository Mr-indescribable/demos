from ...utils.enumeration import MetaEnum


class TCPFieldNames(metaclass=MetaEnum):

    RSV         = 'rsv'
    LEN         = 'len'
    TYPE        = 'type'
    METACRC     = 'metacrc'
    MAC         = 'mac'
    GID         = 'gid'
    SN          = 'sn'
    SRC         = 'src'
    DEST        = 'dest'
    DELIMITER   = 'delimiter'
    FAKE        = 'fake'
    CHANNEL_ID  = 'channel_id'
    DATA        = 'data'
    IV          = 'iv'
    TRANSACTION = 'transaction'
    IS_IPV4     = 'is_ipv4'
    V4ADDR      = 'v4addr'
    V6ADDR      = 'v6addr'
    ERRNO       = 'errno'
    SUBJECT     = 'subject'
    ARGS        = 'args'


TCP_META_DATA_FIELDS = [
    TCPFieldNames.RSV,
    TCPFieldNames.LEN,
    TCPFieldNames.TYPE,
    TCPFieldNames.METACRC,
]
