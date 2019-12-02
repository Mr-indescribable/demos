from ..utils.enumeration import MetaEnum


# Transactions of TCP Connection Control
#
# The abbreviation REQ stands for "Request"
# The abbreviation RPT stands for "Report"
class TCPCCTransactions(metaclass=MetaEnum):

    REQ_CONNECT      = 0x01
    REQ_DISCONNECT   = 0X02
    RPT_INPROGRESS   = 0x11
    RPT_CONNECTED    = 0x12
    RPT_DISCONNECTED = 0x13
    RPT_ERROR        = 0x21
