import os
import time

from ..utils.hash import HashTools
from ..glb import GLBComponent, GLBInfo, GLBPktFmt
from .fmt import ComplexedFormat
from ..pkt.general import PktTypes, PktProto


# field calculators for PktFormat classes


TCP_HEADER_LEN_IPV4 = 4 + 2 + 1 + 64 + 8 + 6 + 6
TCP_HEADER_LEN_IPV6 = 4 + 2 + 1 + 64 + 8 + 18 + 18
TCP_DELIMITER_LEN = 32
TCP_CONN_CTRL_LEN = 4 + 16 + 2 + 1


def tcp_len_calculator(pkt):
    if pkt.type == PktTypes.DATA:
        body_len = len(pkt.byte_fields.data)
    elif pkt.type == PktTypes.CONN_CTRL:
        body_len = TCP_CONN_CTRL_LEN
    elif pkt.type == PktTypes.CLST_CTRL:
        body_len = 4 + len(pkt.byte_fields.args)
    else:
        # This should not happen, the upper layer must verify the type
        raise TypeError(f'Unknown packet type: {pkt.type}')

    if GLBInfo.config.net.ipv6:
        return TCP_HEADER_LEN_IPV6 + TCP_DELIMITER_LEN + body_len
    else:
        return TCP_HEADER_LEN_IPV4 + TCP_DELIMITER_LEN + body_len


def tcp_mac_calculator(pkt):
    ''' calculator for calculating the mac field

    Rule of the mac calculating:

        TCP packets has the following structure:

            <rsv> <len> <type> <mac> <other_fields> <delimiter>

        Here, we define the rule of mac calculating as this:

            SHA256( <rsv> <len> <type> <other_fields> <delimiter>)
    '''

    if pkt.proto == PktProto.TCP:
        if pkt.type == PktTypes.DATA:
            fmt = GLBPktFmt.tcp_data
        elif pkt.type == PktTypes.CONN_CTRL:
            fmt = GLBPktFmt.tcp_conn_ctrl
        elif pkt.type == PktTypes.CLST_CTRL:
            fmt = GLBPktFmt.tcp_clst_ctrl
        else:
            # This should not happen, the upper layer must verify the type
            raise RuntimeError(f'Unknown TCP packet type: {pkt.type}')
    elif pkt.proto == PktProto.UDP:
        fmt = GLBPktFmt.udp_data
    else:
        # This should not happen, the upper layer must verify the proto field
        raise RuntimeError(f'Unknown packet proto: {pkt.proto}')

    data_2_hash = b''

    for field_name, definition in fmt.__fmt__.items():
        if field_name == 'mac':
            continue

        data_2_hash += getattr(pkt.byte_fields, field_name)

    return HashTools.sha256(data_2_hash).encode()


def tcp_src_calculator(pkt):
    return (GLBInfo.local_ip, GLBInfo.svr_tcp_port)


def udp_src_calculator(pkt):
    return (GLBInfo.local_ip, GLBInfo.svr_udp_port)


def sn_calculator(pkt):
    return GLBComponent.id_generator.gen()


def salt_calculator(pkt):
    salt_len = GLBInfo.config.net.crypto.salt_len
    return os.urandom(salt_len)


def time_calculator(pkt):
    ''' calculator for the time field
    '''

    return int(
        time.time() * 1000000
    )
