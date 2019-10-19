import os
import time

from ..utils.hash import HashTools
from ..glb import GLBComponent, GLBInfo, GLBPktFmt
from .fmt import ComplexedFormat
from ..pkt.general import PktTypes, PktProto


# field calculators for PktFormat classes


TCP_PKT_DELIMITER = b'\xff' * 32


def tcp_delimiter_calculator(pkt):
    return TCP_PKT_DELIMITER


def tcp_src_calculator(pkt):
    return (GLBInfo.local_ip, GLBInfo.listen_tcp_port)


def udp_src_calculator(pkt):
    return (GLBInfo.local_ip, GLBInfo.listen_udp_port)


def sn_calculator(pkt):
    return GLBComponent.id_generator.gen()


def salt_calculator(pkt):
    salt_len = GLBInfo.config.net.crypto.salt_len
    return os.urandom(salt_len)


def mac_calculator(pkt):
    ''' calculator for calculating the mac field

    Rule of the mac calculating:
        Generally, salt field and mac field are always at the first and the second
        field in the packet header. So, by default, our packets will look like:

            <salt> <mac> <other_fields>

        Here, we define the default rule of mac calculating as this:

            SHA256( <salt> + <other_fields> )
    '''

    data_2_hash = pkt.byte_fields.salt

    if pkt.proto == PktProto.TCP:
        if pkt.type == PktTypes.DATA:
            fmt = GLBPktFmt.tcp_data
        elif pkt.type == PktTypes.CONN_CTRL:
            fmt = GLBPktFmt.tcp_conn_ctrl
        elif pkt.type == PktTypes.CLST_CTRL:
            fmt = GLBPktFmt.tcp_clst_ctrl
        else:
            raise RuntimeError(f'Unknown TCP packet type: {pkt.type}')
    elif pkt.proto == PktProto.UDP:
        fmt = GLBPktFmt.udp_data
    else:
        raise RuntimeError(f'Unknown UDP packet proto: {pkt.proto}')

    for field_name, definition in fmt.__fmt__.items():
        if field_name in ('salt', 'mac'):
            continue

        byte_value = getattr(pkt.byte_fields, field_name)
        data_2_hash += byte_value

    return HashTools.sha256(data_2_hash).encode()


def time_calculator(pkt):
    ''' calculator for the time field
    '''

    return int(
        time.time() * 1000000
    )
