#!/usr/bin/python3.6
#coding: utf-8

import os
import time

from neverland.utils import HashTools
from neverland.node.context import NodeContext
from neverland.protocol.base import ComplexedFormat


def src_calculator(pkt, header_fmt, body_fmt):
    ''' calculator for the src field
    '''

    return (NodeContext.local_ip, NodeContext.listen_port)


def sn_calculator(pkt, header_fmt, body_fmt):
    ''' calculator for the serial number field
    '''

    id_generator = NodeContext.id_generator
    if id_generator is None:
        raise RuntimeError(
            'Node modules are not ready to generate packet serial numbers'
        )

    return id_generator.gen()


def salt_calculator(pkt, header_fmt, body_fmt):
    ''' calculator for the salt field
    '''

    salt_definition = header_fmt.__fmt__.get('salt')
    salt_len = salt_definition.length
    return os.urandom(salt_len)


def mac_calculator(pkt, header_fmt, body_fmt):
    ''' calculator for calculating the mac field

    Rule of the mac calculating:
        Generally, salt field and mac field are always at the first and the second
        field in the packet header. So, by default, our packets will look like:

            <salt> <mac> <other_fields>

        Here, we define the default rule of mac calculating as this:

            SHA256( <salt> + <other_fields> )
    '''

    data_2_hash = pkt.byte_fields.salt
    fmt = ComplexedFormat()
    fmt.combine_fmt(header_fmt)
    fmt.combine_fmt(body_fmt)

    for field_name, definition in fmt.__fmt__.items():
        if field_name in ('salt', 'mac'):
            continue

        byte_value = getattr(pkt.byte_fields, field_name)
        data_2_hash += byte_value

    return HashTools.sha256(data_2_hash).encode()


def time_calculator(*_):
    ''' calculator for the time field
    '''

    return int(
        time.time() * 1000000
    )
