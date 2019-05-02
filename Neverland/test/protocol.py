#!/usr/bin/python3.6
#coding: utf-8

import unittest

import __code_path__
from neverland.pkt import UDPPacket, PktTypes
from neverland.utils import ObjectifiedDict
from neverland.protocol.crypto import Cryptor
from neverland.protocol.v0.wrapper import ProtocolWrapper
from neverland.protocol.v0.fmt import (
    HeaderFormat,
    DataPktFormat,
    CtrlPktFormat,
    ConnCtrlPktFormat,
)
from neverland.node.context import NodeContext
from neverland.components.idgeneration import IDGenerator


id_generator = IDGenerator(1, 1)
NodeContext.id_generator = id_generator

json_config = {
    'net': {
        'ipv6': False,
        'identification': 'a l00o00oOOoOOoo00oOOo00ong identification string',
        'crypto': {
            'password': 'a SUPER SUPER LONG AND VERY INDESCRIBABLE pASSw0rD',
            'cipher': 'kc-aes-256-gcm',
            'iv_len': 12
        }
    }
}
config = ObjectifiedDict(**json_config)


default_cryptor = Cryptor(config)
NodeContext.cryptor_stash.update(
    {'default_cryptor': default_cryptor}
)


wrapper = ProtocolWrapper(
              config,
              HeaderFormat,
              DataPktFormat,
              CtrlPktFormat,
              ConnCtrlPktFormat,
          )


class PWTest(unittest.TestCase):

    def test_0_sort_calculators(self):
        fmt = HeaderFormat
        fmt.gen_fmt(config)
        fmt.sort_calculators()

        print('================== test_0_sort_calculators ==================')
        for field_name, calculator in fmt.__calc_definition__.items():
            print('--------------------------------------')
            print(f"field: {field_name}")
            print(f"calculator: {calculator}")
        print('========================= test_0 ends =======================\n')


    def test_1_wrap_unwrap(self):
        pkt = UDPPacket()
        pkt.fields = ObjectifiedDict(
                         serial=1,
                         type=PktTypes.CONN_CTRL,
                         diverged=0x01,
                         src=('127.0.0.1', 65535),
                         dest=('127.0.0.1', 65535),
                         communicating=0x01,
                         iv_changed=0x01,
                         iv_duration=10000,
                         iv=b'iviviviviviv'
                     )
        pkt.type = pkt.fields.type

        pkt = wrapper.wrap(pkt)
        print(pkt.data)
        print('==================\n')

        pkt1 = UDPPacket()
        # pkt1.type = 0x01
        pkt1.data = pkt.data
        pkt1 = wrapper.unwrap(pkt1)

        self.assertEqual(pkt1.valid, True)
        self.assertEqual(pkt1.type, PktTypes.CONN_CTRL)
        self.assertEqual(pkt1.fields.src, pkt.fields.src)
        self.assertEqual(pkt1.fields.dest, pkt.fields.dest)

        print(
            str(pkt1.fields)
        )


if __name__ == '__main__':
    unittest.main()
