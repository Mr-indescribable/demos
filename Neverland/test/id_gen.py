#!/usr/bin/python3.6
#coding: utf-8

import struct
import unittest

import __code_path__
from neverland.components.idgeneration import IDGenerator


id_generator = IDGenerator(0x01, 0x01)


# Test case for IDGenerator
class IDGTest(unittest.TestCase):

    def test_0_gen(self):
        current = None
        previous = None

        for _ in range(1000000):
            id_ = id_generator.gen()

            previous = current
            current = id_
            self.assertNotEqual(current, previous)

            base2_str = '{0:b}'.format(id_)
            b2_len = len(base2_str)
            self.assertEqual(b2_len, 64)

            print(base2_str)


if __name__ == '__main__':
    unittest.main()
