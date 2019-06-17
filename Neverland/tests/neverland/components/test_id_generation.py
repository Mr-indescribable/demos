#!/usr/bin/python3.6
#coding: utf-8

from neverland.utils import ObjectifiedDict
from neverland.components.idgeneration import IDGenerator


def test_id_gen():
    generator = IDGenerator(0x01, 0x01)

    current = None
    previous = None

    for _ in range(10000000):  # 10M times
        id_ = generator.gen()

        previous = current
        current = id_

        assert previous != current
