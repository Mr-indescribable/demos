#!/usr/bin/python3.6
#coding: utf-8

from neverland.utils import ObjectifiedDict
from neverland.components.idgeneration import IDGenerator


def test_id_gen():
    id_pool = set()
    generator = IDGenerator(0x01, 0x01)

    # 10M times, this will eat up about 600MB memory.
    # for _ in range(10000000):
    for _ in range(1000):
        id_ = generator.gen()
        assert id_ not in id_pool

        id_pool.add(id_)
