import os
import random

from ..glb import GLBInfo


# This class is used to generate or load IV set of the Neverland cluster.
class DefaultIVMgr():

    def __init__(self, iv_len=32):
        self._iv_len = iv_len

    def gen(self, length):
        return os.urandom(length)

    def load(self, data):
        cur = 0
        iv_list = list()
        remaining = len(data)

        while remaining >= self._iv_len:
            iv_list.append( data[cur: cur + self._iv_len] )
            cur += self._iv_len
            remaining -= self._iv_len

        GLBInfo.div_list = iv_list

    def random_div(self):
        return random.choice(GLBInfo.div_list)
