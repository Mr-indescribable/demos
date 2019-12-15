import os
import random

from ..glb import GLBInfo


DIV_DEFAULT_NUM = 4


# This class is used to generate or load IV set of the Neverland cluster.
class DefaultIVMgr():

    def __init__(self, iv_len=None):
        self._iv_len = iv_len

    def set_iv_len(self, iv_len):
        self._iv_len = iv_len

    def gen(self, length):
        return os.urandom(length)

    def _load(self, data, maximum=None):
        max_ = maximum or DIV_DEFAULT_NUM
        load_cnt = 0
        cur = 0
        iv_list = list()
        remaining = len(data)

        while remaining >= self._iv_len and load_cnt < max_:
            iv_list.append( data[cur: cur + self._iv_len] )
            cur += self._iv_len
            remaining -= self._iv_len
            load_cnt += 1

        return iv_list

    def load_as_stmc_iv(self, data, maximum=None):
        iv_list = self._load(data, maximum)
        GLBInfo.stmc_div_list = iv_list

    def load_as_dgmc_iv(self, data, maximum=None):
        iv_list = self._load(data, maximum)
        GLBInfo.dgmc_div_list = iv_list

    def random_stmc_div(self):
        return random.choice(GLBInfo.stmc_div_list)

    def random_dgmc_div(self):
        return random.choice(GLBInfo.dgmc_div_list)

    def get_all_stmc_iv(self):
        return GLBInfo.stmc_div_list

    def get_all_dgmc_iv(self):
        return GLBInfo.dgmc_div_list
