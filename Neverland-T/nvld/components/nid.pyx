from libc.stdlib cimport malloc, free
from libc.stdio cimport printf
from cython.operator cimport dereference as deref

import os

from ..exceptions import NIDError
from .div import DefaultIVMgr
from .conf import ConfigMgr


# NIDMgr is a tool to generate or load .nid files.
#
# An NID file is a garbled file that contains an iv_set and a .json
# config file in it.
cdef class NIDMgr():

    # buffers used by self._bit_cross and self._bit_uncross
    cdef unsigned char __bc_buf[2]
    cdef unsigned char __bu_buf[2]
    cdef int _iv_len

    cdef public:
        object _div_mgr
        object _cfg_mgr

    def __cinit__(self, iv_len=32):
        self._iv_len = iv_len

        self._div_mgr = DefaultIVMgr(iv_len)
        self._cfg_mgr = ConfigMgr()

    cdef unsigned char __bc_shift(
        self,
        unsigned char byte,
        int o_cur,
        int i_cur,
    ):
        if o_cur >= i_cur:
            return byte >> o_cur - i_cur
        else:
            return byte << i_cur - o_cur

    cdef unsigned char __bu_shift(
        self,
        unsigned char byte,
        int i_cur,
        int o_cur,
    ):
        if i_cur >= o_cur:
            return byte << i_cur - o_cur
        else:
            return byte >> o_cur - i_cur

    # Make two bytes crossed
    #
    # The result will be put in self.__bc_buf
    #
    # e.g:
    #     in_byte0:  1 0 0 0 1 1 0 1
    #     in_byte1:   1 1 1 0 1 1 1 1
    #     crossed:   1101010011110111
    #
    #     result: 11010100 11110111
    cdef void _bit_cross(
        self,
        unsigned char *in_byte0,
        unsigned char *in_byte1,
    ):
        cdef unsigned char byte0
        cdef unsigned char byte1
        cdef unsigned char mask
        cdef unsigned char bit0
        cdef unsigned char bit1
        cdef unsigned char r_byte0
        cdef unsigned char r_byte1
        cdef int i_cur
        cdef int o_cur

        byte0 = deref(in_byte0)
        byte1 = deref(in_byte1)

        mask = 0b10000000
        r_byte0 = 0x00
        r_byte1 = 0x00

        r_b1_writing = False
        i_cur = 0  # cursor pointed on the input bytes
        o_cur = 0  # cursor pointed on the output bytes

        while mask != 0:
            bit0 = byte0 & mask
            bit1 = byte1 & mask

            bit0 = self.__bc_shift(bit0, o_cur, i_cur)
            o_cur += 1

            bit1 = self.__bc_shift(bit1, o_cur, i_cur)
            o_cur += 1

            if r_b1_writing:
                r_byte1 |= bit0
                r_byte1 |= bit1
            else:
                r_byte0 |= bit0
                r_byte0 |= bit1

            if o_cur == 8:
                o_cur = 0
                r_b1_writing = True

            mask >>= 1
            i_cur += 1

        self.__bc_buf[0] = r_byte0
        self.__bc_buf[1] = r_byte1

    # parse two crossed bytes
    #
    # The result will be put in self.__bu_buf
    #
    # e.g:
    #     in_2bytes: 1101010011110111
    #     byte0:     1 0 0 0 1 1 0 1
    #     byte1:      1 1 1 0 1 1 1 1
    #
    #     result: 10001101 11101111
    cdef void _bit_uncross(self, unsigned char *in_2bytes):
        cdef unsigned char byte0
        cdef unsigned char byte1
        cdef unsigned char mask
        cdef unsigned char r_byte0
        cdef unsigned char r_byte1
        cdef unsigned char bit0
        cdef unsigned char bit1
        cdef int i_cur
        cdef int o_cur

        byte0 = in_2bytes[0]
        byte1 = in_2bytes[1]

        mask    = 0b10000000
        r_byte0 = 0x00
        r_byte1 = 0x00

        reading_b0 = True
        i_cur = 0  # cursor pointed on the input bytes
        o_cur = 0  # cursor pointed on the output bytes

        while not (mask == 0 and not reading_b0):
            if reading_b0:
                bit0 = byte0 & mask
                mask >>= 1
                bit1 = byte0 & mask
                mask >>= 1
            else:
                bit0 = byte1 & mask
                mask >>= 1
                bit1 = byte1 & mask
                mask >>= 1

            bit0 = self.__bu_shift(bit0, i_cur, o_cur)
            r_byte0 |= bit0
            i_cur += 1

            bit1 = self.__bu_shift(bit1, i_cur, o_cur)
            r_byte1 |= bit1
            i_cur += 1

            o_cur += 1

            if mask == 0 and reading_b0:
                mask = 0b10000000
                reading_b0 = False
                i_cur = 0

        self.__bu_buf[0] = r_byte0
        self.__bu_buf[1] = r_byte1

    def bit_cross(self, byte0, byte1):
        self._bit_cross(byte0, byte1)

        return self.__bc_buf[:2]

    def bit_uncross(self, in_2bytes):
        self._bit_uncross(in_2bytes)

        return self.__bu_buf[0:1], self.__bu_buf[1:2]

    def gen(self, conf_file, nid_file):
        data = b''
        conf_len = 0  # quiets a warning form gcc (could be uninitialized)

        with open(conf_file, 'rb') as cf:
            conf_data = cf.read()
            conf_len = len(conf_data)

        iv_stream = self._div_mgr.gen(conf_len)

        for b_iv, b_cf in zip(iv_stream, conf_data):
            data += self.bit_cross(b_iv, b_cf)

        with open(nid_file, 'wb') as nf:
            nf.write(data)

    def _parse_nid_data(self, nid_data):
        div_data = b''
        conf_data = b''
        nid_len = len(nid_data)

        if nid_len % 2 != 0:
            raise NIDError('NID file corrupted')

        cur = 0
        remaining = nid_len

        while remaining >= 2:
            b_iv, b_cf = self.bit_uncross( nid_data[cur: cur + 2] )

            div_data += b_iv
            conf_data += b_cf

            cur += 2
            remaining -= 2

        return div_data, conf_data

    def load(self, nid_file):
        with open(nid_file, 'rb') as nf:
            nid_data = nf.read()

        div_data, conf_data = self._parse_nid_data(nid_data)

        self._div_mgr.load(div_data)
        self._cfg_mgr.load(conf_data.decode())
