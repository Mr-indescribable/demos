#!/usr/bin/python3.6
#coding: utf-8

import os
import time
import struct
import unittest

import __code_path__
from neverland.utils import ObjectifiedDict as OD
from neverland.protocol.crypto import Modes
from neverland.protocol.crypto.kc.aead.gcm import GCMKernelCryptor


config_json = {
    'net': {
        'identification': 'a l00o00oOOoOOoo00oOOo00ong identification string',
        'crypto': {
            'password': 'a SUPER SUPER LONG AND VERY INDESCRIBABLE pASSw0rD',
            'cipher': 'kc-aes-256-gcm'
        }
    }
}
config = OD(**config_json)


gcm_cipher = GCMKernelCryptor(config, Modes.ENCRYPTING)
gcm_decipher = GCMKernelCryptor(config, Modes.DECRYPTING)

tsum_urandom = 0
tsum_crypto = 0


# Test case for kernel cryptors
class KCTest(unittest.TestCase):

    def test_0_gcm(self):
        global tsum_urandom, tsum_crypto

        times = 50000
        bs = 65535
        total_mb = times * bs / 1024 / 1024
        total_mb = round(total_mb, 2)
        cipher_name = config.net.crypto.cipher

        print(
            f'Running {times} times of {cipher_name} cipher testing with data '
            f'block size {bs}. \nTotal: {total_mb} MB\n'
        )

        for _ in range(times):
            t0 = time.time()
            data_4_test = os.urandom(bs)
            t1 = time.time()

            tsum_urandom += t1 - t0

            t0 = time.time()
            cipher_text = gcm_cipher.update(data_4_test)
            plain_text = gcm_decipher.update(cipher_text)
            t1 = time.time()

            tsum_crypto += t1 - t0

            self.assertEqual(plain_text, data_4_test)

        print(f'Seconds spent on generating random data: {tsum_urandom}')
        print(f'Seconds spent on encrypting & decrypting: {tsum_crypto}')


if __name__ == '__main__':
    unittest.main()
