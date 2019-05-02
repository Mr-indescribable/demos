#!/usr/bin/python3.6
#coding: utf-8

import os
import time
import struct
import logging
import unittest

import __code_path__
from neverland.logging import init_logger
from neverland.utils import ObjectifiedDict as OD
from neverland.utils import errno_from_exception
from neverland.protocol.crypto import Cryptor


logger = logging.getLogger('Crypto')
init_logger(logger, logging.INFO)


kc_config_json = {
    'net': {
        'identification': 'a l00o00oOOoOOoo00oOOo00ong identification string',
        'crypto': {
            'password': 'a SUPER SUPER LONG AND VERY INDESCRIBABLE pASSw0rD',
            'cipher': 'kc-aes-256-gcm'
        }
    }
}
kc_config = OD(**kc_config_json)


openssl_config_json = {
    'net': {
        'identification': 'a l00o00oOOoOOoo00oOOo00ong identification string',
        'crypto': {
            'lib_path': '/usr/lib/libcrypto.so.1.1',
            'password': 'a SUPER SUPER LONG AND VERY INDESCRIBABLE pASSw0rD',
            'cipher': 'aes-256-gcm',
            'iv_len': 12,
        }
    }
}
openssl_config = OD(**openssl_config_json)


# Test case for Cryptor class
class CryptorTest(unittest.TestCase):

    def test_0_kc(self):
        tsum_urandom = 0
        tsum_crypto = 0

        times = 50000
        bs = 65535
        total_mb = times * bs / 1024 / 1024
        total_mb = round(total_mb, 2)
        cipher_name = kc_config.net.crypto.cipher

        print(
            f'Running {times} times of {cipher_name} cipher test '
            f'with data block size {bs}. \nTotal: {total_mb} MB\n'
        )

        kc_cryptor = Cryptor(kc_config)

        for _ in range(times):
            t0 = time.time()
            data_4_test = os.urandom(bs)
            t1 = time.time()

            tsum_urandom += t1 - t0

            t0 = time.time()
            cipher_text = kc_cryptor.encrypt(data_4_test)
            plain_text = kc_cryptor.decrypt(cipher_text)
            t1 = time.time()

            tsum_crypto += t1 - t0

            self.assertEqual(plain_text, data_4_test)

        print(f'Seconds spent on generating random data: {tsum_urandom}')
        print(f'Seconds spent on encrypting & decrypting: {tsum_crypto}')

    def test_1_openssl(self):
        tsum_urandom = 0
        tsum_crypto = 0

        times = 50000
        bs = 65535
        total_mb = times * bs / 1024 / 1024
        total_mb = round(total_mb, 2)
        cipher_name = openssl_config.net.crypto.cipher

        print(
            f'\n\nRunning {times} times of {cipher_name} cipher test '
            f'with data block size {bs}. \nTotal: {total_mb} MB\n'
        )

        openssl_cryptor = Cryptor(openssl_config)

        for _ in range(times):
            t0 = time.time()
            data_4_test = os.urandom(bs)
            t1 = time.time()

            tsum_urandom += t1 - t0

            t0 = time.time()
            cipher_text = openssl_cryptor.encrypt(data_4_test)
            plain_text = openssl_cryptor.decrypt(cipher_text)
            t1 = time.time()

            tsum_crypto += t1 - t0

            self.assertEqual(plain_text, data_4_test)

        print(f'Seconds spent on generating random data: {tsum_urandom}')
        print(f'Seconds spent on encrypting & decrypting: {tsum_crypto}')

    def test_2_kc_decryption_failure(self):
        print('\n Testing decryption failure of KC')
        kc_cryptor = Cryptor(kc_config)
        data_4_test = os.urandom(32)
        try:
            plain_text = kc_cryptor.decrypt(data_4_test)
        except OSError as e:
            errno = errno_from_exception(e)
            print(f'OSError catched, error: {errno}')
            self.assertEqual(errno, 74)

if __name__ == '__main__':
    unittest.main()
