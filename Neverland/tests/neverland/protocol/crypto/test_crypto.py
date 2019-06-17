#!/usr/bin/python3.6
#coding: utf-8

import os

from neverland.config import JsonConfig
from neverland.utils import ObjectifiedDict
from neverland.protocol.crypto import Cryptor
from neverland.protocol.crypto.openssl import OpenSSLCryptor
from neverland.protocol.crypto.kc.aead.gcm import GCMKernelCryptor


crypto_config_dict = {
    'net': {
        'identification': 'testing-node',
        'crypto': {
            'password': 'The_P@5sw0RD',
            'cipher': None,  # should be overridden later
            'salt_len': 8,
            'iv_len': 12,
            'iv_duration_range': [1000, 2000],
            'lib_path': None # should be overridden too if needed
        }
    }
}


def test_openssl():
    config = JsonConfig(**crypto_config_dict)
    config.net.crypto.__update__(lib_path='libcrypto.so.1.1')

    for cipher_name in OpenSSLCryptor.supported_ciphers:
        config.net.crypto.__update__(cipher=cipher_name)
        _test_cipher(config)


def test_kc_gcm():
    config = JsonConfig(**crypto_config_dict)

    for cipher_name in GCMKernelCryptor.supported_ciphers:
        config.net.crypto.__update__(cipher=cipher_name)
        _test_cipher(config)


def _test_cipher(config):
    cryptor = Cryptor(config)

    for _ in range(3000):
        src_data = os.urandom(65536)
        encrypted_data = cryptor.encrypt(src_data)
        decrypted_data = cryptor.decrypt(encrypted_data)

        assert src_data != encrypted_data
        assert src_data not in encrypted_data
        assert src_data == decrypted_data
