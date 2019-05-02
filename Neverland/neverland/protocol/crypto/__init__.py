#!/usr/bin/python3.6
# coding: utf-8

import logging

from neverland.exceptions import ArgumentError
from neverland.protocol.crypto.mode import Modes
from neverland.protocol.crypto.openssl import OpenSSLCryptor, load_libcrypto
from neverland.protocol.crypto.kc.aead.gcm import GCMKernelCryptor


logger = logging.getLogger('Crypto')


openssl_ciphers = {
    cipher: OpenSSLCryptor for cipher in OpenSSLCryptor.supported_ciphers
}

kc_aead_ciphers = {
    cipher: GCMKernelCryptor for cipher in GCMKernelCryptor.supported_ciphers
}

supported_ciphers = dict()
supported_ciphers.update(openssl_ciphers)
supported_ciphers.update(kc_aead_ciphers)


openssl_preload_func_map = {
    cipher: load_libcrypto for cipher in OpenSSLCryptor.supported_ciphers
}


preload_funcs = {}
preload_funcs.update(openssl_preload_func_map)


def preload_crypto_lib(cipher_name, libpath=None):
    preload_func = preload_funcs.get(cipher_name)
    if preload_func is not None:
        preload_func(libpath)


class Cryptor():

    # we tag the cryptor with a label of the socket address of the remote node
    # type: str, format: "ip:port"
    attribution = None

    def __init__(self, config, key=None, iv=None, attribution=None):
        ''' Constructor

        :param config: the config
        :param key: optional, if this argument is not given, then the default
                    key derived by neverland.utils.HashTools.hkdf will be used
        :param iv: optional, if this argument is not given, then the default
                   IV derived by neverland.utils.HashTools.hdivdf will be used
        :param attribution: a tag about which remote node that this cryptor
                            belongs to.
        '''

        self.config = config
        self.attribution = attribution

        self._cipher_name = self.config.net.crypto.cipher
        self._cipher_cls = supported_ciphers.get(self._cipher_name)

        if self._cipher_cls is None:
            raise Exception('unsupported cipher')

        if self._cipher_name.startswith('kc-'):
            self._cipher_cls.check_kernel_version()

        self._init_ciphers(key, iv)

        logger.info(
            f'Loadded crypto implementation {self._cipher_cls.__name__} '
            f'with cipher {self._cipher_name}'
        )

    def _init_ciphers(self, key, iv):
        self._cipher = self._cipher_cls(self.config, Modes.ENCRYPTING, key, iv)
        self._decipher = self._cipher_cls(self.config, Modes.DECRYPTING, key, iv)

    def reset(self):
        self._cipher.reset()
        self._decipher.reset()

    def encrypt(self, data):
        return self._cipher.update(data)

    def decrypt(self, data):
        return self._decipher.update(data)

    @property
    def iv(self):
        return self._cipher._iv
