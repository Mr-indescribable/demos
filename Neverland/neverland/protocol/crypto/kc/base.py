#!/usr/bin/python3.6
#coding: utf-8

import os
import socket
import platform

from neverland.exceptions import ArgumentError
from neverland.utils import HashTools
from neverland.protocol.crypto.mode import Modes


''' The kernel crypto module

By default, Linux kernel >= 4.9 is required
'''


_kernel_version_checked = False


# The errno of KC decription failure
KC_DECRYPTION_FAILED = 74


class BaseKernelCryptor():

    ''' The base class of kernel cryptors
    '''

    # The minimum of required version of the Linux kernel
    KERNEL_MOJOR_VERSION = 4
    KERNEL_MINOR_VERSION = 9

    supported_ciphers = []

    _iv_len = None
    _key_len = None

    _kc_cipher_type = None
    _kc_cipher_name = None

    _aad_len = None

    _aead = False

    @classmethod
    def check_kernel_version(cls):
        uname = platform.uname()
        kernel_versions = uname.release.split('.')

        try:
            major_version = int(kernel_versions[0])
            minor_version = int(kernel_versions[1])
        except Exception:
            raise RuntimeError('Unrecognized kernel version')

        if major_version > cls.KERNEL_MOJOR_VERSION:
            return

        if minor_version > cls.KERNEL_MINOR_VERSION:
            return

        raise RuntimeError(
            f'Unsupported kernel version, Linux Kernel >= '
            f'{KERNEL_MOJOR_VERSION}.{KERNEL_MINOR_VERSION} is required.'
        )

    def __init__(self, config, mode, key=None, iv=None):
        ''' Constructor

        :param config: the config
        :param mode: the working mod of the cryptor,
                    0 to decrypting and 1 to encrypting
        :param key: the crypto key which will be used in encryption and
                    decryption, if it's not provided, then the default key
                    derived from the password will be used
        :param iv: the IV used in encryption and decryption, if it's not
                   provided, then the default iv derived from the
                   identification string will be used
        '''

        self.config = config
        self._mode = mode

        self.cipher_name = self.config.net.crypto.cipher
        self.__identification = self.config.net.identification
        self.__passwd = self.config.net.crypto.password

        self.prepare()
        self.checkup()

        self._key = key or HashTools.hkdf(self.__passwd, self._key_len)
        self._iv = iv or HashTools.hdivdf(self.__identification, self._iv_len)

        self.init_cryptor()

    def prepare(self):
        ''' prepare attributes before checking and initializing the cryptor

        The following attributes of the instance should get assigned here:
            self._key_len
            self._iv_len
            self._kc_cipher_type
            self._kc_cipher_name
            self._aead

            attributes for aead:
                self._aad_len
        '''

    def checkup(self):
        ''' put verifications here
        '''

        global _kernel_version_checked

        if not _kernel_version_checked:
            BaseKernelCryptor.check_kernel_version()
            _kernel_version_checked = True

        if self.cipher_name not in self.supported_ciphers:
            raise ArgumentError(f'Unsupported cipher name: {self.cipher_name}')

        if self._mode not in Modes:
            raise ArgumentError(f'Invalid mod: {self._mode}')

        cls_name = self.__class__.__name__

        if self._key_len is None:
            raise RuntimeError(f'{cls_name}._key_len is None')

        if self._iv_len is None:
            raise RuntimeError(f'{cls_name}._iv_len is None')

        if self._kc_cipher_type is None:
            raise RuntimeError(f'{cls_name}._kc_cipher_type is None')

        if self._kc_cipher_name is None:
            raise RuntimeError(f'{cls_name}._kc_cipher_name is None')

    def init_cryptor(self):
        ''' initialization of the cryptor instance
        '''

        if self._mode == Modes.ENCRYPTING:
            self._op = socket.ALG_OP_ENCRYPT
        elif self._mode == Modes.DECRYPTING:
            self._op = socket.ALG_OP_DECRYPT
        else:
            raise ArgumentError(f'Invalid mod: {self._mode}')

        self.alg_sock = self.create_alg_sock()
        self.alg_conn, _ = self.alg_sock.accept()

    def create_alg_sock(self):
        alg_sock = socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET)
        alg_sock.bind(
            (self._kc_cipher_type, self._kc_cipher_name)
        )

        alg_sock.setsockopt(socket.SOL_ALG, socket.ALG_SET_KEY, self._key)

        if self._aead:
            alg_sock.setsockopt(
                socket.SOL_ALG,
                socket.ALG_SET_AEAD_AUTHSIZE,
                None,
                self._aad_len,
            )

        return alg_sock

    def update(self, data):
        ''' do encryption or decryption
        '''

        raise NotImplemented

    def change_iv(self, iv):
        self._iv = iv

    def clean(self):
        ''' clean/close the cryptor and release resources
        '''

        if hasattr(self, 'alg_conn'):
            self.alg_conn.close()

        if hasattr(self, 'alg_sock'):
            self.alg_sock.close()

    def reset(self):
        ''' reset the cryptor

        Nothing needs to be done here.
        This method is reserved for the compatibility (with OpenSSL).
        '''

    def __del__(self):
        self.clean()
