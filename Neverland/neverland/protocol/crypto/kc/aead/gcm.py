#!/usr/bin/python3.6
#coding: utf-8

import os
import socket
import platform

from neverland.exceptions import ArgumentError
from neverland.utils import HashTools
from neverland.protocol.crypto.mode import Modes
from neverland.protocol.crypto.kc.base import BaseKernelCryptor


''' The KC GCM Crypto Module

Supported algorithms:
    kc-aes-128-gcm
    kc-aes-192-gcm
    kc-aes-256-gcm

Linux kernel >= 4.9 is required
'''


# According to the GCM specification,
# the IV length shall be fixed in 12 bytes (96 bits).
GCM_IV_LENGTH = 12

# The length of Associated Authentication Data (AAD) in AEAD
AAD_LENGTH = 16

# The length of Integrity Check Value (ICV, a.k.a. tag) in gcm
ICV_LENGTH = 16


class GCMKernelCryptor(BaseKernelCryptor):

    supported_ciphers = [
        'kc-aes-128-gcm',
        'kc-aes-192-gcm',
        'kc-aes-256-gcm',
    ]

    key_length_mapping = {
        'kc-aes-128-gcm': 16,
        'kc-aes-192-gcm': 24,
        'kc-aes-256-gcm': 32,
    }

    def prepare(self):
        self._key_len = self.key_length_mapping.get(self.cipher_name)
        self._iv_len = GCM_IV_LENGTH
        self._kc_cipher_type = 'aead'
        self._kc_cipher_name = 'gcm(aes)'

        self._aead = True
        self._aad_len = AAD_LENGTH
        self._icv_len = ICV_LENGTH

    def update(self, data):
        ''' do encryption or decryption
        '''

        if self._mode == Modes.ENCRYPTING:
            aad = os.urandom(self._aad_len)
            msg = aad + data

            recv_buffer_len = self._aad_len + len(data) + self._icv_len
        else:
            msg = data
            recv_buffer_len = len(data)

        self.alg_conn.sendmsg_afalg(
            [msg],
            op=self._op,
            iv=self._iv,
            assoclen=self._aad_len,
        )

        res = self.alg_conn.recv(recv_buffer_len)

        if self._mode == Modes.ENCRYPTING:
            # In encrypting mode of GCM ciphers,
            # the kernel crypto api returns cipher text in following format:
            #
            #     |     AAD       |        cipher text       |      ICV      |
            #     +---------------+--------------------------+---------------|
            #
            # We don't need to transform it into another format.
            # It can be sent to the remote directly.
            return res
        else:
            # Here we extract the plain text and return the plain text only
            return res[self._aad_len: recv_buffer_len - self._icv_len]
