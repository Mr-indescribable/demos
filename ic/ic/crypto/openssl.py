#!/usr/bin/python3.6
# coding: utf-8

import logging
from ctypes import (
    byref,
    CDLL,
    c_void_p,
    c_int,
    c_long,
    c_char_p,
    create_string_buffer,
)


libcrypto = None
lib_loaded = False


def load_libcrypto(libpath='libcrypto.so.1.1'):
    global lib_loaded, libcrypto
    if not lib_loaded:
        libcrypto = CDLL(libpath)

        libcrypto.EVP_get_cipherbyname.restype = c_void_p
        libcrypto.EVP_CIPHER_CTX_new.restype = c_void_p
        libcrypto.EVP_CIPHER_CTX_free.argtypes = [c_void_p]
        libcrypto.EVP_CIPHER_CTX_reset.argtypes = [c_void_p]
        libcrypto.EVP_CipherInit_ex.argtypes = [
            c_void_p, c_void_p, c_char_p, c_char_p, c_char_p, c_int
        ]
        libcrypto.EVP_CipherUpdate.argtypes = [
            c_void_p, c_void_p, c_void_p, c_char_p, c_int
        ]

        lib_loaded = True
        logging.info('Successfully loaded crypto library from {libpath}')


def new_cipher_ctx(cipher_name, key, iv, mod):
    if libcrypto is None:
        raise Exception('libcrypto is not loaded, cannot init cipher')

    cipher_ctx = libcrypto.EVP_CIPHER_CTX_new()
    cipher = libcrypto.EVP_get_cipherbyname(cipher_name)
    res = libcrypto.EVP_CipherInit_ex(
             cipher_ctx, cipher, None, key, iv, c_int(mod)
          )

    if bool(res) is False:
        raise Exception('cipher init failed')
    return cipher_ctx, cipher


class OpenSSLCryptor(object):

    buf_size = 2048
    supported_ciphers = [
        'aes-128-cfb',
        'aes-192-cfb',
        'aes-256-cfb',
        'aes-128-ofb',
        'aes-192-ofb',
        'aes-256-ofb',
        'aes-128-gcm',
        'aes-192-gcm',
        'aes-256-gcm',
        'chacha20',
        'chacha20-poly1305',
        'idea-cfb',
        'idea-ofb',
        'rc4',
        'rc4-40',
        'rc4-hmac-md5',
    ]

    def __init__(self, cipher_name, key, iv, mod, libpath='libcrypto.so.1.1'):
        if cipher_name not in self.supported_ciphers:
            raise Exception('cipher not supported')

        if not lib_loaded:
            load_libcrypto(libpath)
        cipher_name = cipher_name.encode('utf-8')
        self._cph_ctx, self._cph = new_cipher_ctx(cipher_name, key, iv, mod)
        self._key = key
        self._iv = iv
        self._mod = mod

    def update(self, data):
        in_ = c_char_p(data)
        inl = len(data)
        buf_size = self.buf_size if self.buf_size >= inl else inl * 2
        out = create_string_buffer(buf_size)
        outl = c_long(0)

        libcrypto.EVP_CipherUpdate(
            self._cph_ctx,
            byref(out),
            byref(outl),
            in_,
            inl,
        )
        self.reset()
        return out.raw[:outl.value]

    def clean(self):
        if hasattr(self, '_cph_ctx'):
            libcrypto.EVP_CIPHER_CTX_reset(self._cph_ctx)
            libcrypto.EVP_CIPHER_CTX_free(self._cph_ctx)
            self._cipher_ctx = None
        if hasattr(self, '_cph'):
            self._cph = None

    def reset(self):
        libcrypto.EVP_CIPHER_CTX_reset(self._cph_ctx)
        libcrypto.EVP_CipherInit_ex(
            self._cph_ctx,
            self._cph,
            None,
            self._key,
            self._iv,
            c_int(self._mod)
        )

    def __del__(self):
        self.clean()
