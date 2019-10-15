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

from ..exceptions import ArgumentError
from ..utils.hash import HashTools
from .mode import Modes


''' The OpenSSL crypto module

libcrypto.so.1.1 is required

Currently, it's not used.
'''


logger = logging.getLogger('Crypto')


EVP_MAX_KEY_LENGTH = 64
EVP_MAX_IV_LENGTH = 16


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
        logger.info(f'Successfully loaded crypto library from {libpath}')


def new_cipher_ctx(cipher_name, key, iv, mod):
    ''' create a new EVP cipher context
    '''

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
    ]
    key_len_mapping = {
        'aes-128-cfb': 16,
        'aes-192-cfb': 24,
        'aes-256-cfb': 32,
        'aes-128-ofb': 16,
        'aes-192-ofb': 24,
        'aes-256-ofb': 34,
        'aes-128-gcm': 16,
        'aes-192-gcm': 24,
        'aes-256-gcm': 32,
        'chacha20': 32,
        'chacha20-poly1305': 32,
    }

    def __init__(self, config, mode, key=None, iv=None):
        ''' Constructor

        :param config: the config
        :param mode: mod argument for EVP_CipherInit_ex. 0 or 1,
                     0 means decrypting and 1 means encrypting,
        :param key: the crypto key which will be used in encryption and
                    decryption, if it's not provided, then the default key
                    derived from the password will be used
        :param iv: the IV used in encryption and decryption, if it's not
                   provided, then the default iv derived from the
                   identification string will be used
        '''

        self.config = config
        self.cipher_name = self.config.net.crypto.cipher
        self.libpath = self.config.net.crypto.lib_path or 'libcrypto.so.1.1'

        self._mod = mode
        if self._mod not in Modes:
            raise ArgumentError(f'Invalid mode: {mode}')

        self.__identification = self.config.net.identification
        self.__passwd = self.config.net.crypto.password
        self._iv_len = self.config.net.crypto.iv_len
        self._key_len = self.key_len_mapping.get(self.cipher_name)

        if self._iv_len > EVP_MAX_IV_LENGTH:
            raise ArgumentError('IV length overflows')

        self._key = key or HashTools.hkdf(self.__passwd, self._key_len)
        self._iv = iv or HashTools.hdivdf(self.__identification, self._iv_len)

        if self.cipher_name not in self.supported_ciphers:
            raise ArgumentError(f'Unsupported cipher name: {self.cipher_name}')

        if not lib_loaded:
            load_libcrypto(self.libpath)

        self._cph_ctx, self._cph = new_cipher_ctx(
            self.cipher_name.encode(), self._key, self._iv, self._mod
        )

    def update(self, data):
        ''' do encryption or decryption
        '''

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
