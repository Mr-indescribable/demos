from libc.stdlib cimport malloc, free
from cython.operator cimport dereference as deref
from cython.operator cimport address     as byref

from ._libcrypto cimport (
    EVP_CIPHER_CTX,
    EVP_CIPHER,
    EVP_get_cipherbyname,
    EVP_CIPHER_CTX_new,
    EVP_CIPHER_CTX_reset,
    EVP_CIPHER_CTX_free,
    EVP_CipherInit_ex,
    EVP_CipherUpdate,
)


cdef class OpenSSLCryptor:

    ''' The wrapper class for libcrypto.so.1.1
    '''

    _CINIT = True

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

    key_len_map = {
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

    # libcrypto will automatically trim the iv,
    # So, we can simply leave the work to libcrypto
    iv_len_map = {
        'aes-128-cfb': 32,
        'aes-192-cfb': 32,
        'aes-256-cfb': 32,
        'aes-128-ofb': 32,
        'aes-192-ofb': 32,
        'aes-256-ofb': 32,
        'aes-128-gcm': 32,
        'aes-192-gcm': 32,
        'aes-256-gcm': 32,
        'chacha20': 32,
        'chacha20-poly1305': 32,
    }

    cdef char *_cipher_name
    cdef unsigned char *_key
    cdef unsigned char *_iv
    cdef int _mod

    # output buffer for update()
    cdef unsigned char *_o_buf
    cdef int            _o_len

    cdef EVP_CIPHER_CTX *_ctx
    cdef EVP_CIPHER     *_cph

    def __cinit__(self,
        char *cipher_name,
        int mode,
        unsigned char *key,
        unsigned char *iv,
    ):
        self._o_buf = NULL

        self._key = key
        self._iv = iv
        self._mod = mode
        self._cipher_name = cipher_name
        self._cph = EVP_get_cipherbyname(self._cipher_name)
        self._ctx = EVP_CIPHER_CTX_new()

        EVP_CipherInit_ex(
            self._ctx, self._cph, NULL, self._key, self._iv, self._mod
        )

    def __dealloc__(self):
        self.destroy()

    cdef void _reset_o_buf(self, int size):
        # According to the doc of glibc, realloc could copy the data
        # into a new place if it needs to be relocated.
        #
        # So, I'd rather free it and get a new block.
        if self._o_buf is not NULL:
            free(self._o_buf)

        self._o_buf = <unsigned char *>malloc(size)

    cdef int _update(self, unsigned char *data, int data_len):
        self._reset_o_buf(data_len)

        return EVP_CipherUpdate(
            self._ctx, self._o_buf, byref(self._o_len), data, data_len
        )

    def update(self, data):
        self._update(data, len(data))
        return self._o_buf[:self._o_len]

    def reset(self):
        EVP_CIPHER_CTX_reset(self._ctx)
        EVP_CipherInit_ex(
            self._ctx, self._cph, NULL, self._key, self._iv, self._mod
        )

    def destroy(self):
        EVP_CIPHER_CTX_free(self._ctx)

        if (self._o_buf is not NULL):
            free(self._o_buf)

        self._ctx = NULL
        self._cph = NULL
