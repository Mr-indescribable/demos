cdef extern from 'openssl/ossl_typ.h':

    ctypedef struct EVP_CIPHER_CTX:
        pass

    ctypedef struct EVP_CIPHER:
        pass

    ctypedef struct ENGINE:
        pass


cdef extern from 'openssl/evp.h':

    EVP_CIPHER *EVP_get_cipherbyname(const char *name)

    EVP_CIPHER_CTX *EVP_CIPHER_CTX_new()
    int EVP_CIPHER_CTX_reset(EVP_CIPHER_CTX *c)
    void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *c)
    # void EVP_CIPHER_meth_free(EVP_CIPHER *cipher)

    int EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx,
                          const EVP_CIPHER *cipher, ENGINE *impl,
                          const unsigned char *key,
                          const unsigned char *iv, int enc)

    int EVP_CipherUpdate(EVP_CIPHER_CTX *ctx,
                         unsigned char *out, int *outl,
                         const unsigned char *in_, int inl)
