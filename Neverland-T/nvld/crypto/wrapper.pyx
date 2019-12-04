import logging

from ..exceptions import ConfigError
from ..utils.hash import HashTools
from .mode import Modes
from .openssl import OpenSSLCryptor
from .kc.aead.gcm import GCMKernelCryptor
from ..glb import GLBInfo, GLBComponent


__all__ = [
    'IV_LEN_MAP',
    'ALL_CIPHERS',
    'OPENSSL_CIPHERS',
    'KC_AEAD_CIPHERS',
    'SUPPORTED_CIPHERS',
    'Cryptor',
    'StreamCryptor',
    'DGramCryptor',
]


logger = logging.getLogger('Crypto')


OPENSSL_CIPHERS = {
    cipher: OpenSSLCryptor for cipher in OpenSSLCryptor.supported_ciphers
}

KC_AEAD_CIPHERS = {
    cipher: GCMKernelCryptor for cipher in GCMKernelCryptor.supported_ciphers
}

SUPPORTED_CIPHERS = dict()
SUPPORTED_CIPHERS.update(OPENSSL_CIPHERS)
SUPPORTED_CIPHERS.update(KC_AEAD_CIPHERS)


IV_LEN_MAP = dict()
IV_LEN_MAP.update(OpenSSLCryptor.iv_len_map)
IV_LEN_MAP.update(GCMKernelCryptor.iv_len_map)


ALL_CIPHERS = list(SUPPORTED_CIPHERS.keys())


class Cryptor():

    # we tag the cryptor with a label of the socket address of the remote node
    # type: str, format: "ip:port"
    attribution = None

    def __init__(
        self,
        cipher_name,
        iv,
        key=None,
        attribution=None,
        stream_mod=False,
    ):
        # Constructor
        #
        # :param cipher_name: pick a cipher name from ALL_CIPHERS
        # :param iv: optional, if this argument is not given, then the default
        #            IV derived by neverland.utils.HashTools.hdivdf will be used
        # :param key: optional, if this argument is not given, then the default
        #             key derived by neverland.utils.HashTools.hkdf will be used
        # :param attribution: a tag about which remote node that this cryptor
        #                     belongs to.
        # :param stream_mod: if is argument is False, then the Cryptor will
        #                    not work in stream mode, it will reset the cipher
        #                    after each time of encryption or decryption

        self.attribution = attribution
        self._stream_mod = stream_mod

        self._cipher_name = cipher_name
        self._cipher_cls = SUPPORTED_CIPHERS.get(self._cipher_name)
        if self._cipher_cls is None:
            raise ConfigError(f'unsupported cipher: {self._cipher_name}')

        self.__passwd = GLBInfo.config.net.crypto.password
        self._key_len = self._cipher_cls.key_len_map[self._cipher_name]
        self._iv_len = self._cipher_cls.iv_len_map[self._cipher_name]

        self._iv = iv
        if self._iv_len != len(self._iv):
            raise RuntimeError(
                f'IV length error, '
                f'expected: {self._iv_len}, got: {len(self._iv)}'
            )

        self._key = key or HashTools.hkdf(self.__passwd, self._key_len)

        self._key = self._key[:self._key_len]
        self._iv = self._iv[:self._iv_len]

        if self._cipher_cls is None:
            raise ConfigError('unsupported cipher')

        if self._cipher_name.startswith('kc-'):
            self._cipher_cls.check_kernel_version()

        self._init_ciphers()

        logger.info(
            f'Loadded crypto implementation {self._cipher_cls.__name__} '
            f'with cipher {self._cipher_name}'
        )

    def _init_ciphers(self):
        if self._cipher_cls._CINIT:
            cipher_name = self._cipher_name.encode()
        else:
            cipher_name = self._cipher_name

        self._cipher = self._cipher_cls(
            cipher_name,
            Modes.ENCRYPTING,
            self._key,
            self._iv,
        )
        self._decipher = self._cipher_cls(
            cipher_name,
            Modes.DECRYPTING,
            self._key,
            self._iv,
        )

    def reset(self):
        self._cipher.reset()
        self._decipher.reset()

    def encrypt(self, data):
        data = self._cipher.update(data)

        if not self._stream_mod:
            self._cipher.reset()

        return data

    def decrypt(self, data):
        data = self._decipher.update(data)

        if not self._stream_mod:
            self._decipher.reset()

        return data

    @property
    def iv(self):
        return self._cipher._iv


class StreamCryptor(Cryptor):

    def __init__(
        self,
        key=None,
        iv=None,
        attribution=None,
    ):
        cipher = GLBInfo.config.net.crypto.stream_cipher
        iv = iv or GLBComponent.div_mgr.random_stmc_div()
        Cryptor.__init__(self, cipher, key, iv, attribution, stream_mod=True)


# In this manner, the term Stream/DGram stands for Stream socket
# and DGram socket but not stream/block cipher.
#
# So, StreamCryptor and DGramCryptor actually means:
#     Cryptor class for Stream/DGram sockets
class DGramCryptor(Cryptor):

    def __init__(
        self,
        key=None,
        iv=None,
        attribution=None,
    ):
        cipher = GLBInfo.config.net.crypto.dgram_cipher
        iv = iv or GLBComponent.div_mgr.random_dgmc_div()
        Cryptor.__init__(self, cipher, key, iv, attribution, stream_mod=False)
