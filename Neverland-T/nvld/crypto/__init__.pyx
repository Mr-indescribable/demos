import logging

from ..exceptions import ArgumentError
from ..utils.hash import HashTools
from .mode import Modes
from .openssl import OpenSSLCryptor
from .kc.aead.gcm import GCMKernelCryptor


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


ALL_CIPHERS = list(supported_ciphers.keys())


class Cryptor():

    # we tag the cryptor with a label of the socket address of the remote node
    # type: str, format: "ip:port"
    attribution = None

    def __init__(self, config, key=None, iv=None, attribution=None, stream=False):
        ''' Constructor

        :param config: the config
        :param key: optional, if this argument is not given, then the default
                    key derived by neverland.utils.HashTools.hkdf will be used
        :param iv: optional, if this argument is not given, then the default
                   IV derived by neverland.utils.HashTools.hdivdf will be used
        :param attribution: a tag about which remote node that this cryptor
                            belongs to.
        :param stream: if is argument is False, then the Cryptor will
                       not work in stream mode, it will reset the cipher after
                       each time of encryption or decryption
        '''

        self.config = config
        self.attribution = attribution

        self._stream = stream

        self.__identification = self.config.net.identification
        self.__passwd = self.config.net.crypto.password
        self._cipher_name = self.config.net.crypto.cipher
        self._cipher_cls = supported_ciphers.get(self._cipher_name)
        self._key_len = self._cipher_cls.key_len_map[self._cipher_name]
        self._iv_len = self._cipher_cls.iv_len_map[self._cipher_name]

        self._key = key or HashTools.hkdf(self.__passwd, self._key_len)
        self._iv = iv or HashTools.hdivdf(self.__identification, self._iv_len)

        if self._cipher_cls is None:
            raise Exception('unsupported cipher')

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

        if not self._stream:
            self._cipher.reset()

        return data

    def decrypt(self, data):
        data = self._decipher.update(data)

        if not self._stream:
            self._decipher.reset()

        return data

    @property
    def iv(self):
        return self._cipher._iv
