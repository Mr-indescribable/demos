import random

from ..glb import GLBComponent
from ..crypto.wrapper import StreamCryptor, DGramCryptor


class CryptoHelper():

    @classmethod
    def new_stream_cryptor(cls, *args, **kwargs):
        return StreamCryptor(*args, **kwargs)

    @classmethod
    def new_dgram_cryptor(cls, *args, **kwargs):
        return DGramCryptor(*args, **kwargs)

    @classmethod
    def random_defaul_stmc(cls):
        return random.choice(GLBComponent.default_stmc_list)

    @classmethod
    def random_defaul_dgmc(cls):
        return random.choice(GLBComponent.default_dgmc_list)
