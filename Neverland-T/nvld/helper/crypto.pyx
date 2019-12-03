from ..crypto.wrapper import StreamCryptor, DGramCryptor


class CryptoHelper():

    @classmethod
    def new_stream_cryptor(cls, *args, **kwargs):
        return StreamCryptor(*args, **kwargs)

    @classmethod
    def new_dgram_cryptor(cls, *args, **kwargs):
        return DGramCryptor(*args, **kwargs)

    # For each TCP connection in the channel within the NLSwirl,
    # the connection-accepting side must traverse the IV set and
    # find which one is using by the peer before using the connection.
    @classmethod
    def find_iv(cls, cryptor):
        pass
