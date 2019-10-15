import hashlib


class HashTools():

    @classmethod
    def _hash(cls, method, data):
        if isinstance(data, str):
            data = data.encode('utf-8')

        m = getattr(hashlib, method)()
        m.update(data)
        return m.hexdigest()

    @classmethod
    def md5(cls, data):
        return cls._hash('md5', data)

    @classmethod
    def sha1(cls, data):
        return cls._hash('sha1', data)

    @classmethod
    def sha256(cls, data):
        return cls._hash('sha256', data)

    @classmethod
    def sha512(cls, data):
        return cls._hash('sha512', data)

    @classmethod
    def hkdf(cls, password, key_len):
        x = key_len * -1

        return cls.sha256(
            password.encode()
        )[x:].encode()

    @classmethod
    def hdivdf(cls, identification, iv_len):
        ''' Hash-based Default IV Derivation Function

        Before we establish the connection and use random IVs, we will need
        a default IV to use or we cannot establish the initial connection

        And, same as the hkdf, this is enough,
        we don't need something complicated.

        :param identification: The identification string of node
        :param iv_len: length of iv
        '''

        digest = cls.sha256(identification.encode())
        x = iv_len * -1

        return cls.sha256(
            digest.encode()
        )[x:].encode()
