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
