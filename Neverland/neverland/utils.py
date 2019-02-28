#!/usr/bin/python3.6
# coding: utf-8

import json
import uuid
import socket
import hashlib


class ObjectifiedDict():

    def __getattribute__(self, name):
        container = object.__getattribute__(self, '__container__')
        if name in container:
            return container.get(name)
        else:
            try:
                return object.__getattribute__(self, name)
            except AttributeError:
                return None

    def __setattr__(self, name, value):
        self.__update__(**{name: value})

    def __convert__(self, item):
        if isinstance(item, dict):
            return ObjectifiedDict(**item)
        if isinstance(item, list):
            return [self.__convert__(unit) for unit in item]
        if isinstance(item, tuple):
            # this is necessary,
            # by default, this tuple derivation will return a generator
            return tuple(
                (self.__convert__(unit) for unit in item)
            )
        if isinstance(item, set):
            return {self.__convert__(unit) for unit in item}
        else:
            return item

    def __init__(self, **kwargs):
        object.__setattr__(self, '__container__', dict())
        self.__update__(**kwargs)

    def __update__(self, **kwargs):
        for key, value in kwargs.items():
            self.__container__[key] = self.__convert__(value)

    def __iter__(self):
        return iter(
            self.__container__.items()
        )

    def __bool__(self):
        return bool(self.__container__)

    def __get__(self, key):
        return self.__container__.get(key)

    def __clear__(self):
        self.__container__.clear()

    @staticmethod
    def __to_dumpable__(item, keep_bytes=True):
        if item.__class__ is bytes:
            return item if keep_bytes else f'<bytes length={len(item)}>'
        elif isinstance(item, ObjectifiedDict):
            return item.__to_dict__(keep_bytes)
        elif item.__class__ in (list, tuple, set):
            return [ObjectifiedDict.__to_dumpable__(unit) for unit in item]
        elif item.__class__ in (bool, None):
            return item
        elif item.__class__ not in (int, float, str):
            return str(item)

        return item

    def __to_dict__(self, keep_bytes=True):
        d = {}
        for key, value in self.__container__.items():
            d[key] = self.__to_dumpable__(value, keep_bytes)
        return d

    def __str__(self):
        return json.dumps(
            self.__to_dict__(keep_bytes=False), indent=4
        )


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


class Converter():

    @classmethod
    def int_2_hex(cls, num, lower_case=True):
        s = '{0:x}' if lower_case else '{0:X}'
        hex_number = s.format(num)
        return f'0x{hex_number}'


class _BaseEnum():

    ''' The base enumeration class

    Don't inherit it directly, use MetaEnum instead.
    '''

    def __getattribute__(self, name):
        members = object.__getattribute__(self, '__members__')

        if name == '__members__':
            return members
        elif name in ['_keys', '_values']:
            return object.__getattribute__(self, name)
        else:
            return members.get(name)

    def __contains__(self, value):
        return value in self.__members__.values()

    def _keys(self):
        return self.__members__.keys()

    def _values(self):
        return self.__members__.values()

    def __iter__(self):
        return iter(self.__members__.items())


class MetaEnum(type):

    ''' The meta class of enumeration classes
    '''

    def __new__(mcls, name, bases, attrs):
        if '__members__' in attrs:
            raise AttributeError(
                'Please don\'t use __members__ as an attribute '
                'in your enumeration'
            )

        original_attrs = dict(attrs)
        attrs.pop('__module__')
        attrs.pop('__qualname__')
        original_attrs.update(__members__=attrs)

        for attr in attrs.keys():
            original_attrs.pop(attr)

        bases = list(bases)
        bases.append(_BaseEnum)
        bases = tuple(bases)

        # We did some magic here to make enumeration classes affected by
        # those magic methods defined in _BaseEnum.
        #
        # Well, the solution is returning an instance instead of a class
        # So, this also means our enumeration classes are not inheritable.
        return type.__new__(mcls, name, bases, original_attrs)()


def gen_uuid():
    return str(uuid.uuid4())


def get_localhost_ip():
    return socket.gethostbyname(
        socket.gethostname()
    )


# from tornado.util
def errno_from_exception(e):
    """Provides the errno from an Exception object.

    There are cases that the errno attribute was not set so we pull
    the errno out of the args but if someone instatiates an Exception
    without any args you will get a tuple error. So this function
    abstracts all that behavior to give you a safe way to get the
    errno.
    """

    if hasattr(e, 'errno'):
        return e.errno
    elif e.args:
        return e.args[0]
    else:
        return None
