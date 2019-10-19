import json


# The objectified dict class
#
# With this class, we can access dict values
# just like accessing attributes in an object
#
# e.g:
#     od = ODict(a=1, b=2)
#     od.a
#     od.b
class ODict():

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

    def __contains(self, key):
        container = object.__getattribute__(self, '__container__')
        return key in container

    def __convert__(self, item):
        if isinstance(item, dict):
            return ODict(**item)
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

    # use __get__ instead will cause some confliction
    def __getv__(self, key):
        return self.__container__.get(key)

    def __clear__(self):
        self.__container__.clear()

    @staticmethod
    def __to_dumpable__(item, keep_bytes=True):
        if item.__class__ is bytes:
            return item if keep_bytes else f'<bytes length={len(item)}>'
        elif isinstance(item, ODict):
            return item.__to_dict__(keep_bytes)
        elif item.__class__ in (list, tuple, set):
            return [ODict.__to_dumpable__(unit) for unit in item]
        elif item.__class__ is bool or item is None:
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
