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
