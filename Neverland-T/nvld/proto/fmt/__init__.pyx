from ...utils.od import ODict
from ...utils.enumeration import MetaEnum


class SpecialLength(metaclass=MetaEnum):

    # Use all bytes remaining
    USE_ALL  = -1

    # Use all bytes remaining but not including the delimiter
    TCP_EXCEPT_DELIM = -2


class FieldDefinition(ODict):
    pass


class BasePktFormat():

    ''' The format of Neverland packets

    This kind of classes are responsible for describing the format of packets.
    It should contain a dict type attribute named as "__fmt__" which describes
    the format of packets

    The format of the __fmt__: {

        'field_name': ODict(
             length        = <length of the field>,
             type          = <field type, enumerated in FieldTypes>,
             default       = <default value of the field>,
             calculator    = <specify a function to calculate the field>,
             calc_priority = <an integer, smaller number means higher priority>,
         )

    }

    Example of the "calculator":

        def field_calculator(pkt, header_fmt, body_fmt):
            """
            :param pkt: neverland.pkt.UDPPacket instance
            :param header_fmt: the format class of the header of current packet
            :param body_fmt: the format class of the body of current packet
            """

            ## some calculation...

            return value

    -------------------------------------------

    This kind of classes depends on the ordered dict feature which implemented
    in Python 3.6 and becomes a ture feature in Python 3.7. So this also means
    earlier versions (< 3.6) of Python interpreters will not be supported.

    And we also need to define the __type__ attribute, it describes the type of
    the packet format definition. The value should be choosed from pkt.PktTypes
    '''

    __type__ = None
    __fmt__ = dict()

    # field definitions that contains a calculator,
    # sorted by the calculator priority
    __calc_definition__ = dict()

    @classmethod
    def gen_fmt(cls):
        ''' generates the __fmt__ attribute
        '''

    @classmethod
    def sort_calculators(cls):
        '''
        Sort field calculators by the defined priority and
        store them in cls.__calc_definition__
        '''

        def _key(item):
            definition = item[1]
            return definition.calc_priority or 0

        sorted_fmt = sorted(cls.__fmt__.items(), key=_key)

        for field_name, definition in sorted_fmt:
            if definition.calculator is not None:
                cls.__calc_definition__.update({field_name: definition})


class ComplexedFormat(BasePktFormat):

    ''' Complexed packet format

    Sometimes, we will need to combine the header format and the body format.
    '''

    def __init__(self):
        self.__fmt__ = dict()
        self.__calc_definition__ = dict()

    def combine_fmt(self, fmt_cls):
        ''' Combine a new packet format class into the existing fields.

        Fields in fmt_cls will be added after the existing fields.

        Works like dict.update
        '''

        self.__fmt__.update(fmt_cls.__fmt__)

    def sort_calculators(self):
        '''
        Same as BasePktFormat.sort_calculators, but ComplexedFormat must be
        instantiated before we use it, so we cannot use the class method here
        '''

        def _key(item):
            definition = item[1]
            return definition.calc_priority or 0

        sorted_fmt = sorted(self.__fmt__.items(), key=_key)

        for field_name, definition in sorted_fmt:
            if definition.calculator is not None:
                self.__calc_definition__.update({field_name: definition})
