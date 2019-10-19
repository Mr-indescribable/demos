import os
import json
import time
import struct as pystruct

from ..pkt.general import PktProto, PktTypes, FieldTypes
from ..glb import GLBPktFmt
from ..pkt.udp import UDPPacket
from ..utils.od import ODict
from ..utils.hash import HashTools
from ..utils.misc import Converter, get_localhost_ip
from ..exceptions import (
    PktWrappingError,
    PktUnwrappingError,
    InvalidPkt,
    DecryptionFailed,
)


class PacketWrapper():

    ''' The PacketWrapper class

    PacketWrappers are used in wrapping or unwrapping the packets.
    They pack the field values into bytes that can be transmitted or
    parse the received bytes into defined fields.

    Byte Order:
        In the current implementation, we use little-endian on most fields ,
        except socket addresses.
    '''

    def __init__(self):
        pass

    def _find_fmt(self, proto, type_):
        if proto == PktProto.TCP:
            if type_ == PktTypes.DATA:
                return GLBPktFmt.tcp_data
            elif type_ == PktTypes.CONN_CTRL:
                return GLBPktFmt.tcp_conn_ctrl
            elif type_ == PktTypes.CLST_CTRL:
                return GLBPktFmt.tcp_clst_ctrl
        elif proto == PktProto.UDP:
            return GLBPktFmt.udp_data

        return None

    def wrap(self, pkt):
        pkt_fmt = self._find_fmt(pkt.proto, pkt.fields.type)

        pkt.type = pkt.fields.type
        pkt.data = self._make_pkt(pkt, pkt_fmt)
        return pkt

    def _make_pkt(self, pkt, body_fmt):
        udp_data = b''
        fmt = self.complexed_fmt_mapping.get(pkt.fields.type)

        for field_name, definition in fmt.__fmt__.items():
            value = getattr(pkt.fields, field_name)

            if value is None:
                if definition.calculator is None:
                    if definition.default is not None:
                        value = definition.default
                        pkt.fields.__update__(**{field_name: value})
                    else:
                        raise PktWrappingError(
                            f'Field {field_name} has no value '
                            f'nor calculator or a default value'
                        )
                else:
                    # we will calculate it later by the specified calculator
                    continue

            fragment = self._pack_field(value, definition.type)
            pkt.byte_fields.__update__(**{field_name: fragment})

        for field_name, definition in fmt.__calc_definition__.items():
            value = getattr(pkt.fields, field_name)

            if value is None:
                value = definition.calculator(pkt)

                if value is None:
                    raise PktWrappingError(
                        f'Field {field_name}: calculator doesn\'t '
                        f'return a valid value'
                    )

                pkt.fields.__update__(**{field_name: value})

                fragment = self._pack_field(value, definition.type)
                pkt.byte_fields.__update__(**{field_name: fragment})

        # Finally, all fields are ready. Now we can combine them into udp_data
        for field_name, definition in fmt.__fmt__.items():
            bytes_ = getattr(pkt.byte_fields, field_name)

            udp_data += bytes_

        return udp_data

    def _pack_field(self, value, field_type):
        ''' pack a single field

        :param value: value of the field
        :param field_type: type of the field, select from FieldTypes
        :return: bytes
        '''

        if field_type == FieldTypes.STRUCT_U_CHAR:
            return pystruct.pack('<B', value)
        if field_type == FieldTypes.STRUCT_U_SHORT:
            return pystruct.pack('<H', value)
        if field_type == FieldTypes.STRUCT_U_INT:
            return pystruct.pack('<I', value)
        if field_type == FieldTypes.STRUCT_U_LONG_LONG:
            return pystruct.pack('<Q', value)
        if field_type == FieldTypes.STRUCT_IPV4_SA:
            # ipv4 socket address should in the following format: (ip, port)
            ip, port = value[0], value[1]
            ip = [int(u) for u in ip.split('.')]
            return pystruct.pack('!BBBBH', *ip, port)
        if field_type == FieldTypes.STRUCT_IPV6_SA:
            # TODO ipv6 support
            raise NotImplemented
        if field_type == FieldTypes.PY_BYTES:
            if isinstance(value, bytes):
                return value
            elif isinstance(value, str):
                return value.encode()
            else:
                raise PktWrappingError(
                    f'{type(value)} cannot be packed as PY_BYTES'
                )
        if field_type == FieldTypes.PY_DICT:
            if isinstance(value, dict):
                data = json.dumps(value)
                return data.encode()
            elif isinstance(value, ODict):
                data = json.dumps(value.__to_dict__())
                return data.encode()
            else:
                raise PktWrappingError(
                    f'{type(value)} cannot be packed as PY_DICT'
                )

    def unwrap(self, pkt):
        raise NotImplemented

    def _parse_pkt(self, pkt):
        cur = 0   # cursor
        fields = ODict()
        byte_fields = ODict()

        # parse the header first
        for field_name, definition in self.header_fmt.__fmt__.items():
            # -1 means this field is the last field of the packet
            # and it consumes all remaining space of the packet
            if definition.length == -1:
                field_data = pkt.data[cur:]
            else:
                field_data = pkt.data[cur: cur + definition.length]

            # Packet too short, it must be invalid
            if len(field_data) == 0:
                raise InvalidPkt('packet too short')

            try:
                value = self._unpack_field(field_data, definition.type)
            except pystruct.error:
                raise InvalidPkt('unpack failed')

            fields.__update__(**{field_name: value})
            byte_fields.__update__(**{field_name: field_data})
            cur += definition.length

        body_type = fields.type
        body_fmt = self._find_fmt(pkt.proto, body_type)
        if body_fmt is None:
            raise InvalidPkt('invalid type')

        # parse the body
        for field_name, definition in body_fmt.__fmt__.items():
            # -1 means this field is the last fields of the packet
            # and it consumes all remaining space of the packet
            if definition.length == -1:
                field_data = pkt.data[cur:]
            else:
                field_data = pkt.data[cur: cur + definition.length]

            # Packet too short, it must be invalid
            if len(field_data) == 0:
                raise InvalidPkt('packet too short')

            try:
                value = self._unpack_field(field_data, definition.type)
            except pystruct.error:
                raise InvalidPkt('unpack failed')

            fields.__update__(**{field_name: value})
            byte_fields.__update__(**{field_name: field_data})
            cur += definition.length

        return fields, byte_fields

    def _unpack_field(self, data, field_type):
        ''' unpack a single field

        :param data: bytes
        :param field_type: type of the field, choosed from FieldTypes
        :return: the unpacked value
        '''

        if field_type == FieldTypes.STRUCT_U_CHAR:
            return pystruct.unpack('<B', data)[0]
        if field_type == FieldTypes.STRUCT_U_SHORT:
            return pystruct.unpack('<H', data)[0]
        if field_type == FieldTypes.STRUCT_U_INT:
            return pystruct.unpack('<I', data)[0]
        if field_type == FieldTypes.STRUCT_U_LONG_LONG:
            return pystruct.unpack('<Q', data)[0]
        if field_type == FieldTypes.STRUCT_IPV4_SA:
            info = pystruct.unpack('!BBBBH', data)
            ip = '.'.join(
                    [str(unit) for unit in info[0:4]]
                 )
            port = info[-1]
            return (ip, port)
        if field_type == FieldTypes.STRUCT_IPV6_SA:
            # TODO ipv6 support
            return None
        if field_type == FieldTypes.PY_BYTES:
            return data
        if field_type == FieldTypes.PY_DICT:
            try:
                return json.loads(data.decode())
            except json.decoder.JSONDecodeError:
                raise InvalidPkt('failed to parse a PY_DICT field')
            except UnicodeDecodeError:
                raise InvalidPkt('failed to decode a PY_DICT field')
