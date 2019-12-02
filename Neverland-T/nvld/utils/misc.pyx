import os
import uuid
import socket
import ipaddress


class Shell():

    @classmethod
    def rm(cls, filename):
        if os.path.exists(filename):
            if os.path.isdir(filename):
                raise Exception(
                    f'Cannot remove {filename}, it\'s a directory'
                )
            else:
                os.remove(filename)

    @classmethod
    def mkdir(cls, folder):
        os.makedirs(folder)


# Tools used in verifications
class VerifiTools():

    # determines if an object matches a type
    #
    # :param obj: any object needs to be verified
    # :param types: the expected type
    @classmethod
    def type_matched(cls, obj, type):

        obj_type = obj.__class__ if obj is not None else None
        return obj_type == type

    # determines if an object is a string that contains an IPv4 address
    @classmethod
    def is_ipv4(cls, obj):
        if not isinstance(obj, str):
            return False

        try:
            ip = ipaddress.ip_address(obj)
            return isinstance(ip, ipaddress.IPv4Address)
        except ValueError:
            return False

    # determines if an object is a string that contains an IPv6 address
    @classmethod
    def is_ipv6(cls, obj):
        if not isinstance(obj, str):
            return False

        try:
            ip = ipaddress.ip_address(obj)
            return isinstance(ip, ipaddress.IPv6Address)
        except ValueError:
            return False


class Converter():

    @classmethod
    def int_2_hex(cls, num, lower_case=True):
        s = '{0:x}' if lower_case else '{0:X}'
        hex_number = s.format(num)
        return f'0x{hex_number}'

    # converts a socket address into a string
    #
    # :param sa: socket address in tuple format: (ip, port)
    # :returns: "ip:port"
    @classmethod
    def sa_2_str(cls, sa):
        return f'{sa[0]}:{sa[1]}'


def gen_uuid():
    return str(uuid.uuid4())


def get_localhost_ip():
    return socket.gethostbyname(
        socket.gethostname()
    )


def errno_from_exception(e):
    if hasattr(e, 'errno'):
        return e.errno
    elif e.args:
        return e.args[0]
    else:
        return None
