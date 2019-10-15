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


class VerifiTools():

    ''' Tools used in verifications
    '''

    @classmethod
    def type_matched(cls, obj, type):
        ''' determines if an object matches a type

        :param obj: any object needs to be verified
        :param types: the expected type
        '''

        obj_type = obj.__class__ if obj is not None else None
        return obj_type == type

    @classmethod
    def is_ipv4(cls, obj):
        ''' determines if an object is a string that contains an IPv4 address
        '''

        if not isinstance(obj, str):
            return False

        try:
            ip = ipaddress.ip_address(obj)
            return isinstance(ip, ipaddress.IPv4Address)
        except ValueError:
            return False

    @classmethod
    def is_ipv6(cls, obj):
        ''' determines if an object is a string that contains an IPv6 address
        '''

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

    @classmethod
    def sa_2_str(cls, sa):
        ''' convert a socket address into a string

        :param sa: socket address in tuple format: (ip, port)
        :returns: "ip:port"
        '''

        return f'{sa[0]}:{sa[1]}'


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
