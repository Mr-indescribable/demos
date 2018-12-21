#!/usr/bin/python3.6
#coding: utf-8

import socket
import struct

from neverland.pkt import UDPPacket


UDP_BUFFER_SIZE = 65535


class UDPReceiver():

    ''' A normal implementation of the afferents
    '''

    def __init__(self, config, listen_addr=None, listen_port=None):
        self.config = config

        self.listen_addr = listen_addr or self.config.listen_addr
        self.listen_port = listen_port or self.config.listen_port

        self._sock = self.create_socket()
        self.setsockopt(self._sock)
        self._fd = self._sock.fileno()

    def create_socket(self):
        af, type_, proto, canon, sa = socket.getaddrinfo(
                                          host=self.listen_addr,
                                          port=self.listen_port,
                                          proto=socket.SOL_UDP,
                                      )[0]

        sock = socket.socket(af, type_, proto)
        sock.setblocking(False)
        return sock

    def setsockopt(self, sock):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        return sock

    def listen(self):
        self._sock.bind(
            (self.listen_addr, self.listen_port)
        )

    def distory(self):
        self._sock.close()
        self._sock = None

    def recv(self):
        data, src = self._sock.recvfrom(UDP_BUFFER_SIZE)
        pkt = UDPPacket(
                  data=data,
                  previous_hop={'addr': src[0], 'port': src[1]}
              )
        return pkt

    @property
    def fd(self):
        return self._fd


class ClientUDPReceiver(UDPReceiver):

    def setsockopt(self, sock):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

        # We need these options to receive udp packet and get it's
        # destination from tproxy redirect.
        sock.setsockopt(socket.SOL_IP, IP_TRANSPARENT, 1)
        sock.setsockopt(socket.SOL_IP, IP_RECVORIGDSTADDR, 1)
        return sock

    def recv(self):
        ''' receive data from tproxy redirect
        '''

        # TODO ipv6 support
        data, anc, flags, src = self._sock.recvmsg(
                                    UDP_BUFFER_SIZE,
                                    socket.CMSG_SPACE(24),
                                )

        # get and unpack the cmsg_data field from anc
        # https://docs.python.org/3/library/socket.html#socket.socket.recvmsg
        cmsg = struct.unpack('!HHBBBB', anc[0][2][:8])

        dest_port = cmsg[1]
        dest_addr = '.'.join(
            [str(u) for u in cmsg[2:]]
        )

        pkt = UDPPacket(
                  data=data,
                  src={'addr': src[0], 'port': src[1]},
                  dest={'addr': dest_addr, 'port': dest_port},
              )
        return pkt
