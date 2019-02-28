#!/usr/bin/python3.6
#coding: utf-8

import socket


class UDPTransmitter():

    def __init__(self, config, shared_socket=None):
        ''' Constructor

        :param config: The global config instance
        :shared_socket: Efferents can use a shared socket from other modules.
                        If the shared socket is not offered, then the
                        UDPTransmitter will create a socket itself.
        '''

        self.config = config
        if shared_socket is not None:
            self._sock = shared_socket
        else:
            self._sock = self.create_socket()

    def create_socket(self, bind_port=None):
        # TODO ipv6 support
        af, type_, proto, canon, sa = socket.getaddrinfo(
                                          host='0.0.0.0',
                                          port=bind_port or 0,
                                          proto=socket.SOL_UDP,
                                      )[0]
        sock = socket.socket(af, type_, proto)

        self.setsockopt(sock)
        sock.setblocking(False)
        sock.bind(sa)
        return sock

    def setsockopt(self, sock):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return sock

    def transmit(self, pkt):
        ''' transmit a packet

        :param pkt: neverland.pkt.UDPPacket object
        '''

        data = pkt.data
        target = pkt.next_hop

        if isinstance(target, list):
            target = tuple(target)

        self._sock.sendto(data, target)
