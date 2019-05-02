#!/usr/bin/python3.6
#coding: utf-8

import time
import logging

from neverland.pkt import PktTypes
from neverland.utils import Converter, HashTools
from neverland.components.connmgmt import SLOT_0, SLOT_1, SLOT_2
from neverland.node.context import NodeContext
from neverland.protocol.crypto import Cryptor
from neverland.protocol.base import BaseProtocolWrapper
from neverland.exceptions import (
    PktWrappingError,
    PktUnwrappingError,
    InvalidPkt,
    DecryptionFailed,
    ConnNotEstablished,
)


logger = logging.getLogger('Main')


class ProtocolWrapper(BaseProtocolWrapper):

    def __sync_cryptor_stash(self, remote_sa):
        ''' Update cryptor_stash with the newest connection info.

        :param remote_sa: socket address of the remote node, (ip, port)
        '''

        remote_sa_str = Converter.sa_2_str(remote_sa)
        conns = NodeContext.conn_mgr.get_conns(remote_sa)
        stash = NodeContext.cryptor_stash.get(remote_sa_str)

        if stash is None:
            stash = {
                'main_cryptor': None,
                'fallback_cryptor': None,
            }

        main_cryptor = stash.get('main_cryptor')
        fallback_cryptor = stash.get('fallback_cryptor')

        conn1 = conns.get(SLOT_1)
        conn0 = conns.get(SLOT_0)

        if main_cryptor is None or main_cryptor.iv != conn1.iv:
            if conn1 is None:
                main_cryptor = None
            else:
                main_cryptor = Cryptor(
                                   self.config,
                                   iv=conn1.iv,
                                   attribution=remote_sa_str,
                               )

        if fallback_cryptor is None or fallback_cryptor.iv != conn0.iv:
            if conn0 is None:
                fallback_cryptor = None
            else:
                fallback_cryptor = Cryptor(
                                       self.config,
                                       iv=conn0.iv,
                                       attribution=remote_sa_str,
                                   )
        stash = {
            'main_cryptor': main_cryptor,
            'fallback_cryptor': fallback_cryptor,
        }
        NodeContext.cryptor_stash.update(
            {remote_sa_str: stash}
        )

    def _encrypt(self, pkt):
        ''' Encrypt a packet which is going to be sent
        '''

        if pkt.type in (PktTypes.CONN_CTRL, PktTypes.CONN_CTRL_ACK):
            cryptor = NodeContext.cryptor_stash.get('default_cryptor')
        else:
            remote_sa = pkt.next_hop
            remote_sa_str = Converter.sa_2_str(remote_sa)

            # We must check the update time before we use the cryptors, for
            # ensuring the consistency of informations between connections
            # and cryptors.
            conn_utime = NodeContext.conn_mgr.get_conn_update_time(remote_sa)
            cryptor_utime = NodeContext.cryptor_update_time.get(remote_sa_str)
            if conn_utime is None:
                raise ConnNotEstablished(
                    f'No usable connection between remote node: {remote_sa_str}'
                )
            if conn_utime > cryptor_utime:
                self.__sync_cryptor_stash(remote_sa)

                ts = time.time()
                NodeContext.conn_mgr.set_conn_update_time(remote_sa, ts)
                NodeContext.cryptor_update_time.update(remote_sa_str, ts)

            stash = NodeContext.cryptor_stash.get(remote_sa_str)
            cryptor = stash.get('main_cryptor') or stash.get('fallback_cryptor')

            if cryptor is None:
                msg = f'No usable cryptor instance for remote node {remote_sa_str}'
                logger.error(msg)
                raise ConnNotEstablished(msg)

        pkt.data = cryptor.encrypt(pkt.data)
        return pkt

    def wrap(self, pkt):
        ''' make a valid Neverland UDP packet

        :param pkt: neverland.pkt.UDPPacket object
        :return: neverland.pkt.UDPPacket object
        '''

        _type = pkt.fields.type
        if _type is None:
            raise PktWrappingError('packet.fields.type is not specified')

        pkt_fmt = self._body_fmt_mapping.get(_type)
        if pkt_fmt is None:
            raise PktWrappingError(f'Unknown packet type: {_type}')

        pkt.type = _type
        udp_data = self.make_udp_pkt(pkt, pkt_fmt)
        pkt.data = udp_data
        return self._encrypt(pkt)

    def _validate_pkt(self, fields, byte_fields):
        if fields.type not in PktTypes:
            raise InvalidPkt

        # calculate and validate mac
        data_2_hash = byte_fields.salt
        fmt = self.complexed_fmt_mapping.get(fields.type)
        for field_name, definition in fmt.__fmt__.items():
            if field_name in ('salt', 'mac'):
                continue

            byte_value = getattr(byte_fields, field_name)
            data_2_hash += byte_value

        mac = HashTools.sha256(data_2_hash).encode()
        if mac != fields.mac:
            raise InvalidPkt

    def unwrap(self, pkt):
        ''' unpack a raw UDP packet

        :param pkt: neverland.pkt.UDPPacket object
        :return: neverland.pkt.UDPPacket object
        '''

        remote_sa = pkt.previous_hop
        remote_sa_str = Converter.sa_2_str(remote_sa)

        # conn_update_time = NodeContext.conn_mgr.get_conn_update_time(remote_sa)
        # cryptor_update_time = NodeContext.cryptor_update_time.get(remote_sa_str)

        # if conn_update_time > cryptor_update_time:
            # self.__sync_cryptor_stash(remote_sa)

            # ts = time.time()
            # NodeContext.conn_mgr.set_conn_update_time(remote_sa, ts)
            # NodeContext.cryptor_update_time.update(remote_sa_str, ts)

        cryptor_stash = NodeContext.cryptor_stash.get(remote_sa_str)
        default_cryptor = NodeContext.cryptor_stash.get('default_cryptor')

        if cryptor_stash is None:
            main_cryptor = None
            fallback_cryptor = None
        else:
            main_cryptor = cryptor_stash.get('main_cryptor')
            fallback_cryptor = cryptor_stash.get('fallback_cryptor')

        for cryptor in (main_cryptor, fallback_cryptor, default_cryptor):
            if cryptor is None:
                continue

            try:
                pkt.data = cryptor.decrypt(pkt.data)
            except DecryptionFailed:
                continue

            try:
                fields, byte_fields = self.parse_udp_pkt(pkt)
                self._validate_pkt(fields, byte_fields)
            except InvalidPkt:
                break

            # The default_cryptor is only allowed to handle CONN_CTRL packets.
            if (
                cryptor == default_cryptor and
                fields.type not in (PktTypes.CONN_CTRL, PktTypes.CONN_CTRL_ACK)
            ):
                break

            pkt.fields = fields
            pkt.byte_fields = byte_fields
            pkt.type = fields.type
            pkt.valid = True
            return pkt

        pkt.fields = None
        pkt.byte_fields = None
        pkt.valid = False
        return pkt
