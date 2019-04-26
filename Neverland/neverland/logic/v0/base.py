#!/usr/bin/python3.6
#coding: utf-8

import logging

from neverland.exceptions import (
    DropPacket,
    FailedToJoinCluster,
    SuccessfullyJoinedCluster,
    ConnSlotNotAvailable,
)
from neverland.pkt import PktTypes, UDPPacket
from neverland.utils import ObjectifiedDict, Converter
from neverland.node.context import NodeContext
from neverland.core.state import ClusterControllingStates as CCStates
from neverland.components.shm import SharedMemoryManager
from neverland.components.connmgmt import SLOT_0, SLOT_1, SLOT_2, SLOTS
from neverland.logic.base import BaseLogicHandler as _BaseLogicHandler
from neverland.protocol.crypto import Cryptor
from neverland.protocol.v0.subjects import\
        ClusterControllingSubjects as CCSubjects


logger = logging.getLogger('Logic')


class BaseLogicHandler(_BaseLogicHandler):

    ''' The base logic handlers for protocol v0
    '''

    def __init__(self, config):
        self.config = config

        self.shm_mgr = SharedMemoryManager(self.config)

    def handle_data(self, pkt):
        ''' handle packets with type flag 0x01 DATA
        '''

        if NodeContext.core.cc_state != CCStates.WORKING:
            raise DropPacket

    def handle_ctrl(self, pkt):
        ''' handle packets with type flag 0x02 CTRL
        '''

        if pkt.fields.subject == CCSubjects.RESPONSE:
            return self.handle_ctrl_response(pkt)
        else:
            return self.handle_ctrl_request(pkt)

    def handle_ctrl_request(self, pkt):
        ''' handle requests sent in CTRL packets

        This method shall be implemented in .controller.logic_handler
        '''

    def handle_ctrl_response(self, resp_pkt):
        ''' handle responses sent in CTRL packets
        '''

        content = resp_pkt.fields.content
        if not isinstance(content, ObjectifiedDict):
            raise DropPacket

        responding_sn = content.responding_sn
        if responding_sn is None:
            raise DropPacket

        pkt_mgr = NodeContext.pkt_mgr
        pkt = pkt_mgr.get_pkt(responding_sn)

        if pkt is None:
            logger.debug(
                f'Packet manager can\'t find the original pkt, sn: {sn}. '
                f'Drop the response packet.'
            )
            raise DropPacket

        if pkt.fields.type == PktTypes.CTRL:
            if pkt.fields.subject == CCSubjects.JOIN_CLUSTER:
                self.handle_resp_0x01_join_cluster(pkt, resp_pkt)
            if pkt.fields.subject == CCSubjects.LEAVE_CLUSTER:
                self.handle_resp_0x02_leave_cluster(pkt, resp_pkt)

    def handle_resp_0x01_join_cluster(self, pkt, resp_pkt):
        if NodeContext.core.cc_state != CCStates.WAITING_FOR_JOIN:
            raise DropPacket

        resp_content = resp_pkt.fields.content
        resp_body = resp_content.body

        if resp_body.permitted:
            NodeContext.core.set_cc_state(CCStates.JOINED_CLUSTER)
            NodeContext.pkt_mgr.cancel_repeat(pkt.fields.sn)
            raise SuccessfullyJoinedCluster
        else:
            raise FailedToJoinCluster

    def handle_resp_0x02_leave_cluster(self, pkt, resp_pkt):
        if NodeContext.core.cc_state != CCStates.WAITING_FOR_LEAVE:
            raise DropPacket

    def handle_conn_ctrl(self, pkt):
        remote_sa = pkt.fields.src
        remote_sa_str = Converter.sa_2_str(remote)

        communicating = pkt.fields.communicating
        iv_changed = pkt.fields.iv_changed
        iv_duration = pkt.fields.iv_duration
        iv = pkt.fields.iv

        stash = NodeContext.cryptor_stash.get(remote_sa_str)

        if communicating == 0x00:
            if stash is not None:
                NodeContext.cryptor_stash.pop(remote_sa_str)
            return

        # currently, we have nothing to do with this case
        if iv_changed == 0x00:
            return

        if stash is None:
            stash = {
                'main_cryptor': None,
                'fallback_cryptor': None,
            }
            NodeContext.cryptor_stash.update({remote_sa_str: stash})

        # check if we already have this IV
        conns = NodeContext.conn_mgr.get_conns(remote_sa)
        conn0 = conns.get(SLOT_0)
        conn1 = conns.get(SLOT_1)
        if conn0.iv == iv or conn1.iv == iv:
            return

        try:
            conn = NodeContext.conn_mgr.new_conn(
                       remote_sa,
                       received_iv=iv,
                       iv_duration=iv_duration,
                   )
        except ConnSlotNotAvailable as e:
            logger.warn(e.args[0])
            return

        conn_attribution = f'{conn.remote.ip}:{conn.remote.port}'
        new_cryptor = Cryptor(
                          self.config,
                          iv=conn.iv,
                          attribution=conn_attribution,
                      )
        stash = {
            'fallback_cryptor': stash.get('main_cryptor'),
            'main_cryptor': new_cryptor,
        }
        NodeContext.cryptor_stash.update({remote_sa_str: stash})

        # The response
        resp_pkt = UDPPacket()
        resp_pkt.fields = ObjectifiedDict(
                              type=PktTypes.CONN_CTRL_ACK,
                              dest=pkt.fields.src,
                              resp_sn=pkt.fields.sn,
                          )
        return resp_pkt

    def handle_conn_ctrl_ack(self, pkt):
        responding_sn = pkt.fields.resp_sn

        if responding_sn is None:
            raise DropPacket

        original_pkt = NodeContext.pkt_mgr.get_pkt(responding_sn)
