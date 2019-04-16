#!/usr/bin/python3.6
#coding: utf-8

from neverland.pkt import PktTypes
from neverland.node.context import NodeContext
from neverland.exceptions import DropPacket


class BaseLogicHandler():

    ''' The base class of logic handlers

    Logic handlers handle the received packets and determine where these
    packets should go and how many lanes should they use.
    '''

    SHM_SOCKET_NAME_TEMPLATE = 'SHM-BaseLogicHandler-NotRenamed-%d.socket'

    def __init__(self, config):
        self.config = config
        self.shm_mgr = None

    def init_shm(self):
        ''' initialize the shared memory
        '''

        self.shm_mgr.connect(
            self.SHM_SOCKET_NAME_TEMPLATE % NodeContext.pid
        )

    def close_shm(self):
        if self.shm_mgr is not None:
            self.shm_mgr.disconnect()

    def handle_logic(self, pkt):
        if pkt.fields.type == PktTypes.DATA:
            return self.handle_data(pkt)
        elif pkt.fields.type == PktTypes.CTRL:
            return self.handle_ctrl(pkt)
        elif pkt.fields.type == PktTypes.CONN_CTRL:
            return self.handle_conn_ctrl
        elif pkt.fields.type == PktTypes.CONN_CTRL_ACK:
            return self.handle_conn_ctrl
        else:
            raise DropPacket

    def handle_data(self, pkt):
        ''' handle packets with type flag 0x01 DATA
        '''

    def handle_ctrl(self, pkt):
        ''' handle packets with type flag 0x02 CTRL
        '''

    def handle_conn_ctrl(self, pkt):
        ''' handle packets with type flag 0x03 CONN_CTRL
        '''

    def handle_conn_ctrl_ack(self, pkt):
        ''' handle packets with type flag 0x04 CONN_CTRL_ACK
        '''
