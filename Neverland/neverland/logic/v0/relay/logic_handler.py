#!/usr/bin/python3.6
#coding: utf-8

from neverland.logic.v0.base import BaseLogicHandler


class RelayLogicHandler(BaseLogicHandler):

    SHM_SOCKET_NAME_TEMPLATE = 'SHM-Logic-Relay-%d.socket'

    def __init__(self, *args, **kwargs):
        BaseLogicHandler.__init__(self, *args, **kwargs)

    def handle_0x01_join_cluster(self, pkt):
        ''' handle requests of joining cluster from client nodes
        '''

    def handle_0x02_leave_cluster(self, pkt):
        ''' handle requests of joining cluster from client nodes
        '''

    def handle_resp_0x01_join_cluster(self, pkt, resp_pkt):
        pass

    def handle_resp_0x02_leave_cluster(self, pkt, resp_pkt):
        pass
