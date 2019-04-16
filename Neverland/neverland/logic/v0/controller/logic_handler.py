#!/usr/bin/python3.6
#coding: utf-8

import logging

from neverland.pkt import PktTypes, UDPPacket
from neverland.utils import ObjectifiedDict
from neverland.node import Roles
from neverland.node.context import NodeContext
from neverland.logic.v0.base import BaseLogicHandler
from neverland.components.shm import SHMContainerTypes
from neverland.protocol.v0.subjects import\
        ClusterControllingSubjects as CCSubjects
from neverland.exceptions import (
    ConfigError,
    DropPacket,
    SharedMemoryError,
)


logger = logging.getLogger('Logic')
ROLE_NAMES = Roles._keys()


class ControllerLogicHandler(BaseLogicHandler):

    SHM_SOCKET_NAME_TEMPLATE = 'SHM-Logic-Ctrl-%d.socket'

    # SHM container for containing all nodes added into the cluster
    # data structure:
    #     {
    #         identification: {
    #             'ip': ip,
    #             'port': port,
    #             'role': neverland.node.Roles.*,
    #         }
    #     }
    SHM_KEY_CLUSTER_NODES = 'CtrlLogic_ClusterNodes'

    def __init__(self, *args, **kwargs):
        BaseLogicHandler.__init__(self, *args, **kwargs)

        self.identification = self.config.net.identification
        self.configured_cluster_nodes = self.config.cluster_nodes

        self._verify_config()

    def _verify_config(self):
        if self.configured_cluster_nodes is None:
            raise ConfigError('cluster_nodes is not configured')

        for identification, definition in self.configured_cluster_nodes:
            role_name = definition.role
            ip = definition.ip

            if role_name is None or ip is None:
                raise ConfigError(
                    f'cluster_nodes has been configured in a wrong format'
                )

            if role_name not in ROLE_NAMES:
                raise ConfigError(
                    f'Invalid role name in cluster_nodes: {role_name}'
                )

    def init_shm(self):
        ''' initialize the shared memory
        '''

        self.shm_mgr.connect(
            self.SHM_SOCKET_NAME_TEMPLATE % NodeContext.pid
        )
        self.shm_mgr.create_key_and_ignore_conflict(
            self.SHM_KEY_CLUSTER_NODES,
            SHMContainerTypes.DICT,
        )

    def _gen_resp_pkt(self, content, dest):
        resp_pkt = UDPPacket()
        resp_pkt.fields = ObjectifiedDict(
                              type=PktTypes.CTRL,
                              dest=dest,
                              subject=CCSubjects.RESPONSE,
                              content=content,
                          )

        relay_nodes = self.get_relay_list()

        # If we have relay nodes in our cluster, then just give the packet
        # to a relay node. If we have no relay node, then send the packet to
        # the requester directly.
        if len(relay_nodes) == 0:
            resp_pkt.next_hop = dest
        else:
            relay = relay_nodes[0]
            resp_pkt.next_hop = (relay.get('ip'), relay.get('port'))

        return resp_pkt

    def add_cluster_node(self, identification, ip, port, role):
        ''' add a new node into the cluster

        To do this, the controller node should add identification and ip address
        of a node into the {SHM_KEY_CLUSTER_NODES} field in the shared memory
        as a pair of key value.
        '''

        node_value = {
            identification: {
                'ip': ip,
                'port': port,
                'role': role,
            }
        }
        self.shm_mgr.add_value(
            self.SHM_KEY_CLUSTER_NODES,
            node_value,
        )

    def remove_cluster_node(self, identification):
        self.shm_mgr.remove_value(
            self.SHM_KEY_CLUSTER_NODES,
            identification,
        )

    def get_cluster_nodes(self):
        resp = self.shm_mgr.read_key(self.SHM_KEY_CLUSTER_NODES)
        return resp.get('value')

    def get_relay_nodes(self):
        all_nodes = self.get_cluster_nodes()

        return {
            identification: node_info
            for identification, node_info in all_nodes.items()
            if node_info.get('role') == Roles.RELAY
        }

    def get_relay_list(self):
        ''' same as above, but will be returned in a list
        '''

        relay_nodes = self.get_relay_nodes()
        return [
            {
                'identification': identification,
                'ip': node_info.get('ip'),
                'port': node_info.get('port'),
                'role': node_info.get('role'),
            }
            for identification, node_info in relay_nodes.items()
        ]

    def handle_ctrl_request(self, pkt):
        if pkt.fields.subject == CCSubjects.JOIN_CLUSTER:
            return self.handle_0x01_join_cluster(pkt)
        elif pkt.fields.subject == CCSubjects.LEAVE_CLUSTER:
            return self.handle_0x02_leave_cluster(pkt)
        elif pkt.fields.subject == CCSubjects.READ_CLUSTER_CONFIG:
            return self.handle_0x11_reading_config(pkt)
        else:
            raise DropPacket

    def handle_0x01_join_cluster(self, pkt):
        ''' handle requests of joining cluster
        '''

        content = pkt.fields.content

        if content is None:
            raise DropPacket

        identification = content.identification
        node_ip = content.ip
        node_port = content.listen_port

        if (
            identification is None or
            node_ip is None or
            node_port is None
        ):
            raise DropPacket

        logger.debug('Start to handle logic 0x01 <join cluster>')

        node_definition = self.configured_cluster_nodes.__get__(identification)

        if node_definition is None:
            permitted = False
        else:
            configured_ip = node_definition.ip
            configured_role = node_definition.role

            if configured_ip == node_ip:
                permitted = True
                self.add_cluster_node(
                    identification,
                    configured_ip,
                    node_port,
                    getattr(Roles, configured_role),  # it's verified
                )
                logger.info(
                    f'Permitted a request of joining the cluster, '
                    f'node_ip: {node_ip}, node_port: {node_port}'
                )
            else:
                logger.info(
                    f'Rejected a request of joining the cluster, '
                    f'node_ip: {node_ip}, node_port: {node_port}'
                )
                permitted = False

        content = {
            'identification': self.identification,
            'responding_sn': pkt.fields.sn,
            'body': {
                'permitted': permitted,
            }
        }
        return self._gen_resp_pkt(content, pkt.fields.src)

    def handle_0x02_leave_cluster(self, pkt):
        ''' handle requests of joining cluster
        '''

        content = pkt.fields.content
        identification = content.get('identification')

        cluster_nodes = self.get_cluster_nodes()
        if identification in cluster_nodes:
            permitted = True
            self.remove_cluster_node(identification)
        else:
            permitted = False

        content = {
            'identification': self.identification,
            'responding_sn': pkt.fields.sn,
            'body': {
                'permitted': permitted,
            }
        }
        return self._gen_resp_pkt(content, pkt.fields.src)

    def handle_0x11_reading_config(self, pkt):
        ''' handle requests of fetching config

        Here, the controller node sends the cluster config to other nodes
        '''
