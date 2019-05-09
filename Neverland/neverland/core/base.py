#!/usr/bin/python3.6
#coding: utf-8

import os
import json
import time
import select
import logging

from neverland.pkt import UDPPacket, PktTypes
from neverland.node.context import NodeContext
from neverland.utils import (
    Converter,
    ObjectifiedDict,
    get_localhost_ip,
)
from neverland.exceptions import (
    DropPacket,
    ConfigError,
    ArgumentError,
    SharedMemoryError,
    SHMResponseTimeout,
)
from neverland.protocol.v0.subjects import\
        ClusterControllingSubjects as CCSubjects
from neverland.core.state import ClusterControllingStates as CCStates
from neverland.components.idgeneration import IDGenerator
from neverland.components.shm import (
    ReturnCodes,
    SHMContainerTypes,
    SharedMemoryManager,
)


POLL_TIMEOUT = 4

logger = logging.getLogger('Core')


class BaseCore():

    ''' The base model of cores

    Literally, the core is supposed to be a kernel-like component.
    It organizes other components to work together and administrate them.
    Some components are plugable, and some others are necessary.

    Here is the list of all components:
        afferents in neverland.afferents, plugable
        efferents in neverland.efferents, necessary
        logic handlers in neverland.logic, necessary
        protocol wrappers in neverland.protocol, necessary

    In the initial version, all these components are necessary, and afferents
    could be multiple.
    '''

    EV_MASK = select.EPOLLIN

    SHM_SOCKET_NAME_TEMPLATE = 'SHM-Core-%d.socket'

    # SHM container for containing allocated core id
    # data structure:
    #     [1, 2, 3, 4]
    SHM_KEY_CORE_ID = 'Core_id'

    # The shared status of cluster controlling,
    # enumerated in neverland.core.state.ClusterControllingStates
    SHM_KEY_CC_STATE = 'Core_CCState'

    def __init__(
        self, config, efferent, logic_handler,
        protocol_wrapper, main_afferent, minor_afferents=tuple(),
    ):
        ''' constructor

        :param config: the config
        :param efferent: an efferent instance
        :param logic_handler: a logic handler instance
        :param protocol_wrapper: a protocol wrapper instance
        :param main_afferent: the main afferent
        :param minor_afferents: a group of minor afferents,
                                any iterable type contains afferent instances
        '''

        self.__running = False

        self.core_id = None
        self._epoll = select.epoll()
        self.afferent_mapping = {}

        self.config = config
        self.main_afferent = main_afferent
        self.efferent = efferent
        self.logic_handler = logic_handler
        self.protocol_wrapper = protocol_wrapper

        self.shm_mgr = SharedMemoryManager(self.config)

        self.plug_afferent(self.main_afferent)
        for afferent in minor_afferents:
            self.plug_afferent(afferent)

        self.entrance = self.config.cluster_entrance
        self.identification = self.config.net.identification

    def set_cc_state(self, status):
        self.shm_mgr.set_value(self.SHM_KEY_CC_STATE, status)

    def get_cc_state(self):
        resp = self.shm_mgr.read_key(self.SHM_KEY_CC_STATE)
        return resp.get('value')

    @property
    def cc_state(self):
        return self.get_cc_state()

    def init_shm(self):
        self.shm_mgr.connect(
            self.SHM_SOCKET_NAME_TEMPLATE % NodeContext.pid
        )

        self.shm_mgr.create_key_and_ignore_conflict(
            self.SHM_KEY_CORE_ID,
            SHMContainerTypes.LIST,
        )
        self.shm_mgr.create_key_and_ignore_conflict(
            self.SHM_KEY_CC_STATE,
            SHMContainerTypes.INT,
            CCStates.INIT,
        )

        logger.debug(f'init_shm for core of worker {NodeContext.pid} has done')

    def close_shm(self):
        self.shm_mgr.disconnect()

    def self_allocate_core_id(self):
        ''' Let the core pick up an id for itself
        '''

        try:
            resp = self.shm_mgr.lock_key(self.SHM_KEY_CORE_ID)
        except SHMResponseTimeout:
            # Currently, SHM_MAX_BLOCKING_TIME is 4 seconds and
            # these works can be definitely done in 4 seconds.
            # If a SHMResponseTimeout occurred, then there must
            # be a deadlock
            raise SHMResponseTimeout(
                f'deadlock of key: {self.SHM_KEY_CORE_ID}'
            )

        resp = self.shm_mgr.read_key(self.SHM_KEY_CORE_ID)
        allocated_id = resp.get('value')

        if len(allocated_id) == 0:
            id_ = 0
        else:
            last_id = allocated_id[-1]
            id_ = last_id + 1

        self.shm_mgr.add_value(
            self.SHM_KEY_CORE_ID,
            [id_],
        )
        self.core_id = id_

        self.shm_mgr.unlock_key(self.SHM_KEY_CORE_ID)
        logger.debug(
            f'core of worker {NodeContext.pid} has self-allocated id: {id_}'
        )

    def plug_afferent(self, afferent):
        self._epoll.register(afferent.fd, self.EV_MASK)
        self.afferent_mapping.update(
            {afferent.fd: afferent}
        )

    def unplug_afferent(self, fd):
        ''' remove an afferent from the core

        :param fd: the file discriptor of the afferent, int
        '''

        if fd not in self.afferent_mapping:
            return

        self._epoll.unregister(fd)
        self.afferent_mapping.pop(fd)

    def conn_entrance(self):
        ''' establish a connection with the entrance of cluster
        '''

        entrance = (
            self.config.cluster_entrance.ip,
            self.config.cluster_entrance.port,
        )
        conn = NodeContext.conn_mgr.new_conn(entrance, synchronous=True)
        # TODO:
        #     To be continued...

    def establish_conns(self):
        '''
        establish connections between remote nodes that we need to
        communicate with
        '''

    def fetch_link_table(self):
        ''' get the link table from the controller node
        '''

    def request_to_join_cluster(self):
        ''' send a request of the node is going to join the cluster
        '''

        logger.info('Trying to join cluster...')

        content = {
            'identification': self.identification,
            'ip': get_localhost_ip(),
            'listen_port': self.config.net.aff_listen_port,
        }
        subject = CCSubjects.JOIN_CLUSTER
        dest = (self.entrance.ip, self.entrance.port)

        pkt = UDPPacket()
        pkt.fields = ObjectifiedDict(
                         type=PktTypes.CTRL,
                         dest=dest,
                         subject=subject,
                         content=content,
                     )
        pkt.next_hop = dest
        pkt = self.protocol_wrapper.wrap(pkt)

        NodeContext.pkt_mgr.repeat_pkt(pkt)
        logger.info(
            f'Sending request to cluster entrance {entrance.ip}:{entrance.port}'
        )

        logger.info('[Node Status] WAITING_FOR_JOIN')
        self.set_cc_state(CCStates.WAITING_FOR_JOIN)

    def request_to_leave_cluster(self):
        ''' send a request of the node is going to detach from the cluster
        '''

        logger.info('Trying to leave cluster...')

        content = {"identification": self.identification}
        subject = CCSubjects.LEAVE_CLUSTER
        dest = (self.entrance.ip, self.entrance.port)

        pkt = UDPPacket()
        pkt.fields = ObjectifiedDict(
                         type=PktTypes.CTRL,
                         dest=dest,
                         subject=subject,
                         content=content,
                     )
        pkt.next_hop = dest
        pkt = self.protocol_wrapper.wrap(pkt)

        NodeContext.pkt_mgr.repeat_pkt(pkt)
        logger.info(
            f'Sent request to cluster entrance {entrance.ip}:{entrance.port}'
        )

        logger.info('[Node Status] WAITING_FOR_LEAVE')
        self.set_cc_state(CCStates.WAITING_FOR_LEAVE)

    def handle_pkt(self, pkt):
        try:
            pkt = self.protocol_wrapper.unwrap(pkt)
            if not pkt.valid:
                return

            pkt = self.logic_handler.handle_logic(pkt)

        # Actually we have catched all InvalidPkt in protocol_wrapper,
        # but maybe we will use it in future.
        except (DropPacket, InvalidPkt) as e:
            return

        pkt = self.protocol_wrapper.wrap(pkt)
        self.efferent.transmit(pkt)

    def _poll(self):
        events = self._epoll.poll(POLL_TIMEOUT)

        for fd, evt in events:
            afferent = self.afferent_mapping[fd]

            if evt & select.EPOLLERR:
                self.unplug_afferent(fd)
                afferent.destroy()
            elif evt & select.EPOLLIN:
                pkt = afferent.recv()
                self.handle_pkt(pkt)

    def run(self):
        self.set_cc_state(CCStates.WORKING)
        self.__running = True

        self.main_afferent.listen()
        addr = self.main_afferent.listen_addr
        port = self.main_afferent.listen_port
        logger.info(f'Main afferent is listening on {addr}:{port}')

        while self.__running:
            self._poll()

    def run_for_a_while(self, duration=None, polling_times=None):
        ''' run the core within the specified duration time or poll times

        :param duration: the duration time, seconds in int
        :param polling_times: times the _poll method shall be invoked, int

        These 2 arguments will not work together, if duration specified, the
        poll_times will be ignored
        '''

        if duration is None and polling_times is None:
            raise ArgumentError('no argument passed')

        self.main_afferent.listen()
        addr = self.main_afferent.listen_addr
        port = self.main_afferent.listen_port
        logger.info(f'Main afferent is listening on {addr}:{port}')

        if duration is not None:
            starting_time = time.time()
            while time.time() - starting_time <= duration:
                self._poll()
        elif polling_times is not None:
            for _ in polling_times:
                self._poll()

    def shutdown(self):
        self.__running = False
