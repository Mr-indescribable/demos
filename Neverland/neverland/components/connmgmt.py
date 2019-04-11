#!/usr/bin/python3.6
#coding: utf-8

import os
import time
import base64
import random
import logging

from neverland.exceptions import (
    ArgumentError,
    ConnSlotNotAvailable,
    NoConnAvailable,
)
from neverland.pkt import UDPPacket, PktTypes
from neverland.utils import ObjectifiedDict, MetaEnum
from neverland.node.context import NodeContext
from neverland.components.shm import SharedMemoryManager
from neverland.protocol.crypto.openssl import EVP_MAX_IV_LENGTH


''' The connection management module

Nodes in the Neverland cluster shall complete a fake connection before
they start to communicate with each other. Within establishing this
connection, the initiator shall send an IV to the recipient. And then,
they will use this IV in encryption. So, actually the connection is
bound with the encryption, connections are like channels with unique
IVs that link nodes into a web.


Details of connection management:
    The connection is node-to-node but not core-to-core, but all
    functionalities of communication is in the core and one node
    may have multiple cores (in multiple workers). So this means
    we need to build the connection on node layer and all core
    objects in the node shall share it.

    Due to the limitation of SharedMemoryManager's implementation,
    we cannot simply share the Cryptor object between cores.

    So the solution is sharing IV and IV duration between cores.

    At the initial stage of a node, each node have a default IV that
    derived from the password. This IV will be used to establish the
    initial connection. After it, the initial IV will be placed aside
    and the node will start to communicate with other node with the
    new IV of initial connection. Once the IV of initial connection
    exceeds its duration, next connection will be established with the
    last IV, but the last connection and its IV will not be removed
    immediately, it will be kept until the third connection is established.

    During the whole process, we will keep at most 2 connections between
    2 nodes and once the third connection is established, the first one
    will be removed. And the default IV will never be removed, it's only
    used to establish the initial connection.

    So, the mind mapping is like this:

        +------------+
        | Default IV |
        +------------+

                     +--------------+   +--------------+   +--------------+
                     | Slot-0       |   | Slot-1       |   | Slot-2       |
         Removed     |              |   |              |   |              |
        +--------+   |  +--------+  |   |  +--------+  |   |  +--------+  |
        | IV n-1 |<--|  |  IV n  |  |<--|  | IV n+1 |  |<--|  |incoming|  |
        +--------+   |  +--------+  |   |  +--------+  |   |  +--------+  |
                     |              |   |              |   |   unusable   |
                     +--------------+   +--------------+   +--------------+
'''


logger = logging.getLogger('CONN')


class Connection(ObjectifiedDict):

    '''
    This class is used to contain the context of a connection.
    It's the entity what the ConnectionManager shall manage.

    Inner data structure:
        {
            "remote": {
                          "ip": str,
                          "port": int
                      },
            "sn": int,
            "state": int,
            "slot": str,
            "iv": bytes,
            "iv_duration": int,
        }


    Field Description:
        remote: the remote socket address
        sn: the serial number of a conntion
        state: the state of the conection
        slot: the slot name of this connection
        iv: the IV used in the Cryptor object of this connection
        iv_duration: number of packets that could be encrypted by this IV
                     once the iv_duration is exceeded, a new connection
                     will be established.
    '''


class ConnStates(metaclass=MetaEnum):

    ''' Connection States
    '''

    # The initial state of connection object. When a Connection object
    # completes its instantiation, the first state is INIT.
    INIT = 0x00

    # This state means a request of establishing connection has been sent
    # to the remote, and we are waiting for the response.
    ESTABLISHING = 0x01

    # This state means we have received the response of the connection
    # establishing request, and the remote has accepted the connection.
    ESTABLISHED = 0x02

    # This state means the IV of this connection has exceeds its duration and
    # a new connection is establishing. This connection will be removed soon.
    REMOVING = 0x03

    # This state means the connection has been removed.
    REMOVED = 0x04


SLOT_0 = 'slot-0'
SLOT_1 = 'slot-1'
SLOT_2 = 'slot-2'
SLOTS = [SLOT_0, SLOT_1, SLOT_2]


class ConnectionManager():

    ''' The Connection Manager

    We will store all informations of established connections in the shared
    memory. This ConnectionManager is aimed on converting these informations
    between JSONs and Connection objects. Providing Connection objects to the
    upper layer and store Connection objects in the shared memory in JSONs.

    As a manager, it should provide functionalities of establishing connection
    and closing connection as well.
    '''

    SHM_SOCKET_NAME_TEMPLATE = 'SHM-ConnectionManager-%d.socket'

    # The SHM container to store established connections.
    #
    # Data structure:
    #     {
    #         "ip:port": {
    #             "slot-0": {
    #                 "status": int,
    #                 "sn": int,
    #                 "iv": b64encode(iv),
    #                 "iv_duration": int,
    #             },
    #             "slot-1": {
    #                 "status": int,
    #                 "sn": int,
    #                 "iv": b64encode(iv),
    #                 "iv_duration": int,
    #             },
    #             "slot-2": {
    #                 "status": int,
    #                 "sn": int,
    #                 "iv": b64encode(iv),
    #                 "iv_duration": int,
    #             },
    #         }
    #     }
    SHM_KEY_TMP_CONNS = 'ConnectionManager-%d_Conns'

    def __init__(self, config, iv_len=None):
        ''' Constructor

        :param config: the config
        :param iv_len: override config.net.crypto.iv_len
        '''

        self.config = config
        self.iv_len = iv_len or self.config.net.crypto.iv_len
        self.iv_duration_range = self.config.net.crypto.iv_duration_range

        if not 0 < self.iv_len < EVP_MAX_IV_LENGTH:
            raise ArgumentError('iv_len out of range')

        self.pid = NodeContext.pid

    def init_shm(self):
        ''' initialize the shared memory manager
        '''

        self.shm_mgr = SharedMemoryManager(self.config)
        self.shm_mgr.connect(
            self.SHM_SOCKET_NAME_TEMPLATE % self.pid
        )

        self.shm_key_conns = self.SHM_KEY_TMP_CONNS % self.pid
        self.shm_mgr.create_key_and_ignore_conflict(
            self.shm_key_conns,
            SHMContainerTypes.DICT,
        )

    def _remote_sa_2_key(self, remote):
        ''' convert remote socket address to a key string
        '''

        ip = remote[0]
        port = remote[1]
        return f'{ip}:{port}'

    def _get_native_conn_info(self, remote):
        ''' get the native JSON data of connections
        '''

        remote_name = self._remote_sa_2_key(remote)
        shm_data = self.shm_mgr.get_dict_value(self.shm_key_conns, remote_name)
        shm_value = shm_data.get('value')

        if shm_value is None:
            return {
                SLOT_0: None,
                SLOT_1: None,
                SLOT_2: None,
            }
        else:
            return shm_value

    def get_conns(self, remote):
        ''' get all connections of a remote node

        :param remote: socket address in tuple format, (ip, port)
        :returns: a dict of Connection objects:
                    {
                        SLOT_0: conn,
                        SLOT_1: conn,
                        SLOT_2: conn,
                    }
        '''

        ip = remote[0]
        port = remote[1]
        native_info = self._get_native_conn_info(remote)

        result = dict()
        for slot_name in SLOTS:
            conn_info = native_info.get(slot_name)

            if conn_info is None:
                conn = None
            else:
                iv = conn_info.get('iv')
                if iv is not None:
                    iv = base64.b64decode(iv)

                conn_info.update(
                    slot=slot_name,
                    remote={'ip': ip, 'port': port},
                    iv=iv,
                )
                conn = Connection(**conn_info)

            result.update(
                {slot_name: conn}
            )
        return result

    def store_conn(self, conn, slot, override=False):
        ''' store a connection object to a slot

        :param conn: a Connection object
        :param slot: slot name, enumerated in SLOTS
        '''

        remote = (conn.remote.ip, conn.remote.port)
        remote_name = self._remote_sa_2_key(remote)

        if not override:
            usable_slots = self.get_usable_slots(remote)
            if slot not in usable_slots:
                raise ConnSlotNotAvailable

        iv = conn.iv
        if iv is not None:
            # the base64 string must be str but not bytes
            iv = b64encode(iv).decode()

        conn_info = conn.__to_dict__()
        conn_info.update(iv=iv)

        self.shm_mgr.update_dict(
            key=self.shm_key_conns,
            dict_key=remote_name,
            value=conn_info,
        )

    def get_usable_slots(self, remote):
        ''' get all usable slots of a remote

        :param remote: remote socket address, (ip, port)
        :returns: a list of slot names
        '''

        usable_slots = list(SLOTS)

        conns = self.get_conns(remote)
        for slot in SLOTS:
            conn = conns.get(slot)
            if conn is None:
                break
            else:
                usable_slots.remove(slot)

        return usable_slots

    def new_conn(self, remote, synchronous=False, timeout=2, interval=0.1):
        ''' establish a new connection

        The establishing connection will be placed in slot-2.

        After the new connection is established, if we have established 2
        connections with the specified node already then the connection in
        slot-0 will be removed and the connection in slot-1 will be moved
        to slot-0. The new connection will be placed in slot-1.

        :param remote: remote socket address, (ip, port)
        :param synchronous:
                    If the sync argument is True, then the new_conn method
                    will try to wait the connection complete and return a
                    connection object. This operation will be blocking until
                    it reaches the timeout or the connection completes.

                    If the sync argument is False, then the new_conn method
                    will return None immediately without waiting.
        :param timeout: seconds to timeout
        :param interval: the interval time of connection checking
        '''

        usable_slots = self.get_usable_slots(remote)
        remote_name = self._remote_sa_2_key(remote)

        if SLOT_2 not in usable_slots:
            raise ConnSlotNotAvailable(
                f'slot-2 to {remote_name} is in using, '
                f'cannot establish connection now'
            )

        iv = os.urandom(self.iv_len)
        iv_duration = random.randint(*self.iv_duration_range)

        pkt = UDPPacket()
        pkt.fields = ObjectifiedDict(
                         type=PktTypes.CONN_CTRL,
                         dest=remote,
                         communicating=1,
                         iv_changed=1,
                         iv_duration=iv_duration,
                         iv=iv,
                     )
        pkt.next_hop = remote
        pkt = NodeContext.protocol_wrapper.wrap(pkt)
        NodeContext.pkt_mgr.repeat_pkt(pkt)

        conn_sn = NodeContext.id_generator.gen()
        conn = {
            "remote": {
                          "ip": remote[0],
                          "port": remote[1],
                      },
            "sn": conn_sn,
            "state": ConnStates.ESTABLISHING,
            "slot": SLOT_2,
            "iv": iv,
            "iv_duration": iv_duration,
        }
        conn = Connection(**conn)

        # though we have checked the SLOT_2 already,
        # but it still has the possibility...
        try:
            self.store_conn(conn, SLOT_2)
        except ConnSlotNotAvailable:
            logger.warn(
                f'slot-2 to {remote_name} seized, abort the establishment'
            )

        # The request is sending, now we wait for the response
        if not synchronous:
            return None

        # while timeout > 0:
            # # TODO complete this after the response processing logic is done

            # timeout -= interval
            # time.sleep(interval)

    def get_conn(self, remote):
        ''' get a Connection object of the specified remote

        :param remote: remote socket address, (ip, port)
        :returns: Connection object
        '''

        conns = self.get_conns()

        # according to the explanations above, the priority of slots is 1 > 0
        conn_s1 = conns.get(SLOT_1)
        if conn_s1 is not None and conn_s1.state == ConnStates.ESTABLISHED:
            return conn_s1

        conn_s0 = conns.get(SLOT_0)
        if conn_s0 is not None and conn_s1.state == ConnStates.ESTABLISHED:
            return conn_s0

        raise NoConnAvailable

    def remove_conn(self, remote, slot):
        ''' close a connection

        :param remote: remote socket address, (ip, port)
        :param slot: slot name, enumerated in SLOTS
        '''

        ip = remote[0]
        port = remote[1]
        remote_name = f'{ip}:{port}'

        native_info = self._get_native_conn_info(remote)
        native_info[slot] = None

        self.shm_mgr.update_dict(
            key=self.shm_key_conns,
            dict_key=remote_name,
            value=native_info,
        )
