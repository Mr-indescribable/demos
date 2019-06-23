#!/usr/bin/python3.6
#coding: utf-8

import os
import json
import select
import socket
import logging

from neverland.exceptions import (
    DropPacket,
    AddressAlreadyInUse,
    SharedMemoryError,
    SHMRequestFailed,
    SHMContainerLocked,
    SHMRequestBacklogged,
    SHMResponseTimeout,
    SHMWorkerNotConnected,
    SHMWorkerConnectFailed,
)
from neverland.utils import MetaEnum, ObjectifiedDict, gen_uuid


__all__ = [
    'Actions',
    'SHMContainerTypes',
    'SharedMemoryManager',
]


''' The shared memory module

For keeping consistency of some resources, I decided to make a
special worker that aimed on processing shared resources.

This SharedMemoryManager is not only the resource managing worker but also
the resource accessing client, it plays 2 roles simultaneously.

The SharedMemoryManager worker is designed to communicate with the client
by the socket-based IPC, and it shall only support the Unix domain socket.

And it's not necessary to make this communication become encrypted. We can
simply solve the security problem by using the permission mechanism of Linux.


The protocol of communication:
    The choice of transport layer protocol is UDP.

    Here are 2 reasons for choosing UDP:

        1. Using UDP will apply a limitation to the Neverland cluster.
           When the cluster is too big, a part of packets will exceed
           the max size of UDP packet (65507 bytes) and then some node
           will crash. This can prevent users from building a big Neverland
           cluster. I'm really afraid that a big cluster could make
           "some organization" get noticed by something which they could
           never hear about and in this case some people will in danger.

        2. UDP is much easier to handle than TCP, and in the case of local
           communication, UDP is reliable (because we don't need to keep UDP
           packets in-sequence, and it's nearly impossible to loss a UDP
           packet in local communication).

    And because of the feature of the UDP Unix domain socket, we cannot
    simply send back responses through the socket. So we need do a fake
    connection with UDP sockets.

    Before the data accessing requests are sent out, the client needs to offer
    an unique socket name and listen on it, and the manager will send back
    responses through this socket.

    Then, we can simply transfer stringified JSON through the socket.

    Fields in request body:

        socket:
            name of the socket to recieve responses

        conn_id:
            connection ID acquired from the response of establishing a connection

        action:
            tell server side what to do, choose from Actions

        key:
            container name

        type:
            container type

        size:
            size of container, only used in creating fifo-queues.

            When the size is given, the size of a fifo-queue will be
            limited. Once it reached this limitation, the item at the head
            of the queue will be removed and the new item will be added
            at the tail of the queue.

            This one is optional, the default size of fifo-queues is 1024.

        value:
            value for the container

        value_key:
            the key of a value in a container

        backlogging:
            backlog the request if the container is locked, if backlogging
            is not enabled, then the server side shall respond immediately
            with the return code 0x21

            Default: True


    JSON structures in request:

        if action in [CONNECT]:
            {
                "socket": str,
                "action": int,
            }

        if action in [DISCONNECT]:
            {
                "conn_id": str,
                "action": int,
            }

        if action in [CREATE]:
            {
                "conn_id": str,
                "action": int,
                "key": str,
                "type": int,
                "size": int,
                "value": same with the container type,
                "backlogging": bool,
            }

        if action in [ADD]:
            {
                "conn_id": str,
                "action": int,
                "key": str,
                "value": same with the container type,
                "backlogging": bool,
            }

        if action in [DICT_GET]:
            {
                "conn_id": str,
                "action": int,
                "key": str,
                "value_key": any serializable type in json,
                "backlogging": bool,
            }

        if action in [DICT_UPDATE]:
            {
                "conn_id": str,
                "action": int,
                "key": str,
                "value_key": any serializable type in json,
                "value": any serializable type in json,
                "backlogging": bool,
            }

        if action in [REMOVE]:
            {
                "conn_id": str,
                "action": int,
                "key": str,
                "value": list of values need to be removed,
                "backlogging": bool,
            }

        if action in [SET]:
            {
                "conn_id": str,
                "action": int,
                "key": str,
                "value": same with the container type,
                "backlogging": bool,
            }

            The SET action has been limited, it can only be used on
            single-value containers.

        if action in [READ, CLEAN]:
            {
                "conn_id": str,
                "action": int,
                "key": str,
                "backlogging": bool,
            }

        if action in [LOCK, UNLOCK]:
            {
                "conn_id": str,
                "action": int,
                "key": str,
                "backlogging": bool,
            }


    JSON structures in response:

        if action != DISCONNECT:
            {
                'succeeded': bool,
                'value': the requested value,  # sets will be responded in lists
                'rcode': the return code,
            }

        if action == DISCONNECT:
            In this case, nothing shall be sent back.
            The connection will be removed immediately.
'''


logger = logging.getLogger('SHM')


POLL_TIMEOUT = 1
UDP_BUFFER_SIZE = 65507

# The max blocing time at the client side of the SharedMemoryManager
SHM_MAX_BLOCKING_TIME = 4

MSG_NOT_CONNECTED = 'Not connected with SharedMemoryManager Worker yet'
MSG_CONN_FAILED = 'Failed to connect to SharedMemoryManager Worker'
MSG_INVALID_DATA = 'SharedMemoryManager didn\'t handle the request correctly'
MSG_TIMEOUT = 'SharedMemoryManager worker timeout'


class Actions(metaclass=MetaEnum):

    # Create a new container with the given key. If the container is already
    # existing, then the request will fail with status 0x10 KEY_CONFLICT
    CREATE = 0x01

    # read value from a key
    # this action will cause the shared memory manager respond with
    # whole value in the accessing container. If the value's length is
    # greater than 65507 then there will be some exceptions
    READ = 0x02

    # change value of a key
    SET = 0x03

    # add a new value into a multi-value container
    ADD = 0x04

    # get value from a dict container
    DICT_GET = 0x05

    # update a dict container
    DICT_UPDATE = 0x06

    # append a value into a FIFO queue
    FIFO_APPEND = 0x11

    # pop a value from a FIFO queue
    FIFO_POP = 0x12

    # completely remove a key from stored resources
    CLEAN = 0x41

    # remove a value from a multi-value container
    REMOVE = 0x42

    # acquire the lock of a container and lock it
    LOCK = 0x51

    # release a lock
    UNLOCK = 0x52

    # create a new connection
    CONNECT = 0xf0

    # close a connection
    DISCONNECT = 0xff


ACTIONS_2_HANDLE_LOCK = [
    Actions.CREATE,
    Actions.READ,
    Actions.SET,
    Actions.ADD,
    Actions.CLEAN,
    Actions.REMOVE,
    Actions.LOCK,
    Actions.UNLOCK,
]


class ReturnCodes(metaclass=MetaEnum):

    # request completed successfully
    OK = 0x00

    # The given key is already existing
    KEY_CONFLICT = 0x10

    # The container which client side is accessing dose not exists
    KEY_ERROR = 0x11

    # Value type is not matched with the container's type
    # or value type is not supported.
    TYPE_ERROR = 0x12

    FIFO_ERROR = 0x21

    # The container which client side is accessing has been locked
    LOCKED = 0x51

    # The container which client side is trying to unlock is not locked
    NOT_LOCKED = 0x52

    # something bad happend :(
    UNKNOWN_ERROR = 0xff


class SHMContainerTypes(metaclass=MetaEnum):

    # Actually, we treat all types as "containers". And here, the difference
    # between STR and LIST type is only the size of the container, STR can
    # contain only one value but LIST can contain multiple, that's all.
    # So, we name some of these types as "single-value container".
    #
    # But the difference still makes things different, these single-value
    # containers shall not be supported by Actions.ADD and Actions.REMOVE
    STR = 0x01
    INT = 0x02
    FLOAT = 0x03
    BOOL = 0x04

    SET = 0x11
    LIST = 0x13

    DICT = 0x21

    FIFO_QUEUE = 0x31


PY_TYPE_MAPPING = {
    SHMContainerTypes.STR: str,
    SHMContainerTypes.INT: int,
    SHMContainerTypes.FLOAT: float,
    SHMContainerTypes.BOOL: bool,
    SHMContainerTypes.SET: set,
    SHMContainerTypes.LIST: list,
    SHMContainerTypes.DICT: dict,
}


# we need this to make JSON types compatible with Python types
# in verification and updating values
COMPATIBLE_TYPE_MAPPING = {
    SHMContainerTypes.STR: str,
    SHMContainerTypes.INT: int,
    SHMContainerTypes.FLOAT: float,
    SHMContainerTypes.BOOL: bool,
    SHMContainerTypes.SET: list,
    SHMContainerTypes.LIST: list,
    SHMContainerTypes.DICT: ObjectifiedDict,
}


class Connection(ObjectifiedDict):

    ''' The connections class for SharedMemoryManager
    '''


class SharedMemoryManager():

    EV_MASK = select.EPOLLIN

    def __init__(self, config, sensitive=True):
        ''' Constructor

        :param config: the config
        :param sensitive: The sensitive mode will make the client become
                          sensitive, it will raise an SHMRequestFailed
                          exception with a return code in exception.args[0]
                          when the request is not successful.
        '''

        self.sensitive = sensitive
        self.config = config
        self.socket_dir = config.shm.socket_dir

        ## the current connection between the SharedMemoryManager worker
        self.current_connection = None

        ## attributes below are for the SharedMemoryManager worker
        self.worker_socket_path = os.path.join(
                                      self.socket_dir,
                                      self.config.shm.manager_socket_name,
                                  )

        self.__running = False

        # the resource container, most of shared memories will be stored in it
        # structure: {key: container}
        self.resources = {}

        # the fifo-queue container, fifo-queues will be stored in it
        # structure: {key: {'items': [], 'size': int}}
        self.fifo_queues = {}

        # locks have been acquired by the client side
        # structure: {key: connection_id}
        self.locks = {}

        # connection container, all established connections will be stored in it
        # structure: {connection_id: Connection}
        self.connections = {}

        # Because of the lock mechanism, some of requests can not be handled
        # promptly, so they will be backlogged and will be handled later.
        #
        # structure: {serial_number, data}
        self.backlogged_requests = {}

        # serial number counter for backlogged_requests
        self.backlog_sn = 0

    def _create_socket(self, socket_path=None, blocking=False):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        sock.setblocking(blocking)
        try:
            if socket_path is not None:
                logger.debug(
                    f'created socket and tring to bind on {socket_path}'
                )
                sock.bind(socket_path)
        except OSError as err:
            if err.errno == 98:
                raise AddressAlreadyInUse(
                    f'{socket_path} is already in use, cannot bind on it'
                )
            else:
                raise err

        return sock

    def gen_conn_id(self):
        return gen_uuid()

    def gen_backlog_sn(self):
        self.backlog_sn += 1
        return self.backlog_sn

    def get_compatible_value(self, key):
        ''' make the value type become compatible with json

        currently, we just need to convert set type into lists
        '''

        value = self.resources.get(key)

        if isinstance(value, set):
            return list(value)
        else:
            return value

    def _add_value_2_container(self, key, values):
        container = self.resources[key]
        container_type = type(container)

        if container_type is set:
            for value in values:
                container.add(value)

        if container_type is list:
            for value in values:
                container.append(value)

        if container_type is dict:
            if isinstance(values, dict):
                container.update(values)
            elif isinstance(values, ObjectifiedDict):
                container.update(values.__to_dict__())
            else:
                raise TypeError

    def _remove_value_from_container(self, key, *values):
        ''' remove values from a container

        :param values: multipurpose parameter, when the type is dict, it will
                       be the key of dict, otherwise, it will be the value of
                       set and list
        '''

        container = self.resources[key]
        type_ = type(container)

        if type_ in (set, list):
            for value in values:
                try:
                    container.remove(value)
                except (ValueError, KeyError):
                    pass

        if type_ is dict:
            for value in values:
                container.pop(value, None)

    def _save_connection(self, conn_id, conn):
        self.connections.update(
            {conn_id: conn}
        )

    def _remove_connection(self, conn_id):
        self.connections.pop(conn_id, None)

    def _gen_response_json(self, conn_id, succeeded, value=None, rcode=None):
        if rcode is None:
            rcode = ReturnCodes.OK if succeeded else ReturnCodes.UNKNOWN_ERROR

        return {
            'conn_id': conn_id,
            'data': {
                'succeeded': succeeded,
                'value': value,
                'rcode': rcode,
            }
        }

    def _create_fifo_queue(self, data):
        ''' creates a fifo queue
        '''

        key = data.key
        conn_id = data.conn_id
        size = data.size

        if key in self.fifo_queues:
            return self._gen_response_json(
                conn_id=conn_id,
                succeeded=False,
                rcode=ReturnCodes.KEY_CONFLICT,
            )

        queue = {
            'size': size or 1024,
            'items': [],
        }

        self.fifo_queues.update(
            {key: queue}
        )

        return self._gen_response_json(conn_id=conn_id, succeeded=True)

    def handle_connect(self, data):
        resp_sock_path = os.path.join(self.socket_dir, data.socket)
        conn_id = self.gen_conn_id()
        sock = self._create_socket()
        conn = Connection(
                   conn_id=conn_id,
                   socket=sock,
                   resp_socket=resp_sock_path,
               )

        self._save_connection(conn_id, conn)

        return {
            'conn_id': conn_id,
            'data': {
                'succeeded': True,
                'conn_id': conn_id,
                'value': None,
                'rcode': ReturnCodes.OK,
            }
        }

    def handle_disconnect(self, data):
        self._remove_connection(data.conn_id)
        return None

    def handle_lock(self, data):
        key = data.key
        conn_id = data.conn_id

        # Actually, we have done all necessary verifications before invoking
        # this method. And we don't need to verify if the key exists, because
        # pre-locking is allowed.
        self.locks.update(
            {key: conn_id}
        )
        return self._gen_response_json(conn_id=conn_id, succeeded=True)

    def handle_unlock(self, data):
        key = data.key
        conn_id = data.conn_id

        if key not in self.locks:
            return self._gen_response_json(
                conn_id=conn_id,
                succeeded=True,
                rcode=ReturnCodes.NOT_LOCKED,
            )

        self.locks.pop(key)
        return self._gen_response_json(conn_id=conn_id, succeeded=True)

    def handle_create(self, data):
        key = data.key
        conn_id = data.conn_id
        type_ = data.type
        value = data.value
        compatible_type = COMPATIBLE_TYPE_MAPPING.get(type_)

        if type_ == SHMContainerTypes.FIFO_QUEUE:
            return self._create_fifo_queue(data)

        if key in self.resources:
            return self._gen_response_json(
                conn_id=conn_id,
                succeeded=False,
                rcode=ReturnCodes.KEY_CONFLICT,
            )

        if value is not None and (
            (type_ not in SHMContainerTypes) or
            (
                type_ in SHMContainerTypes and
                not isinstance(value, compatible_type)
            )
        ):
            return self._gen_response_json(
                conn_id=conn_id,
                succeeded=False,
                rcode=ReturnCodes.TYPE_ERROR,
            )

        py_type = PY_TYPE_MAPPING.get(type_)
        container = py_type()
        self.resources.update(
            {key: container}
        )

        if value is not None:
            if type_ <= SHMContainerTypes.BOOL:
                self.resources[key] = value
            else:
                self._add_value_2_container(key, value)

        return self._gen_response_json(conn_id=conn_id, succeeded=True)

    def handle_read(self, data):
        conn_id = data.conn_id
        key = data.key

        if key not in self.resources:
            return self._gen_response_json(
                conn_id=conn_id,
                succeeded=False,
                rcode=ReturnCodes.KEY_ERROR,
            )

        return self._gen_response_json(
            conn_id=conn_id,
            succeeded=True,
            value=self.get_compatible_value(key),
        )

    def handle_set(self, data):
        key = data.key
        value = data.value
        conn_id = data.conn_id

        if key not in self.resources:
            return self._gen_response_json(
                conn_id=conn_id,
                succeeded=False,
                rcode=ReturnCodes.KEY_ERROR,
            )

        if type(self.resources.get(key)) not in (int, float, bool, str):
            return self._gen_response_json(
                conn_id=conn_id,
                succeeded=False,
                rcode=ReturnCodes.TYPE_ERROR,
            )
        else:
            self.resources[key] = value
            return self._gen_response_json(conn_id=conn_id, succeeded=True)

    def handle_add(self, data):
        key = data.key
        value = data.value
        conn_id = data.conn_id

        if key not in self.resources:
            return self._gen_response_json(
                conn_id=conn_id,
                succeeded=False,
                rcode=ReturnCodes.KEY_ERROR,
            )

        try:
            self._add_value_2_container(key, value)
            return self._gen_response_json(conn_id=conn_id, succeeded=True)
        except TypeError:
            return self._gen_response_json(
                conn_id=conn_id,
                succeeded=False,
                rcode=ReturnCodes.TYPE_ERROR,
            )
        except ValueError:
            return self._gen_response_json(conn_id=conn_id, succeeded=False)

    def handle_dict_get(self, data):
        key = data.key
        value_key = data.value_key
        conn_id = data.conn_id

        if key not in self.resources:
            return self._gen_response_json(
                conn_id=conn_id,
                succeeded=False,
                rcode=ReturnCodes.KEY_ERROR,
            )

        container = self.get_compatible_value(key)
        if not isinstance(container, dict):
            return self._gen_response_json(
                conn_id=conn_id,
                succeeded=False,
                rcode=ReturnCodes.TYPE_ERROR,
            )

        return self._gen_response_json(
            conn_id=conn_id,
            succeeded=True,
            value=container.get(value_key),
        )

    def handle_dict_update(self, data):
        key = data.key
        value_key = data.value_key
        value = data.value
        conn_id = data.conn_id

        if key not in self.resources:
            return self._gen_response_json(
                conn_id=conn_id,
                succeeded=False,
                rcode=ReturnCodes.KEY_ERROR,
            )

        container = self.get_compatible_value(key)
        if not isinstance(container, dict):
            return self._gen_response_json(
                conn_id=conn_id,
                succeeded=False,
                rcode=ReturnCodes.TYPE_ERROR,
            )

        if isinstance(value, ObjectifiedDict):
            value = value.__to_dict__()

        self.resources[key].update(
            {value_key: value}
        )
        return self._gen_response_json(
            conn_id=conn_id,
            succeeded=True,
        )

    def handle_fifo_append(self, data):
        key = data.key
        value = data.value
        conn_id = data.conn_id

        if key not in self.fifo_queues:
            return self._gen_response_json(
                conn_id=conn_id,
                succeeded=False,
                rcode=ReturnCodes.KEY_ERROR,
            )

        queue = self.fifo_queues[key]
        q_items = queue['items']
        q_len = len(q_items)
        q_size = queue['size']

        if q_len == q_size:
            try:
                q_items.pop(0)
            except IndexError:
                # In this case, the size of FIFO queue must be 0.
                # Actually, it could not happen.
                return self._gen_response_json(
                    conn_id=conn_id,
                    succeeded=False,
                    rcode=ReturnCodes.FIFO_ERROR,
                )

        q_items.append(value)
        return self._gen_response_json(conn_id=conn_id, succeeded=True)

    def handle_fifo_pop(self, data):
        key = data.key
        value = data.value
        conn_id = data.conn_id

        if key not in self.fifo_queues:
            return self._gen_response_json(
                conn_id=conn_id,
                succeeded=False,
                rcode=ReturnCodes.KEY_ERROR,
            )

        queue = self.fifo_queues[key]
        q_items = queue['items']
        q_len = len(q_items)

        if q_len == 0:
            value = None
        else:
            value = q_items.pop(0)

        return self._gen_response_json(
            conn_id=conn_id,
            succeeded=True,
            value=value,
        )

    def handle_clean(self, data):
        key = data.key
        value = data.value
        conn_id = data.conn_id

        if key not in self.resources:
            return self._gen_response_json(
                conn_id=conn_id,
                succeeded=False,
                rcode=ReturnCodes.KEY_ERROR,
            )

        self.resources.pop(key)
        return self._gen_response_json(conn_id=conn_id, succeeded=True)

    def handle_remove(self, data):
        key = data.key
        value = data.value
        conn_id = data.conn_id

        if key not in self.resources:
            return self._gen_response_json(
                conn_id=conn_id,
                succeeded=False,
                rcode=ReturnCodes.KEY_ERROR,
            )

        self._remove_value_from_container(key, *value)
        return self._gen_response_json(conn_id=conn_id, succeeded=True)

    def prehandle_lock(self, data):
        ''' prehandle the lock

        If the client is trying to access a locked container,
        then we raise a SHMContainerLocked error here
        '''

        if not data.action in ACTIONS_2_HANDLE_LOCK:
            return

        conn_id = self.locks.get(data.key)

        if conn_id is None:
            return
        elif conn_id != data.conn_id:
            raise SHMContainerLocked

    def handle_request(self, data, data_parsed=False, backlogging=None):
        ''' handle the request

        :param data: the data of request
        :param data_parsed: Tell the method if the data has been parsed.
                            If it has not been parsed then the data should
                            be bytes. If it has been parsed, then the data
                            should be an ObjectifiedDict instance

        :param backlogging: To override the backlogging option in the data.
        '''

        if not data_parsed:
            try:
                data = json.loads(data.decode('utf-8'))
                if not isinstance(data, dict):
                    raise ValueError
            except (UnicodeDecodeError, ValueError):
                # If this was the packet which we sent, then it could not
                # cause any of these errors, so we can simply ignore it.
                raise DropPacket

            data = ObjectifiedDict(**data)

        if not data.action in Actions:
            # same as above
            raise DropPacket

        if backlogging is None:
            backlogging = data.backlogging
            backlogging = True if backlogging is None else backlogging

        try:
            self.prehandle_lock(data)
        except SHMContainerLocked:
            if backlogging:
                sn = self.gen_backlog_sn()
                self.backlogged_requests.update(
                    {sn: data}
                )
                backlog_count = len(self.backlogged_requests)
                logger.debug(
                    f'request backlogged, current: {backlog_count}'
                )
                raise SHMRequestBacklogged
            else:
                return self._gen_response_json(
                    conn_id=data.conn_id,
                    succeeded=False,
                    rcode=ReturnCodes.LOCKED,
                )

        if data.action == Actions.CREATE:
            return self.handle_create(data)
        if data.action == Actions.READ:
            return self.handle_read(data)
        if data.action == Actions.SET:
            return self.handle_set(data)
        if data.action == Actions.ADD:
            return self.handle_add(data)
        if data.action == Actions.DICT_GET:
            return self.handle_dict_get(data)
        if data.action == Actions.DICT_UPDATE:
            return self.handle_dict_update(data)
        if data.action == Actions.FIFO_APPEND:
            return self.handle_fifo_append(data)
        if data.action == Actions.FIFO_POP:
            return self.handle_fifo_pop(data)
        if data.action == Actions.CLEAN:
            return self.handle_clean(data)
        if data.action == Actions.REMOVE:
            return self.handle_remove(data)
        if data.action == Actions.LOCK:
            return self.handle_lock(data)
        if data.action == Actions.UNLOCK:
            return self.handle_unlock(data)
        if data.action == Actions.CONNECT:
            return self.handle_connect(data)
        if data.action == Actions.DISCONNECT:
            return self.handle_disconnect(data)

        raise DropPacket

    def handle_backlogged_request(self, bl_sn, data):
        ''' handle the backlogged request

        :param bl_sn: serial number of backlogged request
        :param data: data of the request
        '''

        resp = self.handle_request(data, data_parsed=True, backlogging=False)

        rdata = resp.get('data')
        succeeded = rdata.get('succeeded')
        rcode = rdata.get('rcode')

        if not succeeded and rcode == ReturnCodes.LOCKED:
            raise SHMContainerLocked('Container still locked')
        else:
            self.backlogged_requests.pop(bl_sn, None)
            remaining_bl = len(self.backlogged_requests)
            logger.debug(
                f'backlogged request <{bl_sn}> processed, '
                f'remaining: {remaining_bl}'
            )
            return resp

    def handle_responding(self, resp):
        ''' handle responding

        send back the response through the given socket

        :param resp: information of the response, dict or None
                     dict structure: {
                                         "conn_id": connection ID,
                                         "data": data to send back,
                                     }
        '''

        if resp is None:
            return

        conn_id = resp['conn_id']
        conn = self.connections.get(conn_id)
        data = json.dumps(resp['data']).encode()

        try:
            conn.socket.sendto(data, conn.resp_socket)
        except ConnectionRefusedError:
            logger.warn(
                f'Socket <{conn.resp_socket}> closed when sending back response'
            )
            self._remove_connection(conn_id)

    def run_as_worker(self):
        pid = os.getpid()
        logger.debug(f'Running SharedMemoryManager worker {pid}')

        self._epoll = select.epoll()

        self._worker_sock = self._create_socket(self.worker_socket_path)
        self._epoll.register(self._worker_sock.fileno(), self.EV_MASK)

        self.__running = True
        while self.__running:
            pt = POLL_TIMEOUT if len(self.backlogged_requests) == 0 else 0.001
            events = self._epoll.poll(pt)

            for fd, evt in events:
                if evt & select.EPOLLERR:
                    msg = 'Unexpected epoll error occurred'
                    logger.error(msg)
                    raise OSError(msg)
                elif evt & select.EPOLLIN:
                    data, address = self._worker_sock.recvfrom(UDP_BUFFER_SIZE)

                    try:
                        resp = self.handle_request(data)
                        self.handle_responding(resp)
                    except (DropPacket, SHMRequestBacklogged):
                        pass

            # we will change self.backlogged_requests during the iteration
            dup = dict(self.backlogged_requests)

            for bl_sn, data in dup.items():
                try:
                    resp = self.handle_backlogged_request(bl_sn, data)
                    self.handle_responding(resp)
                except SHMContainerLocked:
                    logger.debug(
                        f'backlogged request <{bl_sn}> still locked'
                    )
                except (DropPacket, SHMRequestBacklogged):
                    pass

        self._worker_sock.close()
        os.remove(self.worker_socket_path)
        logger.info('SharedMemoryManager Worker exited successfully')

    def shutdown_worker(self):
        if self.__running:
            self.__running = False
        else:
            msg = 'SharedMemoryManager is not running as a worker'
            logger.error(msg)
            raise RuntimeError(msg)

    ## Methods below will be used by the client side
    def send_request(self, **request_args):
        conn = self.current_connection
        if conn is None:
            raise SHMWorkerNotConnected(MSG_NOT_CONNECTED)

        data = json.dumps(request_args).encode('utf-8')
        try:
            conn.socket.sendto(data, self.worker_socket_path)
        except (ConnectionRefusedError, FileNotFoundError):
            err_msg = (
                f'Connection to {self.worker_socket_path} '
                f'failed, seems SHM worker is not running.'
            )
            logger.error(err_msg)
            raise SharedMemoryError(err_msg)

    def read_response(self, conn_id):
        ''' read responses from the worker

        It was designed to be blocking so that the shared memory could works
        a bit more like the true memory.
        '''

        conn = self.current_connection
        if conn is None:
            raise SHMWorkerNotConnected(MSG_NOT_CONNECTED)

        try:
            data, address = conn.socket.recvfrom(UDP_BUFFER_SIZE)
            data = json.loads(data.decode('utf-8'))
            if not isinstance(data, dict):
                raise ValueError

            if not data.get('succeeded') and self.sensitive:
                rcode = data.get('rcode')
                raise SHMRequestFailed(rcode)

            return data
        except socket.timeout:
            logger.error(MSG_TIMEOUT)
            raise SHMResponseTimeout(MSG_TIMEOUT)
        except (UnicodeDecodeError, ValueError):
            logger.error(MSG_INVALID_DATA)
            raise SharedMemoryError(MSG_INVALID_DATA)

    def connect(self, socket_name):
        ''' Connect to the SharedMemoryManager worker

        :param socket_name: name of the socket to receive responses
        '''

        socket_path = os.path.join(self.socket_dir, socket_name)
        sock = self._create_socket(socket_path, blocking=True)
        sock.settimeout(SHM_MAX_BLOCKING_TIME)

        data = {
            'socket': socket_name,
            'action': Actions.CONNECT,
        }
        data = json.dumps(data).encode('utf-8')
        sock.sendto(data, self.worker_socket_path)

        try:
            data, address = sock.recvfrom(UDP_BUFFER_SIZE)
            data = json.loads(data.decode('utf-8'))
            if not isinstance(data, dict):
                raise ValueError
        except socket.timeout:
            logger.error(MSG_CONN_FAILED)
            raise SHMWorkerConnectFailed(MSG_CONN_FAILED)
        except (UnicodeDecodeError, ValueError):
            logger.error(MSG_INVALID_DATA)
            raise SharedMemoryError(MSG_INVALID_DATA)

        if not data.get('succeeded'):
            logger.error(
                f'Failed to connect to the SharedMemoryManager Worker. '
                f'Worker returns: {data}'
            )
            raise SHMWorkerConnectFailed(MSG_CONN_FAILED)
        else:
            conn_id = data.get('conn_id')
            self.current_connection = Connection(
                                          socket=sock,
                                          socket_name=socket_name,
                                          conn_id=conn_id,
                                      )

    def disconnect(self):
        ''' disconnect from the SharedMemoryManager worker
        '''

        conn = self.current_connection
        self.send_request(
            conn_id=conn.conn_id,
            action=Actions.DISCONNECT,
        )

        conn.socket.close()
        socket_path = os.path.join(self.socket_dir, conn.socket_name)
        os.remove(socket_path)

        logger.debug(f'remove socket: {socket_path}')
        self.current_connection = None

    def lock_key(self, key, backlogging=True):
        ''' acquire the lock of a container
        '''

        self.send_request(
            conn_id=self.current_connection.conn_id,
            action=Actions.LOCK,
            key=key,
            backlogging=backlogging,
        )
        return self.read_response(self.current_connection.conn_id)

    def unlock_key(self, key, backlogging=True):
        ''' release the lock of a container
        '''

        self.send_request(
            conn_id=self.current_connection.conn_id,
            action=Actions.UNLOCK,
            key=key,
            backlogging=backlogging,
        )
        return self.read_response(self.current_connection.conn_id)

    def create_key(self, key, type_, value=None, backlogging=True):
        ''' create a new container

        :param key: the container key
        :param type_: type of container, enumerated in SHMContainerTypes
        :param value: the initial value, type of the value should be same with
                      the container type
        '''

        value = list(value) if type_ == SHMContainerTypes.SET else value
        self.send_request(
            conn_id=self.current_connection.conn_id,
            action=Actions.CREATE,
            key=key,
            type=type_,
            value=value,
            backlogging=backlogging,
        )
        return self.read_response(self.current_connection.conn_id)

    def create_key_and_ignore_conflict(self, *args, **kwargs):
        ''' invoke self.create_key and ignore the KEY_CONFLICT fault
        '''

        try:
            self.create_key(*args, **kwargs)
        except SHMRequestFailed as e:
            rcode = e.args[0]
            if rcode != ReturnCodes.KEY_CONFLICT:
                raise e

    def set_value(self, key, value, backlogging=True):
        ''' change the value of a key

        allowed container types:
            STR, INT, FLOAT, BOOL

        :param key: the container key
        :param value: values to be set
        '''

        self.send_request(
            conn_id=self.current_connection.conn_id,
            action=Actions.SET,
            key=key,
            value=value,
            backlogging=backlogging,
        )
        return self.read_response(self.current_connection.conn_id)

    def add_value(self, key, value, backlogging=True):
        ''' add values into the container

        allowed container types:
            SET, LIST, DICT

        :param key: the container key
        :param value: values to be added,
                      type of the value should be same with the container type
        '''

        value = list(value) if isinstance(value, set) else value
        self.send_request(
            conn_id=self.current_connection.conn_id,
            action=Actions.ADD,
            key=key,
            value=value,
            backlogging=backlogging,
        )
        return self.read_response(self.current_connection.conn_id)

    def remove_value(self, key, values, backlogging=True):
        ''' remove values from the container

        :param key: the container key
        :param values: a group of values that need be removed.

                       When the container type is SET or LIST, values is
                       a group of value in the container.

                       When the container type is DICT, values is a group
                       of keys in the dict container.
        '''

        try:
            vl = list(values)
        except TypeError:
            # TypeError means values is not iterable
            vl = [values]

        self.send_request(
            conn_id=self.current_connection.conn_id,
            action=Actions.REMOVE,
            key=key,
            value=vl,
            backlogging=backlogging,
        )
        return self.read_response(self.current_connection.conn_id)

    def fifo_pop(self, key, backlogging=True):
        ''' pops one value from a FIFO queue
        '''

        self.send_request(
            conn_id=self.current_connection.conn_id,
            action=Actions.FIFO_POP,
            key=key,
            backlogging=backlogging,
        )
        return self.read_response(self.current_connection.conn_id)

    def fifo_append(self, key, value, backlogging=True):
        ''' appends one value into a FIFO queue
        '''

        self.send_request(
            conn_id=self.current_connection.conn_id,
            action=Actions.FIFO_APPEND,
            key=key,
            value=value,
            backlogging=backlogging,
        )
        return self.read_response(self.current_connection.conn_id)

    def read_key(self, key, backlogging=True):
        ''' read the whole container
        '''

        self.send_request(
            conn_id=self.current_connection.conn_id,
            action=Actions.READ,
            key=key,
            backlogging=backlogging,
        )
        return self.read_response(self.current_connection.conn_id)

    def clean_key(self, key, backlogging=True):
        ''' completely remove a container
        '''

        self.send_request(
            conn_id=self.current_connection.conn_id,
            action=Actions.CLEAN,
            key=key,
            backlogging=backlogging,
        )
        return self.read_response(self.current_connection.conn_id)

    def get_dict_value(self, key, dict_key, backlogging=True):
        ''' get a value from a dict container

        allowed container type: DICT

        :param key: the container key
        :param dict_key: key in the dict container
        '''

        # value_key arguments in integer will be automatically converted into
        # strings in the JSON serialization. We can use integers as a dict key
        # in Python dicts but it's invalid in JSON. The SHM client communicates
        # with the SHM worker by transporting JSONs, so we have to convert
        # value_key arguments in integer into strings here.
        self.send_request(
            conn_id=self.current_connection.conn_id,
            action=Actions.DICT_GET,
            key=key,
            value_key=str(dict_key),
            backlogging=backlogging,
        )
        return self.read_response(self.current_connection.conn_id)

    def update_dict(self, key, dict_key, value, backlogging=True):
        ''' change a value of a dict container

        allowed container type: DICT

        :param key: the container key
        :param dict_key: key in the dict container
        :param value: value for dict.update()
        '''

        self.send_request(
            conn_id=self.current_connection.conn_id,
            action=Actions.DICT_UPDATE,
            key=key,
            value_key=str(dict_key),
            value=value,
            backlogging=backlogging,
        )
        return self.read_response(self.current_connection.conn_id)
