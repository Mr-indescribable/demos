import os
import json
import select
import socket
import struct as pystruct
import logging

from ..glb import GLBInfo
from ..utils.od import ODict
from ..utils.misc import VerifiTools
from ..exceptions import (
    AddressAlreadyInUse,
    ConnectionLost,
    TryAgain,
    SHMError,
)
from ..fdx.tcp import FDXTCPConn
from ..aff.tcp import TCPServerAff
from ..ev.epoll import EpollPoller
from ..helper.tcp import (
    TCPConnHelper,
    TCPPacketHelper,
    NonblockingTCPIOHelper,
)


logger = logging.getLogger('SHM')


SHM_ACT_REP  = 0x10
SHM_ACT_INIT = 0x11
SHM_ACT_RA   = 0x12
SHM_ACT_GET  = 0x13
SHM_ACT_SET  = 0x14
SHM_ACT_PUT  = 0x15
SHM_ACT_RM   = 0X16
SHM_ACT_DLT  = 0x17

SHM_TYPE_NC  = 0x20
SHM_TYPE_ARY = 0x21
SHM_TYPE_OBJ = 0x22

SHM_RCODE_OK              = 0x50
SHM_RCODE_NO_SUCH_ACTION  = 0x51
SHM_RCODE_NO_SUCH_KEY     = 0x52
SHM_RCODE_KEY_CONFLICTION = 0x53
SHM_RCODE_TYPE_ERROR      = 0x54
SHM_RCODE_INDEX_ERROR     = 0x55
SHM_RCODE_INNER_KEY_ERROR = 0x56


class SHMServerAff(TCPServerAff):

    def __init__(self, sock_path):
        self._sock_path = sock_path
        self._sock = self.__create_sock(self._sock_path, 64)
        self.fd = self._sock.fileno()

    def __create_sock(self, sock_path, backlog):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.setblocking(False)

        try:
            if sock_path is not None:
                logger.debug(
                    f'created socket and tring to bind on {sock_path}'
                )
                sock.bind(sock_path)
        except OSError as e:
            if e.errno == 98:
                raise AddressAlreadyInUse(
                    f'{sock_path} is already in use, cannot bind on it'
                )
            else:
                raise e

        sock.listen(backlog)
        return sock

    def destroy(self):
        self._sock.close()
        self._sock = None
        os.remove(self._sock_path)


# A descriptor for helping the SHMServer in processing requests.
# It prechecks the incoming key in the request and replies with error
# if the key does not exist.
def __existence_confirmed(func):

    def wrapper(self, pkt, conn):
        if not VerifiTools.type_matched(pkt.key, str):
            self._replay(
                conn,
                self._gen_err_resp(
                    SHM_RCODE_TYPE_ERROR,
                    f'unsupported type of key'
                )
            )
            return

        if pkt.key not in self._mem_pool:
            self._replay(
                conn,
                self._gen_err_resp(
                    SHM_RCODE_NO_SUCH_KEY,
                    f'not such key: {pkt.key}'
                )
            )
            return

        return func(self, pkt, conn)

    return wrapper


def __try_to_parse_next_blk_size(conn):
    if conn.next_blk_size is None and conn.recv_buf_len >= 4:
        # pop out 4 bytes of the length field, and then, we'll need to
        # receive a block that matchs the length
        length_bt = conn.pop_data(4)
        length = pystruct.unpack('<I', length_bt)[0]
        conn.set_next_blk_size(length)


# The Shared Memory Server
#
# The shared memory server is a simple TCP server that works with Unix sockets.
# It provides storages to store data in several Python types.
#
# We don't need any encryption or authentication for the shared memory system
# since it's mode for the local inter-process communication only.
#
# Packet format:
#
#     | 4 bytes |        Length bytes       |
#     +---------+---------------------------+
#     | Length  |          Payload          |
#     +---------+---------------------------+
#
#     Length:
#         The length field marks the length of the payload field,
#         it will be packed or parsed as an unsigned integer in little-endian.
#
#     Payload:
#         The payload contains the data we need to transfer, it's length should
#         always match the length field.
#
#         The content of payload field is a serialized JSON string.
#
#     Inner JSON format:
#         We shall have the following fields in the JSON payload in general:
#
#             action:
#                 An integer that describes what does the current packet do.
#
#                 Currently, we have 8 actions:
#
#                     Reply:
#                         Means this is a reply from the server side which
#                         responding the request from client side.
#
#                     Init:
#                         Means to initialize a key in the memory pool.
#
#                         When using the Init action, the Data will be ignored,
#                         the server will create a new key in the memory pool
#                         and give it a default value.
#
#                         The default value is depends on the Type,
#                         non-container types will be initialized as a null,
#                         arrays will be initialized as empty arrays ([]),
#                         objects will be initialized as empty JSON objects ({})
#
#                     ReadAll:
#                         Means to read all content on a key in any type.
#
#                     Get:
#                         Means to get a single element from a container.
#
#                         With an Array type container, the Data field should
#                         be an integer which means the index of the element
#                         in the container.
#
#                         With an Object type container, the Data field should
#                         be a string which means the inner key of the container
#
#                     Set:
#                         Means to set a value on an Non-Container type key.
#                         The server will override the original value, and
#                         will initialize the key of it not initialized.
#
#                     Put:
#                         Means to put new elements into a container.
#
#                         With an Array type container, the Data field should
#                         be a JSON Array as well, each elements in the data
#                         will be appended on the tail of the container.
#
#                         With an Object type container, the Data field should
#                         be a JSON object as well, each elements int the
#                         data will be written into the container, if any
#                         elements in the data conflicts with elements in
#                         the container, then the new data will override
#                         the old one. This behaviour should be same as
#                         dict.update() in Python3.
#
#                     Remove:
#                         Means to remove an element in a container.
#
#                         In this case, the Data field should be a single
#                         element to remove.
#
#                         For Array type containers, the Data field
#                         should be a index in the container.
#
#                         For Object type containers, the Data field
#                         should be an inner key of the container.
#
#                     Delete:
#                         Means to delete a key from the memory pool.
#
#                         In this case, the Data field should be a string
#                         which contains the key to be deleted.
#
#             type:
#                 An integer that marks the type of the interchanging data.
#
#                 Currently, we have only three types in tow kinds:
#
#                     Container Type Array:
#                         Means the Data is in the JSON Array format.
#
#                    Container Type Object:
#                         Means the Data is in the JSON Object format.
#
#                     Non-Container Type:
#                         Means the Data may be a number, a string or a boolean,
#                         it may in any format that cannot contain sub-elements.
#
#             key:
#                 A string key name that constitutes the key-value pair
#                 with the Data field.
#
#             data:
#                 A JSON object that contains any kinds of data which
#                 constitutes the the key-value pair with the Key field.
#
#                 Inner Structure:
#                     Depends on the scenario, any structure supported
#                     by JSON may be used here.
#
#             rt:
#                 A JSON object that contains additional information which
#                 may help the data interchange and the reporting of status.
#
#                 This field should be only written by the server side, and
#                 be read by the client side.
#
#                 Inner Structure:
#                     {
#                         "rcode": integer,
#                         "rmsg": string,
#                     }
class SHMServer():

    def __init__(self):
        self._sock_path = GLBInfo.config.shm.socket
        self._server_aff = SHMServerAff(self._sock_path)
        self._server_fd = self._server_aff.fd

        self._poller = EpollPoller()
        self._poller.register(
            self._server_fd,
            self._poller.EV_IN,
            self._server_aff,
        )

        self._io_helper = NonblockingTCPIOHelper(self._poller)

        self._mem_pool = dict()
        self._running = False

    def run(self):
        logger.info('SHMServer starts')

        self._running = True
        while self._running:
            evs = self._poller.poll()

            for fd, ev in evs:
                self._handle_ev(fd, ev)

        self._server_aff.destroy()
        logger.info('SHMServer stops')

    def shutdown(self):
        self._running = False

    def _gen_resp(
        self,
        data=None,
        rcode=SHM_RCODE_OK,
        rmsg=None,
        key=None,
        type_=None,
        action=SHM_ACT_REP,
    ):
        r_json = {
            'action': action,
            'key': key,
            'type': type_,
            'data': data,
            'rt': {
                'rcode': rcode,
                'rmsg': rmsg,
            }
        }
        r_bytes = json.dumps(r_json).encode()
        len_byte = len(r_bytes)

        return pystruct.pack('<I', len_byte) + r_bytes

    def _gen_ok_resp(self, data=None, rmsg=None):
        return self._gen_resp(data=data, rcode=SHM_RCODE_OK, rmsg=rmsg)

    def _gen_err_resp(self, rcode, rmsg):
        return self._gen_resp(data=None, rcode=rcode, rmsg=rmsg)

    def _replay(self, conn, data):
        self._io_helper.append_data(conn, data)

    def _handle_ev(self, fd, ev):
        if fd == self._server_fd and ev & self._poller.EV_IN:
            self._accept()
            return

        if ev & self._poller.EV_ERR | ev & self._poller.EV_RDHUP:
            self._handle_destroy(fd)
            return
        elif ev & self._poller.EV_OUT:
            self._handle_out(fd)
            return
        elif ev & self._poller.EV_IN:
            self._handle_in(fd)
            return
        else:
            logger.debug(f'unrecognized ev code: {ev}')
            return

    def _accept(self):
        try:
            conn, src = self._server_aff.accept_raw()
        except TryAgain:
            return

        fdxconn = FDXTCPConn(conn, src)
        self._poller.register(fdxconn.fd, self._poller.DEFAULT_EV, fdxconn)

    def _handle_in(self, fd):
        conn = self._poller.get_registered_obj(fd)
        pkt_ready = False

        # We should do a recv() first, no matter what will happen next or
        # what we've got now
        try:
            pkt = self._io_helper.handle_recv(conn)
            pkt_ready = True
        except TryAgain:
            # the TryAgain raised by the helper means we've not completely
            # reveived the next packet yet or the next_blk_size is not set.
            # So, if the next_blk_size is not set, then we should try to
            # parse it here.
            if conn.next_blk_size is not None:
                # otherwise, we are waiting for the rest data of the packet.
                return

            __try_to_parse_next_blk_size(conn)

            # And we may try again and see if the packet is ready to be parsed.
            try:
                pkt = TCPPacketHelper.pop_packet(conn)
                pkt_ready = True
            except TryAgain:
                # In this case, nothing we can do now,
                # we need to wait the rest data of the packet.
                return
        except ConnectionLost:
            self._handle_destroy(fd)
            return

        if pkt_ready:
            conn.set_next_blk_size(None)
            self._handle_pkt(pkt, conn)

    def _handle_out(self, fd):
        conn = self._poller.get_registered_obj(fd)
        self._io_helper.handle_send(conn)

    def _handle_destroy(self, fd):
        conn = self._poller.get_registered_obj(fd)

        self._poller.unregister(fd)
        conn.destroy()

    def _handle_pkt(self, pkt_bt, conn):
        try:
            pkt = json.loads(pkt_bt.decode())
            pkt = ODict(**pkt)
        except Exception:
            # We don't care what excetpion occurred, if we cannot parse
            # the data, then just disconnect it.
            self._handle_destroy(conn.fd)

            logger.info(
                f'Unable to parse the data, '
                f'connection from {conn._src} has been removed.'
            )
            return

        if pkt.action == SHM_ACT_INIT:
            self._handle_init(pkt, conn)
        elif pkt.action == SHM_ACT_RA:
            self._handle_read_all(pkt, conn)
        elif pkt.action == SHM_ACT_GET:
            self._handle_get(pkt, conn)
        elif pkt.action == SHM_ACT_SET:
            self._handle_set(pkt, conn)
        elif pkt.action == SHM_ACT_PUT:
            self._handle_put(pkt, conn)
        elif pkt.action == SHM_ACT_RM:
            self._handle_remove(pkt, conn)
        elif pkt.action == SHM_ACT_DLT:
            self._handle_delete(pkt, conn)
        else:
            self._replay(
                conn,
                self._gen_err_resp(
                    SHM_RCODE_NO_SUCH_ACTION,
                    f'unknown action: {pkt.action}',
                )
            )
            return

    def _handle_init(self, pkt, conn):
        if pkt.key in self._mem_pool:
            self._replay(
                conn,
                self._gen_err_resp(
                    SHM_RCODE_KEY_CONFLICTION,
                    f'key exists: {pkt.key}'
                )
            )
            return

        if not VerifiTools.type_matched(pkt.key, str):
            self._replay(
                conn,
                self._gen_err_resp(
                    SHM_RCODE_TYPE_ERROR,
                    f'invalid type of key'
                )
            )
            return

        if pkt.type == SHM_TYPE_NC:
            dv = None
        elif pkt.type == SHM_TYPE_ARY:
            dv = list()
        elif pkt.type == SHM_TYPE_OBJ:
            dv = dict()

        self._mem_pool.update( {pkt.key: dv} )
        self._replay(conn, self._gen_ok_resp())

    @__existence_confirmed
    def _handle_read_all(self, pkt, conn):
        data = self._mem_pool.get(pkt.key)
        self._replay(conn, self._gen_ok_resp(data))

    @__existence_confirmed
    def _handle_get(self, pkt, conn):
        container = self._mem_pool.get(pkt.key)

        # SHM_TYPE_ARY
        if VerifiTools.type_matched(container, list):
            index = pkt.data

            if not (
                VerifiTools.type_matched(index, int) and
                len(container) - 1 >= index
            ):
                self._replay(
                    conn,
                    self._gen_err_resp(
                        SHM_RCODE_INDEX_ERROR,
                        f'invalid index: {index}'
                    )
                )
                return

            self._replay(conn, self._gen_ok_resp(container[index]))
            return

        # SHM_TYPE_OBJ
        elif VerifiTools.type_matched(container, dict):
            ik = pkt.data

            if not VerifiTools.type_matched(ik, str):
                self._replay(
                    conn,
                    self._gen_err_resp(
                        SHM_RCODE_INNER_KEY_ERROR,
                        f'invalid inner key: {ik}'
                    )
                )
                return

            self._replay(conn, self._gen_ok_resp(container.get(ik)))
            return
        else:
            self._replay(
                conn,
                self._gen_err_resp(
                    SHM_RCODE_TYPE_ERROR,
                    f'unsupported type: {pkt.type}'
                )
            )
            return

    @__existence_confirmed
    def _handle_set(self, pkt, conn):
        if pkt.type != SHM_TYPE_NC:
            self._replay(
                conn,
                self._gen_err_resp(
                    SHM_RCODE_TYPE_ERROR,
                    f'unsupported type: {pkt.type}'
                )
            )

        self._mem_pool.update({pkt.key: pkt.data})
        self._replay(conn, self._gen_ok_resp())

    @__existence_confirmed
    def _handle_put(self, pkt, conn):
        container = self._mem_pool.get(pkt.key)

        # SHM_TYPE_ARY
        if VerifiTools.type_matched(container, list):
            data = pkt.data
            if not VerifiTools.type_matched(data, list):
                self._replay(
                    conn,
                    self._gen_err_resp(
                        SHM_RCODE_TYPE_ERROR,
                        f'invalid data type'
                    )
                )
                return

            container.extend(data)
            self._replay(conn, self._gen_ok_resp())
            return

        # SHM_TYPE_OBJ
        elif VerifiTools.type_matched(container, dict):
            if not VerifiTools.type_matched(pkt.data, ODict):
                self._replay(
                    conn,
                    self._gen_err_resp(
                        SHM_RCODE_TYPE_ERROR,
                        f'invalid data type'
                    )
                )
                return

            data = pkt.data.__to_dict__()
            container.update(**data)
            self._replay(conn, self._gen_ok_resp())
            return
        else:
            self._replay(
                conn,
                self._gen_err_resp(
                    SHM_RCODE_TYPE_ERROR,
                    f'unsupported type: {pkt.type}'
                )
            )
            return

    @__existence_confirmed
    def _handle_remove(self, pkt, conn):
        container = self._mem_pool.get(pkt.key)

        # SHM_TYPE_ARY
        if VerifiTools.type_matched(container, list):
            index = pkt.data
            container = self._mem_pool.get(pkt.key)

            if not (
                VerifiTools.type_matched(index, int) and
                len(container) - 1 >= index
            ):
                self._replay(
                    conn,
                    self._gen_err_resp(
                        SHM_RCODE_INDEX_ERROR,
                        f'invalid index: {index}'
                    )
                )
                return

            container.pop(index)
            self._replay(conn, self._gen_ok_resp())
            return

        # SHM_TYPE_OBJ
        elif VerifiTools.type_matched(container, dict):
            ik = pkt.data

            if not VerifiTools.type_matched(ik, str):
                self._replay(
                    conn,
                    self._gen_err_resp(
                        SHM_RCODE_INNER_KEY_ERROR,
                        f'invalid inner key: {ik}'
                    )
                )
                return

            container.pop(ik)
            self._replay(conn, self._gen_ok_resp())
            return
        else:
            self._replay(
                conn,
                self._gen_err_resp(
                    SHM_RCODE_TYPE_ERROR,
                    f'unsupported type: {pkt.type}'
                )
            )
            return

    @__existence_confirmed
    def _handle_delete(self, pkt, conn):
        self._mem_pool.pop(pkt.key)
        self._replay(conn, self._gen_ok_resp())


# handles unexpected exceptions for SHMClient,
# converts all exceptions except SHMError to SHMError
def __other_exceptions_handled(func):

    def wrapper(self, *args):
        try:
            return func(self, *args)
        except SHMError as shm_err:
            raise shm_err
        except Exception as err:
            if len(err.args > 0):
                raise SHMError(
                    f'Unexpected exception {type(err)} '
                    f'with message: {err.args[0]}'
                )
            else:
                raise SHMError(
                    f'Unexpected exception {type(err)} '
                    f'with no additional information'
                )

    return wrapper


class SHMClient():

    SOCK_TIMEOUT = 1
    RECV_MAX_RETRY = 4

    def __init__(self):
        self._sock_path = GLBInfo.config.shm.socket

        conn = TCPConnHelper.conn_to_uds(
            self._sock_path,
            blocking=True,
            timeout=self.SOCK_TIMEOUT
        )
        self._conn = FDXTCPConn(conn, src=None, blocking=True)

    def _gen_req(self, action, key, type_=None, data=None):
        r_json = {
            'action': action,
            'key': key,
            'type': type_,
            'data': data,
        }
        r_bytes = json.dumps(r_json).encode()
        len_byte = len(r_bytes)

        return pystruct.pack('<I', len_byte) + r_bytes

    # Sends a request to the SHMServer and returns the response
    def _req(self, action, key, type_=None, data=None):
        tried_times = 0
        pkt_ready = False

        req_data = self._gen_req(action, key, type_, data)
        sent = self._conn.send(req_data)

        # The server must answer correctly, otherwise we can no longer let
        # the program run. The SHMError is similar with a failure of malloc()
        # or segmentation fault.
        while tried_times < self.RECV_MAX_RETRY:
            try:
                self._conn.recv()
                __try_to_parse_next_blk_size(self._conn)

                pkt = TCPPacketHelper.pop_packet(self._conn)
                pkt_ready = True
                break
            except (socket.timeout, TryAgain):
                tried_times += 1
                continue

        if not pkt_ready:
            raise SHMError('No sufficient bytes received from SHMServer')

        try:
            j_resp = json.loads(pkt.decode())
            return ODict(**j_resp)
        except Exception:
            raise SHMError('SHMServer does not respond correctly')

    def _check_rcode(self, resp, op_name):
        if not resp.rt.rcode == SHM_RCODE_OK:
            raise SHMError(
                f'Operation {op_name} failed, '
                f'rcode: {resp.rt.rcode}, rmsg: {resp.rt.rmsg}'
            )

    @__other_exceptions_handled
    def init(self, key, type_):
        resp = self._req(SHM_ACT_INIT, key, type_=type_)
        self._check_rcode(resp, 'INIT')

    @__other_exceptions_handled
    def read_all(self, key):
        resp = self._req(SHM_ACT_RA, key)
        self._check_rcode(resp, 'READ_ALL')
        return resp.data

    @__other_exceptions_handled
    def get(self, key, data):
        resp = self._req(SHM_ACT_GET, key, data=data)
        self._check_rcode(resp, 'GET')
        return resp.data

    @__other_exceptions_handled
    def set(self, key, data):
        resp = self._req(SHM_ACT_SET, key, data=data)
        self._check_rcode(resp, 'SET')

    @__other_exceptions_handled
    def put(self, key, data):
        resp = self._req(SHM_ACT_PUT, key, data=data)
        self._check_rcode(resp, 'PUT')

    @__other_exceptions_handled
    def remove(self, key, data):
        resp = self._req(SHM_ACT_RM, key, data=data)
        self._check_rcode(resp, 'REMOVE')

    @__other_exceptions_handled
    def delete(self, key):
        resp = self._req(SHM_ACT_DLT, key)
        self._check_rcode(resp, 'DELETE')
