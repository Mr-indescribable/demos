#!/usr/bin/python3.6
#coding: utf-8

import os
import time
import base64
import random
import socket
import signal as sig
import logging

from neverland.pkt import UDPPacket
from neverland.utils import Converter
from neverland.exceptions import InvalidPkt, SharedMemoryError
from neverland.node.context import NodeContext
from neverland.efferents.udp import UDPTransmitter
from neverland.components.shm import (
    SharedMemoryManager,
    SHMContainerTypes,
)


logger = logging.getLogger('PktMgr')


# SHM container for storing special packets
# data structure:
#     {
#         sn: {
#             type: int,
#             fields: {}
#             previous_hop: [ip, port],
#             next_hop: [ip, port],
#         }
#     }
SHM_KEY_PKTS = 'SpecPktMgr_Packets'


# SHM container for storing serial numbers of packets that need
# to be sent repeatedly
# data structure:
#     [sn_0, sn_1]
SHM_KEY_PKTS_TO_REPEAT = 'SpecPktRpter_PacketsToRepeat'

# SHM container for storing the last repeat time of packets
# data structure:
#     {sn: timestamp}
SHM_KEY_LAST_REPEAT_TIME = 'SpecialPktRpter_LastRptTime'

# similar with the above one, but contains the timestamp of the next repeat time
SHM_KEY_NEXT_REPEAT_TIME = 'SpecialPktRpter_NextRptTime'

# SHM container for storing how many times packets could be repeated
# data structure:
#     {sn: integer}
SHM_KEY_MAX_REPEAT_TIMES = 'SpecialPktRpter_MaxRepeatTimes'

# SHM container for storing how many times packets have been repeated
# data structure:
#     {sn: integer}
SHM_KEY_REPEATED_TIMES = 'SpecialPktRpter_RepeatedTimes'


class SpecialPacketManager():

    SHM_SOCKET_NAME_TEMPLATE = 'SHM-SpecialPacketManager-%d.socket'

    def __init__(self, config, shm_socket_template=None):
        ''' Constructor

        :param config: the config
        :param shm_socket_template: An alternative of SHM_SOCKET_NAME_TEMPLATE.
        '''

        self.config = config
        self.shm_socket_template =\
                shm_socket_template or self.SHM_SOCKET_NAME_TEMPLATE

        self.pid = os.getpid()

        self.shm_key_pkts = SHM_KEY_PKTS

        # These containers are for the SpecialPacketRepeater, the repeater
        # will also access special packets by the manager.
        self.shm_key_pkts_to_repeat = SHM_KEY_PKTS_TO_REPEAT
        self.shm_key_last_repeat_time = SHM_KEY_LAST_REPEAT_TIME
        self.shm_key_next_repeat_time = SHM_KEY_NEXT_REPEAT_TIME
        self.shm_key_max_repeat_times = SHM_KEY_MAX_REPEAT_TIMES
        self.shm_key_repeated_times = SHM_KEY_REPEATED_TIMES

    def init_shm(self):
        ''' initialize the shared memory manager
        '''

        self.shm_mgr = SharedMemoryManager(self.config)
        self.shm_mgr.connect(
            self.shm_socket_template % self.pid
        )
        self.shm_mgr.create_key_and_ignore_conflict(
            self.shm_key_pkts,
            SHMContainerTypes.DICT,
        )
        self.shm_mgr.create_key_and_ignore_conflict(
            self.shm_key_pkts_to_repeat,
            SHMContainerTypes.LIST,
        )
        self.shm_mgr.create_key_and_ignore_conflict(
            self.shm_key_last_repeat_time,
            SHMContainerTypes.DICT,
        )
        self.shm_mgr.create_key_and_ignore_conflict(
            self.shm_key_next_repeat_time,
            SHMContainerTypes.DICT,
        )
        self.shm_mgr.create_key_and_ignore_conflict(
            self.shm_key_max_repeat_times,
            SHMContainerTypes.DICT,
        )
        self.shm_mgr.create_key_and_ignore_conflict(
            self.shm_key_repeated_times,
            SHMContainerTypes.DICT,
        )

    def close_shm(self):
        self.shm_mgr.disconnect()

    def store_pkt(self, pkt, need_repeat=False, max_rpt_times=5):
        if pkt.fields.sn is None:
            raise InvalidPkt(
                'Packets to be stored must contain a serial number'
            )

        sn_key = str(pkt.fields.sn)
        type_ = pkt.fields.type

        # The salt field is bytes, so we cannot serialize it in a JSON.
        # So, we shall encode it into a base64 string before store it.
        #
        # Though this fields is useless, but as a low-level module, the
        # SpecialPacketManager should not change the content of packets
        fields = pkt.fields.__to_dict__()

        if 'salt' in fields:
            salt = fields.get('salt')
            if salt is not None:
                salt_b64 = base64.b64encode(salt).decode()
                fields.update(salt=salt_b64)

        # As well as the mac and the data
        if 'mac' in fields:
            mac = fields.get('mac')
            if mac is not None:
                mac_b64 = base64.b64encode(mac).decode()
                fields.update(mac=mac_b64)

        previous_hop = list(pkt.previous_hop)
        next_hop = list(pkt.next_hop)

        pkt_data = {
            'type': type_,
            'fields': fields,
            'previous_hop': previous_hop,
            'next_hop': next_hop,
        }

        if 'data' in pkt:
            data = pkt.data
            if data is not None:
                data = base64.b64encode(data).decode()

            pkt_data.update(data=data)

        shm_value = {sn_key: pkt_data}
        self.shm_mgr.add_value(self.shm_key_pkts, shm_value)

        if need_repeat:
            self.shm_mgr.add_value(self.shm_key_pkts_to_repeat, [sn_key])
            self.set_pkt_max_repeat_times(sn_key, max_rpt_times)
            self.set_pkt_repeated_times(sn_key, 0)

        hex_type = Converter.int_2_hex(type_)
        logger.debug(
            f'Stored a special packet, need_repeat: {need_repeat}, '
            f'sn: {sn_key}, type: {hex_type}, dest: {pkt.fields.dest}'
        )

    def get_pkt(self, sn, pop=False):
        ''' get a packet form the packet manager

        :param pop: specifies whether the packet will be remoted from
                    the storage after the get_pkt invocation.
        '''

        sn_key = str(sn)

        shm_data = self.shm_mgr.get_dict_value(self.shm_key_pkts, sn_key)
        shm_value = shm_data.get('value')

        if shm_value is None:
            return None

        if pop:
            self.remove_pkt(sn_key)

        fields = shm_value.get('fields')

        if 'salt' in fields:
            salt = fields.get('salt')
            salt = base64.b64decode(salt) if salt is not None else salt
            fields.update(salt=salt)

        if 'mac' in fields:
            mac = fields.get('mac')
            mac = base64.b64decode(mac) if mac is not None else mac
            fields.update(mac=mac)

        pkt = UDPPacket(
            fields=fields,
            type=shm_value.get('type'),
            previous_hop=shm_value.get('previous_hop'),
            next_hop=shm_value.get('next_hop'),
        )

        if 'data' in shm_value:
            data = shm_value.get('data')
            data = base64.b64decode(data) if data is not None else data
            pkt.__update__(data=data)

        return pkt

    def pop_pkt(self, sn):
        return self.get_pkt(sn, pop=True)

    def remove_pkt(self, sn):
        sn_key = str(sn)

        self.cancel_repeat(sn_key)
        self.shm_mgr.remove_value(self.shm_key_pkts, sn_key)

        logger.debug(
            f'Removed a special packet, sn: {sn_key}'
        )

    def cancel_repeat(self, sn):
        sn_key = str(sn)

        self.shm_mgr.remove_value(self.shm_key_pkts_to_repeat, sn_key)
        self.shm_mgr.remove_value(self.shm_key_last_repeat_time, sn_key)
        self.shm_mgr.remove_value(self.shm_key_next_repeat_time, sn_key)
        self.shm_mgr.remove_value(self.shm_key_max_repeat_times, sn_key)
        self.shm_mgr.remove_value(self.shm_key_repeated_times, sn_key)
        logger.debug(
            f'Cancelled repeat for a packet, sn: {sn_key}'
        )

    def repeat_pkt(self, pkt, max_rpt_times=5):
        self.store_pkt(pkt, need_repeat=True, max_rpt_times=max_rpt_times)

    def get_repeating_sn_list(self):
        shm_data = self.shm_mgr.read_key(self.shm_key_pkts_to_repeat)
        return shm_data.get('value')

    def set_pkt_last_repeat_time(self, sn, timestamp):
        sn = str(sn)
        self.shm_mgr.add_value(self.shm_key_last_repeat_time, {sn: timestamp})
        logger.debug(f'set_pkt_last_repeat_time, sn: {sn}, ts: {timestamp}')

    def get_pkt_last_repeat_time(self, sn):
        sn = str(sn)
        shm_data = self.shm_mgr.get_dict_value(self.shm_key_last_repeat_time, sn)
        return shm_data.get('value')

    def set_pkt_next_repeat_time(self, sn, timestamp):
        sn = str(sn)
        self.shm_mgr.add_value(self.shm_key_next_repeat_time, {sn: timestamp})
        logger.debug(f'set_pkt_next_repeat_time, sn: {sn}, ts: {timestamp}')

    def get_pkt_next_repeat_time(self, sn):
        sn = str(sn)
        shm_data = self.shm_mgr.get_dict_value(self.shm_key_next_repeat_time, sn)
        return shm_data.get('value')

    def set_pkt_max_repeat_times(self, sn, times):
        sn = str(sn)
        self.shm_mgr.add_value(self.shm_key_max_repeat_times, {sn: times})
        logger.debug(f'set_pkt_max_repeat_times, sn: {sn}, times: {times}')

    def get_pkt_max_repeat_times(self, sn):
        sn = str(sn)
        shm_data = self.shm_mgr.get_dict_value(self.shm_key_max_repeat_times, sn)
        return shm_data.get('value')

    def set_pkt_repeated_times(self, sn, times):
        sn = str(sn)
        self.shm_mgr.add_value(self.shm_key_repeated_times, {sn: times})
        logger.debug(f'set_pkt_repeated_times, sn: {sn}, times: {times}')

    def get_pkt_repeated_times(self, sn):
        sn = str(sn)
        shm_data = self.shm_mgr.get_dict_value(self.shm_key_repeated_times, sn)
        return shm_data.get('value')

    def increase_pkt_repeated_times(self, sn):
        sn = str(sn)
        repeated_times = self.get_pkt_repeated_times(sn)

        if repeated_times is None:
            repeated_times = 1
        else:
            repeated_times += 1

        self.set_pkt_repeated_times(sn, repeated_times)


class SpecialPacketRepeater():

    ''' The repeater for special packets

    A special worker for sending special packets repeatedly.

    Actually, the packet repeater is a part of the packet manager though
    we made it standalone, but it still work together with the packet manager.
    '''

    def __init__(self, config, interval_args=(0.5, 1)):
        ''' Constructor

        :param config: the config instance
        :param interval_args: a pair of number in tuple or list format
                              that will be used in random.uniform to
                              generate a random interval time
        '''

        self.__running = False
        self.config = config
        self.interval_args = interval_args

        self.efferent = UDPTransmitter(self.config)

        shm_socket_tmp = 'SHM-SpecialPacketRepeater-PktMgmt-%d.socket'
        self.pkt_mgr = SpecialPacketManager(self.config, shm_socket_tmp)
        self.pkt_mgr.init_shm()

    def shutdown(self):
        self.__running = False

    def gen_interval(self):
        return random.uniform(*self.interval_args)

    def repeat(self, sn, pkt, current_ts):
        interval = self.gen_interval()
        next_rpt_ts = current_ts + interval

        self.efferent.transmit(pkt)
        self.pkt_mgr.set_pkt_last_repeat_time(sn, current_ts)
        self.pkt_mgr.set_pkt_next_repeat_time(sn, next_rpt_ts)
        self.pkt_mgr.increase_pkt_repeated_times(sn)

        type_ = Converter.int_2_hex(pkt.fields.type)
        logger.debug(
            f'Repeated a special packet, sn: {pkt.fields.sn}, '
            f'type: {type_}, dest: {pkt.fields.dest}'
        )

    def run(self):
        pid = os.getpid()
        logger.debug(f'Running SpecialPacketRepeater worker {pid}')

        self.__running = True

        while self.__running:
            sn_list = self.pkt_mgr.get_repeating_sn_list()
            interval_to_next_poll = 1

            for sn in sn_list:
                pkt = self.pkt_mgr.get_pkt(sn)

                if pkt is None:
                    # packet has been removed in the interval of these 2 times
                    # of shared memory request, we just need to skip it
                    #
                    # Maybe we need to invoke remove_pkt here again to ensure
                    # that this serial number has been removed?
                    continue

                last_rpt_ts = self.pkt_mgr.get_pkt_last_repeat_time(sn)
                next_rpt_ts = self.pkt_mgr.get_pkt_next_repeat_time(sn)
                max_rpt_times = self.pkt_mgr.get_pkt_max_repeat_times(sn)
                rpted_times = self.pkt_mgr.get_pkt_repeated_times(sn)
                current_ts = time.time()

                if rpted_times >= max_rpt_times:
                    self.pkt_mgr.cancel_repeat(sn)
                elif last_rpt_ts is None or next_rpt_ts is None:
                    self.repeat(sn, pkt, current_ts)
                elif current_ts < next_rpt_ts:
                    # here, we calculate a minimum interval time that we need
                    # to sleep to the next poll
                    interval = next_rpt_ts - current_ts
                    if interval < interval_to_next_poll:
                        interval_to_next_poll = interval
                else:
                    self.repeat(sn, pkt, current_ts)

            time.sleep(interval_to_next_poll)

        self.pkt_mgr.close_shm()
        logger.info(f'SpecialPacketRepeater worker {pid} exits')
