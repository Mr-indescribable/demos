#!/usr/bin/python3.6
#coding: utf-8

import os
import time
import signal as sig
import shutil
import unittest

import __code_path__
from neverland.utils import ObjectifiedDict
from neverland.components.shm import (
    SharedMemoryManager,
    SHMContainerTypes,
    ReturnCodes,
)


json_config = {
    'shm': {
        'socket_dir': '/tmp/nl_shm_sock/',
        'manager_socket_name': 'manager',
    }
}
config = ObjectifiedDict(**json_config)


# clean the socket directory
if os.path.isdir(config.shm.socket_dir):
    shutil.rmtree(config.shm.socket_dir)
os.mkdir(config.shm.socket_dir)


KEY = 'k0'
DATA = [
    {
        'name': 'testing-list',
        'type': SHMContainerTypes.LIST,
        '2_create': [1, 2, 3],
        '2_add': [4],
        '2_remove': [1, 2, 4],
        'remaining': 3,
        'remaining_key': 0,
    },
    {
        'name': 'testing-set',
        'type': SHMContainerTypes.SET,
        '2_create': [1, 2, 3],
        '2_add': {4,},
        '2_remove': [1, 2, 4],
        'remaining': 3,
        'remaining_key': 0,
    },
    {
        'name': 'testing-dict',
        'type': SHMContainerTypes.DICT,
        # '2_create': None,
        '2_create': {'a': 1, 'b': 2, 'c': 3},
        '2_add': {'d': 4},
        '2_remove': ['a', 'b', 'd'],
        'remaining': 3,
        'remaining_key': 'c',
    },
]


worker_pid = None
shm_mgr = None

do_not_kill_shm_worker = False


def launch_shm_worker():
    global worker_pid, shm_mgr

    pid = os.fork()

    if pid == -1:
        raise OSError('fork failed, unable to run SharedMemoryManager')

    # run SHM worker in the child process
    elif pid == 0:
        shm_mgr = SharedMemoryManager(config)
        shm_mgr.run_as_worker()

    # send testing request in the parent process
    else:
        # wait for shm worker
        time.sleep(1)
        worker_pid = pid

    return pid


# Test case for SharedMemoryManager
class SHMTest(unittest.TestCase):

    def test_0_normal_ops(self):
        shm_mgr = SharedMemoryManager(config, sensitive=False)
        shm_mgr.connect('test')
        print('conn_id: ', shm_mgr.current_connection.conn_id)
        self.assertIsInstance(shm_mgr.current_connection.conn_id, str)

        for td in DATA:
            print(f'\n==================={td["name"]}===================\n')

            # try to remove this KEY first
            resp = shm_mgr.clean_key(KEY)
            if not resp.get('succeeded'):
                self.assertEqual(resp.get('rcode'), ReturnCodes.KEY_ERROR)

            resp = shm_mgr.create_key(KEY, td['type'], td['2_create'])
            print('\n-----------Create-----------')
            print(resp)
            self.assertTrue(resp.get('succeeded'))

            resp = shm_mgr.read_key(KEY)
            print('\n-----------Read-----------')
            print(resp)
            self.assertTrue(resp.get('succeeded'))

            resp = shm_mgr.add_value(KEY, td['2_add'])
            print('\n-----------Add-----------')
            print(resp)
            self.assertTrue(resp.get('succeeded'))

            resp = shm_mgr.read_key(KEY)
            print('\n-----------Read-----------')
            print(resp)
            self.assertTrue(resp.get('succeeded'))

            resp = shm_mgr.remove_value(KEY, td['2_remove'])
            print('\n-----------Remove-----------')
            print(resp)
            self.assertTrue(resp.get('succeeded'))

            resp = shm_mgr.read_key(KEY)
            print('\n-----------Read-----------')
            print(resp)
            self.assertTrue(resp.get('succeeded'))
            self.assertEqual(
                resp.get('value')[td['remaining_key']],
                td['remaining'],
            )

        shm_mgr.disconnect()
        self.assertEqual(shm_mgr.current_connection, None)

    def test_1_set(self):
        KEY_FOR_SET = 'set_test'
        VALUE_FOR_SET = 'aaaaaaaaaaaaa'

        print('\n\n=====================set-value====================')
        shm_mgr = SharedMemoryManager(config, sensitive=False)
        shm_mgr.connect('test_set')
        print('conn_id: ', shm_mgr.current_connection.conn_id)
        self.assertIsInstance(shm_mgr.current_connection.conn_id, str)

        resp = shm_mgr.create_key(KEY_FOR_SET, SHMContainerTypes.STR)
        self.assertTrue(resp.get('succeeded'))

        resp = shm_mgr.set_value(KEY_FOR_SET, VALUE_FOR_SET)
        self.assertTrue(resp.get('succeeded'))

        resp = shm_mgr.read_key(KEY_FOR_SET)
        self.assertTrue(resp.get('succeeded'))
        self.assertEqual(resp.get('value'), VALUE_FOR_SET)
        print(resp)

        shm_mgr.disconnect()
        self.assertEqual(shm_mgr.current_connection, None)

    def test_2_rcode(self):
        shm_mgr = SharedMemoryManager(config, sensitive=False)
        shm_mgr.connect('test_err')

        print('\n\n=====================key-error-test====================')
        resp = shm_mgr.add_value(
                   key='not_exists',
                   value='a',
                   backlogging=False,
               )
        print(resp)
        self.assertEqual(resp.get('succeeded'), False)
        self.assertEqual(resp.get('rcode'), ReturnCodes.KEY_ERROR)

        print('\n\n=====================type-error-test====================')
        resp = shm_mgr.create_key(
                   'testing',
                   SHMContainerTypes.DICT,
                   value='a',
                   backlogging=False,
               )
        print(resp)
        self.assertEqual(resp.get('succeeded'), False)
        self.assertEqual(resp.get('rcode'), ReturnCodes.TYPE_ERROR)

        print('\n\n===================unlock-not-locked-test==================')
        resp = shm_mgr.unlock_key('testing')
        print(resp)
        self.assertEqual(resp.get('succeeded'), True)
        self.assertEqual(resp.get('rcode'), ReturnCodes.NOT_LOCKED)

        print('\n\n=====================lock-test====================')
        print('------create-container------')
        resp = shm_mgr.create_key(
                   'testing',
                   SHMContainerTypes.LIST,
                   backlogging=False,
               )
        self.assertEqual(resp.get('succeeded'), True)
        self.assertEqual(resp.get('rcode'), ReturnCodes.OK)

        print('------lock-container------')
        resp = shm_mgr.lock_key('testing')
        print(resp)
        self.assertEqual(resp.get('succeeded'), True)
        self.assertEqual(resp.get('rcode'), ReturnCodes.OK)

        print('------access-locked-container------')
        shm_mgr1 = SharedMemoryManager(config, sensitive=False)
        shm_mgr1.connect('test_err_1')
        resp = shm_mgr1.add_value(
                   'testing',
                   [1, 2, 3],
                   backlogging=False,
               )
        print(resp)
        self.assertEqual(resp.get('succeeded'), False)
        self.assertEqual(resp.get('rcode'), ReturnCodes.LOCKED)

        print('------unlock-container----------')
        resp = shm_mgr.unlock_key('testing')
        print(resp)
        self.assertEqual(resp.get('succeeded'), True)
        self.assertEqual(resp.get('rcode'), ReturnCodes.OK)

        print('------access-locked-container-again------')
        resp = shm_mgr1.add_value(
                   'testing',
                   [1, 2, 3],
                   backlogging=False,
               )
        print(resp)
        self.assertEqual(resp.get('succeeded'), True)
        self.assertEqual(resp.get('rcode'), ReturnCodes.OK)

        shm_mgr.disconnect()
        shm_mgr1.disconnect()

    def test_3_fifo(self):
        pass

    def test_999_backlog(self):
        global do_not_kill_shm_worker

        key = 'bl0'

        shm_mgr = SharedMemoryManager(config, sensitive=False)
        shm_mgr.connect('test_bl')
        shm_mgr.create_key(key, SHMContainerTypes.LIST)
        shm_mgr.lock_key(key)

        pid = os.fork()
        if pid == -1:
            raise OSError('fork failed')

        if pid == 0:
            # This socket will cause a warning, so we close it here
            shm_mgr.current_connection.socket.close()

            do_not_kill_shm_worker = True
            shm_mgr1 = SharedMemoryManager(config, sensitive=False)
            shm_mgr1.connect('test_bl1')

            print('\n\n==============access-locked-container===============')
            t0 = time.time()
            resp = shm_mgr1.read_key(key)
            t1 = time.time()

            print(resp)

            delay = t1 - t0
            print(f'delay: {delay}')

            self.assertEqual(resp.get('succeeded'), True)
            self.assertTrue(delay >= 1)

            shm_mgr1.disconnect()
        else:
            time.sleep(1)
            print('------------release-lock-------------')
            shm_mgr.unlock_key(key)
            shm_mgr.disconnect()
            os.waitpid(-1, 0)


if __name__ == '__main__':
    pid = launch_shm_worker()

    # pid from fork
    if pid > 0:
        try:
            unittest.main()
        finally:
            if not do_not_kill_shm_worker:
                os.kill(worker_pid, sig.SIGTERM)
