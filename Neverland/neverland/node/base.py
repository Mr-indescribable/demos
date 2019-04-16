#!/usr/bin/python3.6
#coding: utf-8

import os
import sys
import time
import select
import signal as sig
import logging
import traceback

from neverland.exceptions import (
    PidFileNotExists,
    FailedToJoinCluster,
    FailedToDetachFromCluster,
    SuccessfullyJoinedCluster,
)
from neverland.utils import get_localhost_ip
from neverland.node import Roles
from neverland.node.context import NodeContext
from neverland.core.client import ClientCore
from neverland.core.relay import RelayCore
from neverland.core.outlet import OutletCore
from neverland.core.controller import ControllerCore
from neverland.afferents.udp import UDPReceiver, ClientUDPReceiver
from neverland.efferents.udp import UDPTransmitter
from neverland.logic.v0.client.logic_handler import ClientLogicHandler
from neverland.logic.v0.controller.logic_handler import ControllerLogicHandler
from neverland.logic.v0.outlet.logic_handler import OutletLogicHandler
from neverland.logic.v0.relay.logic_handler import RelayLogicHandler
from neverland.protocol.v0 import ProtocolWrapper
from neverland.protocol.v0.fmt import (
    HeaderFormat,
    DataPktFormat,
    CtrlPktFormat,
    ConnCtrlPktFormat,
)
from neverland.components.idgeneration import IDGenerator
from neverland.components.shm import SharedMemoryManager
from neverland.components.pktmgmt import (
    SpecialPacketManager,
    SpecialPacketRepeater,
)
from neverland.components.connmgmt import ConnectionManager


logger = logging.getLogger('Node')
shm_logger = logging.getLogger('SHM')


AFFERENT_MAPPING = {
    Roles.CLIENT: ClientUDPReceiver,
    Roles.RELAY: UDPReceiver,
    Roles.OUTLET: UDPReceiver,
    Roles.CONTROLLER: UDPReceiver,
}

LOGIC_HANDLER_MAPPING = {
    Roles.CLIENT: ClientLogicHandler,
    Roles.RELAY: RelayLogicHandler,
    Roles.OUTLET: OutletLogicHandler,
    Roles.CONTROLLER: ControllerLogicHandler,
}

CORE_MAPPING = {
    Roles.CLIENT: ClientCore,
    Roles.RELAY: RelayCore,
    Roles.OUTLET: OutletCore,
    Roles.CONTROLLER: ControllerCore,
}


TERM_SIGNALS = [sig.SIGINT, sig.SIGQUIT, sig.SIGTERM]


class BaseNode():

    ''' The Base Class of Nodes
    '''

    role = None

    def __init__(self, config, role=None):
        self.config = config
        self.role = role or self.role

        self.worker_pids = []
        self.shm_worker_pid = None
        self.pkt_rpter_worker_pid = None

        self.node_id = self.config.basic.node_id

    def _write_master_pid(self):
        pid_path = self.config.basic.pid_file
        pid = os.getpid()

        with open(pid_path, 'w') as f:
            f.write(str(pid))

        logger.debug(
            f'wrote pid file {pid_path} for master process, pid: {pid}'
        )

    def _read_master_pid(self):
        pid_path = self.config.basic.pid_file

        try:
            with open(pid_path, 'r') as f:
                content = f.read()
        except FileNotFoundError:
            raise PidFileNotExists

        try:
            return int(content)
        except ValueError:
            raise ValueError('pid file has beed tampered')

    def _handle_term_master(self, signal, sf):
        logger.debug(f'Master process received signal: {signal}')
        logger.debug(f'The master process starts to shut down workers')
        self.shutdown_workers()

        pid_path = self.config.basic.pid_file
        if os.path.isfile(pid_path):
            logger.debug(f'Remove pid file: {pid_path}')
            os.remove(pid_path)

    def _handle_term_worker(self, signal, sf):
        pid = os.getpid()
        logger.debug(f'Worker {pid} received signal: {signal}')
        logger.debug(f'Shutting down worker {pid}')
        self.core.shutdown()

    def _handle_term_shm(self, signal, sf):
        pid = os.getpid()
        logger.debug(f'SharedMemoryManager {pid} received signal: {signal}')
        logger.debug(f'Shutting down SharedMemoryManager {pid}')
        self.shm_mgr.shutdown_worker()

    def _handle_term_pkt_rpter(self, signal, sf):
        pid = os.getpid()
        logger.debug(f'SpecialPacketRepeater {pid} received signal: {signal}')
        logger.debug(f'Shutting down SpecialPacketRepeater {pid}')
        self.pkt_rpter.shutdown()

    def _sig_master(self):
        sig.signal(sig.SIGHUP, sig.SIG_IGN)
        for s in TERM_SIGNALS:
            sig.signal(s, self._handle_term_master)

    def _sig_normal_worker(self):
        sig.signal(sig.SIGHUP, sig.SIG_IGN)
        for s in TERM_SIGNALS:
            sig.signal(s, self._handle_term_worker)

    def _sig_shm_worker(self):
        sig.signal(sig.SIGHUP, sig.SIG_IGN)
        for s in TERM_SIGNALS:
            sig.signal(s, self._handle_term_shm)

    def _sig_pkt_rpter_worker(self):
        sig.signal(sig.SIGHUP, sig.SIG_IGN)
        for s in TERM_SIGNALS:
            sig.signal(s, self._handle_term_pkt_rpter)

    def shutdown_workers(self):
        for pid in self.worker_pids:
            self._kill(pid)

        # wait for workers to exit
        remaining = list(self.worker_pids)
        while True:
            for pid in list(remaining):
                if self._process_exists(pid):
                    os.waitpid(pid, os.WNOHANG)
                else:
                    logger.debug(f'Worker {pid} terminated')
                    remaining.remove(pid)

            if len(remaining) == 0:
                break

            time.sleep(0.5)

        # shutdown SharedMemoryManager worker at last
        shm_pid = self.shm_worker_pid
        self._kill(shm_pid)
        os.waitpid(shm_pid, 0)
        logger.debug(f'SharedMemoryManager worker {shm_pid} terminated')

        logger.debug('All workers terminated')

    def _kill(self, pid):
        try:
            logger.debug(f'Sending SIGTERM to {pid}')
            os.kill(pid, sig.SIGTERM)
        except ProcessLookupError:
            pass

    def _process_exists(self, pid):
        try:
            os.kill(pid, 0)
        except OSError:
            logger.debug(f'Process {pid} not exists')
            return False
        else:
            logger.debug(f'Process {pid} exists')
            return True

    def daemonize(self):
        pid = os.fork()
        if pid == -1: 
            raise OSError('fork failed when doing daemonize')
        elif pid > 0:
            # double fork magic
            sys.exit(0)

        pid = os.fork()
        if pid == -1: 
            raise OSError('fork failed when doing daemonize')

        def quit(sg, sf):
            sys.exit(0)

        if pid > 0:
            for s in TERM_SIGNALS:
                sig.signal(s, quit)
            time.sleep(5)
        else:
            self._sig_master()
            ppid = os.getppid()
            os.kill(ppid, sig.SIGTERM)
            os.setsid()

        logger.debug('Node daemonized')

    def _start_shm_mgr(self):
        self.shm_mgr = SharedMemoryManager(self.config)

        # start SharedMemoryManager worker
        pid = os.fork()
        if pid == -1:
            raise OSError('fork failed')
        elif pid == 0:
            self._sig_shm_worker()
            try:
                self.shm_mgr.run_as_worker()
            except Exception:
                err_msg = traceback.format_exc()
                shm_logger.error(
                    f'Unexpected error occurred, SHM worker crashed. '
                    f'Traceback:\n{err_msg}'
                )
                sys.exit(1)

            sys.exit(0)  # the sub-process ends here
        else:
            self.shm_worker_pid = pid
            logger.info(f'Started SharedMemoryManager: {pid}')

    def _start_pkt_rpter(self):
        '''
        The Repeater needs some components from the node,
        so we shouldn't use this method before components are initialized
        '''

        pid = os.fork()
        if pid == -1:
            raise OSError('fork failed')
        elif pid == 0:
            self._sig_pkt_rpter_worker()
            self.pkt_rpter = SpecialPacketRepeater(
                                 self.config,
                                 self.efferent,
                                 self.protocol_wrapper,
                             )

            try:
                self.pkt_rpter.init_shm()
                self.pkt_rpter.run()
            except Exception:
                err_msg = traceback.format_exc()
                logger.error(
                    f'Unexpected error occurred, SpecialPacketRepeater worker '
                    f'crashed. Traceback:\n{err_msg}'
                )
                sys.exit(1)

            sys.exit(0)  # the sub-process ends here
        else:
            self.pkt_rpter = SpecialPacketRepeater(
                                 self.config,
                                 self.efferent,
                                 self.protocol_wrapper,
                             )
            self.pkt_rpter_worker_pid = pid
            logger.info(f'Started SpecialPacketRepeater: {pid}')

    def _load_modules(self):
        self.afferent_cls = AFFERENT_MAPPING[self.role]
        self.main_afferent = self.afferent_cls(self.config)

        self.efferent = UDPTransmitter(self.config)

        self.protocol_wrapper = ProtocolWrapper(
                                    self.config,
                                    HeaderFormat,
                                    DataPktFormat,
                                    CtrlPktFormat,
                                    ConnCtrlPktFormat,
                                )

        self.logic_handler_cls = LOGIC_HANDLER_MAPPING[self.role]
        self.logic_handler = self.logic_handler_cls(self.config)

        self.core_cls = CORE_MAPPING.get(self.role)
        self.core = self.core_cls(
                        self.config,
                        main_afferent=self.main_afferent,
                        minor_afferents=[],
                        efferent=self.efferent,
                        logic_handler=self.logic_handler,
                        protocol_wrapper=self.protocol_wrapper,
                    )

        self.pkt_mgr = SpecialPacketManager(self.config)

        self.conn_mgr = ConnectionManager(self.config)

        # The packet repeater is a part of the packet manager, so we will
        # use it as a normal module. Each worker shall have it's own packet
        # repeater but not share it like the shared memory manager worker
        self._start_pkt_rpter()

        self.logic_handler.init_shm()

        self.core.init_shm()
        self.core.self_allocate_core_id()

        self.pkt_mgr.init_shm()

        self.conn_mgr.init_shm()

        pid = os.getpid()
        logger.debug(f'Worker {pid} loaded modules')

    def _clean_modules(self):
        self._kill(self.pkt_rpter_worker_pid)
        os.waitpid(self.pkt_rpter_worker_pid, 0)
        logger.debug(
            f'SpecialPacketRepeater worker '
            f'{self.pkt_rpter_worker_pid} terminated'
        )

        self.core.shutdown()
        self.main_afferent.destroy()

        self.logic_handler.close_shm()
        self.core.close_shm()
        self.pkt_mgr.close_shm()

        self.main_afferent = None
        self.efferent = None
        self.protocol_wrapper = None
        self.logic_handler = None
        self.core = None
        self.pkt_mgr = None
        self.conn_mgr = None

        pid = os.getpid()
        logger.debug(f'Worker {pid} cleaned modules')

    def get_context():
        return NodeContext

    def _create_context(self):
        NodeContext.pkt_rpter_pid = self.pkt_rpter_worker_pid
        NodeContext.local_ip = get_localhost_ip()
        NodeContext.listen_port = self.config.net.aff_listen_port
        NodeContext.core = self.core
        NodeContext.main_efferent = self.efferent
        NodeContext.protocol_wrapper = self.protocol_wrapper
        NodeContext.pkt_mgr = self.pkt_mgr
        NodeContext.conn_mgr = self.conn_mgr
        NodeContext.id_generator = IDGenerator(self.node_id, self.core.core_id)

        pid = os.getpid()
        logger.debug(f'Worker {pid} created NodeContext')

    def _clean_context(self):
        NodeContext.pkt_rpter_pid = None
        NodeContext.local_ip = None
        NodeContext.listen_port = None
        NodeContext.core = None
        NodeContext.main_efferent = None
        NodeContext.protocol_wrapper = None
        NodeContext.pkt_mgr = None
        NodeContext.conn_mgr = None
        NodeContext.id_generator = None

        pid = os.getpid()
        logger.debug(f'Worker {pid} cleaned NodeContext')

    def join_cluster(self):
        if self.role == Roles.CONTROLLER:
            raise RuntimeError(
                'Controller node is the root node of the cluster'
            )

        self.core.request_to_join_cluster()
        self.core.run_for_a_while(5)
        raise TimeoutError

    def run(self):
        pid_fl = self.config.basic.pid_file
        try:
            pid = self._read_master_pid()
            logger.warn(
                f'\n\tThe Neverland node is already running or the pid file\n'
                f'\t{pid_fl} is not removed, current pid: {pid}.\n'
                f'\tMake sure that the node is not running and try again.\n\n'
                f'\tIf you need to run multiple node on this computer, then\n'
                f'\tyou need to at least configure another pid file for it.'
            )
            return
        except ValueError:
            logger.error(
                f'\n\tThe pid file {pid_fl} exists but seems it\'s not\n'
                f'\twritten by the Neverland node. Please make sure the node\n'
                f'\tis not running and the pid file is not occupied.'
            )
            return
        except PidFileNotExists:
            pass

        self.daemonize()
        NodeContext.pid = os.getpid()

        self._write_master_pid()
        self._start_shm_mgr()

        # Before we start workers, we need to join the cluster first.
        if self.role != Roles.CONTROLLER:
            # Before we join the cluster, we need to load modules at first,
            # once we have joined the cluster, modules in the Master worker
            # shall be removed.
            self._load_modules()
            self._create_context()

            try:
                self.join_cluster()
            except SuccessfullyJoinedCluster:
                logger.info('Successfully joined the cluster.')
            except FailedToJoinCluster:
                logger.error('Cannot join the cluster, request not permitted')
                self._clean_modules()
                self._clean_context()
                self._on_break()
                return
            except TimeoutError:
                logger.error(
                    'No response from entrance node, Failed to join the cluster'
                )
                self._clean_modules()
                self._clean_context()
                self._on_break()
                return

            self._clean_modules()
            self._clean_context()

        # start normal workers
        worker_amount = self.config.basic.worker_amount
        for _ in range(worker_amount):
            pid = os.fork()
            NodeContext.pid = os.getpid()

            if pid == -1:
                raise OSError('fork failed')
            elif pid == 0:
                self._sig_normal_worker()
                self._load_modules()
                self._create_context()

                try:
                    self.core.run()
                except Exception:
                    err_msg = traceback.format_exc()
                    logger.error(
                        f'Unexpected error occurred, node crashed. '
                        f'Traceback:\n{err_msg}'
                    )

                    self._clean_modules()
                    self._clean_context()
                    sys.exit(1)

                self._clean_modules()
                self._clean_context()
                sys.exit(0)  # the sub-process ends here
            else:
                self.worker_pids.append(pid)
                logger.info(f'Started Worker: {pid}')

        while True:
            try:
                os.waitpid(-1, 0)
            except ChildProcessError:
                break

    def shutdown(self):
        pid = self._read_master_pid()
        self._kill(pid)
        logger.info('Sent SIGTERM to the master process')

    def _on_break(self):
        '''
        a hook that needs to be invoked while self.run has been broken
        by some exception
        '''

        shm_pid = self.shm_worker_pid
        self._kill(shm_pid)
        os.waitpid(shm_pid, 0)
        logger.debug(f'SharedMemoryManager worker {shm_pid} terminated')

        pid_fl = self.config.basic.pid_file
        os.remove(pid_fl)
        logger.debug(f'Removed pid file: {pid_fl}')
        logger.info('Master process exits.\n\n')
