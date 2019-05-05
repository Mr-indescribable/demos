#!/usr/bin/python3.6
#coding: utf-8

import os
import sys
import logging
import argparse

from neverland.logging import init_all_loggers
from neverland.exceptions import ArgumentError, PidFileNotExists
from neverland.utils import Shell
from neverland.config import ConfigLoader
from neverland.node import Roles
from neverland.node.relay import RelayNode
from neverland.node.client import ClientNode
from neverland.node.outlet import OutletNode
from neverland.node.controller import ControllerNode


logger = logging.getLogger('Main')


STANDARD_ROLE_NAME_MAPPING = {
    'client': Roles.CLIENT,
    'relay': Roles.RELAY,
    'outlet': Roles.OUTLET,
    'controller': Roles.CONTROLLER,
}

CODE_STYLE_ROLE_NAME_MAPPING = {
    '0x01': Roles.CLIENT,
    '0x02': Roles.RELAY,
    '0x03': Roles.OUTLET,
    '0x04': Roles.CONTROLLER,
}

ROLE_NODE_CLS_MAPPING = {
    Roles.CLIENT: ClientNode,
    Roles.RELAY: RelayNode,
    Roles.OUTLET: OutletNode,
    Roles.CONTROLLER: ControllerNode,
}


def parse_cli_args():
    argp = argparse.ArgumentParser(
               prog='Neverland',
               description='Construct your very own Neverland',
           )
    argp.add_argument(
        'action',
        metavar='<action>',
        help='The operation you want to do. Options: start/stop/status/clean',
    )
    argp.add_argument(
        '-c',
        metavar='<path>',
        default='./nl.json',
        help='Specify the config file. default: ./nl.json',
    )
    argp.add_argument(
        '-r',
        metavar='<role>',
        help='Specify role for the node',
    )
    args = argp.parse_args()
    return args


def mkdirs(config):
    def from_fn(filename):
        try:
            return os.path.split(filename)[0]
        except Exception:
            raise Exception(f'Invalid directory name or file name: {filename}')

    dirs = {
        config.shm.socket_dir,
        from_fn(config.basic.pid_file),
        from_fn(config.log.main.path),
        from_fn(config.log.shm.path),
        from_fn(config.log.conn.path),
    }

    for d in dirs:
        if os.path.exists(d) and not os.path.isdir(d):
            raise Exception(
                f'File name seized, cannot create directory: {d}'
            )
        elif not os.path.exists(d):
            Shell.mkdir(d)


def launch():
    args = parse_cli_args()

    config_path = args.c
    config = ConfigLoader.load_json_file(config_path)

    mkdirs(config)

    init_all_loggers(config)

    node_role_name = args.r
    if node_role_name is None:
        raise ArgumentError('Role is not specified')

    node_role = (
        STANDARD_ROLE_NAME_MAPPING.get(node_role_name) or
        CODE_STYLE_ROLE_NAME_MAPPING.get(node_role_name)
    )
    if node_role is None:
        raise ArgumentError(f'Invalid role: {node_role_name}')

    node_cls = ROLE_NODE_CLS_MAPPING.get(node_role)

    node = node_cls(config)

    if args.action == 'start':
        node.main()
    elif args.action == 'stop':
        try:
            node.shutdown()
        except PidFileNotExists:
            logger.info(
                'pid file doesn\'t exists, seems Neverland is not running'
            )
            sys.exit(1)
    elif args.action == 'status':
        raise NotImplementedError('Not Implemented yet')
    elif args.action == 'clean':
        node.clean_files()


if __name__ == '__main__':
    launch()
