import os
import sys
import logging
import argparse

from .logging import init_all_loggers
from .exceptions import ArgumentError, PidFileNotExists
from .utils import Shell
from .config import ConfigLoader


logger = logging.getLogger('Main')


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
    print("Done")

    # node_name = config.basic.role
    # node_role = getattr(Roles, node_name)
    # node_cls = ROLE_NODE_CLS_MAPPING.get(node_role)
    # node = node_cls(config)

    # if args.action == 'start':
        # node.main()
    # elif args.action == 'stop':
        # try:
            # node.shutdown()
        # except PidFileNotExists:
            # logger.info(
                # 'pid file doesn\'t exists, seems Neverland is not running'
            # )
            # sys.exit(1)
    # elif args.action == 'status':
        # raise NotImplementedError('Not Implemented yet')
    # elif args.action == 'clean':
        # node.clean_files()
