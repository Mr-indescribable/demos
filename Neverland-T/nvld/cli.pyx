import os
import sys
import logging
import argparse

from .logging import init_all_loggers
from .exceptions import ArgumentError, PidFileNotExists
from .utils.misc import Shell

from .components.nid import NIDMgr


logger = logging.getLogger('Main')


def parse_cli_args():
    argp = argparse.ArgumentParser(
               prog='Neverland',
               description='Construct your very own Neverland',
           )
    argp.add_argument(
        'action',
        metavar='<action>',
        help='The operation you want to do. Options: start/stop/status/gennid',
    )
    argp.add_argument(
        '-n',
        metavar='<path>',
        default='./nvld.nid',
        help='Specify the NID file. default: ./nvld.nid',
    )
    argp.add_argument(
        '-j',
        metavar='<path>',
        default='./nvld.json',
        help='Specify the JSON file. default: ./nvld.json',
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


def gen_nid(json_f, nid_f):
    nid_mgr = NIDMgr()
    nid_mgr.gen_nid_file(json_f, nid_f)


def main():
    args = parse_cli_args()

    print(args)

    if args.action == 'gennid':
        gen_nid(args.j, args.n)
    elif args.action == 'start':
        pass
    elif args.action == 'stop':
        pass
    elif args.action == 'status':
        pass
