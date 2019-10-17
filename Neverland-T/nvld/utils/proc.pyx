import os
import sys
import time
import signal as sig
import logging


logger = logging.getLogger('Main')


class ProcTools():

    @classmethod
    def daemonize(cls):
        pid = os.fork()

        if pid == -1: 
            raise OSError('fork() failed')

        if pid > 0:
            # double fork magic
            sys.exit(0)

        os.setsid()

        pid = os.fork()
        if pid == -1: 
            raise OSError('fork() failed')

        if pid > 0:
            sys.exit(0)

    @classmethod
    def waitpid(self, pid, options=0):
        try:
            os.waitpid(pid, options)
        except ChildProcessError:
            pass

    @classmethod
    def kill(cls, pid, signal=sig.SIGTERM):
        try:
            logger.debug(f'Sending SIGTERM to {pid}')
            os.kill(pid, signal)
        except ProcessLookupError:
            pass

    @classmethod
    def process_exists(self, pid):
        try:
            os.kill(pid, 0)
        except OSError:
            return False
        else:
            return True
