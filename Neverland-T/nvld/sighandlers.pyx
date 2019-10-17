import logging
import signal as sig

from .glb import GLBNodeState


logger = logging.getLogger('Main')


def shm_sigterm_handler(signal, sf):
    pass


def node_sigterm_handler(signal, sf):
    logger.info('Received signal: {signal}')

    GLBNodeState.running = False
