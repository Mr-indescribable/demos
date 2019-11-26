from threading import Lock

import pytest


# Session level global lock
#
# Actaully, this is a wrapper of threading.Lock, it's not essential,
# we can use theading.Lock directly instead. But this wrapper
# provides potential flexibility for further use.
class GLock:

    def __init__(self):
        self.l = Lock()

    def acquire(self):
        self.l.acquire()

    def release(self):
        self.l.release()


# The global lock for Neverland's global config.
# We will need this to avoid some race conditions of the global config.
_gl_config = GLock()


@pytest.fixture(scope='session')
def gl_config():
    return _gl_config
