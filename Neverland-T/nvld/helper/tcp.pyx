

class NonblockingTCPIOHelper():

    def __init__(self, poller):
        self._poller = poller
        self._ev_ro = self._poller.EV_IN | self._poller.EV_RDHUP
        self._ev_rw = self._ev_ro | self._poller.EV_OUT

    def handle_recv(self):
        pass

    def handle_send(self, data):
        pass
