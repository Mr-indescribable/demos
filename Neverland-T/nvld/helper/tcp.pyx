from ..exceptions import EAgain


class NonblockingTCPIOHelper():

    def __init__(self, poller):
        self._poller = poller
        self._ev_ro = self._poller.EV_IN | self._poller.EV_RDHUP
        self._ev_rw = self._ev_ro | self._poller.EV_OUT

    # receives data from an afferent
    def handle_recv(self, aff):
        # The helper doesn't handle ConnectionLost
        aff.recv()

        if aff.recv_buf_len > 0:
            return aff.pop_data(aff.recv_buf_len)
        else:
            raise EAgain()

    # sends data from the efferent's buffer
    # the data argument is not essential since it's not the actual data to send
    # but the data to append into the efferent's buffer.
    def handle_send(self, eff, data=b''):
        bt_sent = eff.send(data)

        if eff.send_buf_len == 0:
            self._poller.modify(eff.fd, self._ev_ro)
        else:
            self._poller.modify(eff.fd, self._ev_rw)

        return bt_sent
