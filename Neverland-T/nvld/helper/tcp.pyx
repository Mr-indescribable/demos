from ..exceptions import TryAgain


class NonblockingTCPIOHelper():

    def __init__(self, poller):
        self._poller = poller
        self._ev_ro = self._poller.EV_IN | self._poller.EV_RDHUP
        self._ev_rw = self._ev_ro | self._poller.EV_OUT

    # receives data from an afferent and keep it in afferent's buffer
    #
    # If the next_blk_size has been set in the afferent, then this method
    # will try to retrieval the block which conforms the next_blk_size
    def handle_recv(self, aff):
        # The helper doesn't handle ConnectionLost
        aff.recv()

        return self.pop_packet(aff)

    def pop_packet(self, aff):
        if (
            aff.next_blk_size is not None and
            aff.recv_buf_len > aff.next_blk_size
        ):
            return aff.pop_data(aff.next_blk_size)
        else:
            raise TryAgain()

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

    def append_data(self, eff, data):
        eff.append_data(data)
        self._poller.modify(eff.fd, self._ev_rw)
