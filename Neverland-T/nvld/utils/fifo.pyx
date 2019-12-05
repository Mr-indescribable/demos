import collections


# A wrapper of the deque, removes some functionalities that we don't need,
# and provides an additional feature.
#
# While a new object is appended into the FIFO queue, the object which will
# be pushed out of the queue will be returned.
#
# And the NLFifo should always be fixed-length.
class NLFifo():

    def __init__(self, maxlen):
        self._maxlen = maxlen
        self._maxlen_reached = False
        self._dq = collections.deque(maxlen=maxlen)

    def append(self, obj):
        if self._maxlen_reached:
            r = self._dq[0]
            self._dq.append(obj)
            return r
        else:
            self._dq.append(obj)
            if len(self._dq) == self._maxlen:
                self._maxlen_reached = True
            return None

    @property
    def maxlen_reached(self):
        return self._maxlen_reached
