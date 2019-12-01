# The swirl module of Neverland
#
# The NLSwirl module provides a special method to handle TCP traffic
# between nodes. It maintains multiple TCP connection and abstract them
# into one single channel, and generates random data to fill the empty
# channel up to full. Once we have actual data to transfer, the swirl
# reduce the same amount of random data and insert the actual data
# into the random data flow with high priority.


class NLSwirl():

    def __init__(self):
        pass
