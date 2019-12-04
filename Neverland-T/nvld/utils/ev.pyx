from threading import Lock


# literally, this class is used to pass an disposable event
# from A to B for only once.
class DisposableEvent():

    def __init__(self):
        self.__lk = Lock()
        self.__lk.acquire()
        self.__used = False

    def trigger(self):
        if not self.__used:
            self.__lk.release()
            self.__used = True
        else:
            raise RuntimeError('reusing DisposableEvent instances is forbidden')

    def wait(self):
        self.__lk.acquire()
