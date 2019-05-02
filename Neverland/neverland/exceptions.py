#!/usr/bin/python3.6
#coding: utf-8


class ArgumentError(Exception):
    pass


class ConfigError(Exception):
    pass


class PidFileNotExists(FileNotFoundError):
    pass


class PktWrappingError(Exception):
    pass


class PktUnwrappingError(Exception):
    pass


class InvalidPkt(Exception):
    pass


class DecryptionFailed(InvalidPkt):
    pass


class AddressAlreadyInUse(Exception):
    pass


class DropPacket(Exception):

    ''' Current packet shall be dropped
    '''


class SharedMemoryError(Exception):
    pass


class SHMRequestFailed(SharedMemoryError):
    pass


class SHMContainerLocked(SharedMemoryError):
    pass


class SHMRequestBacklogged(SharedMemoryError):
    pass


class SHMWorkerNotConnected(SharedMemoryError):
    pass


class SHMWorkerConnectFailed(SharedMemoryError):
    pass


class SHMResponseTimeout(SharedMemoryError):
    pass


class Info(Exception):

    ''' special informations
    
    This kind of exceptions are not true exceptions, they are used to break
    the logic chain and send back a special information to the upper-layer
    '''

class SuccessfullyJoinedCluster(Info):
    pass


class FailedToJoinCluster(Info):
    pass


class FailedToDetachFromCluster(Info):
    pass


class ConnError(Exception):

    ''' The base class of connection management error
    '''


class ConnSlotNotAvailable(ConnError):

    ''' Specified slot is not available
    '''


class ConnNotEstablished(ConnError):

    ''' No connection established between a remote node.
    '''


class ConnTimeout(ConnError):

    ''' The connection cannot be established in the specified time
    '''


class NoConnAvailable(ConnError):

    ''' No connection available currently
    '''
