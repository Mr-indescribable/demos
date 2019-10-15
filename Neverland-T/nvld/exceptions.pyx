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
