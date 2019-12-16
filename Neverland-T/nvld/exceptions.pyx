class ArgumentError(Exception):
    pass


class ConfigError(Exception):
    pass


class NIDError(ConfigError):
    pass


class PidFileNotExists(FileNotFoundError):
    pass


class NotEnoughData(Exception):
    pass


class PktWrappingError(Exception):
    pass


class PktUnwrappingError(Exception):
    pass


class InvalidPkt(Exception):
    pass


class DecryptionFailed(InvalidPkt):
    pass


class InvalidIV(InvalidPkt):
    pass


class AddressAlreadyInUse(Exception):
    pass


# Current packet shall be dropped
class DropPacket(Exception):
    pass


class SHMError(Exception):
    pass


# special informations
#
# This kind of exceptions are not true exceptions, they are used to break
# the logic chain and send back a special information to the upper-layer
class Info(Exception):
    pass


# try again later 
class TryAgain(Info):
    pass


class TCPError(Exception):
    pass


class ConnectionLost(TCPError):
    pass


class NLSChannelClosed(TCPError):
    pass


class NLSRemoteError(NLSChannelClosed):
    pass


class NLSHandShakeError(NLSRemoteError):
    pass
