from ..utils.od import ODict


# UDP Packet
#
# Inner Data Structure:
#     {
#         valid: bool or None,
#         proto: int,
#         type: int,
#         data: bytes,
#         fields: ODict,
#         byte_fields: ODict,
#         previous_hop: (ip, port)
#         next_hop: (ip, port),
#     }
#
# By default, the "valid" field is None. It should be set
# during the unpacking if the packet is from other node.
#
# The "data" field is bytes which is going to transmit or just received.
#
# The "fields" field is the data that hasn't been wrapped or has been parsed.
# The "byte_fields" fields is a duplicate of the "fields" field,
# the difference is data in this field is bytes.
class UDPPacket(ODict):

    def __init__(self, **kwargs):
        for kw in ['previous_hop', 'next_hop']:
            if kw not in kwargs:
                kwargs.update(
                    {kw: (None, None)}
                )

        for kw in ['fields', 'byte_fields']:
            if kw not in kwargs:
                kwargs.update(
                    {kw: ODict()}
                )

        if 'valid' not in kwargs:
            kwargs.update(valid=None)

        ODict.__init__(self, **kwargs)
