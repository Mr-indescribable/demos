from ..glb import GLBComponent


class TCPPacketHelper():

    @classmethod
    def pkt_2_bytes(cls, pkt):
        wrapped_pkt = GLBComponent.tcp_pkt_wrapper.wrap(pkt)
        return wrapped_pkt.data
