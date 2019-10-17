# The global module
#
# This module stores global objects in order to avoid some
# redundant calculations and provide global singleton objects.


class GLBNodeState:

    running = False
    state = None


class GLBPktFmt:

    udp_data = None

    tcp_data      = None
    tcp_conn_ctrl = None
    tcp_clst_ctrl = None


class GLBComponent:

    id_generator = None

    default_cryptor = None

    main_tcp_aff = None
    main_udp_aff = None

    tcp_pkt_wrapper = None
    udp_pkt_wrapper = None

    logic_handler = None


class GLBInfo:

    local_ip = None

    svr_tcp_port = None
    svr_udp_port = None

    svr_tcp_sa = None
    svr_udp_sa = None