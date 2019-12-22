# The global module
#
# This module stores global objects in order to avoid some
# redundant calculations and provide global singleton objects.


class GLBNodeState:

    _INITED = True

    running = False
    state = None


class GLBPktFmt:

    _INITED = False

    tcp_data      = None
    tcp_iv_ctrl   = None
    tcp_conn_ctrl = None
    tcp_clst_ctrl = None

    udp_data = None


class GLBComponent:

    _INITED = False

    div_mgr = None

    id_generator = None

    default_stmc_list = None
    default_dgmc_list = None

    tcp_pkt_wrapper = None
    udp_pkt_wrapper = None

    main_tcp_aff = None
    main_udp_aff = None

    logic_handler = None


class GLBInfo:

    _INITED = False

    config = None

    max_iv_len = None  # the maximum length of IV among all ciphers

    stmc_div_list = None  # iv set for StreamCryptor
    dgmc_div_list = None  # iv set for DGramCryptor

    local_ip = None

    svr_tcp_port = None
    svr_udp_port = None

    svr_tcp_sa = None
    svr_udp_sa = None
