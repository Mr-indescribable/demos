# Initializers for the glb module


import logging

from .glb import GLBPktFmt, GLBInfo
from .components.nid import NIDMgr
from .utils.misc import get_localhost_ip
from .proto.fmt import ComplexedFormat
from .proto.fmt.tcp import (
    TCPHeaderFormat,
    TCPDelimiterPktFormat,
    TCPDataPktFormat,
    TCPConnCtrlPktFormat,
    TCPClstCtrlPktFormat,
)


logger = logging.getLogger('Main')


def ginit_glb_pktfmt():
    if GLBPktFmt._INITED:
        logger.error('multiple times of initialization invoked on GLBInfo')
        return

    GLBPktFmt._INITED = True

    if not GLBInfo._INITED:
        raise RuntimeError('GLBInfo must be initialized first')

    TCPHeaderFormat.gen_fmt()
    TCPDelimiterPktFormat.gen_fmt()
    TCPDataPktFormat.gen_fmt()
    TCPConnCtrlPktFormat.gen_fmt()
    TCPClstCtrlPktFormat.gen_fmt()

    GLBPktFmt.tcp_data      = ComplexedFormat()
    GLBPktFmt.tcp_conn_ctrl = ComplexedFormat()
    GLBPktFmt.tcp_clst_ctrl = ComplexedFormat()

    GLBPktFmt.tcp_data.combine_fmt(TCPHeaderFormat)
    GLBPktFmt.tcp_data.combine_fmt(TCPDataPktFormat)
    GLBPktFmt.tcp_data.combine_fmt(TCPDelimiterPktFormat)

    GLBPktFmt.tcp_conn_ctrl.combine_fmt(TCPHeaderFormat)
    GLBPktFmt.tcp_conn_ctrl.combine_fmt(TCPConnCtrlPktFormat)
    GLBPktFmt.tcp_conn_ctrl.combine_fmt(TCPDelimiterPktFormat)

    GLBPktFmt.tcp_clst_ctrl.combine_fmt(TCPHeaderFormat)
    GLBPktFmt.tcp_clst_ctrl.combine_fmt(TCPClstCtrlPktFormat)
    GLBPktFmt.tcp_clst_ctrl.combine_fmt(TCPDelimiterPktFormat)

    TCPHeaderFormat.sort_calculators()
    TCPDelimiterPktFormat.sort_calculators()
    TCPDataPktFormat.sort_calculators()
    TCPConnCtrlPktFormat.sort_calculators()
    TCPClstCtrlPktFormat.sort_calculators()

    GLBPktFmt.tcp_data.sort_calculators()
    GLBPktFmt.tcp_conn_ctrl.sort_calculators()
    GLBPktFmt.tcp_clst_ctrl.sort_calculators()


def ginit_glb_info(args):
    if GLBInfo._INITED:
        logger.error('multiple times of initialization invoked on GLBInfo')
        return

    GLBInfo._INITED = True

    # init config and div_set
    nid_mgr = NIDMgr()
    nid_mgr.load(args.n)

    GLBInfo.local_ip     = get_localhost_ip()
    GLBInfo.svr_tcp_port = GLBInfo.config.net.tcp.aff_listen_port
    GLBInfo.svr_udp_port = GLBInfo.config.net.udp.aff_listen_port
    GLBInfo.svr_tcp_sa   = (GLBInfo.local_ip, GLBInfo.svr_tcp_port)
    GLBInfo.svr_udp_sa   = (GLBInfo.local_ip, GLBInfo.svr_udp_port)