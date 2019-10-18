from nvld.components.nid import NIDMgr


def test_cross():
    nid_mgr = NIDMgr()

    byte0  = b'\xe3'     # 1 1 1 0 0 0 1 1
    byte1  = b'\x6a'     #  0 1 1 0 1 0 1 0
    result = b'\xbc\x4e' # 1011110001001110

    r = nid_mgr.bit_cross(byte0, byte1)

    assert r == result


def test_uncross():
    nid_mgr = NIDMgr()

    in_byte = b'\xbc\x4e' # 1011110001001110
    byte0   = b'\xe3'     # 1 1 1 0 0 0 1 1
    byte1   = b'\x6a'     #  0 1 1 0 1 0 1 0

    o_b0, o_b1 = nid_mgr.bit_uncross(in_byte)

    assert o_b0 == byte0
    assert o_b1 == byte1
