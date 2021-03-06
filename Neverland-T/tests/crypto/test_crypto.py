import os

from nvld.glb import GLBInfo, GLBComponent
from nvld.components.conf import JsonConfig
from nvld.components.div import DefaultIVMgr
from nvld.utils.od import ODict
from nvld.crypto import StreamCryptor, DGramCryptor, ALL_CIPHERS


div_mgr = DefaultIVMgr(iv_len=32)
div_mgr.load_as_stmc_iv( os.urandom(32 * 12) )
div_mgr.load_as_dgmc_iv( os.urandom(32 * 12) )
GLBComponent.div_mgr = div_mgr


crypto_config_dict = {
    'net': {
        'crypto': {
            'password': 'The_P@5sw0RD',
            'stream_cipher': None,  # should be overridden later
            'dgram_cipher': None,
            'salt_len': 8,
            'iv_len': 12,
            'iv_duration_range': [1000, 2000],
        }
    }
}


def _update_config(**kwargs):
    config = JsonConfig(**crypto_config_dict)
    config.net.crypto.__update__(**kwargs)

    GLBInfo.config = config


# We must lock up the global config in all these tests,
# otherwise we'll face race conditions.
def test_all(gl_config):
    try:
        gl_config.acquire()

        for cipher_name in ALL_CIPHERS:
            _update_config(
                stream_cipher=cipher_name,
                dgram_cipher=cipher_name,
            )
            _test_cipher()
    finally:
        gl_config.release()


def _test_cipher():
    if GLBInfo.config.net.crypto.stream_cipher.startswith('kc-'):
        cryptors = (DGramCryptor(), )
    else:
        cryptors = (StreamCryptor(), DGramCryptor())

    for cryptor in cryptors:
        for _ in range(256):
            src_data = os.urandom(65536)
            encrypted_data = cryptor.encrypt(src_data)
            decrypted_data = cryptor.decrypt(encrypted_data)

            assert src_data != encrypted_data
            assert src_data not in encrypted_data
            assert src_data == decrypted_data
