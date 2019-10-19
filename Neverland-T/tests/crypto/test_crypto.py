import os

from nvld.glb import GLBInfo, GLBComponent
from nvld.components.conf import JsonConfig
from nvld.components.div import DefaultIVMgr
from nvld.utils.od import ODict
from nvld.crypto import Cryptor
from nvld.crypto.openssl import OpenSSLCryptor
from nvld.crypto.kc.aead.gcm import GCMKernelCryptor


div_mgr = DefaultIVMgr()
div_mgr.load( os.urandom(32 * 12) )
GLBComponent.div_mgr = div_mgr


crypto_config_dict = {
    'net': {
        'identification': 'testing-node',
        'crypto': {
            'password': 'The_P@5sw0RD',
            'cipher': None,  # should be overridden later
            'salt_len': 8,
            'iv_len': 12,
            'iv_duration_range': [1000, 2000],
            'lib_path': None # should be overridden too if needed
        }
    }
}


def _update_config(**kwargs):
    config = JsonConfig(**crypto_config_dict)
    config.net.crypto.__update__(**kwargs)

    GLBInfo.config = config


def test_openssl():
    for cipher_name in OpenSSLCryptor.supported_ciphers:
        _update_config(cipher=cipher_name)
        _test_cipher()


def test_kc_gcm():
    for cipher_name in GCMKernelCryptor.supported_ciphers:
        _update_config(cipher=cipher_name)
        _test_cipher()


def _test_cipher():
    cryptor = Cryptor()

    for _ in range(1024):
        src_data = os.urandom(65536)
        encrypted_data = cryptor.encrypt(src_data)
        decrypted_data = cryptor.decrypt(encrypted_data)

        assert src_data != encrypted_data
        assert src_data not in encrypted_data
        assert src_data == decrypted_data
