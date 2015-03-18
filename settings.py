
BEE2EVP_ENGINE_LIBRARY_PATH = 'libbee2evp.so'

OPENSSL_EXE_PATH = 'openssl.exe'

try:
    from local_settings import *
except ImportError:
    pass
