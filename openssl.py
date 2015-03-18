import subprocess
import os
import locale
from termcolor import colored
from colorama import init
init()

OPENSSL_DIR = '/home/mihas/openssl/openssl-OpenSSL_1_0_2'

OPENSSL_EXE = OPENSSL_DIR + '/apps/openssl'
#OPENSSL_EXE = 'C:\dev\openssl-1.0.2-i386-win32\openssl.exe'

os.environ['LD_LIBRARY_PATH'] = OPENSSL_DIR

os.environ['OPENSSL_CONF'] = './openssl.cnf'
try:
    from local_settings import *
except ImportError:
    pass

encoding = locale.getdefaultlocale()[1]


OPENSSL_OUTPUT_COLOR = 'magenta'


def openssl_call(cmd):

    print(colored('openssl ' + cmd, 'green'))
    p = subprocess.Popen(OPENSSL_EXE + ' ' + cmd,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE,
                         stdin=subprocess.PIPE,
                         shell=True)
    out, err_out = p.communicate()

    retcode = p.poll()
    if retcode:
        err_out = err_out.decode(encoding)
        print(colored(err_out, 'red', 'on_grey'))
        raise RuntimeError('Openssl call fails with status %s' % retcode)
    out = out.decode(encoding)
    print(colored(out, OPENSSL_OUTPUT_COLOR))
    return out
