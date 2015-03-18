import subprocess
import os
import locale
from termcolor import colored
import settings
from colorama import init

init()

os.environ['OPENSSL_CONF'] = './openssl.cnf'

encoding = locale.getdefaultlocale()[1]

OPENSSL_OUTPUT_COLOR = 'magenta'

# Create openssl.cnf file
import jinja
template = jinja.from_string(open('openssl.cnf.template').read())
cnf = template.render(BEE2EVP_ENGINE_LIBRARY_PATH=settings.BEE2EVP_ENGINE_LIBRARY_PATH)
cnf_file = open('openssl.cnf', 'w')
cnf_file.write(cnf)
cnf_file.close()
#########################


def openssl_call(cmd):

    print(colored('openssl ' + cmd, 'green'))
    p = subprocess.Popen(settings.OPENSSL_EXE_PATH + ' ' + cmd,
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
