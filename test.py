import subprocess
from unittest import TestCase
import itertools
import os
import locale
from pyasn1_modules.pem import readPemFromFile
from termcolor import colored

encoding = locale.getdefaultlocale()[1]

OPENSSL_EXE = './op'
OPENSSL_OUTPUT_COLOR = 'magenta'


class BaseTest(TestCase):

    def openssl_call(self, cmd):
        if isinstance(cmd, str):
            cmd_list = cmd.split(' ')
        elif isinstance(cmd, list):
            cmd_list = list(itertools.chain(
                    *(arg.split(' ') if isinstance(arg, str) else [str(arg)] for arg in cmd)
                ))
        else:
            raise AttributeError()
        out = subprocess.check_output([OPENSSL_EXE] + cmd_list).decode(encoding)
        print colored(out, OPENSSL_OUTPUT_COLOR)
        return out

    @classmethod
    def setUpClass(cls):
        super(BaseTest, cls).setUpClass()
        os.environ['OPENSSL_CNF'] = './openssl.cnf'


class TestOpenssl(BaseTest):

    def test_engine_on(self):

        p = self.openssl_call('engine')

        self.assertIn('btls_e', p)

    def test_genpkey(self):

        out = self.openssl_call('genpkey -algorithm bign-pubkey')
        begin = '-----BEGIN PRIVATE KEY-----'
        self.assertTrue(out.startswith(begin))
        end = '-----END PRIVATE KEY-----\n'
        self.assertTrue(out.endswith(end))

        middle = out[len(begin)+1:-len(end)-1]

        self.assertEqual(len(middle), 89)


class TestCertificates(BaseTest):

    def test_x509(self):

        self.openssl_call('genpkey -algorithm bign-pubkey -out priv.key')
        cert_pem_file = "cert.pem"
        out = self.openssl_call([
            "req -x509",
            "-subj", u"/CN=www.mydom.com/O=My Dom, Inc./C=US/ST=Oregon/L=Portland",
            ("-new -key priv.key -engine btls_e -out %s" % cert_pem_file)])

        from pyasn1.codec.der.decoder import decode
        from pyasn1_modules import rfc2459, pkcs12, rfc5208
        cert, rest = decode(readPemFromFile(open(cert_pem_file)), asn1Spec=rfc5208.Certificate())
        self.assertFalse(rest)
        print colored(cert.prettyPrint(), 'cyan')

        self.assertIsNotNone(cert.getComponentByName('signatureValue'))
        self.assertIsNotNone(cert.getComponentByName('signatureAlgorithm'))
        self.assertEqual(str(cert.getComponentByName('signatureAlgorithm').getComponentByName('algorithm')),
            '1.2.112.0.2.0.34.101.45.12')
