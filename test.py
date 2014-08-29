import random
import subprocess
from unittest import TestCase, skip
import itertools
import os
import locale
from pyasn1_modules.pem import readPemFromFile
from termcolor import colored
from pyasn1.codec.der.decoder import decode
from pyasn1_modules import rfc2459, pkcs12, rfc5208

encoding = locale.getdefaultlocale()[1]

OPENSSL_EXE = './op'
OPENSSL_OUTPUT_COLOR = 'magenta'


class BaseTest(TestCase):

    @staticmethod
    def openssl_call(cmd):

        if isinstance(cmd, str):
            cmd_list = cmd.split(' ')
        elif isinstance(cmd, list):
            cmd_list = list(itertools.chain(
                    *(arg.split(' ') if isinstance(arg, str) else [str(arg)] for arg in cmd)
                ))
        else:
            raise AttributeError()

        print colored('openssl ' + ' '.join(cmd_list), 'green')
        out = subprocess.check_output([OPENSSL_EXE] + cmd_list).decode(encoding)
        print colored(out, OPENSSL_OUTPUT_COLOR)
        return out

    @classmethod
    def setUpClass(cls):
        super(BaseTest, cls).setUpClass()
        os.environ['OPENSSL_CONF'] = './openssl.cnf'


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


class TestCa(BaseTest):

    PRIV_KEY_FILE = 'priv.key'
    CAPRIV_KEY_FILE = 'demoCA/private/cakey.pem'
    CERT_FILE = "cert.pem"
    CACERT_FILE = "demoCA/cacert.pem"
    REQ_FILE = 'req.pem'

    @classmethod
    def setUpClass(cls):

        super(TestCa, cls).setUpClass()
        subprocess.call(['rm', "demoCA/index.txt"])
        subprocess.call(['touch', "demoCA/index.txt"])

        cls.openssl_call('genpkey -algorithm bign-pubkey -out %s' % cls.PRIV_KEY_FILE)
        cls.openssl_call('genpkey -algorithm bign-pubkey -out %s' % cls.CAPRIV_KEY_FILE)

        cls.openssl_call([
            "req",
            "-subj", u"/CN=www.mydom.com/O=My Dom, Inc./C=US/ST=Oregon/L=Portland",
            ("-new -key %s -engine btls_e -out %s" % (cls.PRIV_KEY_FILE, cls.REQ_FILE))])

        out = cls.openssl_call([
            "req -x509",
            "-subj", u"/CN={CN}/O=My Dom, Inc./C=US/ST=Oregon/L=Portland".format(CN='www.mydom_%s.com' % random.randint(0, 10000)),
            ("-new -key %s -engine btls_e -out %s" % (cls.CAPRIV_KEY_FILE, cls.CACERT_FILE))])

    def test_ca(self):
        out = self.openssl_call([
            "ca",
            "-in " + self.REQ_FILE,
            "-cert " + self.CACERT_FILE,
            "-batch",
            ("-keyfile %s -engine btls_e -out %s" % (self.CAPRIV_KEY_FILE, self.CERT_FILE))])

        out = self.openssl_call('verify -CAfile {ca_cert} -engine btls_e {cert}'.format(ca_cert=self.CACERT_FILE, cert=self.CERT_FILE))

        self.assertEqual(out, 'cert.pem: OK\n')

    def test_crl(self):

        self.openssl_call('ca -gencrl -out %s' % 'crl.der')
        out = self.openssl_call('crl -in %s -text -noout' % 'crl.der')
        self.assertIn('No Revoked Certificates.', out)
        self.assertNotIn('\nRevoked Certificates:\n    Serial Number: ', out)

    def test_revoke(self):

        self.openssl_call('ca -revoke %s' % self.CERT_FILE)
        self.openssl_call('ca -gencrl -out %s' % 'crl.der')
        out = self.openssl_call('crl -in %s -text -noout' % 'crl.der')
        self.assertIn('\nRevoked Certificates:\n    Serial Number: ', out)
        self.assertNotIn('No Revoked Certificates.', out)


class TestCms(TestCa):

    @classmethod
    def setUpClass(cls):
        super(TestCms, cls).setUpClass()

        out = cls.openssl_call([
            "ca",
            "-in " + cls.REQ_FILE,
            "-cert " + cls.CACERT_FILE,
            "-batch",
            ("-keyfile %s -engine btls_e -out %s" % (cls.CAPRIV_KEY_FILE, cls.CERT_FILE))])

    def test_cms_sign_smime(self):
        self.openssl_call('cms -sign '
                          '-in message.txt '
                          #'-md belt'
                          '-out mail.msg '
                          '-signer %s -inkey %s' % (self.CERT_FILE, self.PRIV_KEY_FILE, ))
        out = self.openssl_call('cms -verify -in mail.msg -CAfile %s' % (self.CACERT_FILE, ))
        self.assertEqual(out, 'This is a message\r\n')

    def SKIPtest_cms_resign(self):
        self.openssl_call('cms -sign '
                          '-in message.txt '
                          '-out mail.msg '
                          '-signer %s -inkey %s' % (self.CERT_FILE, self.PRIV_KEY_FILE, ))
        self.openssl_call('cms -resign '
                          '-in -out mail.msg '
                          '-text -out mail2.msg '
                          '-signer %s -inkey %s' % (self.CERT_FILE, self.PRIV_KEY_FILE, ))
        out = self.openssl_call('cms -verify -in mail.msg -CAfile %s' % (self.CACERT_FILE, ))
        self.assertEqual(out, 'Content-Type: text/plain\r\n\r\nThis is a message\r\n')

    def SKIPtest_sign_der(self):
        self.openssl_call('cms -sign -in message.txt -text -out sig.der -content content.txt -outform DER -signer %s -inkey %s' % (self.CERT_FILE, self.PRIV_KEY_FILE, ))
        out = self.openssl_call('cms -verify -in sig.der -inform DER -content content.txt -CAfile %s' % (self.CACERT_FILE, ))
        self.assertEqual(out, 'Content-Type: text/plain\r\n\r\nThis is a message\r\n')

    def test_enc_dec(self):

        self.openssl_call('cms -encrypt -in message.txt -out smencsign.txt cert.pem')
        self.assertEqual(self.openssl_call('cms -decrypt -in smencsign.txt -inkey priv.key'),
                         'This is a message\r\n')


class TestCertificates(BaseTest):

    PRIV_KEY_FILE = 'priv.key'
    CERT_FILE = "cert.pem"

    @classmethod
    def setUpClass(cls):

        super(TestCertificates, cls).setUpClass()

        cls.openssl_call('genpkey -algorithm bign-pubkey -out %s' % cls.PRIV_KEY_FILE)

    def _assert_extensions(self, cert, ID_list):

        tbs = cert.getComponentByName('tbsCertificate')

        extensions = tbs.getComponentByName('extensions')
        self.assertIsNotNone(extensions)

        print colored(extensions.prettyPrint(), 'grey')

        self.assertEqual([str(extensions.getComponentByPosition(i).getComponentByName('extnID'))
                          for i in range(0, len(ID_list))],
                         ID_list)

        with self.assertRaises(IndexError):
            extensions.getComponentByPosition(len(ID_list))

    def test_request(self):
        request_file = 'req.pem'
        out = self.openssl_call([
            "req",
            "-subj", u"/CN=www.mydom.com/O=My Dom, Inc./C=US/ST=Oregon/L=Portland",
            ("-new -key priv.key -engine btls_e -out %s" % request_file)])

        out = self.openssl_call([
            "x509 -req",
            "-in " + request_file,
            ("-signkey priv.key -engine btls_e -out %s" % self.CERT_FILE)])

        cert, rest = decode(readPemFromFile(open(self.CERT_FILE)), asn1Spec=rfc5208.Certificate())
        self.assertFalse(rest)
        print colored(cert.prettyPrint(), 'grey')

        self.assertIsNotNone(cert.getComponentByName('signatureValue'))
        self.assertIsNotNone(cert.getComponentByName('signatureAlgorithm'))
        self.assertEqual(str(cert.getComponentByName('signatureAlgorithm').getComponentByName('algorithm')),
                         '1.2.112.0.2.0.34.101.45.12')

        # TODO:: #self._assert_extensions(cert, ['2.5.29.14', '2.5.29.35', '2.5.29.19'])

    def test_x509(self):


        out = self.openssl_call([
            "req -x509",
            "-subj", u"/CN=www.mydom.com/O=My Dom, Inc./C=US/ST=Oregon/L=Portland",
            ("-new -key priv.key -engine btls_e -out %s" % self.CERT_FILE)])

        cert, rest = decode(readPemFromFile(open(self.CERT_FILE)), asn1Spec=rfc5208.Certificate())
        self.assertFalse(rest)
        print colored(cert.prettyPrint(), 'grey')

        self.assertIsNotNone(cert.getComponentByName('signatureValue'))
        self.assertIsNotNone(cert.getComponentByName('signatureAlgorithm'))
        self.assertEqual(str(cert.getComponentByName('signatureAlgorithm').getComponentByName('algorithm')),
                         '1.2.112.0.2.0.34.101.45.12')

        self._assert_extensions(cert, ['2.5.29.14', '2.5.29.35', '2.5.29.19'])

    def test_extensions_X509v3(self):

        out = self.openssl_call([
            "req -x509",
            "-extensions single_extension",
            "-subj", u"/CN=www.mydom.com/O=My Dom, Inc./C=US/ST=Oregon/L=Portland",
            ("-new -key priv.key -engine btls_e -out %s" % self.CERT_FILE)])

        cert, rest = decode(readPemFromFile(open(self.CERT_FILE)), asn1Spec=rfc5208.Certificate())
        self.assertFalse(rest)
        print colored(cert.prettyPrint(), 'grey')

        self._assert_extensions(cert, ['2.5.29.15'])

    def test_all_extensions(self):

        out = self.openssl_call([
            "req -x509",
            "-extensions all_exts",
            "-subj", u"/CN=www.mydom.com/O=My Dom, Inc./C=US/ST=Oregon/L=Portland",
            ("-new -key priv.key -engine btls_e -out %s" % self.CERT_FILE)])

        cert, rest = decode(readPemFromFile(open(self.CERT_FILE)), asn1Spec=rfc5208.Certificate())
        self.assertFalse(rest)
        print colored(cert.prettyPrint(), 'grey')

        self._assert_extensions(cert,
                                [
                                    '2.5.29.35',
                                    '2.5.29.14',
                                    '2.5.29.15',
                                    '2.5.29.32',
                                    '2.5.29.17',
                                    '2.5.29.18',
                                    '2.5.29.19',
                                    '2.5.29.30',
                                    '2.5.29.36',
                                    '2.5.29.37',
                                    '2.5.29.31',
                                    '2.5.29.54',
                                    '1.3.6.1.5.5.7.1.1',
                                ]
        )
