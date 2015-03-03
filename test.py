import random
import subprocess
from unittest import TestCase, skip
import itertools
import unittest
import os
import locale
from pyasn1_modules.pem import readPemFromFile
from termcolor import colored
from pyasn1.codec.der.decoder import decode
from pyasn1_modules import rfc2459, pkcs12, rfc5208
# [Belt-ecb128, Belt-ecb192, Belt-ecb, Belt-cbc128, Belt-cbc192, Belt-cbc, Belt-cfb128, Belt-cfb192, Belt-cfb, Belt-ctr128, Belt-ctr192, Belt-ctr, Belt-dwp128, Belt-dwp192, Belt-dwp, Belt-kwp128, Belt-kwp192, Belt-kwp, Belt-hash, Bign-with-hspec, Bign-with-hbelt, Bign-keytransport, Bign-pubkey, Bign-curve256v1, Bign-curve384v1, Bign-curve512v1, Bign-primefield, Belt-mac128, Belt-mac192, Belt-mac, Belt-hmac]
OPENSSL_DIR = '/home/mihas/openssl/openssl-OpenSSL_1_0_2'

OPENSSL_EXE = OPENSSL_DIR + '/apps/openssl'
os.environ['LD_LIBRARY_PATH'] = OPENSSL_DIR

os.environ['OPENSSL_CONF'] = './openssl.cnf'

encoding = locale.getdefaultlocale()[1]


OPENSSL_OUTPUT_COLOR = 'magenta'


def openssl_call(cmd):

    print colored('openssl ' + cmd, 'green')
    p = subprocess.Popen(OPENSSL_EXE + ' ' + cmd,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE,
                         stdin=subprocess.PIPE,
                         shell=True)
    out, err_out = p.communicate()

    retcode = p.poll()
    if retcode:
        err_out = err_out.decode(encoding)
        print colored(err_out, 'red', 'on_grey')
        return
        #raise RuntimeError('Openssl call fails with status %s' % retcode)
    out = out.decode(encoding)
    print colored(out, OPENSSL_OUTPUT_COLOR)
    return out

openssl_call('')

class BaseTest(TestCase):

    @classmethod
    def setUpClass(cls):
        super(BaseTest, cls).setUpClass()


class TestOpenssl(BaseTest):

    def test_engine_on(self):

        p = openssl_call('engine -c')

        self.assertIn('bee2evp', p)

    def test_cipher(self):

        out = openssl_call('enc -belt-ctr -md belt-hash -k 1231adasd -p -in message.txt -out encrypted.msg')

        self.assertIn('key=', out)

    @skip
    def test_mac_hex_key(self):

        out = openssl_call('dgst -mac belt-mac -macopt key:11111111101111111110111111111011 message.txt')

        prefix = 'belt-mac-belt-mac(message.txt)= '
        self.assertTrue(out.startswith(prefix))
        self.assertEqual(len(out.strip()), len(prefix) + 16)

        out2 = openssl_call('dgst -mac belt-mac -macopt hexkey:3131313131313131313031313131313131313130313131313131313131303131 message.txt')

        self.assertEqual(out, out2)

    def test_hash(self):

        out = openssl_call('dgst -belt-hash message.txt')

        self.assertIn('belt-hash(message.txt)= ', out)
        self.assertEqual(len(out), 89)

    def test_genpkey(self):
        openssl_call(
            'genpkey -genparam -algorithm bign -pkeyopt params:bign-curve256v1 -pkeyopt enc_params:specified -pkeyopt enc_params:cofactor -out params256'
        )
        openssl_call('pkeyparam -in params256 -noout -text')
        out = openssl_call(
            'genpkey -paramfile params256 -belt-kwp -pass pass:root'
        ).strip()
        begin = '-----BEGIN ENCRYPTED PRIVATE KEY-----'
        self.assertTrue(out.startswith(begin))
        end = '-----END ENCRYPTED PRIVATE KEY-----'
        self.assertTrue(out.endswith(end))

        middle = out[len(begin)+1:-len(end)-1]

        self.assertEqual(len(middle), 223)


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

        openssl_call('genpkey -algorithm bign-pubkey -out %s' % cls.PRIV_KEY_FILE)
        openssl_call('genpkey -algorithm bign-pubkey -out %s' % cls.CAPRIV_KEY_FILE)

        openssl_call([
            "req",
            "-subj", u"/CN=www.mydom.com/O=My Dom, Inc./C=US/ST=Oregon/L=Portland",
            ("-new -key %s -out %s" % (cls.PRIV_KEY_FILE, cls.REQ_FILE))])

        out = openssl_call([
            "req -x509",
            "-subj", u"/CN={CN}/O=My Dom, Inc./C=US/ST=Oregon/L=Portland".format(CN='www.mydom_%s.com' % random.randint(0, 10000)),
            ("-new -key %s -out %s" % (cls.CAPRIV_KEY_FILE, cls.CACERT_FILE))])

    def test_ca(self):
        self._issue_cert()

        out = openssl_call('verify -CAfile {ca_cert} {cert}'.format(ca_cert=self.CACERT_FILE, cert=self.CERT_FILE))

        self.assertEqual(out, 'cert.pem: OK\n')

    def test_crl(self):

        openssl_call('ca -gencrl -out %s' % 'crl.pem')
        out = openssl_call('crl -in %s -text -noout' % 'crl.pem')
        self.assertIn('No Revoked Certificates.', out)
        self.assertNotIn('\nRevoked Certificates:\n    Serial Number: ', out)

    def test_revoke(self):
        self._issue_cert()

        openssl_call('ca -revoke %s' % self.CERT_FILE)
        openssl_call('ca -gencrl -out %s' % 'crl.pem')
        out = openssl_call('crl -in %s -text -noout' % 'crl.pem')
        self.assertIn('\nRevoked Certificates:\n    Serial Number: ', out)
        self.assertNotIn('No Revoked Certificates.', out)

    def _issue_cert(self):
        out = openssl_call([
            "ca",
            "-in " + self.REQ_FILE,
            "-cert " + self.CACERT_FILE,
            "-batch",
            ("-keyfile %s -out %s" % (self.CAPRIV_KEY_FILE, self.CERT_FILE))])

    def test_ocsp(self):

        self._issue_cert()


        openssl_call('ocsp '
                          '-issuer {issuer} '
                          '-cert {cert} '
                          '-reqout req_oscp.der '
                          '-belt-hash '
                          .format(issuer=self.CACERT_FILE, cert=self.CERT_FILE))
        openssl_call('ocsp '
                          '-index demoCA/index.txt '
                          '-rkey {rkey} '
                          '-rsigner {rsigner} '
                          '-CA {ca} '
                          '-reqin req_oscp.der '
                          '-respout resp_oscp.der '
                          '-belt-hash '
                          .format(rsigner=self.CACERT_FILE, rkey=self.CAPRIV_KEY_FILE, ca=self.CACERT_FILE))

        out = openssl_call('ocsp -VAfile {signer} -respin resp_oscp.der -text'.format(signer=self.CACERT_FILE))

        self.assertIn('OCSP Response Status: successful (0x0)', out)
        self.assertIn('Signature Algorithm: bign-with-hbelt', out)
        self.assertIn('Public Key Algorithm: bign-pubkey', out)
        self.assertNotIn('Cert Status: revoked', out)
        self.assertIn('Cert Status: good', out)


    def test_ocsp_revoked(self):

        self._issue_cert()

        openssl_call('ca -revoke %s' % self.CERT_FILE)

        openssl_call('ocsp '
                          '-issuer {issuer} '
                          '-cert {cert} '
                          '-reqout req_oscp.der '
                          '-belt-hash '
                          .format(issuer=self.CACERT_FILE, cert=self.CERT_FILE))
        openssl_call('ocsp '
                          '-index demoCA/index.txt '
                          '-rkey {rkey} '
                          '-rsigner {rsigner} '
                          '-CA {ca} '
                          '-reqin req_oscp.der '
                          '-respout resp_oscp.der '
                          '-belt-hash '
                          .format(rsigner=self.CACERT_FILE, rkey=self.CAPRIV_KEY_FILE, ca=self.CACERT_FILE))

        out = openssl_call('ocsp -VAfile {signer} -respin resp_oscp.der -text'.format(signer=self.CACERT_FILE))

        self.assertIn('OCSP Response Status: successful (0x0)', out)
        self.assertIn('Signature Algorithm: bign-with-hbelt', out)
        self.assertIn('Public Key Algorithm: bign-pubkey', out)
        self.assertIn('Cert Status: revoked', out)

class TestCms(TestCa):

    @classmethod
    def setUpClass(cls):
        super(TestCms, cls).setUpClass()

        out = openssl_call([
            "ca",
            "-in " + cls.REQ_FILE,
            "-cert " + cls.CACERT_FILE,
            "-batch",
            ("-keyfile %s -out %s" % (cls.CAPRIV_KEY_FILE, cls.CERT_FILE))])
# TODO DETACHED
    def test_cms_sign_smime(self):
        openssl_call('cms -sign '
                          '-in message.txt '
                          '-nodetach '
                          '-out mail.msg '
                          '-signer %s -inkey %s' % (self.CERT_FILE, self.PRIV_KEY_FILE, ))
        out = openssl_call('cms -verify -in mail.msg -CAfile %s' % (self.CACERT_FILE, ))
        self.assertIn('This is a message', out)

    def test_cms_resign(self):
        openssl_call('cms -sign '
                          '-in message.txt '
                          '-out mail.msg '
                          '-signer %s -inkey %s' % (self.CERT_FILE, self.PRIV_KEY_FILE, ))
        openssl_call('cms -resign '
                          '-in mail.msg '
                          '-text -out mail2.msg '
                          '-signer %s -inkey %s' % (self.CACERT_FILE, self.CAPRIV_KEY_FILE, ))
        out = openssl_call('cms -verify -in mail.msg -CAfile %s' % (self.CACERT_FILE, ))
        self.assertIn('This is a message', out)

    def SKIPtest_sign_der(self):
        openssl_call('cms -sign -in message.txt -text -out sig.der -content content.txt -outform DER -signer %s -inkey %s' % (self.CERT_FILE, self.PRIV_KEY_FILE, ))
        out = openssl_call('cms -verify -in sig.der -inform DER -content content.txt -CAfile %s' % (self.CACERT_FILE, ))
        self.assertEqual(out, 'Content-Type: text/plain\r\n\r\nThis is a message\r\n')

    def test_enc_dec(self):

        openssl_call('cms -encrypt -belt-ctr -in message.txt -out smencsign.txt cert.pem')
        self.assertEqual(openssl_call('cms -decrypt -in smencsign.txt -inkey priv.key'),
                         'This is a message\r\n')

    def test_encrypted_data(self):

        openssl_call('cms -EncryptedData_encrypt -in message.txt -belt-ctr -secretkey 07DE2FD6328EFADD6BE85BCC64245BF0A997BE43A8DFC7A31B298D656DC88D33 -out smencsign.txt')
        self.assertEqual(
            openssl_call('cms -EncryptedData_decrypt '
                              '-in smencsign.txt '
                              '-belt-ctr '
                              '-secretkey 07DE2FD6328EFADD6BE85BCC64245BF0A997BE43A8DFC7A31B298D656DC88D33'),
                         'This is a message\r\n')

    def test_digest(self):

        openssl_call('cms -digest_create -md belt-hash -in message.txt -out mail_digested.msg')
        out = openssl_call('cms -digest_verify -in mail_digested.msg')
        self.assertIn('This is a message', out)


class TestCertificates(BaseTest):

    PRIV_KEY_FILE = 'priv.key'
    CERT_FILE = "cert.pem"

    @classmethod
    def setUpClass(cls):

        super(TestCertificates, cls).setUpClass()

        openssl_call('genpkey -algorithm bign-pubkey -out %s' % cls.PRIV_KEY_FILE)

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
        return {
            str(c.getComponentByName('extnID')): str(c.getComponentByName('extnValue'))
            for c in [extensions.getComponentByPosition(i) for i in range(0, len(ID_list))]
        }

    def test_request(self):
        request_file = 'req.pem'
        out = openssl_call([
            "req",
            "-subj", u"/CN=www.mydom.com/O=My Dom, Inc./C=US/ST=Oregon/L=Portland",
            ("-new -key priv.key -out %s" % request_file)])

        out = openssl_call([
            "x509 -req",
            "-in " + request_file,
            ("-signkey priv.key -out %s" % self.CERT_FILE)])

        cert, rest = decode(readPemFromFile(open(self.CERT_FILE)), asn1Spec=rfc5208.Certificate())
        self.assertFalse(rest)
        print colored(cert.prettyPrint(), 'grey')

        self.assertIsNotNone(cert.getComponentByName('signatureValue'))
        self.assertIsNotNone(cert.getComponentByName('signatureAlgorithm'))
        self.assertEqual(str(cert.getComponentByName('signatureAlgorithm').getComponentByName('algorithm')),
                         '1.2.112.0.2.0.34.101.45.12')

        # TODO:: #self._assert_extensions(cert, ['2.5.29.14', '2.5.29.35', '2.5.29.19'])

    def test_x509_der(self):


        out = openssl_call([
            "req -x509",
            "-subj", u"/CN=www.mydom.com/O=My Dom, Inc./C=US/ST=Oregon/L=Portland",
            '-outform DER',
            ("-new -key priv.key -out %s" % 'cert.der')])

    def test_x509(self):


        out = openssl_call([
            "req -x509",
            "-subj", u"/CN=www.mydom.com/O=My Dom, Inc./C=US/ST=Oregon/L=Portland",
            ("-new -key priv.key -out %s" % self.CERT_FILE)])

        cert, rest = decode(readPemFromFile(open(self.CERT_FILE)), asn1Spec=rfc5208.Certificate())
        self.assertFalse(rest)
        print colored(cert.prettyPrint(), 'grey')

        self.assertIsNotNone(cert.getComponentByName('signatureValue'))
        self.assertIsNotNone(cert.getComponentByName('signatureAlgorithm'))
        self.assertEqual(str(cert.getComponentByName('signatureAlgorithm').getComponentByName('algorithm')),
                         '1.2.112.0.2.0.34.101.45.12')

        self._assert_extensions(cert, ['2.5.29.14', '2.5.29.35', '2.5.29.19'])

    def test_extensions_X509v3(self):

        out = openssl_call([
            "req -x509",
            "-extensions single_extension",
            "-subj", u"/CN=www.mydom.com/O=My Dom, Inc./C=US/ST=Oregon/L=Portland",
            ("-new -key priv.key -out %s" % self.CERT_FILE)])

        cert, rest = decode(readPemFromFile(open(self.CERT_FILE)), asn1Spec=rfc5208.Certificate())
        self.assertFalse(rest)
        print colored(cert.prettyPrint(), 'grey')

        self._assert_extensions(cert, ['2.5.29.15'])

    def test_subjectKeyIdentifier(self):

        out = openssl_call([
            "req -x509",
            "-extensions ski_ext",
            "-subj", u"/CN=www.mydom.com/O=My Dom, Inc./C=US/ST=Oregon/L=Portland",
            ("-new -key priv.key -out %s" % self.CERT_FILE)])

        cert, rest = decode(readPemFromFile(open(self.CERT_FILE)), asn1Spec=rfc5208.Certificate())
        self.assertFalse(rest)
        print colored(cert.prettyPrint(), 'grey')

        exts = self._assert_extensions(cert, ['2.5.29.14'])
        self.assertEqual(len(exts['2.5.29.14']), 24)

    def test_subjectKeyIdentifier_belt_hash(self):

        out = openssl_call([
            "req -x509",
            "-extensions ski_belt_ext",
            "-subj", u"/CN=www.mydom.com/O=My Dom, Inc./C=US/ST=Oregon/L=Portland",
            ("-new -key priv.key -out %s" % self.CERT_FILE)])

        cert, rest = decode(readPemFromFile(open(self.CERT_FILE)), asn1Spec=rfc5208.Certificate())
        self.assertFalse(rest)
        print colored(cert.prettyPrint(), 'grey'.lower())

        exts = self._assert_extensions(cert, ['2.5.29.14'])
        belt_hash = exts['2.5.29.14']
        print colored('Subject key identifier on belt is: ' + belt_hash, 'yellow')
        self.assertEqual(len(belt_hash), 36)

    def test_all_extensions(self):

        out = openssl_call([
            "req -x509",
            "-extensions all_exts",
            "-subj", u"/CN=www.mydom.com/O=My Dom, Inc./C=US/ST=Oregon/L=Portland",
            ("-new -key priv.key -out %s" % self.CERT_FILE)])

        cert, rest = decode(readPemFromFile(open(self.CERT_FILE)), asn1Spec=rfc2459.Certificate())
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
