import subprocess
from unittest import TestCase, skip
from base import BaseTest
from openssl import openssl_call as _
from pyasn1_modules.pem import readPemFromFile
from termcolor import colored
from pyasn1.codec.der.decoder import decode
from pyasn1_modules import rfc2459, pkcs12, rfc5208


class TestCertificates(BaseTest):

    PRIV_KEY_FILE = 'priv.key'
    CERT_FILE = "cert.pem"

    @classmethod
    def setUpClass(cls):

        super(TestCertificates, cls).setUpClass()

        _('genpkey -algorithm bign -pkeyopt params:bign-curve256v1 -out %s' % cls.PRIV_KEY_FILE)

    def _asn_print(self, asn1_obj):
        print(colored(asn1_obj.prettyPrint(), 'cyan'))

    def _assert_extensions(self, cert, ID_list):

        tbs = cert.getComponentByName('tbsCertificate')

        extensions = tbs.getComponentByName('extensions')
        self.assertIsNotNone(extensions)

        self._asn_print(extensions)

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
        out = _(
            'req -subj "/CN=www.mydom.com/O=My Dom, Inc./C=US/ST=Oregon/L=Portland" -new -key priv.key -out {out}'
            .format(out=request_file))

        out = _(
            'x509 -req -in {req_file} -signkey priv.key -out {out}'
                .format(req_file=request_file, out=self.CERT_FILE))

        cert, rest = decode(readPemFromFile(open(self.CERT_FILE)), asn1Spec=rfc5208.Certificate())
        self.assertFalse(rest)
        self._asn_print(cert)

        self.assertIsNotNone(cert.getComponentByName('signatureValue'))
        self.assertIsNotNone(cert.getComponentByName('signatureAlgorithm'))
        self.assertEqual(str(cert.getComponentByName('signatureAlgorithm').getComponentByName('algorithm')),
                         '1.2.112.0.2.0.34.101.45.12')

        # TODO:: #self._assert_extensions(cert, ['2.5.29.14', '2.5.29.35', '2.5.29.19'])

    def test_x509_der(self):


        out = _(
            'req -x509 -subj "/CN=www.mydom.com/O=My Dom, Inc./C=US/ST=Oregon/L=Portland" -outform DER -new -key priv.key -out %s'
            % 'cert.der'
        )

    def test_x509(self):


        out = _(
            "req -x509 "
            '-subj "/CN=www.mydom.com/O=My Dom, Inc./C=US/ST=Oregon/L=Portland" '
            "-new -key priv.key -out %s" % self.CERT_FILE
        )

        cert, rest = decode(readPemFromFile(open(self.CERT_FILE)), asn1Spec=rfc5208.Certificate())
        self.assertFalse(rest)
        self._asn_print(cert)

        self.assertIsNotNone(cert.getComponentByName('signatureValue'))
        self.assertIsNotNone(cert.getComponentByName('signatureAlgorithm'))
        self.assertEqual(str(cert.getComponentByName('signatureAlgorithm').getComponentByName('algorithm')),
                         '1.2.112.0.2.0.34.101.45.12')

        self._assert_extensions(cert, ['2.5.29.14', '2.5.29.35', '2.5.29.19'])

    def test_extensions_X509v3(self):

        out = _(
            "req -x509 "
            "-extensions single_extension "
            '-subj "/CN=www.mydom.com/O=My Dom, Inc./C=US/ST=Oregon/L=Portland" '
            "-new -key priv.key -out %s" % self.CERT_FILE)

        cert, rest = decode(readPemFromFile(open(self.CERT_FILE)), asn1Spec=rfc5208.Certificate())
        self.assertFalse(rest)
        self._asn_print(cert)

        self._assert_extensions(cert, ['2.5.29.15'])

    def test_subjectKeyIdentifier(self):

        out = _(
            "req -x509 "
            "-extensions ski_ext "
            '-subj "/CN=www.mydom.com/O=My Dom, Inc./C=US/ST=Oregon/L=Portland" '
            "-new -key priv.key -out %s" % self.CERT_FILE
        )

        cert, rest = decode(readPemFromFile(open(self.CERT_FILE)), asn1Spec=rfc5208.Certificate())
        self.assertFalse(rest)
        self._asn_print(cert)

        exts = self._assert_extensions(cert, ['2.5.29.14'])
        self.assertEqual(len(exts['2.5.29.14']), 24)

    @skip('SKI requires specific chagnges in openssl')
    def test_subjectKeyIdentifier_belt_hash(self):

        out = _(
            "req -x509 "
            "-extensions ski_belt_ext "
            '-subj "/CN=www.mydom.com/O=My Dom, Inc./C=US/ST=Oregon/L=Portland" ' 
            "-new -key priv.key -out %s" % self.CERT_FILE
        )

        cert, rest = decode(readPemFromFile(open(self.CERT_FILE)), asn1Spec=rfc5208.Certificate())
        self.assertFalse(rest)
        self._asn_print(cert)

        exts = self._assert_extensions(cert, ['2.5.29.14'])
        belt_hash = exts['2.5.29.14']
        print(colored('Subject key identifier on belt is: ' + belt_hash, 'yellow'))
        self.assertEqual(len(belt_hash), 36)

    def test_all_extensions(self):

        out = _(
            "req -x509 "
            "-extensions all_exts "
            '-subj "/CN=www.mydom.com/O=My Dom, Inc./C=US/ST=Oregon/L=Portland" '
            "-new -key priv.key -out %s" % self.CERT_FILE
        )

        cert, rest = decode(readPemFromFile(open(self.CERT_FILE)), asn1Spec=rfc2459.Certificate())
        self.assertFalse(rest)
        self._asn_print(cert)

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

