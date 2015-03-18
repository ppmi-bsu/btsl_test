from base import BaseTest
import subprocess
from openssl import openssl_call as _
import random
import os
from os.path import join as p


class TestCa(BaseTest):

    PRIV_KEY_FILE = 'priv.key'
    CAPRIV_KEY_FILE = p('demoCA', 'private','cakey.pem')
    CERT_FILE = "cert.pem"
    CACERT_FILE = p('demoCA', 'cacert.pem')
    REQ_FILE = 'req.pem'

    @classmethod
    def setUpClass(cls):

        super(TestCa, cls).setUpClass()
	if os.access(p('demoCA', 'index.txt'), 0):
            os.remove(p("demoCA", "index.txt"))
	open(p("demoCA", "index.txt"), 'w').close()
	_('engine -c')

        _('genpkey -algorithm bign -pkeyopt params:bign-curve256v1 -out {outfile}'.format(outfile=cls.PRIV_KEY_FILE))
        _('genpkey -algorithm bign -pkeyopt params:bign-curve256v1 -out {outfile}'.format(outfile=cls.CAPRIV_KEY_FILE))

        _('req -subj "/CN=www.mydom.com/O=My Dom, Inc./C=US/ST=Oregon/L=Portland" -new -key {key} -out {out}'
            .format(key=cls.PRIV_KEY_FILE, out=cls.REQ_FILE))

        _('req -x509 -subj "/CN={CN}/O=My Dom, Inc./C=US/ST=Oregon/L=Portland" -new -key {key} -out {out}'
            .format(key=cls.CAPRIV_KEY_FILE, out=cls.CACERT_FILE, CN='www.mydom_%s.com' % random.randint(0, 10000)))

    def test_ca(self):
        self._issue_cert()

        out = _('verify -CAfile {ca_cert} {cert}'.format(ca_cert=self.CACERT_FILE, cert=self.CERT_FILE))

        self.assertEqual(out.strip('\n\r'), 'cert.pem: OK')

    def test_crl(self):

        _('ca -gencrl -out %s' % 'crl.pem')
        out = _('crl -in %s -text -noout' % 'crl.pem')
        self.assertIn('No Revoked Certificates.', out)
        self.assertNotIn('\nRevoked Certificates:\n    Serial Number: ', out)

    def test_revoke(self):
        self._issue_cert()

        _('ca -revoke %s' % self.CERT_FILE)
        _('ca -gencrl -out %s' % 'crl.pem')
        out = _('crl -in %s -text -noout' % 'crl.pem')
        self.assertIn('\nRevoked Certificates:\n    Serial Number: ', out)
        self.assertNotIn('No Revoked Certificates.', out)

    @classmethod
    def _issue_cert(cls):
        out = _(
            "ca "
            "-in {req_file} "
            "-cert {ca_cert} "
            "-batch "
            "-keyfile {key} -out {out_cert}"
            .format(req_file=cls.REQ_FILE, ca_cert=cls.CACERT_FILE, key=cls.CAPRIV_KEY_FILE, out_cert=cls.CERT_FILE)
        )

    def test_ocsp(self):

        self._issue_cert()


        _('ocsp '
                          '-issuer {issuer} '
                          '-cert {cert} '
                          '-reqout req_oscp.der '
                          '-belt-hash '
                          .format(issuer=self.CACERT_FILE, cert=self.CERT_FILE))
        _('ocsp '
                          '-index demoCA/index.txt '
                          '-rkey {rkey} '
                          '-rsigner {rsigner} '
                          '-CA {ca} '
                          '-reqin req_oscp.der '
                          '-respout resp_oscp.der '
                          '-belt-hash '
                          .format(rsigner=self.CACERT_FILE, rkey=self.CAPRIV_KEY_FILE, ca=self.CACERT_FILE))

        out = _('ocsp -VAfile {signer} -respin resp_oscp.der -text'.format(signer=self.CACERT_FILE))

        self.assertIn('OCSP Response Status: successful (0x0)', out)
        self.assertIn('Signature Algorithm: bign-with-hbelt', out)
        self.assertIn('Public Key Algorithm: bign-pubkey', out)
        self.assertNotIn('Cert Status: revoked', out)
        self.assertIn('Cert Status: good', out)


    def test_ocsp_revoked(self):

        self._issue_cert()

        _('ca -revoke %s' % self.CERT_FILE)

        _('ocsp '
                          '-issuer {issuer} '
                          '-cert {cert} '
                          '-reqout req_oscp.der '
                          '-belt-hash '
                          .format(issuer=self.CACERT_FILE, cert=self.CERT_FILE))
        _('ocsp '
                          '-index demoCA/index.txt '
                          '-rkey {rkey} '
                          '-rsigner {rsigner} '
                          '-CA {ca} '
                          '-reqin req_oscp.der '
                          '-respout resp_oscp.der '
                          '-belt-hash '
                          .format(rsigner=self.CACERT_FILE, rkey=self.CAPRIV_KEY_FILE, ca=self.CACERT_FILE))

        out = _('ocsp -VAfile {signer} -respin resp_oscp.der -text'.format(signer=self.CACERT_FILE))

        self.assertIn('OCSP Response Status: successful (0x0)', out)
        self.assertIn('Signature Algorithm: bign-with-hbelt', out)
        self.assertIn('Public Key Algorithm: bign-pubkey', out)
        self.assertIn('Cert Status: revoked', out)
