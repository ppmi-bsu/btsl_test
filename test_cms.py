
from openssl import openssl_call as _
from test_ca import TestCa
class TestCms(TestCa):

    @classmethod
    def setUpClass(cls):
        super(TestCms, cls).setUpClass()

        cls._issue_cert()
# TODO DETACHED

    def test_cms_sign_smime(self):
        _('cms -sign '
                          '-in message.txt '
                          '-nodetach '
                          '-out mail.msg '
                          '-signer %s -inkey %s' % (self.CERT_FILE, self.PRIV_KEY_FILE, ))
        out = _('cms -verify -in mail.msg -CAfile %s' % (self.CACERT_FILE, ))
        self.assertIn('This is a message', out)

    def test_cms_resign(self):
        _('cms -sign '
                          '-in message.txt '
                          '-out mail.msg '
                          '-signer %s -inkey %s' % (self.CERT_FILE, self.PRIV_KEY_FILE, ))
        _('cms -resign '
                          '-in mail.msg '
                          '-text -out mail2.msg '
                          '-signer %s -inkey %s' % (self.CACERT_FILE, self.CAPRIV_KEY_FILE, ))
        out = _('cms -verify -in mail.msg -CAfile %s' % (self.CACERT_FILE, ))
        self.assertIn('This is a message', out)

    def SKIPtest_sign_der(self):
        _('cms -sign -in message.txt -text -out sig.der -content content.txt -outform DER -signer %s -inkey %s' % (self.CERT_FILE, self.PRIV_KEY_FILE, ))
        out = _('cms -verify -in sig.der -inform DER -content content.txt -CAfile %s' % (self.CACERT_FILE, ))
        self.assertEqual(out, 'Content-Type: text/plain\r\n\r\nThis is a message\r\n')

    def test_enc_dec(self):

        _('cms -encrypt -belt-ctr -in message.txt -out smencsign.txt cert.pem')
        self.assertEqual(_('cms -decrypt -in smencsign.txt -inkey priv.key'),
                         'This is a message\r\n')

    def test_encrypted_data(self):

        _('cms -EncryptedData_encrypt -in message.txt -belt-ctr -secretkey 07DE2FD6328EFADD6BE85BCC64245BF0A997BE43A8DFC7A31B298D656DC88D33 -out smencsign.txt')
        self.assertEqual(
            _('cms -EncryptedData_decrypt '
                              '-in smencsign.txt '
                              '-belt-ctr '
                              '-secretkey 07DE2FD6328EFADD6BE85BCC64245BF0A997BE43A8DFC7A31B298D656DC88D33'),
                         'This is a message\r\n')

    def test_digest(self):

        _('cms -digest_create -md belt-hash -in message.txt -out mail_digested.msg')
        out = _('cms -digest_verify -in mail_digested.msg')
        self.assertIn('This is a message', out)

