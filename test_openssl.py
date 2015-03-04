from unittest import skip
from base import BaseTest
from openssl import openssl_call as _


class TestOpenssl(BaseTest):

    def test_engine_on(self):

        p = _('engine -c')

        self.assertIn('bee2evp', p)

    def test_cipher(self):

        out = _('enc -belt-ctr -md belt-hash -k 1231adasd -p -in message.txt -out encrypted.msg')

        self.assertIn('key=', out)

    @skip('')
    def test_mac_hex_key(self):

        out = _('dgst -mac belt-mac -macopt key:11111111101111111110111111111011 message.txt')

        prefix = 'belt-mac-belt-mac(message.txt)= '
        self.assertTrue(out.startswith(prefix))
        self.assertEqual(len(out.strip()), len(prefix) + 16)

        out2 = _('dgst -mac belt-mac -macopt hexkey:3131313131313131313031313131313131313130313131313131313131303131 message.txt')

        self.assertEqual(out, out2)

    def test_hash(self):

        out = _('dgst -belt-hash message.txt')

        self.assertIn('belt-hash(message.txt)= ', out)
        self.assertEqual(len(out), 89)

        self.assertEqual(_('dgst -belt-hash message.txt'), out,
                         'Hash must be the same')

    def test_genpkey(self):
        _('genpkey -genparam -algorithm bign -pkeyopt params:bign-curve256v1 -pkeyopt enc_params:specified -pkeyopt enc_params:cofactor -out params256')
        _('pkeyparam -in params256 -noout -text')
        out = _('genpkey -paramfile params256 -belt-kwp -pass pass:root').strip()
        begin = '-----BEGIN ENCRYPTED PRIVATE KEY-----'
        self.assertTrue(out.startswith(begin))
        end = '-----END ENCRYPTED PRIVATE KEY-----'
        self.assertTrue(out.endswith(end))

        middle = out[len(begin)+1:-len(end)-1]

        self.assertEqual(len(middle), 223)
