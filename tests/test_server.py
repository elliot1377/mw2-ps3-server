"""Self-tests of the server's protocol code (no game needed):  python -m unittest discover tests"""
import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'server'))

from Crypto.Cipher import DES3  # noqa: E402

import dwcore  # noqa: E402
import dwserver  # noqa: E402

dwserver.SETTINGS['log'] = ''           # no log file while testing
COOKIE = b'abcdefghijklmnopqrstuvwx'   # 24 chars = the 3DES key of the auth reply
USER_ID = 0x1122334455667788


def np_ticket(online_id='tester', cookie=COOKIE):
    """a minimal Sony NP ticket v2.1 with the fields the server reads"""
    values = [b'serial', b'issuer', b'\0' * 8, b'\0' * 8, struct.pack('>Q', USER_ID),
              online_id.encode().ljust(32, b'\0'), b'us\0\0', b'un\0\0', b'UP0002-BLUS30377_00\0', b'\0' * 4, cookie]
    body = b''.join(struct.pack('>HH', 1, len(v)) + v for v in values)
    section = struct.pack('>HH', 0x3000, len(body)) + body
    return b'\x21\x01\x00\x00' + struct.pack('>I', len(section)) + section


def auth_request(title=0x7d0):
    w = dwcore.BitWriter(True)
    w.u32(title)
    return w.tobytes() + b'\0' * 8 + np_ticket()


class TigerTest(unittest.TestCase):
    def test_vectors(self):
        # official Tiger-192 test vectors - the S-boxes are the standard ones
        self.assertEqual(dwcore.tiger(b'').hex().upper(), '3293AC630C13F0245F92BBB1766E16167A4E58492DDE73F3')
        self.assertEqual(dwcore.tiger(b'abc').hex().upper(), '2AAB1484E8C158F2BFB8C5FF41B57A525129131C957B5F93')


class AuthTest(unittest.TestCase):
    def test_auth_reply_decrypts_to_our_ticket(self):
        frames, rest = dwcore.read_frames(dwserver.auth_reply(auth_request()))
        self.assertEqual(rest, b'')
        enc, mtype, payload = frames[0]
        self.assertEqual((enc, mtype), (0, 19))
        br = dwcore.BitReader(payload)
        self.assertEqual(br.u32()[1], 700)
        seed = br.u32()[1]
        enc_ticket = bytes(br.raw(8) for _ in range(152))
        server_ticket = bytes(br.raw(8) for _ in range(128))
        plain = DES3.new(COOKIE, DES3.MODE_CBC, dwcore.initial_vector(seed)).decrypt(enc_ticket)
        magic, _, title = struct.unpack_from('<IBI', plain)
        self.assertEqual(magic, dwcore.AUTH_TICKET_MAGIC)
        self.assertEqual(title, 0x7d0)
        user = struct.unpack_from('<Q', plain, 25)[0]
        self.assertEqual(user, USER_ID)
        self.assertEqual(plain[33:39], b'tester')
        session_key = plain[97:121]
        # the server ticket carries the same session key and is found again in a lobby login
        self.assertEqual(server_ticket[12:36], session_key)
        login = dwcore.BitWriter(True)
        login.u32(1)
        login.raw(5, 3)                             # anything, to put the ticket off byte alignment
        login.raw_bytes(server_ticket)
        found, _ = dwserver.find_server_ticket(login.tobytes())
        self.assertEqual(found, server_ticket)

    def test_no_ticket(self):
        self.assertIsNone(dwserver.auth_reply(b'\x01\x02\x03'))


class LobbyTest(unittest.TestCase):
    def test_encrypt_decrypt(self):
        key = os.urandom(24)
        msg = dwserver.lsg_encrypt(key, 1, b'hello world')
        length, flag = struct.unpack_from('<IB', msg)
        self.assertEqual((length, flag), (len(msg) - 4, 1))
        _, plain = dwserver.lsg_decrypt(key, msg[5:])
        self.assertEqual(plain[:16], struct.pack('<I', 0xDEADBEEF) + b'\x01hello world')

    def test_file_list_has_every_language(self):
        dwserver.CUR['bytes'] = False
        names = [v for t, v in dwcore.decode_typed(dwserver.task_reply_file_list(), max_fields=1000) if t == 'string']
        for name in ('playlists.patch3', 'motd-english.txt', 'motd-japanese.txt', 'playlists.patch2'):
            self.assertIn(name, names)

    def test_aliases_serve_the_source_file(self):
        files = {name: data for _, name, data in dwserver.file_entries()}
        self.assertTrue(files['playlists.patch3'])
        self.assertEqual(files['playlists.patch2'], files['playlists.patch3'])
        self.assertEqual(files['motd-japanese.txt'], files['motd-english.txt'])


class UdpTest(unittest.TestCase):
    def test_ip_discovery(self):
        reply = dwserver.udp_reply(bytes([30, 2, 0]), ('127.0.0.1', 3076))
        self.assertEqual(reply, bytes([31]) + struct.pack('<H', 2) + dwserver.bd_addr('127.0.0.1', 3076))


if __name__ == '__main__':
    unittest.main()
