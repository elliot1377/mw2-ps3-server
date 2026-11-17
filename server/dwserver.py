"""MW2 PS3 community DemonWare server - a replacement for the shut-down Modern Warfare 2 (and MW3) PS3 online services.

    python dwserver.py [--bind 127.0.0.1] [--public-ip IP] [--log FILE] [--verbose]

Ports: TCP 3074 (auth + lobby), UDP 3074 (IP / NAT discovery). The game is pointed here with RPCS3's "IP swap list"
(or, on a real PS3, a DNS that answers the DemonWare host names with this server - see dnsserver.py).

What it does (reverse engineered from the MW2 PS3 EBOOT, details in docs/PROTOCOL.md):
  - auth: answers the PS3 NP-ticket login (message 18) with an encrypted bdAuthTicket (message 19)
  - lobby (LSG): encrypted task channel - storage (MOTD / playlists / player files), matchmaking sessions,
    bandwidth test; every task is answered in order
  - UDP: IP discovery and NAT type discovery
MW2 uses bit buffers, MW3 (newer DemonWare) typed byte buffers; both are served on the same ports.
"""
import argparse
import datetime
import hashlib
import os
import random
import select
import socket
import struct
import sys
import time
import traceback

from Crypto.Cipher import DES3

import dwcore
import npticket

# folder of the server's data: next to the script, or next to the .exe when built with PyInstaller
HERE = os.path.dirname(os.path.abspath(sys.executable if getattr(sys, 'frozen', False) else __file__))
FILES_DIR = os.path.join(HERE, 'files')          # publisher files served to the game (MOTD, playlists, ...)
MW3_FILES = os.path.join(FILES_DIR, 'mw3')       # publisher files for MW3
USER_FILES = os.path.join(HERE, 'userfiles')     # per player: userfiles/<online id>/<name> (MW3 stats: mpdata)

AUTH_PORT = 3074
EXTRA_TCP = [80, 443, 3005, 3006, 3007, 3075, 3076, 3077, 3078, 3079, 3080, 9000]
EXTRA_UDP = [3074, 3075, 3478, 3479, 3480]
NAT_ALT_PORT = 3481

# settings (command line > environment > defaults); local only by default - public servers bind 0.0.0.0
SETTINGS = {
    'bind': os.environ.get('DW_BIND', '127.0.0.1'),
    'public_ip': os.environ.get('DW_PUBLIC_IP', ''),
    'log': os.path.join(HERE, 'dwserver.log'),
    'verbose': False,
}

# ---------------------------------------------------------------- protocol constants
# bdDataType ids of the typed buffers
BD_BOOL, BD_UINT8, BD_INT32, BD_UINT64, BD_INT64, BD_STRING, BD_BLOB = 1, 3, 7, 10, 9, 16, 19

# lobby (LSG) message types
LSG_TASK_REPLY = 1                  # server -> client: task reply (bdRemoteTaskManager 0x3fb858)
LSG_CONNECTION_ID = 4               # server -> client: connection id, right after the login
LSG_SERVICE_TASK_REPLY = 5          # server -> client: raw reply to a raw task (MW3 bandwidth test: 0x440B34)
LSG_LOGIN = 7                       # client -> server: login with our server ticket

# lobby services
SVC_MATCHMAKING = 5                 # MW2 tasks: 1 create, 2 update, 3 delete, 5 find (bdMatchMaking 0x3f6xxx)
SVC_STORAGE = 10                    # MW2 tasks: 8 list files, 5 get file; MW3: 7 publisher file, 3 user file
SVC_BANDWIDTH = 18
SVC_MW3_MATCHMAKING = 21

SERVER_TICKET_MAGIC = 0x43445845    # 'EXDC': our 128-byte server ticket, given back by the client at the lobby login
BD_NO_FILE = 1000                   # MW3 error "no such file" (error table 0x731E3C)

# MW2 publisher files. The game looks for its own names in the file list (0x30dd8c) and keeps asking until they are
# there; other languages / regions (e.g. Japanese MW2 1.1.478) use other names - served from the same files when
# there is no file of that name.
FILE_NAMES = ['motd-english.txt', 'motd-german.txt', 'playlists.patch3', 'messageoftheday.info']
FILE_ALIASES = {}
for _lang in ('french', 'italian', 'spanish', 'japanese', 'russian', 'polish', 'portuguese', 'korean', 'chinese',
              'dutch', 'traditional_chinese', 'simplified_chinese', 'czech', 'austrian'):
    FILE_ALIASES['motd-%s.txt' % _lang] = 'motd-english.txt'
for _name in ('playlists.patch', 'playlists.patch1', 'playlists.patch2', 'playlists.patch4', 'playlists.patch5',
              'playlists.patch6', 'playlists.info'):
    FILE_ALIASES[_name] = 'playlists.patch3'

# MW3 bandwidth test: upload packets go to UDP 3074 and carry this cookie at offset 4 (told apart from NAT/IP tests)
BW_PORT = 3074
GAME_UDP_PORTS = (3074, 3075)          # the ports MW2 itself binds first (RPCS3 must not share them)
BW_COOKIE = b'BWTEST01'

# ---------------------------------------------------------------- state
_txid = [1]                         # task reply transaction ids (the client matches replies in order anyway)
CUR = {'bytes': False}              # the connection being answered uses typed byte buffers (MW3), not bit buffers
SESSIONS_MM = {}                    # MW2 session id -> {'addr', 'key', 'ints', 'owner'}
SESSIONS_MW3 = {}                   # MW3 session id -> {'owner', 'user', 'args'}
BW = {'packets': 0, 'bytes': 0}
NAT_ALT = {}                        # (ip, port) -> socket for "answer from another address" NAT tests


# ---------------------------------------------------------------- logging
def log(msg):
    line = '%s %s' % (datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3], msg)
    print(line, flush=True)
    if SETTINGS['log']:
        try:
            with open(SETTINGS['log'], 'a', encoding='utf-8') as f:
                f.write(line + '\n')
        except OSError:
            pass


def debug(msg):
    """only with --verbose: packet dumps and the frequent per-task lines"""
    if SETTINGS['verbose']:
        log(msg)


def hexdump(data, limit=768):
    rows = []
    for i in range(0, min(len(data), limit), 16):
        c = data[i:i + 16]
        rows.append('    %04x  %-48s %s' % (i, ' '.join('%02x' % b for b in c),
                                          ''.join(chr(b) if 32 <= b < 127 else '.' for b in c)))
    if len(data) > limit:
        rows.append('    ... %d bytes total' % len(data))
    return '\n'.join(rows)


def read_file(path):
    with open(path, 'rb') as f:
        return f.read()


def short(fields):
    return [(t, v[:48] + '..' if isinstance(v, str) and len(v) > 48 else v) for t, v in fields]


def is_local(ip):
    return ip.startswith(('127.', '192.168.', '10.', '172.'))


# ---------------------------------------------------------------- auth (TCP 3074, message 18 -> 19)
def auth_reply(payload):
    """message 18 = [typed u32 title][NP ticket]; the ticket cookie (24 random chars) is the 3DES key of the reply:
    [u32 700 = ok][u32 iv seed][3DES-CBC(cookie, Tiger(seed)[:8]) of the 152-byte bdAuthTicket][128-byte server
    ticket, opaque to the client - it hands it to the lobby]"""
    br = dwcore.BitReader(payload)
    _, title = br.u32()
    np = npticket.parse_np_ticket(payload)
    if not np or len(np.get('cookie', b'')) != 24:
        log('auth: no NP ticket / cookie in request')
        return None
    session_key = os.urandom(24)
    now = int(time.time())
    ticket = dwcore.pack_auth_ticket(title, now, now + 24 * 3600, 0, np['user_id'], np['online_id'], session_key)
    seed = random.getrandbits(32)
    enc = DES3.new(np['cookie'], DES3.MODE_CBC, dwcore.initial_vector(seed)).encrypt(ticket.ljust(152, b'\0'))
    # our server ticket just carries the session in clear: magic, user id, session key, online id
    server_ticket = struct.pack('<IQ', SERVER_TICKET_MAGIC, np['user_id']) + session_key
    server_ticket = (server_ticket + np['online_id'].encode()[:63].ljust(64, b'\0')).ljust(128, b'\0')
    w = dwcore.BitWriter(True)
    w.u32(700)
    w.u32(seed)
    w.raw_bytes(enc)
    w.raw_bytes(server_ticket)
    log('auth: %s (user %d, title 0x%x) -> authorized' % (np['online_id'], np['user_id'], title))
    return dwcore.frame(19, w.tobytes())


# ---------------------------------------------------------------- lobby (LSG) framing
def find_server_ticket(payload):
    """the lobby login (message 7) carries our 128-byte server ticket somewhere in its bit stream (not byte
    aligned) -> (ticket, bit offset) or (None, None)"""
    br = dwcore.BitReader(payload)
    for start in range(1, len(payload) * 8 - 128 * 8 + 1):
        br.pos = start
        if br.raw(32) == SERVER_TICKET_MAGIC:
            br.pos = start
            return bytes(br.raw(8) for _ in range(128)), start
    return None, None


def lsg_decrypt(key, enc_payload):
    """encrypted frame body after the 01 flag: u32 seed | 3DES-CBC(key, Tiger(seed)[:8])"""
    seed = struct.unpack('<I', enc_payload[:4])[0]
    ct = enc_payload[4:]
    ct = ct[:len(ct) - len(ct) % 8]
    return seed, DES3.new(key, DES3.MODE_CBC, dwcore.initial_vector(seed)).decrypt(ct)


def lsg_encrypt(key, msg_type, body):
    """server -> client: u32 len | 01 | u32 seed | 3DES(key, Tiger(seed)[:8]) of [ef be ad de][type][body][pad 8]"""
    plain = struct.pack('<I', 0xDEADBEEF) + bytes([msg_type]) + body
    plain += b'\0' * (-len(plain) % 8)
    seed = random.getrandbits(32)
    ct = DES3.new(key, DES3.MODE_CBC, dwcore.initial_vector(seed)).encrypt(plain)
    frame = b'\x01' + struct.pack('<I', seed) + ct
    return struct.pack('<I', len(frame)) + frame


def new_writer():
    return dwcore.ByteWriter() if CUR['bytes'] else dwcore.BitWriter(True)


def write_blob(w, data):
    w.data_type(BD_BLOB)
    w.u32(len(data))
    w.raw_bytes(data)


# ---------------------------------------------------------------- MW2 task replies (bit buffers)
def task_reply_header(w, result_type):
    """[typed u64 transaction id][u32 error][typed u8 result type] - replies are matched in order (FIFO)"""
    w.data_type(BD_UINT64)
    w.raw(_txid[0], 64)
    _txid[0] += 1
    w.u32(0)
    w.data_type(BD_UINT8)
    w.raw(result_type, 8)


def task_reply_empty(result_type=4):
    w = new_writer()
    task_reply_header(w, result_type)
    w.u32(0)                         # count
    w.u32(0)                         # total
    return w.tobytes()


def file_entries():
    """[(file id, name, data)] of the MW2 publisher files (aliases served from their source file)"""
    out = []
    for i, name in enumerate(FILE_NAMES + [n for n in FILE_ALIASES if n not in FILE_NAMES]):
        path = os.path.join(FILES_DIR, name)
        if not os.path.exists(path) and name in FILE_ALIASES:
            path = os.path.join(FILES_DIR, FILE_ALIASES[name])
        data = read_file(path) if os.path.exists(path) else b''
        out.append((i + 1, name, data))
    return out


def write_file_header(w, fid, name, data):
    """bdLobbyFileHeader (0x4016c8): [u64 file id][u32 time][u32 size][bool][bool][u64 owner][string name]"""
    w.data_type(BD_UINT64)
    w.raw(fid, 64)
    w.u32(int(time.time()))
    w.u32(len(data))
    w.data_type(BD_BOOL)
    w.raw(1, 1)
    w.data_type(BD_BOOL)
    w.raw(0, 1)
    w.data_type(BD_UINT64)
    w.raw(0, 64)
    w.data_type(BD_STRING)
    w.raw_bytes(name.encode() + b'\0')


def task_reply_file_list():
    """storage task 8 (list files): result type 7 = list [typed u32 count] + one bdListFilesResult per file
    (0x4000f8): [typed u32][bdLobbyFileHeader]"""
    w = new_writer()
    task_reply_header(w, 7)
    files = file_entries()
    w.u32(len(files))
    for fid, name, data in files:
        w.u32(len(data))
        write_file_header(w, fid, name, data)
    return w.tobytes()


def task_reply_get_file(file_id):
    """storage task 5 [u64 file id] (get file): result type 1 = bdGetFileResult (0x3ff2e0):
    [typed u32][bdLobbyFile (0x4011a8): header + blob]"""
    entry = next((e for e in file_entries() if e[0] == file_id), None)
    if not entry:
        return task_reply_empty(0)
    fid, name, data = entry
    w = new_writer()
    task_reply_header(w, 1)
    w.u32(1)
    write_file_header(w, fid, name, data)
    write_blob(w, data)
    log('lsg: file %s (%d bytes) sent' % (name, len(data)))
    return w.tobytes()


def mm_parse_info(args):
    """create/update args: [u8][blob host addr][blob session id][blob key][int32 ...]"""
    blobs = [bytes.fromhex(v) for t, v in args if t == 'blob']
    ints = [v for t, v in args if t == 'int32']
    return blobs, ints


def handle_task(st, service, task, args, raw):
    if CUR['bytes']:
        return handle_task_mw3(st, service, task if isinstance(task, int) else 0, args)
    if service == SVC_STORAGE:
        if task == 8:
            return task_reply_file_list()
        if task == 5:                           # args: [u8 0][u64 file id]
            ids = [v for t, v in args if t == 'uint64']
            return task_reply_get_file(ids[0] if ids else 0)
        return task_reply_empty(4)              # other storage tasks: OK, no results
    if service == SVC_MATCHMAKING:
        if task == 1:                           # create session -> bdSessionCreateResult [blob id][blob key]
            blobs, ints = mm_parse_info(args)
            sid, key = os.urandom(8), os.urandom(16)
            SESSIONS_MM[sid] = {'addr': blobs[0] if blobs else b'', 'key': key, 'ints': ints, 'owner': id(st)}
            log('mm: %s created session %s' % (st.get('user'), sid.hex()))
            w = new_writer()
            task_reply_header(w, 8)
            write_blob(w, sid)
            write_blob(w, key)
            return w.tobytes()
        if task == 2:                           # update session
            blobs, ints = mm_parse_info(args)
            if len(blobs) > 1 and blobs[1] in SESSIONS_MM:
                s = SESSIONS_MM[blobs[1]]
                s['addr'], s['ints'] = blobs[0], ints
                debug('mm: update session %s ints %s' % (blobs[1].hex(), ints))
            return task_reply_empty(0)
        if task == 3:                           # delete session
            blobs = [bytes.fromhex(v) for t, v in args if t == 'blob']
            if blobs and SESSIONS_MM.pop(blobs[0], None):
                log('mm: session %s deleted' % blobs[0].hex())
            return task_reply_empty(0)
        if task == 5:                           # find sessions -> list [u32 total][u32 count][bdMatchMakingInfo ...]
            found = [(sid, s) for sid, s in SESSIONS_MM.items() if s['owner'] != id(st)]
            debug('mm: find sessions -> %d result(s)' % len(found))
            w = new_writer()
            task_reply_header(w, 4)
            w.u32(len(found))
            w.u32(len(found))
            for sid, s in found:
                write_blob(w, s['addr'])
                write_blob(w, sid)
                write_blob(w, s['key'])
                for v in s['ints']:
                    w.data_type(BD_INT32)
                    w.raw(v & 0xffffffff, 32)
            return w.tobytes()
    if service == SVC_BANDWIDTH:
        return task_reply_empty(0)
    debug('lsg: unhandled service %d task %s raw %s' % (service, task, raw.hex()[:200]))
    return task_reply_empty(0)


# ---------------------------------------------------------------- MW3 task replies (typed byte buffers)
# [u64 transaction id][u32 error][u8 task][u32 count][u32 total][results] - the layout of the newer DemonWare lobby
def bb(*items):
    """typed byte buffer from (type, value) items: 'u8', 'u32', 'u64', 'i32', 'i64', 'blob', 'str'"""
    w = dwcore.ByteWriter()
    for kind, v in items:
        if kind == 'u8':
            w.data_type(BD_UINT8)
            w.raw(v, 8)
        elif kind == 'u32':
            w.u32(v)
        elif kind == 'u64':
            w.data_type(BD_UINT64)
            w.raw(v, 64)
        elif kind == 'i32':
            w.data_type(BD_INT32)
            w.raw(v & 0xffffffff, 32)
        elif kind == 'i64':
            w.data_type(BD_INT64)
            w.raw(v & 0xffffffffffffffff, 64)
        elif kind == 'blob':
            write_blob(w, v)
        elif kind == 'str':
            w.data_type(BD_STRING)
            w.raw_bytes(v.encode() + b'\0')
    return w.tobytes()


def mw3_reply(task, results=(), error=0):
    w = dwcore.ByteWriter()
    w.data_type(BD_UINT64)
    w.raw(_txid[0], 64)
    _txid[0] += 1
    w.u32(error)
    w.data_type(BD_UINT8)
    w.raw(task & 0xff, 8)
    if not error:
        w.u32(len(results))
        w.u32(len(results))
        for r in results:
            w.raw_bytes(r)
    return w.tobytes()


def safe_name(name):
    return ''.join(c for c in name if c.isalnum() or c in '._-')[:96] or '_'


def bandwidth_reply(st, data):
    """MW3 bandwidth test, service 18 (raw, little endian; MW3 only runs test type 0 = upload):
    start    [00][type] -> [u8 0 accepted][7 x u32 packetSize, numPackets, senderInitialWait, sendDuration,
             receiverInitialWait, receiveDuration, lingerDuration][u16 port][IPv4][8-byte cookie]; the client then
             sends numPackets UDP packets [u32 seq][cookie][padding] there (counted, not answered)
    finalize [01][5 x u32] -> [u8 0][5 x u32 result]: bytes and milliseconds are used, upload = bytes*8/s.
    250000 bytes in 1000 ms = 1,953,125 bit/s >= band_18players (580000) -> MW3 may host 18-player sessions."""
    head = struct.pack('<Q', _txid[0])
    _txid[0] += 1
    if data[:1] == b'\x01':
        debug('bandwidth: finalize (%d packets / %d bytes arrived)' % (BW['packets'], BW['bytes']))
        return head + b'\x00' + struct.pack('<5I', 250000, 1000, 0, 0, 0)
    client = st['addr'][0]
    if client.startswith('127.'):
        ip = '127.0.0.1'
    elif SETTINGS['public_ip'] and not is_local(client):
        ip = SETTINGS['public_ip']
    else:
        ip = st['sock'].getsockname()[0]
    BW['packets'] = BW['bytes'] = 0
    debug('bandwidth: start from %s -> 10 x 512 bytes to %s:%d' % (st.get('user'), ip, BW_PORT))
    # numPackets must stay < 20: the first byte of a packet is its seq, 20 / 30 would look like NAT / IP requests
    return (head + b'\x00' + struct.pack('<7I', 512, 10, 0, 1000, 0, 1000, 0) + struct.pack('<H', BW_PORT) +
            socket.inet_aton(ip) + BW_COOKIE)


def handle_task_mw3(st, service, task, args):
    strings = [v for t, v in args if t == 'string']
    blobs = [v for t, v in args if t == 'blob']
    if service == SVC_STORAGE and task == 7 and strings:            # get publisher file (by name)
        path = os.path.join(MW3_FILES, safe_name(strings[0]))
        if os.path.exists(path):
            data = read_file(path)
            log('mw3: publisher file %s (%d bytes) sent' % (strings[0], len(data)))
            return mw3_reply(task, [bb(('blob', data))])
        debug('mw3: publisher file %s -> no file' % strings[0])
        return mw3_reply(task, error=BD_NO_FILE)
    if service == SVC_STORAGE and task == 3 and strings:            # get user file (by name)
        path = os.path.join(USER_FILES, safe_name(st.get('user') or '_'), safe_name(strings[0]))
        if os.path.exists(path):
            data = read_file(path)
            log('mw3: user file %s (%d bytes) sent' % (strings[0], len(data)))
            return mw3_reply(task, [bb(('blob', data))])
        # mpdata (stats) = 12288 bytes [u32 BE CRC-32 of the rest][12284 stats]. MW3 treats BD_NO_FILE as a new
        # player (fresh stats) - a made-up blank file would be rejected instead.
        debug('mw3: user file %s -> no file' % strings[0])
        return mw3_reply(task, error=BD_NO_FILE)
    if service == SVC_STORAGE and blobs and strings:                # upload / update a user file (stats: mpdata)
        folder = os.path.join(USER_FILES, safe_name(st.get('user') or '_'))
        os.makedirs(folder, exist_ok=True)
        path = os.path.join(folder, safe_name(strings[0]))
        data = bytes.fromhex(blobs[0])
        if os.path.exists(path):
            os.replace(path, path + '.prev')
        with open(path, 'wb') as f:
            f.write(data)
        file_id = int.from_bytes(hashlib.md5(path.encode()).digest()[:8], 'little') & 0x7fffffffffffffff
        log('mw3: stored user file %s (%d bytes)' % (strings[0], len(data)))
        return mw3_reply(task, [bb(('u64', file_id))])
    if service == SVC_STORAGE and blobs:
        debug('mw3: storage task %d with a blob but no name - not stored, args %s' % (task, short(args)))
    if service == 4 and task == 3:                                  # stats: read by entity -> one row per player
        # bdStatsInfo (0x44351C): [u64 entity][i64 rank][u64 value][string name][u32] + the leaderboard's Int32
        # columns (the count comes from the game's leaderboard definition; extra zeros are not read)
        ids = [v for t, v in args if t == 'uint64']
        cols = [('i32', 0)] * 32
        rows = [bb(('u64', e), ('i64', 1), ('u64', 0), ('str', st.get('user') or 'player'), ('u32', 0), *cols)
                for e in ids]
        return mw3_reply(task, rows)
    if service == 12 and task == 6:                                 # title utilities: server time
        return mw3_reply(task, [bb(('u32', int(time.time())))])
    # MW3 matchmaking (service 21). Find stays "empty OK": after a few failed searches MW3 hosts a session itself.
    if service == SVC_MW3_MATCHMAKING and task == 1:                # create -> 8-byte session id blob
        sid = os.urandom(8)
        SESSIONS_MW3[sid] = {'owner': id(st), 'user': st.get('user'), 'args': args}
        log('mw3: %s created session %s' % (st.get('user'), sid.hex()))
        return mw3_reply(task, [bb(('blob', sid))])
    if service == SVC_MW3_MATCHMAKING and task == 3:                # delete
        for v in [bytes.fromhex(v) for t, v in args if t == 'blob']:
            if SESSIONS_MW3.pop(v, None):
                log('mw3: session %s deleted' % v.hex())
    debug('mw3: service %d task %s -> empty OK' % (service, task))
    return mw3_reply(task)


# ---------------------------------------------------------------- lobby connection handling
def handle_lsg(st, enc, mtype, payload):
    CUR['bytes'] = st.get('bytes', False)
    if enc == 0 and mtype == LSG_LOGIN:
        ticket, bit = find_server_ticket(payload)
        if not ticket:
            log('lsg: login without our server ticket')
            debug(hexdump(payload))
            return
        st['key'] = ticket[12:36]
        st['user'] = ticket[36:100].split(b'\0')[0].decode('ascii', 'replace')
        log('lsg: %s logged in to the lobby%s' % (st['user'], ' (MW3)' if st.get('bytes') else ''))
        w = new_writer()
        w.data_type(BD_UINT64)
        w.raw(random.getrandbits(63), 64)
        st['sock'].sendall(lsg_encrypt(st['key'], LSG_CONNECTION_ID, w.tobytes()))
        return
    if enc == 1 and st.get('key'):
        _, plain = lsg_decrypt(st['key'], bytes([mtype]) + payload)   # read_frames split off the first byte
        # every encrypted client message is a task: [u32 hash][u8 service][typed u8 task][typed args]
        service, msg = plain[4], plain[5:]
        if st.get('bytes') and service == SVC_BANDWIDTH:
            # MW3: raw (untyped) task, answered as message 5 - a type-1 reply leaves the client's raw reply
            # buffer empty ("error 4") and MW3 keeps the default 64000 upload = may not host public matches
            st['sock'].sendall(lsg_encrypt(st['key'], LSG_SERVICE_TASK_REPLY, bandwidth_reply(st, plain[6:])))
            return
        fields = dwcore.decode_bytes(msg) if st.get('bytes') else dwcore.decode_typed(msg)
        task = fields[0][1] if fields else None
        args = fields[1:]
        debug('lsg: service %d task %s args %s' % (service, task, short(args)))
        st['sock'].sendall(lsg_encrypt(st['key'], LSG_TASK_REPLY, handle_task(st, service, task, args, msg)))
        return
    debug('lsg: message enc=%d type=%d %d bytes\n%s' % (enc, mtype, len(payload), hexdump(payload)))


def drop_sessions(owner):
    for table in (SESSIONS_MM, SESSIONS_MW3):
        for sid in [k for k, v in table.items() if v['owner'] == owner]:
            del table[sid]


def handle_conn(conns, s):
    st = conns[s]
    try:
        data = s.recv(65536)
    except OSError:
        data = b''
    if not data:
        debug('tcp %d close %s:%d' % (st['port'], st['addr'][0], st['addr'][1]))
        drop_sessions(id(st))
        del conns[s]
        s.close()
        return
    debug('tcp %d raw %d bytes\n%s' % (st['port'], len(data), hexdump(data, 4096)))
    st['buf'] += data
    # lobby connections start with an 8-byte header: MW2 (bit buffers) b4000000ffff0000, MW3 (byte buffers) c8...
    if not st.get('started') and len(st['buf']) >= 8 and st['buf'][4:6] == b'\xff\xff':
        st['bytes'] = st['buf'][0] == 0xc8
        st['buf'] = st['buf'][8:]
        st['lsg'] = True
    st['started'] = True
    frames, st['buf'] = dwcore.read_frames(st['buf'])
    for enc, mtype, payload in frames:
        if st['port'] == AUTH_PORT and enc == 0 and mtype == 18 and not st.get('lsg'):
            reply = auth_reply(payload)
            if reply:
                s.sendall(reply)
        else:
            handle_lsg(st, enc, mtype, payload)


# ---------------------------------------------------------------- UDP: IP / NAT discovery
def bd_addr(ip, port):
    """bdAddr: IPv4 (network order) + u16 port little endian"""
    return socket.inet_aton(ip) + struct.pack('<H', port)


def udp_reply(data, addr):
    """IP discovery (type 30 -> 31) and NAT type discovery (type 20 -> 21), protocol version 2. Players on the
    server's own PC / LAN are told the public IP (when set), so remote players can reach them."""
    if not data:
        return None
    ip = addr[0]
    if SETTINGS['public_ip'] and is_local(ip):
        addr = (SETTINGS['public_ip'], addr[1])
    if data[0] == 30:
        return bytes([31]) + struct.pack('<H', 2) + bd_addr(*addr)
    if data[0] == 20:
        # [21][u16 2][the client's mapped address][the server's ALTERNATE address]: the client expects the answers
        # to its "from another IP / port" tests from that second address (otherwise MW3 reports a Strict NAT)
        alt_ip = '127.0.0.2' if ip.startswith('127.') else (SETTINGS['public_ip'] or ip)
        return bytes([21]) + struct.pack('<H', 2) + bd_addr(*addr) + bd_addr(alt_ip, NAT_ALT_PORT)
    return None


def nat_alt_socket(client_ip, flags):
    """socket to answer a NAT test from: flags bit 0 = from another port, bit 1 = from another IP
    (127.0.0.2 is another loopback address on Windows)"""
    public = SETTINGS['public_ip'] or SETTINGS['bind']
    if flags & 2:
        ip = '127.0.0.2' if client_ip.startswith('127.') else public
    else:
        ip = '127.0.0.1' if client_ip.startswith('127.') else public
    key = (ip, NAT_ALT_PORT if flags & 1 else AUTH_PORT)
    if key not in NAT_ALT:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(key)
        NAT_ALT[key] = s
    return NAT_ALT[key]


def handle_udp(s, port, udp_seen):
    try:
        data, addr = s.recvfrom(65536)
    except OSError:                          # Windows: WSAECONNRESET after an ICMP "port unreachable"
        return
    if SETTINGS['bind'].startswith('127.') and not addr[0].startswith('127.'):         return                               # local-only server: 3074 / 3075 listen on 0.0.0.0 (see open_sockets)
    if len(data) >= 12 and data[4:12] == BW_COOKIE:      # MW3 bandwidth test upload: count only
        BW['packets'] += 1
        BW['bytes'] += len(data)
        return
    reply = udp_reply(data, addr)
    if data and data[0] == 20 and len(data) >= 4 and data[3] & 3 and reply:
        # NAT test asking for an answer from another port / IP: answering from that address = "Open NAT"
        try:
            nat_alt_socket(addr[0], data[3] & 3).sendto(reply, addr)
        except OSError as e:
            debug('udp NAT test flags %d: alternate send failed: %s' % (data[3], e))
        return
    if reply:
        s.sendto(reply, addr)
        if not udp_seen.get((addr, data[0])):
            udp_seen[(addr, data[0])] = True
            debug('udp %d: type %d from %s:%d answered' % (port, data[0], addr[0], addr[1]))
    else:
        debug('udp %d from %s:%d %d bytes\n%s' % (port, addr[0], addr[1], len(data), hexdump(data)))


# ---------------------------------------------------------------- main loop
def open_sockets():
    listeners, udps = {}, {}
    for p in [AUTH_PORT] + EXTRA_TCP:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if hasattr(socket, 'SO_EXCLUSIVEADDRUSE'):
                # Windows: SO_REUSEADDR would let a second server bind the same port and steal connections
                s.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            else:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((SETTINGS['bind'], p))
            s.listen(16)
            listeners[s] = p
        except OSError as e:
            log('tcp %d: %s' % (p, e))
    for p in EXTRA_UDP:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            address = SETTINGS['bind']
            if hasattr(socket, 'SO_EXCLUSIVEADDRUSE') and p in GAME_UDP_PORTS and address.startswith('127.'):
                # Windows: RPCS3 binds the game's own UDP socket on 0.0.0.0:3074, which is allowed next to our
                # 127.0.0.1:3074 - the game then sends from 127.0.0.1:3074 and our replies land in our own socket
                # (NAT type stays "...", stuck at "Fetching Playlists"). Holding 0.0.0.0 exclusively makes
                # the game take another port; packets from other PCs are still dropped (handle_udp).
                s.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                address = '0.0.0.0'
            s.bind((address, p))
            udps[s] = p
        except OSError as e:
            log('udp %d: %s' % (p, e))
    return listeners, udps


def serve():
    listeners, udps = open_sockets()
    if AUTH_PORT not in listeners.values():
        log('TCP port %d is in use - is the server already running?' % AUTH_PORT)
        return 1
    log('MW2 PS3 DemonWare server on %s (tcp %s, udp %s)%s' % (
        SETTINGS['bind'], ', '.join(map(str, sorted(listeners.values()))), ', '.join(map(str, sorted(udps.values()))),
        ', public IP %s' % SETTINGS['public_ip'] if SETTINGS['public_ip'] else ''))
    conns, udp_seen = {}, {}
    while True:
        ready, _, _ = select.select(list(listeners) + list(udps) + list(conns), [], [], 1.0)
        for s in ready:
            if s in listeners:
                c, addr = s.accept()
                conns[c] = {'port': listeners[s], 'addr': addr, 'buf': b'', 'sock': c}
                debug('tcp %d connect %s:%d' % (listeners[s], addr[0], addr[1]))
            elif s in udps:
                handle_udp(s, udps[s], udp_seen)
            else:
                try:
                    handle_conn(conns, s)
                except Exception:
                    # one bad message must not take the whole server down
                    log('tcp error, dropping connection:\n%s' % traceback.format_exc())
                    drop_sessions(id(conns.get(s)))
                    conns.pop(s, None)
                    s.close()


def main(argv=None):
    ap = argparse.ArgumentParser(description='MW2 PS3 community DemonWare server')
    ap.add_argument('--bind', default=SETTINGS['bind'],
                    help='address to listen on (default %(default)s; 0.0.0.0 for a public server)')
    ap.add_argument('--public-ip', default=SETTINGS['public_ip'],
                    help='public IP told to players on the server\'s own PC / LAN (public servers)')
    ap.add_argument('--log', default=SETTINGS['log'], help='log file (default %(default)s; "" = none)')
    ap.add_argument('--verbose', action='store_true', help='log every task and packet (hex dumps)')
    a = ap.parse_args(argv)
    SETTINGS.update(bind=a.bind, public_ip=a.public_ip, log=a.log, verbose=a.verbose)
    try:
        return serve()
    except KeyboardInterrupt:
        return 0


if __name__ == '__main__':
    sys.exit(main())
