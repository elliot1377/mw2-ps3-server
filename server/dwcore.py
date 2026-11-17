"""DemonWare building blocks for MW2 PS3 (reverse engineered from the BLES00686 EBOOT, see docs/PROTOCOL.md).

- Tiger-192 (the standard Tiger S-boxes: tiger_sboxes.bin, 4 x 256 big-endian u64)
- bdBitBuffer writer/reader (bits LSB first, optional 5-bit type tags; first bit = type checking on/off)
- NP ticket (Sony v2.1 / RPCN) parser
- bdAuthTicket packing (128 bytes, little endian)
- DW frame: u32 LE length | u8 encrypted (0) | u8 message type | bit buffer
"""
import os
import struct
import sys

# next to the script, or next to the .exe when built with PyInstaller
HERE = os.path.dirname(os.path.abspath(sys.executable if getattr(sys, 'frozen', False) else __file__))

# ---------------------------------------------------------------- Tiger-192 (Anderson & Biham), 3 passes, 0x01 padding
with open(os.path.join(HERE, 'tiger_sboxes.bin'), 'rb') as _f:
    _SB = _f.read()
T = [struct.unpack('>256Q', _SB[i * 2048:(i + 1) * 2048]) for i in range(4)]
M64 = (1 << 64) - 1


def _round(a, b, c, x, mul):
    c ^= x
    a = (a - (T[0][c & 0xff] ^ T[1][(c >> 16) & 0xff] ^ T[2][(c >> 32) & 0xff] ^ T[3][(c >> 48) & 0xff])) & M64
    b = (b + (T[3][(c >> 8) & 0xff] ^ T[2][(c >> 24) & 0xff] ^ T[1][(c >> 40) & 0xff] ^ T[0][(c >> 56) & 0xff])) & M64
    b = (b * mul) & M64
    return a, b, c


def _pass(a, b, c, x, mul):
    for i in range(8):
        r = i % 3
        if r == 0:
            a, b, c = _round(a, b, c, x[i], mul)
        elif r == 1:
            b, c, a = _round(b, c, a, x[i], mul)
        else:
            c, a, b = _round(c, a, b, x[i], mul)
    return a, b, c


def _schedule(x):
    x = list(x)
    x[0] = (x[0] - (x[7] ^ 0xA5A5A5A5A5A5A5A5)) & M64
    x[1] ^= x[0]
    x[2] = (x[2] + x[1]) & M64
    x[3] = (x[3] - (x[2] ^ ((~x[1] & M64) << 19 & M64))) & M64
    x[4] ^= x[3]
    x[5] = (x[5] + x[4]) & M64
    x[6] = (x[6] - (x[5] ^ ((~x[4] & M64) >> 23))) & M64
    x[7] ^= x[6]
    x[0] = (x[0] + x[7]) & M64
    x[1] = (x[1] - (x[0] ^ ((~x[7] & M64) << 19 & M64))) & M64
    x[2] ^= x[1]
    x[3] = (x[3] + x[2]) & M64
    x[4] = (x[4] - (x[3] ^ ((~x[2] & M64) >> 23))) & M64
    x[5] ^= x[4]
    x[6] = (x[6] + x[5]) & M64
    x[7] = (x[7] - (x[6] ^ 0x0123456789ABCDEF)) & M64
    return x


def tiger(data):
    a, b, c = 0x0123456789ABCDEF, 0xFEDCBA9876543210, 0xF096A5B4C3B2E187
    msg = data + b'\x01' + b'\x00' * ((55 - len(data)) % 64) + struct.pack('<Q', len(data) * 8)
    for off in range(0, len(msg), 64):
        x = struct.unpack('<8Q', msg[off:off + 64])
        aa, bb, cc = a, b, c
        a, b, c = _pass(a, b, c, x, 5)
        x = _schedule(x)
        c, a, b = _pass(c, a, b, x, 7)
        x = _schedule(x)
        b, c, a = _pass(b, c, a, x, 9)
        a ^= aa
        b = (b - bb) & M64
        c = (c + cc) & M64
    return struct.pack('<3Q', a, b, c)


def initial_vector(seed):
    """bdCryptoUtils::calculateInitialVector (0x49cb88): Tiger of the seed (4 bytes LE), first 8 bytes"""
    return tiger(struct.pack('<I', seed))[:8]


# ---------------------------------------------------------------- bdBitBuffer
BD_UINT32 = 8


class BitWriter:
    def __init__(self, type_checking=True):
        self.bits = []
        self.types = type_checking
        self.bits.append(1 if type_checking else 0)

    def raw(self, value, nbits):
        for i in range(nbits):
            self.bits.append((value >> i) & 1)

    def data_type(self, t):
        if self.types:
            self.raw(t, 5)

    def u32(self, v):
        self.data_type(BD_UINT32)
        self.raw(v & 0xffffffff, 32)

    def raw_bytes(self, data):
        for b in data:
            self.raw(b, 8)

    def tobytes(self):
        out = bytearray((len(self.bits) + 7) // 8)
        for i, bit in enumerate(self.bits):
            if bit:
                out[i >> 3] |= 1 << (i & 7)
        return bytes(out)


class BitReader:
    def __init__(self, data):
        self.data, self.pos = data, 0
        self.types = self.raw(1) == 1

    def raw(self, nbits):
        v = 0
        for i in range(nbits):
            byte = self.data[self.pos >> 3] if (self.pos >> 3) < len(self.data) else 0
            v |= ((byte >> (self.pos & 7)) & 1) << i
            self.pos += 1
        return v

    def data_type(self):
        return self.raw(5) if self.types else None

    def u32(self):
        t = self.data_type()
        return t, self.raw(32)


# ---------------------------------------------------------------- bdByteBuffer (MW3 / newer DemonWare)
# Same type ids as the bit buffer, but byte aligned: [u8 type][value, little endian]; no leading type-check bit.
class ByteWriter:
    def __init__(self, type_checking=True):
        self.out = bytearray()
        self.types = type_checking

    def raw(self, value, nbits):
        n = max(1, (nbits + 7) // 8)
        self.out += (value & ((1 << (8 * n)) - 1)).to_bytes(n, 'little')

    def data_type(self, t):
        if self.types:
            self.out.append(t)

    def u32(self, v):
        self.data_type(BD_UINT32)
        self.raw(v & 0xffffffff, 32)

    def raw_bytes(self, data):
        self.out += data

    def tobytes(self):
        return bytes(self.out)


BB_SIZES = {1: 1, 2: 1, 3: 1, 4: 2, 5: 2, 6: 2, 7: 4, 8: 4, 9: 8, 10: 8, 13: 4, 14: 8}


def decode_bytes(data, max_fields=40):
    """best-effort decode of a typed byte buffer into [(type name, value)]"""
    out, p = [], 0
    while p < len(data) and len(out) < max_fields:
        t = data[p]
        p += 1
        if t in BB_SIZES:
            n = BB_SIZES[t]
            if p + n > len(data):
                break
            v = int.from_bytes(data[p:p + n], 'little')
            if t in (5, 7, 9) and v >> (8 * n - 1):
                v -= 1 << (8 * n)
            out.append((BD_TYPES[t][0], v))
            p += n
        elif t == 16:                                   # string, 0 terminated
            e = data.find(b'\0', p)
            e = len(data) if e < 0 else e
            out.append(('string', data[p:e].decode('latin-1')))
            p = e + 1
        elif t == 19:                                   # blob: typed u32 length + bytes
            if p + 5 > len(data):
                break
            n = int.from_bytes(data[p + 1:p + 5], 'little')
            out.append(('blob', data[p + 5:p + 5 + n].hex()))
            p += 5 + n
        else:
            out.append(('type%d' % t, data[p - 1:p + 8].hex()))
            break
    return out


# ---------------------------------------------------------------- frames
def frame(msg_type, payload):
    body = b'\x00' + bytes([msg_type]) + payload
    return struct.pack('<I', len(body)) + body


def read_frames(buf):
    """split complete frames off buf -> (list of (encrypted, msg_type, payload), rest)"""
    out = []
    while len(buf) >= 4:
        n = struct.unpack('<I', buf[:4])[0]
        if len(buf) < 4 + n:
            break
        body = buf[4:4 + n]
        buf = buf[4 + n:]
        if n >= 2:
            out.append((body[0], body[1], body[2:]))
    return out, buf


# ---------------------------------------------------------------- bdAuthTicket (128 bytes packed, LE)
AUTH_TICKET_MAGIC = 0xEFBDADDE


def pack_auth_ticket(title_id, issued, expires, license_id, user_id, username, session_key):
    t = struct.pack('<IBIIIQQ', AUTH_TICKET_MAGIC, 0, title_id, issued, expires, license_id, user_id)
    t += username.encode('ascii', 'replace')[:63].ljust(64, b'\0')
    t += session_key
    t += b'\0' * (128 - len(t))
    return t


# ---------------------------------------------------------------- typed bit buffer decoding (debug)
BD_TYPES = {1: ('bool', 1), 2: ('char8', 8), 3: ('uchar8', 8), 4: ('wchar16', 16), 5: ('int16', 16),
            6: ('uint16', 16), 7: ('int32', 32), 8: ('uint32', 32), 9: ('int64', 64), 10: ('uint64', 64),
            13: ('float32', 32), 14: ('float64', 64)}


def decode_typed(data, max_fields=40):
    """best-effort decode of a type-checked bit buffer into [(type name, value)]"""
    br = BitReader(data)
    out = []
    if not br.types:
        return [('no type checking', data.hex())]
    while br.pos + 5 <= len(data) * 8 and len(out) < max_fields:
        t = br.raw(5)
        if t in BD_TYPES:
            name, n = BD_TYPES[t]
            out.append((name, br.raw(n)))
        elif t == 16:                       # string: 8-bit chars, 0 terminated
            s = bytearray()
            while br.pos + 8 <= len(data) * 8:
                c = br.raw(8)
                if not c:
                    break
                s.append(c)
            out.append(('string', s.decode('latin-1')))
        elif t == 19:                       # blob: typed u32 length + bytes
            br.raw(5)                       # the length's type tag
            n = br.raw(32)
            out.append(('blob', bytes(br.raw(8) for _ in range(min(n, 4096))).hex()))
        elif t == 0:
            break
        else:
            out.append(('type%d' % t, None))
            break
    return out
