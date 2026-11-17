"""
NP (X-I-5) ticket parser + signature verification.

  * RPCN tickets : SHA-224 over the body section (header included), secp224k1, RPCN public key.
  * PSN tickets  : SHA-1 over everything before the signature value, secp192r1, per-title keys.
                   Disabled by default, a PSN
                   ticket is then only checked for timestamp / service id, and its signature is skipped.
"""
import base64
import hashlib
import re
import struct
import time
from dataclasses import dataclass

# Flip to True to verify PSN signatures.
PSN_VERIFICATION_ENABLED = False

RPCN_SIGNER = 'RPCN'
TIMESTAMP_TOLERANCE_MS = 3600 * 1000  # RPCN is picky about this

T_BODY, T_FOOTER, T_EMPTY, T_BINARY = 0x3000, 0x3002, 0x0000, 0x0008


# --------------------------------------------------------------------------------------------------
# curves + ECDSA
# --------------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class EcCurve:
    name: str
    p: int
    a: int
    b: int
    gx: int
    gy: int
    n: int

    @property
    def field_bytes(self):
        return (self.p.bit_length() + 7) // 8


_CURVES = {}  # name or OID -> EcCurve


def _add_curve(oid, names, p, a, b, gx, gy, n):
    c = EcCurve(names[0], int(p, 16), int(a, 16), int(b, 16), int(gx, 16), int(gy, 16), int(n, 16))
    for k in (oid, *names):
        _CURVES[k.lower()] = c


# secp192r1 / NIST P-192  (PSN legacy tickets)
_add_curve('1.2.840.10045.3.1.1', ['secp192r1', 'prime192v1', 'nistp192'],
           'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF',
           'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC',
           '64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1',
           '188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012',
           '07192B95FFC8DA78631011ED6B24CDD573F977A11E794811',
           'FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831')
# secp224k1 (RPCN)
_add_curve('1.3.132.0.32', ['secp224k1'],
           'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFE56D', '0', '5',
           'A1455B334DF099DF30FC28A169A467E9E47075A90F7E650EB6B7A45C',
           '7E089FED7FBA344282CAFBD6F7E319F7C0B0BD59E2CA4BDB556D61A5',
           '010000000000000000000000000001DCE8D2EC6184CAF0A971769FB1F7')

# Extra curves, only used by the key finder when hunting for the right RPCN curve.
_add_curve('1.3.132.0.33', ['secp224r1', 'nistp224'],
           'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001',
           'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE',
           'B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4',
           'B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21',
           'BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34',
           'FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D')


def curve_from_name(name):
    try:
        return _CURVES[name.lower()]
    except KeyError:
        raise ValueError(f'unsupported curve: {name}') from None


def is_on_curve(c, pt):
    if pt is None:
        return False
    x, y = pt
    if not (0 <= x < c.p and 0 <= y < c.p):
        return False
    return (y * y - (x * x * x + c.a * x + c.b)) % c.p == 0


# Jacobian coordinates (x = X/Z^2, y = Y/Z^3, Z == 0 is infinity)
_JINF = (1, 1, 0)


def _to_affine(c, j):
    X, Y, Z = j
    if Z == 0:
        return None
    zi = pow(Z, -1, c.p)
    zi2 = zi * zi % c.p
    return (X * zi2 % c.p, Y * zi2 % c.p * zi % c.p)


def _twice(c, j):
    X, Y, Z = j
    if Z == 0 or Y == 0:
        return _JINF
    p = c.p
    xx, yy = X * X % p, Y * Y % p
    yyyy, zz = yy * yy % p, Z * Z % p
    s = 4 * X * yy % p
    m = (3 * xx + c.a * (zz * zz % p)) % p
    x3 = (m * m - 2 * s) % p
    return (x3, (m * (s - x3) - 8 * yyyy) % p, 2 * Y * Z % p)


def _add_mixed(c, j, q):
    if q is None:
        return j
    X, Y, Z = j
    if Z == 0:
        return (q[0], q[1], 1)
    p = c.p
    z1z1 = Z * Z % p
    u2 = q[0] * z1z1 % p
    s2 = q[1] * Z % p * z1z1 % p
    h, r = (u2 - X) % p, (s2 - Y) % p
    if h == 0:
        return _twice(c, j) if r == 0 else _JINF
    hh = h * h % p
    hhh = h * hh % p
    v = X * hh % p
    x3 = (r * r - hhh - 2 * v) % p
    return (x3, (r * (v - x3) - Y * hhh) % p, Z * h % p)


def _add_affine(c, a, b):
    if a is None:
        return b
    if b is None:
        return a
    p = c.p
    if a[0] == b[0]:
        if a[1] != b[1] or a[1] == 0:
            return None
        return _to_affine(c, _twice(c, (a[0], a[1], 1)))
    l = (b[1] - a[1]) * pow(b[0] - a[0], -1, p) % p
    x = (l * l - a[0] - b[0]) % p
    return (x, (l * (a[0] - x) - a[1]) % p)


def _multiply_two(c, p1, j, p2, k):
    """p1 * j + p2 * k (Shamir's trick). Returns an affine point or None for infinity."""
    both = _add_affine(c, p1, p2)
    r = _JINF
    for i in range(max(j.bit_length(), k.bit_length()) - 1, -1, -1):
        r = _twice(c, r)
        jb, kb = (j >> i) & 1, (k >> i) & 1
        if jb:
            r = _add_mixed(c, r, both if kb else p1)
        elif kb:
            r = _add_mixed(c, r, p2)
    return _to_affine(c, r)


def _hash_to_int(h, n):
    """Leftmost bits of the hash, as per the ECDSA standard."""
    z = int.from_bytes(h, 'big')
    extra = len(h) * 8 - n.bit_length()
    return z >> extra if extra > 0 else z


def ecdsa_verify(curve, q, hashed, r, s):
    """Standard ECDSA verification of (r, s) over an already hashed message."""
    n = curve.n
    if not (0 < r < n and 0 < s < n) or not is_on_curve(curve, q):
        return False
    w = pow(s, -1, n)
    pt = _multiply_two(curve, (curve.gx, curve.gy), _hash_to_int(hashed, n) * w % n, q, r * w % n)
    return pt is not None and pt[0] % n == r


# --------------------------------------------------------------------------------------------------
# DER signature + public key
# --------------------------------------------------------------------------------------------------
def _tlv(buf, pos):
    """-> (tag, content_start, content_end)"""
    tag, ln = buf[pos], buf[pos + 1]
    pos += 2
    if ln & 0x80:
        nb = ln & 0x7F
        if not 1 <= nb <= 4:
            raise ValueError('bad DER length')
        ln = int.from_bytes(buf[pos:pos + nb], 'big')
        pos += nb
    if pos + ln > len(buf):
        raise ValueError('DER overrun')
    return tag, pos, pos + ln


def _try_parse_sig(der):
    """DER SEQUENCE { INTEGER r, INTEGER s } with nothing after it."""
    try:
        tag, s0, e0 = _tlv(der, 0)
        if tag != 0x30 or e0 != len(der):
            return None
        t1, s1, e1 = _tlv(der, s0)
        t2, s2, e2 = _tlv(der, e1)
        if t1 != 2 or t2 != 2 or e2 != e0 or s1 == e1 or s2 == e2:
            return None
        return int.from_bytes(der[s1:e1], 'big'), int.from_bytes(der[s2:e2], 'big')
    except (IndexError, ValueError):
        return None


def parse_signature(sig):
    """PSN sometimes appends 1-2 stray bytes after the DER blob: drop up to 2 trailing bytes."""
    for _ in range(3):
        rs = _try_parse_sig(sig)
        if rs:
            return rs
        sig = sig[:-1]
    raise ValueError('invalid or unrecoverable DER signature')


def _decode_oid(b):
    parts = [b[0] // 40, b[0] % 40]
    v = 0
    for x in b[1:]:
        v = (v << 7) | (x & 0x7F)
        if not x & 0x80:
            parts.append(v)
            v = 0
    return '.'.join(map(str, parts))


@dataclass(frozen=True)
class EcPublicKey:
    curve: EcCurve
    q: tuple

    def __post_init__(self):
        if not is_on_curve(self.curve, self.q):
            raise ValueError('public key point is not on the curve')

    @staticmethod
    def from_xy_hex(curve_name, xhex, yhex):
        return EcPublicKey(curve_from_name(curve_name), (int(xhex, 16), int(yhex, 16)))

    @staticmethod
    def from_pem(pem):
        b64 = ''.join(l.strip() for l in pem.splitlines() if l.strip() and not l.startswith('-----'))
        return EcPublicKey.from_spki(base64.b64decode(b64))

    @staticmethod
    def from_spki(der):
        _, s, e = _tlv(der, 0)                       # SubjectPublicKeyInfo
        _, as_, ae = _tlv(der, s)                    # AlgorithmIdentifier
        t, os_, oe = _tlv(der, as_)
        if t != 6 or _decode_oid(der[os_:oe]) != '1.2.840.10045.2.1':
            raise ValueError('not an EC public key')
        t, cs, ce = _tlv(der, oe)
        if t != 6:
            raise NotImplementedError('explicit EC parameters are not supported, only named curves')
        curve = curve_from_name(_decode_oid(der[cs:ce]))
        t, bs, be = _tlv(der, ae)                    # BIT STRING: 1 byte unused-bits + point
        pt = der[bs + 1:be]
        size = curve.field_bytes
        if t != 3 or len(pt) != 1 + 2 * size or pt[0] != 4:
            raise NotImplementedError('only uncompressed EC points are supported')
        return EcPublicKey(curve, (int.from_bytes(pt[1:1 + size], 'big'), int.from_bytes(pt[1 + size:], 'big')))

    def verify(self, hashed, r, s):
        return ecdsa_verify(self.curve, self.q, hashed, r, s)


# --------------------------------------------------------------------------------------------------
# keys
# --------------------------------------------------------------------------------------------------
RPCN_KEY = EcPublicKey.from_pem(
    "-----BEGIN PUBLIC KEY-----\n"
    "ME4wEAYHKoZIzj0CAQYFK4EEACADOgAEsHvA8K3bl2V+nziQOejSucl9wqMdMELn\n"
    "0Eebk9gcQrCr32xCGRox4x+TNC+PAzvVKcLFf9taCn0=\n"
    "-----END PUBLIC KEY-----"
)


def _psn(xhex, yhex):
    return EcPublicKey.from_xy_hex('secp192r1', xhex, yhex)


PSN_DEFAULT_KEY = _psn('39c62d061d4ee35c5f3f7531de0af3cf918346526edac727',
                       'a5d578b55113e612bf1878d4cc939d61a41318403b5bdf86')

# Add as many entries as necessary
PSN_TITLE_KEYS = {}


def get_psn_signing_keys(title_id):
    """None = PSN verification disabled (signature skipped)."""
    if not PSN_VERIFICATION_ENABLED:
        return None
    return list(PSN_TITLE_KEYS.get((title_id or '').upper(), [PSN_DEFAULT_KEY]))


# --------------------------------------------------------------------------------------------------
# ticket parsing + verification
# --------------------------------------------------------------------------------------------------
_TITLE_ID_RE = re.compile(r'(?<=-)[A-Z0-9]{9}(?=_)')
_FIELD_NAMES = ['serial', 'issuer', 'issued', 'expires', 'user_id', 'online_id', 'region', 'domain',
                'service_id', 'status', 'cookie']


def _cstr(b):
    return b.split(b'\0')[0].decode('utf-8', 'replace')


def _split_ticket(data):
    """
    Locate the ticket (u32 0x21010000) and cut it into its parts.
    layout: version u16 | header u32 | length u16 | body (0x3000) | footer (0x3002)
    footer: binary(signer id) | binary(signature)
    Returns a dict, or None if there is no (complete) ticket.
    """
    i = data.find(b'\x21\x01\x00\x00')
    if i < 0 or len(data) < i + 12:
        return None
    size = struct.unpack('>H', data[i + 6:i + 8])[0]
    if len(data) < i + 8 + size:
        return None
    t = data[i:i + 8 + size]                     # trimmed: trailing bytes after the ticket are ignored

    btype, blen = struct.unpack('>HH', t[8:12])
    if btype not in (T_BODY, T_EMPTY):
        return None
    body_end = 12 + blen
    if len(t) < body_end + 4:
        return None
    ftype, flen = struct.unpack('>HH', t[body_end:body_end + 4])
    if ftype not in (T_FOOTER, T_EMPTY) or body_end + 4 + flen > len(t):
        return None

    # footer = two binary fields: signer identifier, then the DER signature
    p = body_end + 4
    fend = p + flen
    try:
        t1, n1 = struct.unpack('>HH', t[p:p + 4])
        signer = t[p + 4:p + 4 + n1]
        p += 4 + n1
        t2, n2 = struct.unpack('>HH', t[p:p + 4])
        sig_off = p + 4
        if sig_off + n2 > fend or t1 not in (T_BINARY, T_EMPTY) or t2 not in (T_BINARY, T_EMPTY):
            return None
    except struct.error:
        return None

    return {
        'ticket': t,
        'body': t[12:body_end],                  # body content (fields)
        'full_body': t[8:body_end],              # body incl. its 4 byte section header  (RPCN signs this)
        'signer': _cstr(signer),
        'sig': t[sig_off:sig_off + n2],
        'pre_sig': t[:sig_off],                  # everything before the signature value (PSN signs this)
    }


def _parse_body_fields(body):
    fields, p = [], 0
    while p + 4 <= len(body):
        _, n = struct.unpack('>HH', body[p:p + 4])
        fields.append(body[p + 4:p + 4 + n])
        p += 4 + n
    return fields


def verify_np_ticket(parts, title_id):
    """
    Check the signature of a split ticket.
    Returns (checked, valid, hash_name, curve_name):
      checked=False -> signature not verified (PSN verification disabled), valid is then None.
    """
    try:
        r, s = parse_signature(parts['sig'])
    except ValueError:
        sig_ok = False
        r = s = 0
    else:
        sig_ok = True

    if parts['signer'].upper() == RPCN_SIGNER:
        h = hashlib.sha224(parts['full_body']).digest()
        return True, sig_ok and RPCN_KEY.verify(h, r, s), 'SHA224', 'secp224k1'

    keys = get_psn_signing_keys(title_id)
    if keys is None:                              # PSN verification disabled
        return False, None, 'SHA1', 'secp192r1'
    h = hashlib.sha1(parts['pre_sig']).digest()
    return True, sig_ok and any(k.verify(h, r, s) for k in keys), 'SHA1', 'secp192r1'


def parse_np_ticket(data, verify=True, service_id_criteria=None, now_ms=None):
    """
    Find the ticket (u32 0x21010000), read its first section's fields in order and verify its signature.

    Extra keys on top of the raw fields:
      title_id, signer, signed_by_rpcn, hash, curve,
      timestamp_valid, service_id_valid,
      signature_checked (False when PSN verification is disabled), signature_valid (None if not checked),
      valid  (timestamp + service id + signature; a skipped PSN signature counts as ok)
    Returns None if no complete ticket is found.
    """
    parts = _split_ticket(data)
    if parts is None:
        return None

    info = {k: v for k, v in zip(_FIELD_NAMES, _parse_body_fields(parts['body']))}
    info['online_id'] = _cstr(info.get('online_id', b''))
    info['user_id'] = struct.unpack('>Q', info['user_id'])[0] if len(info.get('user_id', b'')) == 8 else 0

    service_id = _cstr(info.get('service_id', b''))
    m = _TITLE_ID_RE.search(service_id)
    info['title_id'] = m.group(0) if m else None
    info['signer'] = parts['signer']
    info['signed_by_rpcn'] = parts['signer'].upper() == RPCN_SIGNER

    # timestamps are u64 big endian, in milliseconds
    now = int(time.time() * 1000) if now_ms is None else now_ms
    issued = int.from_bytes(info.get('issued', b''), 'big')
    expires = int.from_bytes(info.get('expires', b''), 'big')
    info['timestamp_valid'] = (len(info.get('issued', b'')) == 8 and len(info.get('expires', b'')) == 8
                               and issued <= now + TIMESTAMP_TOLERANCE_MS
                               and expires >= now - TIMESTAMP_TOLERANCE_MS)
    info['service_id_valid'] = not service_id_criteria or service_id_criteria in service_id

    if verify:
        checked, ok, hash_name, curve_name = verify_np_ticket(parts, info['title_id'])
    else:
        checked, ok, hash_name, curve_name = False, None, '', ''
    info.update(signature_checked=checked, signature_valid=ok, hash=hash_name, curve=curve_name)

    info['valid'] = bool(info['timestamp_valid'] and info['service_id_valid'] and ok is not False)
    
    if not info['valid']:
        print(
            f"[NP] Invalid ticket: "
            f"signer={info['signer']}, "
            f"title_id={info['title_id']}, "
            f"timestamp={info['timestamp_valid']}, "
            f"service_id={info['service_id_valid']}, "
            f"signature={info['signature_valid']}"
        )

        guess_ticket_signing_key(parts)
        return None

    return info


# --------------------------------------------------------------------------------------------------
# key finder
#
# An ECDSA signature (r, s) over hash z has at most 4 candidate public keys
#       Q = r^-1 * (s*R - z*G)      with R = (r or r+n, either y parity)
# One ticket therefore cannot tell you the key, but two or more tickets signed by the same key share
# exactly one candidate. The same trick finds the right curve / hash: on a wrong curve or hash the
# candidates of different tickets never coincide.
# --------------------------------------------------------------------------------------------------
def guess_ticket_signing_key(parts):
    try:
        r, s = parse_signature(parts['sig'])

        if parts['signer'].upper() == RPCN_SIGNER:
            curve = curve_from_name('secp224k1')
            hash_name = 'sha224'
            message = parts['full_body']
        else:
            curve = curve_from_name('secp192r1')
            hash_name = 'sha1'
            message = parts['pre_sig']

        hashed = hashlib.new(hash_name, message).digest()
        candidates = recover_public_keys(curve, hashed, r, s)

        if not candidates:
            print('[NP] No signing key candidates found.')
            return

        for x, y in candidates:
            size = curve.field_bytes * 2
            print(
                f'[NP] Possible signing key '
                f'({curve.name}, {hash_name}):\n'
                f'X: {x:0{size}x}\n'
                f'Y: {y:0{size}x}'
            )

    except (ValueError, IndexError) as ex:
        print(f'[NP] Unable to recover signing key: {ex}')


def ressol(a, p):
    """Square root of a mod odd prime p (Tonelli-Shanks, p = 3 mod 4 shortcut). None if a is a non-residue."""
    a %= p
    if a == 0:
        return 0
    if pow(a, (p - 1) >> 1, p) != 1:
        return None
    if p & 3 == 3:
        return pow(a, (p + 1) >> 2, p)
    q, e = p - 1, 0
    while q & 1 == 0:
        q >>= 1
        e += 1
    z = 2
    while pow(z, (p - 1) >> 1, p) != p - 1:
        z += 1
    m, c, t, r = e, pow(z, q, p), pow(a, q, p), pow(a, (q + 1) >> 1, p)
    while t != 1:
        i, tt = 0, t
        while tt != 1:
            tt = tt * tt % p
            i += 1
            if i == m:
                return None
        b = pow(c, 1 << (m - i - 1), p)
        m, c = i, b * b % p
        t, r = t * c % p, r * b % p
    return r


def _point_from_x(c, x, odd):
    if x >= c.p:
        return None
    beta = ressol(x * x * x + c.a * x + c.b, c.p)
    if beta is None:
        return None
    if (beta & 1) != odd:
        beta = (c.p - beta) % c.p
    return (x, beta)


def recover_public_keys(curve, hashed, r, s, verify=True):
    """All public keys (x, y) that make (r, s) a valid signature over `hashed` (up to 4)."""
    n = curve.n
    if not (0 < r < n and 0 < s < n):
        return []
    r_inv = pow(r, -1, n)
    z = _hash_to_int(hashed, n)
    g = (curve.gx, curve.gy)
    found = []
    for j in range(4):
        rp = _point_from_x(curve, r + n if j >> 1 else r, bool(j & 1))
        if rp is None:
            continue
        q = _multiply_two(curve, g, (-z * r_inv) % n, rp, s * r_inv % n)
        if q is None or (verify and not ecdsa_verify(curve, q, hashed, r, s)):
            continue
        if q not in found:
            found.append(q)
    return found


@dataclass(frozen=True)
class KeyCandidate:
    curve: str
    hash: str
    point: tuple
    count: int      # number of tickets that agree on this point
    total: int      # number of tickets examined

    def xy_hex(self):
        size = curve_from_name(self.curve).field_bytes * 2
        return f'{self.point[0]:0{size}x}', f'{self.point[1]:0{size}x}'


def ticket_signature_input(data):
    """-> (message, r, s, title_id) used for key hunting; the message is what the signer hashes."""
    parts = _split_ticket(data)
    if parts is None:
        return None
    r, s = parse_signature(parts['sig'])
    message = parts['full_body'] if parts['signer'].upper() == RPCN_SIGNER else parts['pre_sig']
    fields = _parse_body_fields(parts['body'])
    m = _TITLE_ID_RE.search(_cstr(fields[8])) if len(fields) > 8 else None   # field 8 = service id
    return message, r, s, (m.group(0) if m else None)


def find_signing_key(tickets, curves=None, hashes=('sha1', 'sha224'), min_count=2):
    """
    Hunt for the public key shared by `tickets` (raw ticket bytes, all signed by the SAME key, so group
    them per title id first, see find_signing_keys_by_title).
    Tries every (curve, hash) and returns the points that at least `min_count` tickets agree on, best
    first. Needs >= 2 usable tickets; a wrong curve/hash yields no agreement.
    """
    sigs = []
    for t in tickets:
        try:
            si = ticket_signature_input(t)
        except ValueError:
            si = None
        if si:
            sigs.append(si[:3])
    if len(sigs) < 2:
        raise ValueError('need at least 2 tickets signed by the same key')
    curves = sorted({c.name for c in _CURVES.values()}) if curves is None else curves

    out = []
    for cname in curves:
        c = curve_from_name(cname)
        for hname in hashes:
            tally = {}
            for msg, r, s in sigs:
                h = hashlib.new(hname, msg).digest()
                for q in recover_public_keys(c, h, r, s):
                    tally[q] = tally.get(q, 0) + 1
            out += [KeyCandidate(c.name, hname, q, k, len(sigs)) for q, k in tally.items() if k >= min_count]
    return sorted(out, key=lambda k: -k.count)


def find_signing_keys_by_title(tickets, **kw):
    """Group tickets by (signer, title id) and run the finder on each group with >= 2 tickets."""
    groups = {}
    for t in tickets:
        parts = _split_ticket(t)
        if parts is None:
            continue
        si = ticket_signature_input(t)
        groups.setdefault((parts['signer'], si[3] if si else None), []).append(t)
    return {k: find_signing_key(v, **kw) for k, v in groups.items() if len(v) >= 2}