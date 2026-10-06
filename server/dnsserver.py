"""MW2 PS3 community DNS (for real PS3s): answers the DemonWare / IWNet host names with the server's IP and forwards
every other query to a normal upstream DNS, so PSN, the store etc. keep working on a PS3 that uses this DNS.

    python3 dnsserver.py --ip <public ip of the DW server> [--bind 0.0.0.0] [--port 53] [--upstream 1.1.1.1]

No extra packages needed.
"""
import argparse
import datetime
import socket
import struct
import threading
import time

REDIRECT = [
    'mw2-ps3-auth.mmp3.demonware.net',
    'mw2-ps3-lsg.live.mmp3.demonware.net',
    'mw2-ps3-lsg.cert.mmp3.demonware.net',
    'mw2-ps3-lsg.dev.mmp3.demonware.net',
    'mw2-stun.us.demonware.net',
    'mw2-stun.eu.demonware.net',
    'auth1.ps3.iw4.iwnet.infinityward.com',
    'match1.ps3.iw4.iwnet.infinityward.com',
    'blob1.ps3.iw4.iwnet.infinityward.com',
    'team1.ps3.iw4.iwnet.infinityward.com',
    'ip1.ps3.iw4.iwnet.infinityward.com',
    'log1.ps3.iw4.iwnet.infinityward.com',
    'web1.ps3.iw4.iwnet.infinityward.com',
]


def log(msg):
    print('%s %s' % (datetime.datetime.now().strftime('%H:%M:%S'), msg), flush=True)


def parse_question(pkt):
    """-> (name, qtype, end offset of the question) or None"""
    try:
        p, labels = 12, []
        while pkt[p]:
            n = pkt[p]
            labels.append(pkt[p + 1:p + 1 + n].decode('ascii', 'replace'))
            p += 1 + n
        qtype = struct.unpack('>H', pkt[p + 1:p + 3])[0]
        return '.'.join(labels).lower(), qtype, p + 5
    except (IndexError, struct.error):
        return None


def answer_a(pkt, qend, ip, qtype):
    tid = pkt[:2]
    flags = struct.pack('>H', 0x8180)           # response, recursion desired + available, no error
    if qtype == 1:
        header = tid + flags + struct.pack('>HHHH', 1, 1, 0, 0)
        rr = b'\xc0\x0c' + struct.pack('>HHIH', 1, 1, 60, 4) + socket.inet_aton(ip)
    else:                                       # AAAA etc. for our names: no answer (forces IPv4)
        header = tid + flags + struct.pack('>HHHH', 1, 0, 0, 0)
        rr = b''
    return header + pkt[12:qend] + rr


def forward(pkt, upstream):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    try:
        s.sendto(pkt, (upstream, 53))
        return s.recvfrom(4096)[0]
    except OSError:
        return None
    finally:
        s.close()


def main():
    ap = argparse.ArgumentParser(description='MW2 PS3 community DNS')
    ap.add_argument('--ip', required=True, help='public IP of the DemonWare server')
    ap.add_argument('--bind', default='0.0.0.0', help='address to listen on (default %(default)s)')
    ap.add_argument('--port', type=int, default=53, help='UDP port (default %(default)s)')
    ap.add_argument('--upstream', default='1.1.1.1', help='DNS for every other name (default %(default)s)')
    a = ap.parse_args()
    redirect = set(REDIRECT)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((a.bind, a.port))
    log('MW2 PS3 DNS on %s:%d -> %s (upstream %s)' % (a.bind, a.port, a.ip, a.upstream))

    # abuse protection for a home connection: per-IP rate limit, no ANY / zone transfer / oversized answers
    rate = {}                                   # ip -> (window start, count)
    lock = threading.Lock()
    FORWARD_TYPES = {1, 28, 5, 12, 15, 33, 16}  # A, AAAA, CNAME, PTR, MX, SRV, TXT

    def allowed(ip):
        now = time.time()
        with lock:
            start, n = rate.get(ip, (now, 0))
            if now - start > 10:
                start, n = now, 0
            n += 1
            rate[ip] = (start, n)
            return n <= 60                      # 60 queries / 10 s per address

    def handle(pkt, addr):
        q = parse_question(pkt)
        if not q or not allowed(addr[0]):
            return
        if q[0] in redirect:
            log('%s asked %s -> %s' % (addr[0], q[0], a.ip))
            sock.sendto(answer_a(pkt, q[2], a.ip, q[1]), addr)
            return
        if q[1] not in FORWARD_TYPES:
            return
        reply = forward(pkt, a.upstream)
        if reply and len(reply) <= 1232:        # no large (amplifying) answers
            sock.sendto(reply, addr)

    while True:
        pkt, addr = sock.recvfrom(4096)
        threading.Thread(target=handle, args=(pkt, addr), daemon=True).start()


if __name__ == '__main__':
    main()
