"""Build MW3's playlist file (server/files/mw3/playlists_tu24.aggr) from server/files/mw3/playlists.info.txt.

    python tools/make_mw3_playlist.py

Format read by MW3 1.24 (code at 0x1E8CDC): [u16 BE version = 1][u16 BE offset of the data = 6][u16 BE compressed
size] + a zlib stream, inflated into a 0x3C000-byte buffer; the whole file must be at most 0xF000 bytes.
"""
import os
import struct
import zlib

MW3 = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'server', 'files', 'mw3')


def main():
    with open(os.path.join(MW3, 'playlists.info.txt'), 'rb') as f:
        text = f.read().replace(b'\r\n', b'\n') + b'\0'
    z = zlib.compress(text, 9)
    out = struct.pack('>HHH', 1, 6, len(z)) + z
    if len(out) > 0xF000 or len(text) >= 0x3C000:
        raise SystemExit('playlist too big for MW3 (%d bytes text, %d bytes file)' % (len(text), len(out)))
    with open(os.path.join(MW3, 'playlists_tu24.aggr'), 'wb') as f:
        f.write(out)
    print('playlists_tu24.aggr: %d -> %d bytes' % (len(text), len(out)))


if __name__ == '__main__':
    main()
