# MW2 PS3 DemonWare protocol notes

Reverse engineered from the MW2 PS3 EBOOT (BLES00686, update 1.14); addresses are of that build. MW3 (BLJM60422 1.24)
notes at the end.

## Host names

MW2 connects to `mw2-ps3-auth.mmp3.demonware.net`, `mw2-ps3-lsg.live.mmp3.demonware.net` (lobby),
`mw2-ps3-lsg.cert.mmp3.demonware.net`, `mw2-stun.us/eu.demonware.net` (STUN) and the IWNet names
`auth1/match1/blob1/team1/ip1/log1/web1.ps3.iw4.iwnet.infinityward.com`.

The game's DW states (console): `DW_DNS_RESOLVING` -> `DW_REQUESTED_NP_TICKET` -> `DW_AUTHORIZING` -> `DW_AUTHORIZED`
-> `DW_LOBBY_CONNECTING` -> `DW_LOBBY_CONNECTED`.

## Frames and bit buffers

- Frame: `u32 LE length | u8 encrypted | u8 message type | body`.
- bdBitBuffer: bits LSB first; first bit = type checking on/off; with type checking every value is preceded by a 5-bit
  type tag (`bool 1, char8 2, uchar8 3, wchar16 4, int16 5, uint16 6, int32 7, uint32 8, int64 9, uint64 10,
  float32 13, float64 14, string 16, blob 19`).
- Blob: `[type 19][typed u32 length][bytes]`. String: `[type 16][chars][0]`.

## Auth (TCP 3074)

Request, message 18: `[typed u32 title][...][Sony NP ticket v2.1]`. The ticket cookie is a random 24-character string,
used as the 3DES key of the reply.

Reply, message 19 (`bdAuthService` reply handler 0x404f98, parser 0x4031d0):

```
[1 type checking][typed u32 700 = ok][typed u32 iv seed]
[1216 bits = 3DES-CBC(cookie, IV = Tiger(seed LE)[:8]) of the bdAuthTicket, padded to 152 bytes]
[1024 bits = server ticket - opaque to the client, handed to the lobby]
```

bdAuthTicket (128 bytes, little endian, deserializer 0x40bde8): `u32 0xEFBDADDE, u8 type, u32 title, u32 issued,
u32 expires, u64 license, u64 user id, char[64] name, u8[24] session key`. The IV is
`bdCryptoUtils::calculateInitialVector` (0x49cb88): the first 8 bytes of Tiger-192 of the seed. Tiger uses the
standard S-boxes.

## Lobby (LSG, TCP 3074)

- The connection starts with an 8-byte header: `b4 00 00 00 ff ff 00 00` (MW2) / `c8 ...` (MW3).
- Login, message 7 (not encrypted): a bit stream that contains our 128-byte server ticket (not byte aligned).
  The server replies with message 4 (connection id: typed u64), encrypted.
- Encrypted frames: `u32 len | 01 | u32 seed | 3DES-CBC(session key, Tiger(seed)[:8])`.
  - client -> server plain: `[u32 hash][u8 service][typed u8 task][typed args]`
  - server -> client plain: `[ef be ad de][u8 message type][body][pad to 8]`
- Every encrypted client message is a task, and **every task must be answered, in order**: the client matches replies
  first-in-first-out (`handleTaskReply` 0x3fb858). The bandwidth task (service 18) too, or the next reply lands on it
  and the real task times out.
- Task reply (message 1): `[typed u64 transaction id][typed u32 error][typed u8 result type][...]`, result type 4 =
  list `[u32 count][u32 total][results]`.

### Services

| service | what | tasks |
| --- | --- | --- |
| 5 | matchmaking (bdMatchMaking 0x3f6xxx) | 1 create, 2 update, 3 delete, 5 find |
| 7 | stats | 0 (empty list accepted) |
| 10 | storage | 8 list files, 5 get file, others: OK with no results |
| 18 | bandwidth test | |

Storage has its own reply parser (0x401b68): result types 1/5 = single result, 7/8 = list
`[typed u32 count][results]`, anything else = OK with no results.

- List files (task 8): result type 7, one bdListFilesResult (0x4000f8) per file =
  `[typed u32][bdLobbyFileHeader]`; header (0x4016c8) = `u64 id, u32 time, u32 size, bool, bool, u64 owner,
  string name`.
- The game compares the names (0x30dd8c) and keeps asking until its files are listed: `playlists.patch3`,
  `motd-<language>.txt` (other regions / languages use other names - the server lists aliases of the same files).
- Get file (task 5, `[u8 0][u64 file id]`): result type 1, `[typed u32 1][header][blob]`.

### Matchmaking

- Create (task 1): `[u8][blob host addr][blob id][blob key][13 x int32 game info]` -> result type 8:
  bdSessionCreateResult (0x3f88d8) `[blob session id, 8 bytes][blob session key, 16 bytes]`.
- Update (2): same fields as create. Delete (3): `[blob session id]`.
- Find (5): `[u8][int32 x 9: 2, ping 50, 0, playlist, 139, map pack 2, playlist version, free slots, 0]` ->
  result type 4: `[u32 total][u32 count]` + bdMatchMakingInfo `[blob addr][blob id][blob key][int32 ...]`.

## Playlists

Plain text: `version N`, `rule ...`, `gametype <g>` (+ script / name / teambased), `playlist <n>` (+ name /
description / ranked / maxparty ...). Map entries are comma separated (`mp_afghan,war,1`). The game only downloads
the file again when the version number changes.

## UDP 3074

- IP discovery: type 30 -> `[31][u16 2][bdAddr]` (bdAddr = IPv4 in network order + u16 port LE).
- NAT type discovery: type 20 `[20][u16 2][flags]` -> `[21][u16 2][client's mapped addr][server's alternate addr]`.
  Flags bit 0 / bit 1 ask for the answer from another port / IP; answering from there = Open NAT.

## MW3 (BLJM60422 1.24)

- Typed **byte** buffers instead of bit buffers: `[u8 type][value LE]`, same type ids, no leading type-check bit.
- Task reply: `[u64 transaction id][u32 error][u8 task][u32 count][u32 total][results]`.
- Publisher files by name (storage task 7): `playlists_tu24.aggr` = `[u16 BE 1][u16 BE 6][u16 BE size]` + zlib
  (built by `tools/make_mw3_playlist.py`); `social_TU24.cfg` must exist (any small text) or MW3 stops with error 256.
- User files (stats `mpdata`, 12288 bytes with a CRC-32): "no such file" = error 1000 makes MW3 start fresh stats.
- Bandwidth test (service 18): a raw task answered with lobby message 5; the upload packets go to UDP 3074 with the
  cookie `BWTEST01`.
- Matchmaking is service 21 (create = 8-byte session id blob).
