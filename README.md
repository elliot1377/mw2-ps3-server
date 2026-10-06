# MW2 PS3 Server

A community replacement for the shut-down **Call of Duty: Modern Warfare 2 (PS3)** online servers (DemonWare / IWNet).
Run it on your PC and play MW2's online mode again in **RPCS3** - or host it for real PS3s and friends.
MW3 (PS3) is partly supported too.

No game files are modified and nothing is patched: the game is only pointed at this server.

## What works

- Sign-in (PS3 NP ticket / RPCN), online menu, message of the day
- Playlists, rank and unlocks
- Private matches, matchmaking (create / find sessions)
- All MW2 regions and languages (US, EU, JP)
- IP / NAT discovery, bandwidth test

## Quick start (Windows + RPCS3)

1. Download the latest **`mw2-ps3-server-*-windows.zip`** from [Releases](../../releases) and unzip it.
2. Double-click **`Install Online Fix.bat`** (pick your RPCS3 folder if asked).
3. In RPCS3: *Configuration > RPCN* - create a free account (once).
4. Every time you play: run **`Start Server.bat`**, keep it open, then MW2 > *Multiplayer > Play Online*.

No Python needed for the release. To play on someone else's server instead: `Install Online Fix.bat <their IP>` -
see [docs/PLAYERS.md](docs/PLAYERS.md) (also for real PS3s).

## Running from source

```
pip install -r requirements.txt
python server/dwserver.py                # local only (127.0.0.1)
python server/dwserver.py --verbose      # + every task and packet
```

| option | |
| --- | --- |
| `--bind ADDR` | listen address (default `127.0.0.1`; `0.0.0.0` for a public server) |
| `--public-ip IP` | public IP told to players on the server's own PC / LAN |
| `--log FILE` | log file (default `dwserver.log` next to the server; `""` = none) |
| `--verbose` | log every task and packet |

Ports: TCP 3074 (auth + lobby), UDP 3074 (IP / NAT discovery).

### Public server (VPS)

On a fresh Ubuntu / Debian server, as root:

```
git clone https://github.com/elliot1377/mw2-ps3-server
bash mw2-ps3-server/deploy/install.sh
```

This installs the server and a small DNS (`server/dnsserver.py`) that answers only MW2's DemonWare / IWNet names with
the server's IP, so real PS3s can join by setting that IP as their DNS.

### Building the Windows release

```
pip install -r requirements.txt pyinstaller
powershell -ExecutionPolicy Bypass -File build.ps1 -Version 1.0.0
```

## Repository

| path | |
| --- | --- |
| `server/dwserver.py` | the DemonWare server (auth, lobby, storage, matchmaking, UDP) |
| `server/dwcore.py` | protocol building blocks: Tiger-192, bit / byte buffers, NP ticket, auth ticket |
| `server/dnsserver.py` | DNS for real PS3s |
| `server/files/` | files served to the game: message of the day, playlists (MW2 + MW3) |
| `rpcs3/` | the RPCS3 online fix (sets MW2's IP swap list) |
| `windows/` | `Start Server.bat` of the release |
| `deploy/install.sh` | VPS install (systemd services + firewall) |
| `tools/make_mw3_playlist.py` | builds MW3's compressed playlist file |
| `tests/` | protocol self-tests: `python -m unittest discover tests` |
| `docs/PROTOCOL.md` | reverse-engineering notes |

## Notes

- Your MW3 / player data is stored in `userfiles/` next to the server.
- Edit `server/files/playlists.patch3` to change the MW2 playlists - raise its `version` line, the game only
  downloads a new version.
- This is a fan project, not affiliated with Activision, Infinity Ward, DemonWare or Sony. You need your own copy of
  the game.

## License

[MIT](LICENSE)
