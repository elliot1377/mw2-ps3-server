MW2 PS3 online on RPCS3 - community server
==========================================

Modern Warfare 2's official PS3 online servers are shut down. This runs a small replacement server on your PC and
points MW2 in RPCS3 at it, so you can use MW2's online mode again. No game files are changed and no mods.

You need
  - RPCS3 with Modern Warfare 2 (PS3) installed, with the latest game update.
  - A free RPCN account (RPCS3's online service).

Setup (once)
  1. Unzip this folder anywhere.
  2. Double-click "Install Online Fix.bat". If it asks, pick your RPCS3 folder (the one with rpcs3.exe).
  3. In RPCS3: Configuration > RPCN > create a free account (or sign in).

Every time you play
  1. Double-click "Start Server.bat" and leave that window open.
     (If Windows asks about the firewall, you can say no - the server is only used by this PC.)
  2. Start MW2 in RPCS3 > Multiplayer > Play Online.
  3. When done, close the server window.

Playing on someone else's server
  Run the fix with their IP instead (in a command window in this folder):
      "Install Online Fix.bat" 203.0.113.7
  You don't need Start Server.bat then.

Undo
  RPCS3: right-click MW2 > Remove custom configuration, or rename
  config\custom_configs\config_<game ID>.yml.bak_online back.

Notes
  - Some antivirus programs warn about new .exe files made with PyInstaller. It is only the server; the source
    code is on GitHub: https://github.com/elliot1377/mw2-ps3-server
  - Working: sign-in, online menu, playlists, rank / unlocks, private matches, matchmaking search.
