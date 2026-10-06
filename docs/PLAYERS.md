# Joining a server

Replace `SERVER_IP` with the IP of the server you want to play on (`127.0.0.1` if it runs on your own PC).

## RPCS3

**Easiest:** run `Install Online Fix.bat SERVER_IP` (or without an IP for a server on this PC). It sets MW2's own
RPCS3 settings for every MW2 version (US / EU / JP) and keeps a backup.

**By hand:** right-click MW2 in RPCS3 > *Create / Change Custom Configuration* > *Network*:

- Network Status: **Connected**
- PSN Status: **RPCN** (free account: *Configuration > RPCN*)
- IP/Hosts switches (*IP swap list*), one line:

```
mw2-ps3-auth.mmp3.demonware.net=SERVER_IP&&mw2-ps3-lsg.live.mmp3.demonware.net=SERVER_IP&&mw2-ps3-lsg.cert.mmp3.demonware.net=SERVER_IP&&mw2-stun.us.demonware.net=SERVER_IP&&mw2-stun.eu.demonware.net=SERVER_IP&&auth1.ps3.iw4.iwnet.infinityward.com=SERVER_IP&&match1.ps3.iw4.iwnet.infinityward.com=SERVER_IP&&blob1.ps3.iw4.iwnet.infinityward.com=SERVER_IP&&team1.ps3.iw4.iwnet.infinityward.com=SERVER_IP&&ip1.ps3.iw4.iwnet.infinityward.com=SERVER_IP&&log1.ps3.iw4.iwnet.infinityward.com=SERVER_IP&&web1.ps3.iw4.iwnet.infinityward.com=SERVER_IP
```

## Real PS3

The server must also run the community DNS (`dnsserver.py`, installed by `deploy/install.sh`).

1. *Settings > Network Settings > Internet Connection Settings > Custom*
2. Keep your normal Wi-Fi / cable settings, IP address: *Automatic*
3. DNS Setting: *Manual* - Primary DNS: `SERVER_IP`, Secondary DNS: `1.1.1.1`
4. MTU automatic, proxy: do not use, UPnP: enable
5. Sign in to PSN as usual, start MW2 (latest update) > Multiplayer > Play Online.

Only the old MW2 DemonWare / IWNet names are redirected; PSN, the store and everything else keep working normally.
