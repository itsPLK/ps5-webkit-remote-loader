# Payloads

```sh
python3 tools/send.py <PS5_IP> 9027 payloads/<name>.js --arg <value>
```

Repeat `--arg` for multiple arguments. For a value starting with a dash, use
`--arg=-value`. Filesystem and device access follow the process credentials.
See [docs/API.md](../docs/API.md) for the payload authoring API reference.

| Payload | Purpose | Arguments |
|---|---|---|
| [hello_world.js](hello_world.js) | Loader round trip | None |
| [notify.js](notify.js) | On-screen notification | Message text |
| [sysinfo.js](sysinfo.js) | Credentials, system information, directories | Directory paths |
| [ps.js](ps.js) | Process and thread list | Filter, `pid=N`, `uid=N`, `sort=KEY`, `desc`, `limit=N`, `json`, `help` |
| [netstat.js](netstat.js) | Interfaces and TCP probes | `interfaces`, `listen`, `all`, port number, `range=A-B`, `json`, `help` |
| [df.js](df.js) | Filesystem capacity and mount flags | Paths, `bytes`, `inodes`, `flags`, `all`, `json`, `help` |
| [readfile.js](readfile.js) | Read files | Paths, `text`, `hex`, `both`, `width=N`, `offset=N`, `limit=N` |
| [klog.js](klog.js) | Read `/dev/klog` | `follow`, `timeout=N`, `sec=N`, `grep=TEXT`, `filter=TEXT`, `raw` |
| [relapse.js](relapse.js) | Relapse kernel exploit (FW 7.00–13.60, except 9.05, 11.40) | `map`, `pipes`, `spawn` (default) |
| [poops.js](poops.js) | Poops kernel exploit (FW 7.00–12.00) ladder | See below |

## FTP

```sh
python3 tools/send.py <PS5_IP> 9027 payloads/ftp_server.js \
  --arg port=1337 --arg path=/data --arg persist
```

Keep the sender running. Connect with anonymous plain FTP and one connection.
Active and passive IPv4 transfers are supported. Defaults: port `1337`, directory
`/`, inactivity timeout `300` seconds. `path` sets the initial directory, not a
chroot. The server occupies the loader until it exits; `persist` accepts successive
clients and `SITE STOP` shuts it down. Without `persist`, disconnect or `QUIT`
ends the payload.

## Kernel payloads

* **Relapse** (`payloads/relapse.js`): FW 7.00 – 13.60 (except 9.05 and 11.40; requires an active network interface).
* **Poops** (`payloads/poops.js`): FW 7.00 – 12.00 (covers 9.05 and 11.40).

Relapse and poops attempt privilege escalation and launch the bundled ELF loader
([elfldr](https://github.com/ps5-payload-dev/elfldr)) on port 9021 via kernel shellcode
([ps5-kexp](https://github.com/itsPLK/ps5-kexp); see [shared/README.md](../shared/README.md)).
Their kernel accessors are disabled after cleanup. Relapse refuses
an existing `api.krw`; poops also tracks a session latch and cleanup verdict.

A bare poops send uses `trigger=netcontrol`, `attempts=8`, `sockets=80`, `payload=1`.

```sh
python3 tools/send.py <PS5_IP> 9027 payloads/poops.js --arg trigger=none
python3 tools/send.py <PS5_IP> 9027 payloads/poops.js --arg payload=off
python3 tools/send.py <PS5_IP> 9027 payloads/poops.js --arg payload=dry
```

`trigger=none` selects the negative control. `payload=off` skips stage 5;
`payload=dry` stops after binary mapping and pipe setup, before shellcode execution.
Additional configuration is defined in `makeConfig()` in
[tools/poops_port/adapter.js.txt](../tools/poops_port/adapter.js.txt).

After a dirty or missing poops cleanup verdict, reboot before retrying.
`latch-clear` explicitly overrides the latch. Gadget and syscall checks detect
missing table entries; they do not prove a firmware is exploitable.
