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
| [relapse.js](relapse.js) | Invoke Wobkot's Relapse implementation | None |

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

* **Relapse** (`payloads/relapse.js`) invokes the vendored Wobkot implementation on the active Wobkot userland.
* **Poops is no longer supported** by the active runtime. Its old source remains temporarily as porting reference.

Relapse attempts privilege escalation and launches the bundled ELF loader
([elfldr](https://github.com/ps5-payload-dev/elfldr)) on port 9021 via kernel shellcode
([ps5-kexp](https://github.com/itsPLK/ps5-kexp); see [shared/README.md](../shared/README.md)).
The kernel exploit, cleanup, jailbreak patches, and binary handoff are Wobkot's.
The active integration exposes Relapse on PS5 6.00–13.60; this project has
hardware-verified the complete userland and Relapse flow on 7.61.

### Host syscall benchmark

`syscall_bench.js` profiles individual getpid calls and batches of 1, 8, and 32
through the payload compatibility API. The Wobkot adapter currently replays recorded
batches sequentially and checks every saved result. Run with
`python3 tools/send.py <IP> 9027 payloads/syscall_bench.js`; add `--arg quick`
for a short correctness smoke test. The default uses five samples and one warmup.
This is a host diagnostic; execution timings do not isolate native stack clearing.
