<p align="center">
  <img src="./installer/assets/icon.svg" width="128" />
</p>
<h1 align="center">PS5 WebKit Remote Loader</h1>
<p align="center">JavaScript payload loader for the PS5.<br>Supports firmwares <b>6.00&ndash;13.60</b>.</p>

The loader uses [ufm42/wobkot](https://github.com/ufm42/wobkot) for its WebKit primitive, firmware layouts, native-call ROP, and Relapse implementation. It accepts JavaScript payloads over TCP on port **9027**. Relapse remains an optional payload rather than a prerequisite for the userland loader.

## Firmware support

The active integration accepts PS5 firmware **6.00 through 13.60** for both the
Wobkot userland and Wobkot Relapse paths. Wobkot selects the nearest applicable
firmware implementation from its vendored tables; this range does not mean that
every intermediate firmware has been tested by this project. Userland loading,
the port 9027 transport, and Relapse have been hardware-verified here on **7.61**.

The remote listener uses a normal blocking socket with zero-timeout `poll(2)`
readiness checks. This avoids descriptor-flag operations rejected by the 7.61
WebProcess while ensuring `accept(2)` is called only when it cannot block.

## Setup

Run the PC host from a checkout or use the bundled Python script / Windows
executable from a release. Release builds include the complete vendored Wobkot runtime.

```sh
sudo python3 host.py
```

The default DNS and HTTPS ports are 53 and 443 (elevated privileges may be needed).
Set the PS5's primary DNS to the PC's LAN IP, then open **Settings → User's Guide**.
Restore automatic DNS when finished.

For a homescreen installation, send `webkit-remote-loader-installer_v*.elf` through
an existing ELF loader. It serves an AppCache installer on port 18180 and installs
the homescreen shortcut (`WKRL00001`). See [installer/README.md](installer/README.md).

## Sending payloads

```sh
python3 tools/send.py <PS5_IP> 9027 payloads/hello_world.js
python3 tools/send.py <PS5_IP> 9027 payloads/notify.js --arg "Hello PS5"
python3 tools/send.py <PS5_IP> 9027 --status
```

See [payloads/README.md](payloads/README.md) for bundled payloads and arguments.

## Payload API

Payloads return an async entry function:

```js
return async function (api) {
  const pid = await api.chain.syscall(0x014);
  await api.log(`pid=${pid.low}`);
};
```

For the complete API reference, memory primitives, ROP batching, and execution rules, see [docs/API.md](docs/API.md).

## Single-file builds

Generate self-contained HTML pages bundling the loader, exploits, and payloads:

```sh
python3 tools/build_standalone.py payloads/hello_world.js -o dist/ps5.html --probe
python3 tools/build_standalone.py payloads/relapse.js \
  'payloads/ftp_server.js::port=1337,path=/data' -o dist/ps5.html
sudo python3 tools/host_standalone.py dist/ps5.html
```

* Payloads run sequentially with shared session state. Use `--no-kexp` to omit kernel binaries.
* Call `api.stopQueue(reason)` from any payload to skip the remaining queue cleanly.
* Standalone pages omit the remote connection HUD and run without opening port 9027.

### Embedded assets and PC host

* `--embed URL=FILE`: Embeds arbitrary files accessible via relative `fetch()` offline.
* `--elfldr [URL=]FILE`: Overrides the default bundled ELF loader (optionally at a custom virtual URL).

```sh
python3 tools/build_standalone.py payloads/hello_world.js \
  --embed payload.bin=/path/to/payload.bin --elfldr /path/to/elfldr.elf \
  -o dist/custom.html --probe

# Package into a standalone Python DNS/HTTPS setup host
python3 tools/build_host.py --page dist/custom.html --name "PS5 CUSTOM HOST"
```

The host builder can package explicitly named pages, but the normal host always runs the single Wobkot runtime. The old Poops page router has been removed; Poops is now sent like any other JavaScript payload.

### Custom appearance and startup scripts

* `--css FILE`: Injects custom stylesheets after the default styles.
* `--js FILE`: Injects startup scripts executed (and awaited) before exploit boot.

```sh
python3 tools/build_standalone.py payloads/hello_world.js \
  --css /path/to/theme.css --js /path/to/setup.js -o dist/custom.html --probe
```

## Build and test

Build the bundled host and native installer:

```sh
make host            # Build standalone host script
./build_release.sh   # Build versioned installer ELF and host (Docker required)
```

Run test suites (Node.js and Python 3):

```sh
make test            # Runs Wobkot integration, payload, standalone, and packaging tests
make test-native     # Runs shared native installer tests with stubbed PS5 services
```

## Credits and licenses

* **[Y2JB](https://github.com/Gezine/Y2JB)** and **[remote_lua_loader](https://github.com/n0llptr/remote_lua_loader)** — used for reference.
* Relapse is adapted from [ntfargo](https://github.com/ntfargo) and [Sonic_Iso](https://github.com/soniciso1)'s [Relapse-Exploit](https://github.com/ntfargo/Relapse-Exploit).
* Poops is adapted from [Jordy](https://github.com/jordyidk)'s [slopkit](https://github.com/jordyidk/slopkit).
* **[john-tornblom](https://github.com/john-tornblom)** — [ps5-payload-sdk](https://github.com/ps5-payload-dev/sdk/) and [elfldr](https://github.com/ps5-payload-dev/elfldr)
* **[ufm42](https://github.com/ufm42)** — [wobkot](https://github.com/ufm42/wobkot) and [kexp](https://github.com/ufm42/kexp)
* **[madler](https://github.com/madler)** — [puff](https://github.com/madler/zlib/tree/master/contrib/puff)

The loader, PC host, and client tools are licensed under [MIT](LICENSE).
The installer and its shared native helpers ([installer/common](installer/common/README.md)) are licensed under [GPLv3](installer/LICENSE).

## Disclaimer

This tool is provided as-is for research and development purposes only. Use at your own risk. The developers are not responsible for any damage, data loss, or consequences resulting from the use of this software.

## Donate
- [donate to PLK](DONATE.md)

