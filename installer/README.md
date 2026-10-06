# Native installer

The installer ELF serves the loader on `http://127.0.0.1:18180/`, opens the PS5
browser, and installs the homescreen shortcut (`WKRL00001`) after AppCache installation.
An existing ELF loader is required to run it.

Build from the repository root with `./build_release.sh`. The build uses Docker,
the PS5 payload SDK, `libmicrohttpd`, and the shared helpers in
[`common`](common/README.md). The SDK recipe and all installer sources are in
this repository; no submodules are required.
Output: `webkit-remote-loader-installer_v*.elf`.

App identity and embedded asset paths are configured in
`include/installer_config.h`. Ports, versions, thread names, HTTP routing, and
frontend resources stay in this installer. The release script pins one build
version for the native ELF, cache, and PC host.

Installer sources and binaries use [GPLv3](LICENSE). The loader's license is in
the repository root.
