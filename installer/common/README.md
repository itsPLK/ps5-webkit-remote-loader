# Shared native installer support

This directory owns the native helpers used by the remote-loader and autoloader
installers. It has no dependency on either product's HTTP implementation,
frontend, version generator, or repository layout.

Set `INSTALLER_COMMON` to this directory and include `common.mk` to get
`INSTALLER_COMMON_SRCS` and `INSTALLER_COMMON_HEADERS`. Add this directory and
your project's include directory to the compiler include path. Compile from your
project root so the assembler can resolve the embedded asset paths.

Provide an `installer_config.h` with these string macros:

| Macro | Purpose |
| --- | --- |
| `INSTALLER_APP_NAME` | Human-readable name used in installation notifications |
| `INSTALLER_TITLE_ID` | Homescreen title ID; at most 15 characters |
| `INSTALLER_LOG_PREFIX` | Prefix for helper logs, including brackets |
| `INSTALLER_PARAM_JSON` | Path to generated homescreen metadata |
| `INSTALLER_ICON0_PNG` | Path to the homescreen icon |
| `INSTALLER_CACHE_MANIFEST_ROUTE` | Manifest route used by corruption simulation |

`installer_support.h` declares app installation, browser launch, notification,
WebKit cleanup, and thread-safe log functions. `inflate.h` retains the vendored
puff interface. `http_server.h` declares the shared main/HTTP lifecycle contract;
each product supplies its own handler and state definitions.

Compile with `INSTALLER_SIMULATE_CACHE_CORRUPTION=1` for corruption until a
successful clear, or `=2` for persistent corruption. Without this define the
simulation hooks are no-ops. Consumers call the hooks from their HTTP handlers.

Run `python3 tools/installer_common_test.py` on Linux with Clang or GCC to check
installation/update, app identity and assets, logging, notifications, browser
launch, current-user cleanup, and decompression using stubbed PS5 services.

This native component is licensed under [GPLv3](../LICENSE).
