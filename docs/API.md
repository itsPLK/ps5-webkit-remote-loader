# Payload API

Payloads sent to the loader return an asynchronous entry function receiving the `api` context object:

```js
return async function (api) {
  const pid = await api.chain.syscall(0x014);
  await api.log(`pid=${pid.low}`);
};
```

The Wobkot runtime executes JavaScript payloads. The former Lua translation
layer is not part of this runtime.

The compatibility API is available on the same supported range as the active
Wobkot integration (PS5 6.00–13.60). Hardware validation currently covers 7.61.

## API Reference

| Member | Purpose |
|---|---|
| `api.p` | Memory primitives: `read1/2/4/8`, `write1/2/4/8`, `leakval`, `writestr`, `malloc`, `stringify` |
| `api.allowXotextReads` | Boolean flag; set to `true` to bypass the execute-only memory read guard |
| `api.chain` | Wobkot native calls: `syscall`, `call`, or recorded `clear` / `add_syscall_ret` / `run` batches |
| `api.int64`, `api.toI64(value)` | 64-bit integer class (`add32`, `sub32`, `toString`) and conversion helper |
| `api.fw`, `api.version`, `api.args` | Firmware version string, loader version string, and payload CLI arguments (`string[]`) |
| `api.libKernelBase`, `api.libSceNKWebKitBase`, `api.libSceLibcInternalBase` | `int64` base addresses of mapped system libraries |
| `api.gadgets`, `api.syscalls`, `api.krwLayout` | Compatibility views over Wobkot's firmware implementation |
| `api.log(message, type)` | Screen/client logging (`type`: `"info"`, `"warn"`, `"error"`, `"success"`, `"log"`); returns a promise |
| `api.sendBlob(bytes)` | Return binary data (`Uint8Array`) to client (`send.py --save-blobs`; remote mode only) |
| `api.module(path)` | Import a helper from the host via HTTP or an embedded module registry; returns a promise |
| `api.setPayloadTimeout(ms)` | Reset payload deadline (`0` disables timeout, default is 10 minutes) |
| `api.stopQueue(reason)` | Skip remaining queued payloads (standalone queue runner only) |
| `api.krw` | Session kernel R/W handle; initially `null` (persists across standalone payloads) |
| `api.config` | Binary paths from `src/binaries.js` with `window.LOADER_CONFIG` overrides |
| `api.prefetchKexp(options)` | Fetch and cache kernel payload (`kexp.bin`) and ELF loader (`elfldr.elf`) |
| `api.launchKexp(options)` | Run post-exploit pipeline with an active kernel R/W handle |
| `api.enableSyncGates()`, `api.disableSyncGates()` | Legacy compatibility no-ops; Wobkot does not use the former hijacked-worker gates |
| `api.isFailure(rv)`, `api.isUnexpected(rv)`, `api.describe(rv)` | Syscall return value helpers and errno formatting |

## Execution Model & Constraints

* **Execution**: Payloads execute in the page realm. Wobkot performs native calls through its main-thread ROP pivot. Recorded syscall batches currently replay sequentially on `await api.chain.run()`.
* **Remote transport**: The loader listens on TCP port 9027. Its listener remains blocking, but the receive loop gates `accept(2)` with zero-timeout `poll(2)` calls so the page thread remains responsive without `fcntl`, `FIONBIO`, or socket-type nonblocking flags.
* **Deadlines**: Default payload timeout is 10 minutes (`600000` ms). Persistent services (e.g. servers) should call `api.setPayloadTimeout(0)`.
* **Memory**: `api.p.malloc` limit is 1 MiB per payload. Reading unowned addresses inside execute-only system libraries (`.xotext`) will throw an error unless `api.allowXotextReads = true` is set.
* **Kernel pipeline**: Call `api.prefetchKexp()` before triggering a kernel exploit, then `api.launchKexp({ krw })`. `stopAfter` accepts `'map'`, `'pipes'`, or `'spawn'` (default). Bundles [`ps5-kexp`](https://github.com/itsPLK/ps5-kexp) (kernel payload shellcode) and [`elfldr`](https://github.com/ps5-payload-dev/elfldr) (ELF loader daemon listening on port 9021); see [shared/README.md](../shared/README.md).
