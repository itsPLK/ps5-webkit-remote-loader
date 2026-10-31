# Lua compatibility

The loader runs Lua 5.3 code in a JavaScript-hosted Fengari runtime. It has a
small core API of its own and an optional `remote_lua_loader` compatibility
profile for scripts written against that environment. The profile is partial;
it does not provide a complete PS5 SDK or reproduce every behavior of the
reference loader.

## Select the Lua runtime

Send a Lua file with the project sender:

```sh
python3 tools/send.py <PS5_IP> 9027 payloads/lua/memory_smoke.lua
```

`tools/send.py` and `tools/build_standalone.py` add `compat=remote_lua_loader`
by default for `.lua` files (unless an explicit `compat=` argument, such as
`compat=none`, is specified). The compatibility argument selects the Lua
runtime and enables the `remote_lua_loader` profile without requiring an extra
`lua=1` argument. Other clients can select Lua by putting `--!lua` or `--lua`
on the first line, or by passing `compat=remote_lua_loader` or `lua=1`.

```sh
python3 tools/send.py <PS5_IP> 9027 payloads/lua/compat_smoke.lua
```

Add `--arg service=1` for a long-running WebKit payload. This disables the
loader's payload deadline after compilation and streams `print` output while
the script runs. `service=1` is a WebKit loader option; it is not needed when
running the same script in the original `remote_lua_loader` environment.

Each invocation gets a fresh Lua state. Lua payloads run sequentially with
other payloads. A Lua error is reported as a payload failure; a later payload
starts with a new state.

## Core environment

The core environment is available without the compatibility profile:

- Standard Lua 5.3 language and library behavior provided by Fengari.
- `print(...)`, delivered through the loader's output channel.
- `uint64(value)` for exact 64-bit values.
- `fcall(address)(...)` and `syscall.call(number, ...)` for native calls;
  `syscall.getpid()` is a convenience wrapper for syscall 20.
- `memory.read8/16/32/64`, `memory.write8/16/32/64`,
  `memory.read_buffer`, `memory.write_buffer`, and `memory.alloc`.

The host removes `io`, `os`, `package`, `require`, `dofile`, `loadfile`, and
`debug` from the core environment. The compatibility profile supplies limited
replacements described below. It does not make arbitrary Lua module loading
available.

## `remote_lua_loader` profile

Enable it with `compat=remote_lua_loader`. It adds reference-style names and
helpers to the current Lua state. The main supported areas are:

| Area | Available behavior |
|---|---|
| 64-bit values | Callable `uint64`, `.h`, `.l`, `:tonumber()`, `:pack()`, and `uint64.unpack`; `hex`, `ub8`, and `is_uint64` |
| Formatting and bits | `printf`, `errorf`, `bit32`, `bit64`, and `struct.pack` / `struct.unpack` |
| Memory | `read_byte/word/dword/qword`, matching writes, `read_buffer`, `write_buffer`, `memcpy`, `read_null_terminated_string`, `read_multiple_qwords`, `write_multiple_qwords`, and `hex_dump` |
| Native calls | `syscall.call`, named wrappers created by `syscall.resolve`, and `fcall(address)` |
| Allocation | `memory.alloc`, `memory.free`, and `memory.reset` backed by a bounded `mmap` arena |
| System helpers | `time`, `gmtime`, `gmtime_s`, `os.time`, `os.clock`, `sleep`, `file_exists`, `get_current_ip`, and `is_jailbroken` |
| Reference globals | Firmware and library bases, selected POSIX/Orbis constants, `symbols`, `libc_addrofs`, and `libkernel_addrofs` |

The profile also exposes selected reference modules and helpers such as
`sysctlbyname`, `dlsym`, `shared_bytes`, `ropchain`, and kernel/GPU utilities.
Their behavior depends on firmware, available symbols, gadgets, and the state
of the exploit. Presence of a name does not mean every reference-loader feature
is implemented or usable in every payload.

### 64-bit values

Use decimal or hexadecimal strings for values outside JavaScript's exact integer
range:

```lua
local address = uint64("0xffffffffffffffff")
local next_value = address + 1 -- wraps modulo 2^64
print(hex(next_value))         -- 0x0
```

Lua numbers are accepted only when they are exact safe integers. The profile's
`:tonumber()` returns a signed 64-bit number only when that conversion remains
exact; otherwise it raises an error. `:pack()` and `uint64.unpack(bytes)` use
little-endian binary data. Use these methods instead of converting full-width
values through Lua numbers.

### Memory and allocation

Core buffer transfers are limited to 64 KiB per call. Core `memory.alloc` has a
64 KiB per-invocation budget, including allocator padding, and pins its storage
for the loader session. The compatibility `memory.write_buffer` and
`memory.memcpy` helpers split larger transfers into chunks; `memory.read_buffer`
remains limited to 64 KiB. Scalar and buffer operations use the loader's memory
guard, including its execute-only memory restriction.

Compatibility `memory.alloc(size)` returns zeroed, 16-byte-aligned storage from
a per-invocation arena, with a 16 MiB mapping budget. Call `memory.free(pointer)`
when a temporary allocation is no longer needed; freed blocks can be reused.
`memory.reset()` releases all arena mappings. `memory.free` returns blocks to
the arena and does not unmap them individually.

All memory helpers access native process memory. Supply valid mapped addresses
and sizes; an invalid address can fail the payload or the WebKit process.

### Syscalls and native functions

`syscall.call(number, ...)` accepts a syscall number and up to six integer
arguments. The profile's `syscall.resolve({ name = number, ... })` creates
callable entries such as `syscall.getpid()` and `syscall.open(path, flags)`.
Results are returned as `uint64`; inspect the raw result according to the
syscall's convention. The compatibility layer does not convert every native
error into a Lua exception or provide a universal `errno` value.

`fcall(address)` returns a callable function wrapper. Native calls must run in
the main Lua coroutine; calls from child coroutines are rejected. Native strings
passed through compatibility `syscall` or `fcall` are copied into temporary
NUL-terminated buffers. Each string must be shorter than 4096 bytes, and the
pointer is only valid for that call. Allocate and populate your own memory when
native code retains a pointer or needs a larger string.

The profile wraps `accept` and blocking `recvfrom` with polling, and adapts
`getdents` for smaller caller buffers. These helpers are specific to this
WebKit runtime and should not be assumed to match the reference implementation
in every edge case.

### Runtime limits

The runtime has an instruction-count guard and a 1 MiB output limit. The guard
counts Lua VM instructions, not elapsed time, and expensive native or library
operations may run between checks. Compatibility host operations renew the
instruction budget when they resume. These limits are reliability guards, not
a security boundary. Only run trusted payloads.

In compatibility mode, `print` output is sent while the script runs. In
ordinary Lua mode it is buffered until execution completes. The profile's
`io.open` is a narrow file helper for supported savedata access; it is not the
standard Lua I/O library. `require` only recognizes the profile's built-in
module names and does not load arbitrary files.

## Examples

Compatibility smoke test (default profile):

```sh
python3 tools/send.py <PS5_IP> 9027 payloads/lua/compat_smoke.lua
```

Core Lua smoke test (explicitly opting out of compatibility profile):

```sh
python3 tools/send.py <PS5_IP> 9027 payloads/lua/memory_smoke.lua \
  --arg compat=none
```

Long-running FTP service:

```sh
python3 tools/send.py <PS5_IP> 9027 payloads/lua/ftp_server.lua \
  --arg service=1
```

`src/lua-vm.js` is generated and ignored by Git. The source host and page
builders create it when it is missing or out of date. This requires Node.js
18+ and npm; `tools/lua_runtime/package-lock.json` pins the build dependencies.
To rebuild it directly, run `python3 tools/lua_runtime/build_runtime.py`, then
reload the WebKit loader.
