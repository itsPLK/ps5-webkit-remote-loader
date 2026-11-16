# Lua compatibility

LuaK1t was retired when the project migrated to Wobkot as its userland and ROP
base. The active loader accepts JavaScript payloads only. `tools/send.py` and
`tools/build_standalone.py` reject `.lua` input explicitly instead of silently
running it through an unmaintained translation layer.

The retired translator implementation remains under `tools/lua_runtime/` for
reference. Its sample payloads have been removed.
