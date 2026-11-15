# Lua compatibility

LuaK1t was retired when the project migrated to Wobkot as its userland and ROP
base. The active loader accepts JavaScript payloads only. `tools/send.py` and
`tools/build_standalone.py` reject `.lua` input explicitly instead of silently
running it through an unmaintained translation layer.

The old translator sources and sample payloads remain in the repository for
reference while the migration settles, but they are excluded from release hosts
and native-installer bundles.
