--!lua
-- Userland memory and syscall smoke test; no kernel exploit required.
local p = memory.alloc(64)
memory.write8(p, 0xff)
memory.write16(p + 2, 0xfedc)
memory.write32(p + 4, 4294967295.0)
memory.write64(p + 8, uint64("0xfedcba9889abcdef"))
assert(memory.read8(p) == 255)
assert(memory.read16(p + 2) == 65244)
assert(memory.read32(p + 4) == 4294967295.0)
assert(memory.read64(p + 8) == uint64("0xfedcba9889abcdef"))
local bytes = "a\0b\255\128"
memory.write_buffer(p + 16, bytes)
assert(memory.read_buffer(p + 16, #bytes) == bytes)
print("memory round trip OK", p)
print("pid", syscall.getpid())
