--!lua
-- Select with --arg compat=remote_lua_loader.
syscall.resolve({getppid=39})
printf("pid %d ppid %d",syscall.getpid():tonumber(),syscall.getppid():tonumber())
local p=memory.alloc(32)
local p2=memory.alloc(32)
assert(p ~= p2, "allocations must not alias")
memory.write_dword(p,4294967295.0)
assert(memory.read_dword(p):tonumber()==4294967295.0)
local word=uint64("0xfedcba9876543210")
memory.write_buffer(p,ub8(word))
assert(uint64.unpack(memory.read_buffer(p,8))==word)
memory.free(p)
local p3=memory.alloc(32)
assert(p3 == p and memory.read_qword(p3)==uint64(0), "freed block must be reused and zeroed")
for i=1,300 do
    local b = memory.alloc(36)
    memory.write_dword(b, i)
end
local tloc=memory.alloc(8)
local now=time(tloc):tonumber()
assert(now > 1577836800, "unexpected epoch time")
local tm=memory.alloc(36)
assert(gmtime_s(tloc, tm) == tm)
local year = memory.read_dword(tm + 20):tonumber() + 1900
local mon = memory.read_dword(tm + 16):tonumber() + 1
local mday = memory.read_dword(tm + 12):tonumber()
local hour = memory.read_dword(tm + 8):tonumber()
local min = memory.read_dword(tm + 4):tonumber()
printf("utc %04d-%02d-%02d %02d:%02d (epoch %d, clock %.3f)", year, mon, mday, hour, min, now, os.clock())
assert(bit32.rshift(-1,24)==255)
assert(bit32.bor(1,2,4)==7)
print("compatibility smoke test OK")
