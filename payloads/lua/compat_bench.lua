--!lua
-- Benchmark v3: identical fixed workloads in native remote_lua_loader and WebKit.
-- WebKit: tools/send.py <IP> 9027 payloads/lua/compat_bench.lua
--         --arg compat=remote_lua_loader --arg service=1
-- No output inside timed regions. Counts stay bounded for the VM instruction hook.
local SAMPLES, WARMUPS = 5, 1
local timer = memory.alloc(16)
local cell = memory.alloc(8)
local buffer = memory.alloc(16384)
local cases = {}
syscall.resolve({clock_gettime = 232, getpid = 20})

local function now()
    assert(syscall.clock_gettime(4, timer):tonumber() == 0, "clock_gettime failed")
    -- Keep seconds and nanoseconds separate to avoid large absolute timestamps.
    return memory.read_qword(timer):tonumber(), memory.read_qword(timer + 8):tonumber()
end

local function timed(fn, n)
    local s, ns = now()
    local value = fn(n)
    local e, en = now()
    local elapsed = (e - s) * 1000000 + (en - ns) / 1000
    assert(elapsed >= 0, "clock moved backwards")
    return elapsed, value
end

local function add(name, n, bytes, fn, expected, setup, verify)
    cases[#cases + 1] = {name=name, n=n, bytes=bytes, fn=fn,
        expected=expected, setup=setup, verify=verify, times={}}
end

add("Lua arithmetic", 10000, 0, function(n)
    local x = 1
    for i = 1, n do x = (x * 33 + i) % 1000003 end
    return x
end, 148698)

add("uint64 construct+add", 2000, 0, function(n)
    local x = uint64(1)
    for i = 1, n do x = x + uint64(i) end
    return x:tonumber()
end, 2001001)

local one = uint64(1)
add("uint64 add", 2000, 0, function(n)
    local x = uint64(0)
    for _ = 1, n do x = x + one end
    return x:tonumber()
end, 2000)

add("scalar write+read", 1000, 0, function(n)
    local sum = 0
    for i = 1, n do
        memory.write_dword(cell, i)
        sum = sum + memory.read_dword(cell):tonumber()
    end
    return sum
end, 500500)

for _, size in ipairs({64, 1024, 16384}) do
    -- Binary pattern exercises embedded NULs and bytes above 127.
    local block = string.rep("A\0\255\128", size / 4)
    -- Larger transfers now need more work to rise above the syscall timer floor.
    local total = size == 64 and 32768 or (size == 1024 and 524288 or 2097152)
    local count = total / size
    local function setup() memory.write_buffer(buffer, block) end
    local function verify() assert(memory.read_buffer(buffer, size) == block, "buffer mismatch") end
    add("buffer write " .. size, count, size, function(n)
        for _ = 1, n do memory.write_buffer(buffer, block) end
        return n
    end, count, nil, verify)
    add("buffer read " .. size, count, size, function(n)
        local sum = 0
        for _ = 1, n do sum = sum + #memory.read_buffer(buffer, size) end
        return sum
    end, total, setup, verify)
end

local pid = syscall.getpid():tonumber()
assert(pid > 0, "invalid pid")
add("getpid syscall", 100, 0, function(n)
    local sum = 0
    for _ = 1, n do sum = sum + syscall.getpid():tonumber() end
    return sum
end, pid * 100)

local function sample(c, save)
    if c.setup then c.setup() end
    local elapsed, value = timed(c.fn, c.n)
    assert(value == c.expected, c.name .. " checksum mismatch")
    if c.verify then c.verify() end
    if save then c.times[#c.times + 1] = elapsed end
end

local function stats(values)
    local sorted = {}
    for i, v in ipairs(values) do sorted[i] = v end
    table.sort(sorted)
    return sorted[math.floor(#sorted / 2) + 1], sorted[1], sorted[#sorted]
end

print("compat benchmark v3: 5 samples, 1 warmup/test, clock_gettime(4)")
print("Units: elapsed microseconds; fixed counts; allocation/setup/logging outside timing.")
print("Buffers: 64 B = 32 KiB/sample; 1 KiB = 512 KiB/sample; 16 KiB = 2 MiB/sample.")
print("Compare us/op and MiB/s with v2; larger-buffer total times use different counts.")
for _ = 1, WARMUPS do
    for _, c in ipairs(cases) do sample(c, false) end
end

local overhead = {}
local function empty() return 0 end
for pass = 1, SAMPLES do
    -- Measure the timer floor throughout the run and rotate case order.
    overhead[#overhead + 1] = timed(empty, 1)
    for offset = 0, #cases - 1 do
        local c = cases[(offset + pass - 1) % #cases + 1]
        sample(c, true)
    end
    -- Progress output occurs only between passes, after all measured intervals.
    printf("pass %d/%d complete", pass, SAMPLES)
end

local floor, floor_min, floor_max = stats(overhead)
printf("timer floor: median %.3f us, min %.3f, max %.3f", floor, floor_min, floor_max)
print("Raw times include timer overhead; no baseline subtraction. LOW means median < 10x timer floor.")
print("case | ops/sample | median ms | min ms | max ms | median us/op | MiB/s | signal")
for _, c in ipairs(cases) do
    local med, lo, hi = stats(c.times)
    local rate = "-"
    if c.bytes > 0 and med > 0 then
        rate = string.format("%.3f", c.n * c.bytes / 1048576 / (med / 1000000))
    end
    printf("%s | %d | %.3f | %.3f | %.3f | %.3f | %s | %s",
        c.name, c.n, med / 1000, lo / 1000, hi / 1000, med / c.n,
        rate, med < 10 * floor and "LOW" or "OK")
    local raw = {}
    for i, v in ipairs(c.times) do raw[i] = string.format("%.3f", v) end
    printf("samples_us,%s,%s", c.name, table.concat(raw, ","))
end
print("benchmark complete; checksums and buffer contents verified")
