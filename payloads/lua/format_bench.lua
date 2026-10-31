--!lua
-- Portable formatter benchmark v1; run unchanged on native and WebKit.
-- WebKit: --arg compat=remote_lua_loader --arg service=1
local SAMPLES, WARMUPS = 5, 1
local timer = memory.alloc(16)
local cases = {}
syscall.resolve({clock_gettime = 232})

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

local function format_case(name, fmt, expected, ...)
    local args = {...}
    assert(string.format(fmt, table.unpack(args)) == expected, name .. " output mismatch")
    add(name, 1000, 0, function(n)
        local sum = 0
        for _ = 1, n do sum = sum + #string.format(fmt, table.unpack(args)) end
        return sum
    end, 1000 * #expected)
end
format_case("literal", "literal text", "literal text")
format_case("two integers", "%d %d", "100 200", 100, 200)
format_case("mixed fields", "%s %08x %.2f", "row 0000002a 3.25", "row", 42, 3.25)
format_case("integral floats", "%d %d", "100 200", 100.0, 200.0)
format_case("binary string", "%s", "A\0\255B", "A\0\255B")
format_case("wide decimal fallback", "%d", "4294967295", 4294967295.0)
format_case("uint64 hex fallback", "%x", "1234567887654321", uint64("0x1234567887654321"))
-- Match v4c's direct call separately from table.unpack overhead above.
add("v4c format control", 1000, 0, function(n)
    local sum = 0
    for _ = 1, n do sum = sum + #string.format("%d %d", 100, 200) end
    return sum
end, 7000)

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

print("formatter benchmark v1: 5 samples, 1 warmup/test, clock_gettime(4)")
print("Units: elapsed microseconds; fixed counts; allocation/setup/logging outside timing.")
for _ = 1, WARMUPS do
    for _, c in ipairs(cases) do sample(c, false) end
end

local overhead = {}
local function empty() return 0 end
for pass = 1, SAMPLES do
    overhead[#overhead + 1] = timed(empty, 1)
    for offset = 0, #cases - 1 do
        local c = cases[(offset + pass - 1) % #cases + 1]
        sample(c, true)
    end
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
print("formatter benchmark complete; outputs and checksums verified")
