--!lua
-- Benchmark v4d: stall-phase patterns with bounded, reclaimed scratch memory.
-- Measures host round-trip cost, scalar store dispatch, queue submit/poll/cancel
-- sweep patterns, probe tuple patterns, sysctl marshaling, scan loops, chain
-- batching, result readback, and sleep quantization.
-- WebKit: tools/send.py <IP> 9027 payloads/lua/compat_bench_b.lua
--         --arg compat=remote_lua_loader --arg service=1
-- Native: same file through native remote_lua_loader; no loader arguments needed.
-- No output inside timed regions. Counts stay bounded for the VM instruction hook.
local SAMPLES, WARMUPS = 3, 1
local timer = memory.alloc(16)
syscall.resolve({clock_gettime = 232, getpid = 20, sysctl = 202, nanosleep = 240,
    socketpair = 135, aio_submit_cmd = 669, aio_multi_poll = 664, aio_multi_cancel = 666})

local AF_UNIX, SOCK_STREAM = 1, 1
local AIO_CMD_READ = 1
-- Stall-phase counts taken from the profile of the reference workload:
-- R = host round-trips, S = per-field stores, K = uint64 constructions,
-- F = formatting calls, SL/C = paced sweeps, P = full probes.
local R1, S1, K1, F1, SL1 = 1200, 1800, 400, 4096, 40
local R2, S2, K2, F2, P2_ = 1500, 4900, 500, 200, 1000

local pending_ids = {}
local pending_resources = {}
local aio_states = memory.alloc(0x40)
local cancel_slot = memory.alloc(4)
local release_memory = memory.free or function() end

local function sysint(fn, ...)
    local ret = fn(...)
    local v = ret.l
    if v >= 0x80000000 then v = v - 0x100000000 end
    return v
end

local function now()
    assert(syscall.clock_gettime(4, timer):tonumber() == 0, "clock_gettime failed")
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

local cases = {}
local function add(name, n, loose, fn, expected, setup, verify)
    cases[#cases + 1] = {name = name, n = n, fn = fn, loose = loose,
        expected = expected, setup = setup, verify = verify, times = {}}
end

local function stats(values)
    local sorted = {}
    for i, v in ipairs(values) do sorted[i] = v end
    table.sort(sorted)
    return sorted[math.floor(#sorted / 2) + 1], sorted[1], sorted[#sorted]
end

local function open_pair()
    local buf = memory.alloc(8)
    local rv = sysint(syscall.socketpair, AF_UNIX, SOCK_STREAM, 0, buf)
    assert(rv == 0, "socketpair failed")
    return {memory.read_dword(buf):tonumber(), memory.read_dword(buf + 4):tonumber()}
end

local function close_pair(pair)
    for _, fd in ipairs(pair) do
        sysint(syscall.close, fd)
    end
end

local function submit_blocked_read(fd)
    local request = memory.alloc(0x40)
    local sink = memory.alloc(0x40)
    local id_out = memory.alloc(8)
    memory.write_dword(request + 0x08, 1)
    memory.write_qword(request + 0x10, sink)
    memory.write_dword(request + 0x20, fd)
    local rv = sysint(syscall.aio_submit_cmd, AIO_CMD_READ, request, 1, 3, id_out)
    if rv == 0 then
        local id = memory.read_dword(id_out):tonumber()
        table.insert(pending_ids, id)
        pending_resources[id] = {request = request, sink = sink}
        release_memory(id_out)
        return id
    end
    release_memory(request)
    release_memory(sink)
    release_memory(id_out)
    return nil
end

local function cancel_id(id)
    memory.write_dword(cancel_slot, id)
    local rv = sysint(syscall.aio_multi_cancel, cancel_slot, 1, aio_states)
    local resources = pending_resources[id]
    if rv >= 0 and resources then
        release_memory(resources.request)
        release_memory(resources.sink)
        pending_resources[id] = nil
    end
    if rv >= 0 then
        for i = #pending_ids, 1, -1 do
            if pending_ids[i] == id then table.remove(pending_ids, i) end
        end
    end
    return rv
end

-- controls: round-trip cost, scalar dispatch, uint64 construction, formatting
local pid = syscall.getpid():tonumber()
assert(pid > 0, "invalid pid")

add("getpid control, 40 individual calls", 3, false, function(n)
    local total = 0
    for _ = 1, n do
        for _ = 1, 40 do total = total + syscall.getpid():tonumber() end
    end
    return total
end, 3 * 40 * pid)

add("uint64 construct+add control", 2000, false, function(n)
    local x = uint64(1)
    for i = 1, n do x = x + uint64(i) end
    return x:tonumber()
end, 2001001)

add("scalar store control", 500, false, function(n)
    local sum = 0
    local cell = memory.alloc(8)
    for i = 1, n do
        memory.write_dword(cell, i)
        sum = sum + memory.read_dword(cell):tonumber()
    end
    return sum
end, 125250)

add("string.format control", 1000, false, function(n)
    local sum = 0
    for _ = 1, n do sum = sum + #string.format("%d %d", 100, 200) end
    return sum
end, 7000)

local fmt_u = uint64(0x123456789ABC)
add("uint64 formatting control", 200, false, function(n)
    local sum = 0
    for _ = 1, n do sum = sum + #hex(fmt_u) end
    return sum
end, 200 * 14)

-- queued request submit / poll / cancel sweep
local queue_pair, ids_buf = nil, memory.alloc(0x40)
local function queue_setup()
    if queue_pair then close_pair(queue_pair) end
    queue_pair = open_pair()
end

local function queue_verify(value)
    local seen = {}
    for i = 0, 15 do
        local id = memory.read_dword(ids_buf + i * 4):tonumber()
        if id <= 0 then return "invalid id" end
        if seen[id] then return "duplicate id" end
        seen[id] = true
    end
    return nil
end

add("queue submit pattern", 16, true, function(n)
    local sum = 0
    for i = 0, 15 do
        local id = submit_blocked_read(queue_pair[1])
        if not id then return -1 end
        memory.write_dword(ids_buf + i * 4, id)
        sum = sum + id
    end
    return sum
end, -1, queue_setup, queue_verify)

local function poll_state_sum(single, rounds)
    local ok = 1
    for _ = 1, rounds do
        if single then
            for i = 0, 15 do
                local rv = sysint(syscall.aio_multi_poll, ids_buf + i * 4, 1, aio_states)
                if rv < 0 then ok = -1 end
            end
        else
            for i = 1, rounds do
                local rv = sysint(syscall.aio_multi_poll, ids_buf, 16, aio_states)
                if rv < 0 then ok = -1 end
            end
        end
    end
    return ok
end
add("poll sweep, one call per id", 4, false, function(n)
    return poll_state_sum(true, n)
end, 1)
add("poll sweep, batched calls", 4, false, function(n)
    return poll_state_sum(false, n)
end, 1)

add("cancel sweep + close", 16, false, function(n)
    local ok = 1
    for i = 0, 15 do
        local rv = cancel_id(memory.read_dword(ids_buf + i * 4):tonumber())
        if rv < 0 then ok = -1 end
    end
    close_pair(queue_pair)
    queue_pair = nil
    return ok
end, 1)

-- probe descriptor tuple assembly: per-store versus one bulk transfer
local tuple_str = string.char(1, 0, 0, 0, 0x18, 0, 0, 0) ..
    string.char(0, 0, 0x78, 0x56, 0x34, 0x12, 0, 0) .. string.rep("\0", 8)
local tuple_sum = 0
for i = 1, #tuple_str do tuple_sum = tuple_sum + tuple_str:byte(i) end
local tuple_scratch = memory.alloc(0x40)

local function tuple_checksum(text)
    local sum = 0
    for i = 1, #text do sum = sum + text:byte(i) end
    return sum
end

add("probe tuple stores, per-field", 100, false, function(n)
    for _ = 1, n do
        for i = 0, 0x17, 4 do memory.write_dword(tuple_scratch + i, 0) end
        memory.write_dword(tuple_scratch, 1)
        memory.write_dword(tuple_scratch + 4, 0x18)
        memory.write_qword(tuple_scratch + 8, uint64(0x123456780000))
    end
    return tuple_checksum(memory.read_buffer(tuple_scratch, 24))
end, tuple_sum)

add("probe tuple stores, bulk transfer", 100, false, function(n)
    for _ = 1, n do memory.write_buffer(tuple_scratch, tuple_str) end
    return tuple_checksum(memory.read_buffer(tuple_scratch, 24))
end, tuple_sum)

-- full probe: tuple assembly + one write and one read through a stream pair
local probe_pair, probe_scratch, probe_out = nil, memory.alloc(0x40), memory.alloc(0x40)
local function probe_setup()
    if probe_pair then close_pair(probe_pair) end
    probe_pair = open_pair()
end

add("stream probe, per-field tuple", 40, false, function(n)
    local hits = 0
    for _ = 1, n do
        for i = 0, 0x17, 4 do memory.write_dword(probe_scratch + i, 0) end
        memory.write_dword(probe_scratch, 1)
        memory.write_dword(probe_scratch + 4, 0x18)
        memory.write_qword(probe_scratch + 8, uint64(0x123456780000))
        sysint(syscall.write, probe_pair[2], probe_scratch, 24)
        local got = sysint(syscall.read, probe_pair[1], probe_out, 24)
        if got == 24 and memory.read_buffer(probe_out, 24) == tuple_str
            and memory.read_buffer(probe_scratch, 24) == tuple_str then
            hits = hits + 1
        end
    end
    return hits
end, 40, probe_setup, function(value)
    close_pair(probe_pair)
    probe_pair = nil
    return nil
end)

add("stream probe, bulk tuple transfer", 40, false, function(n)
    local hits = 0
    for _ = 1, n do
        memory.write_buffer(probe_scratch, tuple_str)
        sysint(syscall.write, probe_pair[2], probe_scratch, 24)
        local got = sysint(syscall.read, probe_pair[1], probe_out, 24)
        if got == 24 and memory.read_buffer(probe_out, 24) == tuple_str
            and memory.read_buffer(probe_scratch, 24) == tuple_str then
            hits = hits + 1
        end
    end
    return hits
end, 40, probe_setup, function(value)
    close_pair(probe_pair)
    probe_pair = nil
    return nil
end)

-- sysctl marshaling: read pattern, write pattern, window pattern, name lookup
local sysctl_mib = memory.alloc(0x40)
local sysctl_len = memory.alloc(8)
local sysctl_val = memory.alloc(8)

local function do_sysctl(mib, old_ptr, old_len, new_ptr, new_len)
    for i, value in ipairs(mib) do
        memory.write_dword(sysctl_mib + (i - 1) * 4, value)
    end
    memory.write_dword(sysctl_len, old_len or 0)
    local rv = sysint(syscall.sysctl, sysctl_mib, #mib, old_ptr,
        old_ptr and sysctl_len or nil, new_ptr, new_len)
    local len = 0
    if old_ptr then len = memory.read_dword(sysctl_len):tonumber() end
    return rv, len
end

local ncpu = 0
add("sysctl read pattern", 100, true, function(n)
    local sum = 0
    for _ = 1, n do
        local rv, len = do_sysctl({6, 3}, sysctl_val, 4, nil, 0)
        if rv == 0 and len == 4 then
            sum = sum + memory.read_dword(sysctl_val):tonumber()
        else
            sum = sum - 1
        end
    end
    return sum
end, -1, function()
    local rv, len = do_sysctl({6, 3}, sysctl_val, 4, nil, 0)
    assert(rv == 0 and len == 4, "sysctl read setup failed")
    ncpu = memory.read_dword(sysctl_val):tonumber()
end, function(value)
    if value ~= 100 * ncpu then return "sysctl read checksum mismatch" end
    return nil
end)

add("sysctl write pattern", 100, false, function(n)
    local ok = 1
    for _ = 1, n do
        for i, value in ipairs({6, 3}) do
            memory.write_dword(sysctl_mib + (i - 1) * 4, value)
        end
        memory.write_dword(sysctl_val, 0x41424344)
        local rv = sysint(syscall.sysctl, sysctl_mib, 2, nil, nil, sysctl_val, 4)
        if rv ~= -1 then ok = 0 end
    end
    return ok
end, 1)

add("sysctl window read pattern", 100, true, function(n)
    local sum = 0
    for _ = 1, n do
        memory.write_dword(sysctl_mib, 6)
        memory.write_dword(sysctl_mib + 4, 3)
        memory.write_dword(sysctl_len, 4)
        memory.write_dword(sysctl_val, 0)
        sysint(syscall.sysctl, sysctl_mib, 2, nil, nil, sysctl_val, 4)
        local rv = sysint(syscall.sysctl, sysctl_mib, 2, sysctl_val, sysctl_len, nil, 0)
        if rv == 0 then sum = sum + memory.read_dword(sysctl_val):tonumber() - 1 end
    end
    return sum
end, -1, nil, function(value)
    if value ~= 100 * (ncpu - 1) then return "sysctl window read checksum mismatch" end
    return nil
end)

local mib_sum = 0
add("name-to-index lookup pattern", 30, false, function(n)
    local name = "hw.ncpu"
    local name_buf = memory.alloc(#name + 1)
    local out = memory.alloc(0x60)
    for _ = 1, n do
        memory.write_buffer(name_buf, name)
        local _, len = do_sysctl({0, 3}, out, 0x60, name_buf, #name)
        for i = 0, math.floor(len / 4) - 1 do
            mib_sum = mib_sum + memory.read_dword(out + i * 4):tonumber()
        end
    end
    return 1
end, 1, function()
    mib_sum = 0
end, function(value)
    if mib_sum ~= 30 * (6 + 3) then return "mib checksum mismatch" end
    return nil
end)

-- byte-level record scan versus bulk transfer with Lua-side indexing
local rec_sum = 0
local record_bytes = {}
for i = 1, 32 do
    rec_sum = rec_sum + ((i * 7) % 253 + 1) + ((i * 11) % 253 + 1)
        + ((i * 13) % 253 + 1) + ((i * 3) % 253 + 1)
    for b = 0, 127 do
        record_bytes[(i - 1) * 128 + b + 1] = string.char(0)
    end
    record_bytes[(i - 1) * 128 + 41] = string.char((i * 7) % 253 + 1)
    record_bytes[(i - 1) * 128 + 42] = string.char((i * 11) % 253 + 1)
    record_bytes[(i - 1) * 128 + 43] = string.char((i * 13) % 253 + 1)
    record_bytes[(i - 1) * 128 + 44] = string.char((i * 3) % 253 + 1)
end
local scan_buf = memory.alloc(32 * 128)
memory.write_buffer(scan_buf, table.concat(record_bytes, ""))

add("record scan, per-byte reads", 10, false, function(n)
    local sum = 0
    for _ = 1, n do
        for i = 0, 31 do
            for b = 0, 3 do
                sum = sum + memory.read_byte(scan_buf + i * 128 + 40 + b):tonumber()
            end
        end
    end
    return sum
end, 10 * rec_sum)

add("record scan, bulk transfer + indexing", 10, false, function(n)
    local sum = 0
    for _ = 1, n do
        for i = 0, 31 do
            local chunk = memory.read_buffer(scan_buf + i * 128, 128)
            for b = 0, 3 do sum = sum + chunk:byte(41 + b) end
        end
    end
    return sum
end, 10 * rec_sum)

-- slot table scan: per-field scalar reads versus bulk transfer with indexing
local STRIDE = 0x30
local page = memory.alloc(100 * STRIDE)
local slot_sum = 0
local fill_bytes = {}
for i = 0, 99 do
    local gen = i * 8            -- low 3 bits zero, so the slot check passes
    local state, etype = 0x30000, 0x160
    for b = 0, STRIDE - 1 do
        fill_bytes[i * STRIDE + b + 1] = string.char(0)
    end
    for b = 0, 3 do
        fill_bytes[i * STRIDE + 0x28 + b + 1] = string.char(bit32.band(bit32.rshift(gen, b * 8), 0xff))
        fill_bytes[i * STRIDE + 0x24 + b + 1] = string.char(bit32.band(bit32.rshift(state, b * 8), 0xff))
        fill_bytes[i * STRIDE + 0x20 + b + 1] = string.char(bit32.band(bit32.rshift(etype, b * 8), 0xff))
    end
    local qword = i * 0x30 + 0x100
    for b = 0, 3 do
        fill_bytes[i * STRIDE + 0x10 + b + 1] = string.char(bit32.band(bit32.rshift(qword, b * 8), 0xff))
    end
    fill_bytes[i * STRIDE + 0x10 + 5] = string.char(0xff)
    fill_bytes[i * STRIDE + 0x10 + 6] = string.char(0xff)
    slot_sum = slot_sum + bit32.band(gen, 0xffff) + bit32.rshift(state, 16)
        + bit32.band(etype, 0xffff) + 0xffff
end
memory.write_buffer(page, table.concat(fill_bytes, ""))

add("slot scan, per-field scalar reads", 10, false, function(n)
    local base = page
    local sum = 0
    for pass = 1, n do
        for i = 0, 99 do
            local slot = base + i * STRIDE
            local gen = memory.read_dword(slot + 0x28):tonumber()
            if bit32.band(bit32.bor(bit32.lshift(bit32.band(gen, 0xffff), 13),
                bit32.band(i, 0x7f)), 0xffff) == i then
                sum = sum + bit32.band(gen, 0xffff)
                local state = memory.read_dword(slot + 0x24):tonumber()
                sum = sum + bit32.rshift(state, 16)
                local etype = memory.read_dword(slot + 0x20):tonumber()
                sum = sum + bit32.band(etype, 0xffff)
                local q = memory.read_qword(slot + 0x10)
                if bit32.band(q.h, 0xffff) == 0xffff then
                    sum = sum + bit32.band(q.h, 0xffff)
                end
            end
        end
    end
    return sum
end, 10 * slot_sum)

add("slot scan, bulk transfer + indexing", 10, false, function(n)
    local sum = 0
    for pass = 1, n do
        local blob = memory.read_buffer(page, 100 * STRIDE)
        for i = 0, 99 do
            local off = i * STRIDE
            local gen = blob:byte(off + 0x29) + blob:byte(off + 0x28 + 2) * 0x100
                + blob:byte(off + 0x28 + 3) * 0x10000 + blob:byte(off + 0x28 + 4) * 0x1000000
            if bit32.band(bit32.bor(bit32.lshift(bit32.band(gen, 0xffff), 13),
                bit32.band(i, 0x7f)), 0xffff) == i then
                sum = sum + bit32.band(gen, 0xffff)
                local state = blob:byte(off + 0x25) + blob:byte(off + 0x24 + 2) * 0x100
                    + blob:byte(off + 0x24 + 3) * 0x10000 + blob:byte(off + 0x24 + 4) * 0x1000000
                sum = sum + bit32.rshift(state, 16)
                local etype = blob:byte(off + 0x21) + blob:byte(off + 0x20 + 2) * 0x100
                    + blob:byte(off + 0x20 + 3) * 0x10000 + blob:byte(off + 0x20 + 4) * 0x1000000
                sum = sum + bit32.band(etype, 0xffff)
                if blob:byte(off + 0x16) == 0xff and blob:byte(off + 0x15) == 0xff then
                    sum = sum + 0xffff
                end
            end
        end
    end
    return sum
end, 10 * slot_sum)

-- chain batching: construction, execution, and result read-back
local chain_bufs = nil
local function chain_build(count)
    local chain = ropchain({stack_size = 0x2000})
    for _ = 1, count do
        chain:push_syscall_with_ret(syscall.getpid)
    end
    chain:restore_through_longjmp()
    chain_bufs = chain.retval_addr
    return chain
end
local function chain_release(chain)
    release_memory(chain.stack_base)
    release_memory(chain.jmpbuf)
    for _, addr in ipairs(chain.retval_addr or {}) do release_memory(addr) end
end
local function chain_exec(chain)
    local result = chain:execute_through_coroutine()
    return result == false and 0 or 1
end

add("chain construction (40 pushes)", 3, false, function(n)
    local total = 0
    for _ = 1, n do
        local chain = chain_build(40)
        total = total + 40
        chain_release(chain)
    end
    return total
end, 3 * 40)

add("chain exec, 40-syscall batch", 3, false, function(n)
    local total = 0
    for _ = 1, n do
        local chain = chain_build(40)
        total = total + chain_exec(chain)
        chain_release(chain)
    end
    return total
end, 3)

add("getpid post-chain control, 40 individual calls", 3, false, function(n)
    local total = 0
    for _ = 1, n do
        for _ = 1, 40 do total = total + syscall.getpid():tonumber() end
    end
    return total
end, 3 * 40 * pid)

local function readback_slots()
    local sum = 0
    for i = 1, #chain_bufs do
        sum = sum + memory.read_dword(chain_bufs[i]):tonumber()
    end
    return sum
end

add("chain result readback, per-slot", 3, false, function(n)
    local chain = chain_build(40)
    chain_exec(chain)
    local sum = 0
    for _ = 1, n do sum = sum + readback_slots() end
    chain_release(chain)
    return sum
end, 3 * 40 * pid)

add("chain result readback, bulk transfer", 3, false, function(n)
    local chain = chain_build(40)
    chain_exec(chain)
    local stride = chain_bufs[2].l - chain_bufs[1].l
    local contiguous = (stride == 8 or stride == 16)
    if contiguous then
        for i = 2, #chain_bufs do
            if chain_bufs[i].l ~= chain_bufs[1].l + (i - 1) * stride then
                contiguous = false
                break
            end
        end
    end
    local sum = 0
    for _ = 1, n do
        if contiguous then
            local blob = memory.read_buffer(chain_bufs[1], #chain_bufs * stride)
            for i = 0, #chain_bufs - 1 do
                local p = i * stride
                sum = sum + blob:byte(p + 1) + blob:byte(p + 2) * 0x100
                    + blob:byte(p + 3) * 0x10000 + blob:byte(p + 4) * 0x1000000
            end
        else
            sum = sum + readback_slots()
        end
    end
    chain_release(chain)
    return sum
end, 3 * 40 * pid)

-- sleep pacing and sweep+sleep patterns
local sweep_pair = nil
local function sweep_setup()
    if sweep_pair then close_pair(sweep_pair) end
    sweep_pair = open_pair()
end

add("sweep+sleep, individual calls", 3, false, function(n)
    local ids = memory.alloc(16)
    for i = 0, 3 do
        local id = submit_blocked_read(sweep_pair[1])
        if not id then return -1 end
        memory.write_dword(ids + i * 4, id)
    end
    local ok = 1
    for _ = 1, n do
        for _ = 1, 3 do
            sleep(20, "ms")
            for j = 0, 3 do
                local rv = sysint(syscall.aio_multi_poll, ids + j * 4, 1, aio_states)
                if rv < 0 then ok = -1 end
            end
        end
    end
    for i = 0, 3 do
        cancel_id(memory.read_dword(ids + i * 4):tonumber())
    end
    close_pair(sweep_pair)
    sweep_pair = nil
    release_memory(ids)
    return ok
end, 1, sweep_setup)

add("sweep+sleep, single-chain sweeps", 3, false, function(n)
    local ids = memory.alloc(16)
    for i = 0, 3 do
        local id = submit_blocked_read(sweep_pair[1])
        if not id then return -1 end
        memory.write_dword(ids + i * 4, id)
    end
    local ts = memory.alloc(16)
    memory.write_dword(ts, 0)
    memory.write_dword(ts + 8, 20000000)
    local ok = 1
    for _ = 1, n do
        for _ = 1, 3 do
            local chain = ropchain({stack_size = 0x2000})
            chain:push_syscall(syscall.nanosleep, ts, 0)
            for j = 0, 3 do
                chain:push_syscall(syscall.aio_multi_poll, ids + j * 4, 1, aio_states)
            end
            chain:restore_through_longjmp()
            if chain_exec(chain) ~= 1 then ok = -1 end
            chain_release(chain)
        end
    end
    for i = 0, 3 do
        cancel_id(memory.read_dword(ids + i * 4):tonumber())
    end
    close_pair(sweep_pair)
    sweep_pair = nil
    release_memory(ids)
    release_memory(ts)
    return ok
end, 1, sweep_setup)

add("short sleep quantization (10 x 1 ms)", 10, false, function(n)
    for _ = 1, n do sleep(1, "ms") end
    return n
end, 10)

add("long sleep quantization (3 x 50 ms)", 3, false, function(n)
    for _ = 1, n do sleep(50, "ms") end
    return n
end, 3)

add("cleanup sweep (cancel surviving requests)", 1, false, function(n)
    while #pending_ids > 0 do
        local rv = cancel_id(pending_ids[#pending_ids])
        if rv < 0 then return -1 end
    end
    return 1
end, 1, nil, function(value)
    for i = #pending_ids, 1, -1 do
        table.remove(pending_ids, i)
    end
    return nil
end)

local function sample(c, save)
    if c.setup then c.setup() end
    local elapsed, value = timed(c.fn, c.n)
    if c.loose then
        assert(type(value) == "number" and value >= 0, c.name .. " produced an invalid value")
    else
        assert(type(value) == "number" and value == c.expected,
            c.name .. ": checksum mismatch (" .. tostring(value) .. " vs " .. tostring(c.expected) .. ")")
    end
    if c.verify then
        local msg = c.verify(value)
        if msg then error(c.name .. ": " .. msg) end
    end
    if save then c.times[#c.times + 1] = elapsed end
end

print("compat benchmark v4d: stall-phase patterns, 3 samples, 1 warmup per case")
print("Units: elapsed microseconds; fixed counts; setup/logging/cleanup outside timing.")
print("Case columns: median ms | min ms | max ms | median us per pattern-op | status")

local overhead = {}
local function empty() return 0 end
local run_ok, run_error = pcall(function()
    for pass = 1, WARMUPS do
        for _, c in ipairs(cases) do sample(c, false) end
    end
    print("warmup complete")

    for pass = 1, SAMPLES do
        overhead[#overhead + 1] = timed(empty, 1)
        for _, c in ipairs(cases) do
            sample(c, true)
        end
        printf("pass %d/%d complete", pass, SAMPLES)
    end
end)

if not run_ok then
    while #pending_ids > 0 do
        local id = pending_ids[#pending_ids]
        if cancel_id(id) < 0 then break end
    end
    if queue_pair then close_pair(queue_pair); queue_pair = nil end
    if probe_pair then close_pair(probe_pair); probe_pair = nil end
    if sweep_pair then close_pair(sweep_pair); sweep_pair = nil end
    error(run_error)
end

if queue_pair then close_pair(queue_pair) end

local floor, floor_min, floor_max = stats(overhead)
printf("timer floor: median %.3f us, min %.3f, max %.3f", floor, floor_min, floor_max)

print("case | ops | median ms | min ms | max ms | us/op | signal")
for _, c in ipairs(cases) do
    local med, lo, hi = stats(c.times)
    printf("%s | %d | %.3f | %.3f | %.3f | %.3f | %s",
        c.name, c.n, med / 1000, lo / 1000, hi / 1000, med / c.n,
        med < 10 * floor and "LOW" or "OK")
    local raw = {}
    for i, v in ipairs(c.times) do raw[i] = string.format("%.3f", v) end
    printf("samples_us,%s,%s", c.name, table.concat(raw, ","))
end

local function us_of(name)
    for _, c in ipairs(cases) do
        if c.name == name then
            local med = stats(c.times)
            return med / c.n
        end
    end
    return 0
end

local rt = us_of("getpid control, 40 individual calls") / 40
local store_a = us_of("probe tuple stores, per-field") / 9
local store_b = us_of("probe tuple stores, bulk transfer")
local construct = us_of("uint64 construct+add control")
local format_us = us_of("string.format control")
local hex_us = us_of("uint64 formatting control")
local probe_a = us_of("stream probe, per-field tuple")
local probe_b = us_of("stream probe, bulk tuple transfer")
local sleep_short = us_of("short sleep quantization (10 x 1 ms)")
local sleep_long = us_of("long sleep quantization (3 x 50 ms)")

printf("unit medians: round-trip %.3f us | store dispatch %.3f us | bulk store %.3f us | construct+add %.3f us | format %.3f us | hex %.3f us",
    rt, store_a, store_b, construct, format_us, hex_us)
printf("stream probe per-field %.3f us | stream probe bulk %.3f us | short sleep %.3f us per call | long sleep %.3f us per call",
    probe_a, probe_b, sleep_short, sleep_long)

local phase1 = (R1 * rt + S1 * store_a + K1 * construct + F1 * format_us + SL1 * sleep_long) / 1000
local phase2 = (R2 * rt + S2 * store_a + K2 * construct + F2 * format_us + P2_ * probe_a) / 1000
printf("phase 1 estimate (R%d S%d K%d F%d SL%d): %.1f ms", R1, S1, K1, F1, SL1, phase1)
printf("phase 2 estimate (R%d S%d K%d F%d P%d): %.1f ms", R2, S2, K2, F2, P2_, phase2)
printf("reference phase totals estimate: %.1f ms (counts are profile constants, unit times are measured medians)",
    phase1 + phase2)

print("compat benchmark v4d complete; all checksums verified; requests cancelled; sockets closed")
