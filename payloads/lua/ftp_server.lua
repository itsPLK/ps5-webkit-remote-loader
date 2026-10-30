--!lua
-- Lua FTP server for PS5 WebKit Remote Loader (LuaK1t + remote_lua_loader profile).
-- Ported from Al-Azif / @horror's remote_lua_loader ftp_server.lua with PS5 WebKit
-- fixes: auto-detected LAN IP, 64 KiB getdents buffer, proper PASV port byte order,
-- reused transfer/stat buffers, and SITE STOP support.

FTP_DEBUG_MSG = "on"
conn_types = {
    none = 0x0,
    active = 0x1,
    passive = 0x2
}

ftp = {
    server = {
        ip = get_current_ip and get_current_ip() or "127.0.0.1",
        port = 1337,
        server_sockfd = nil,
        server_sockaddr = memory.alloc(16),
        default_file_buf = 0x200,
        rname = "",
        stopped = false
    },
    client = {
        ctrl_sockfd = nil,
        data_sockfd = nil,
        pasv_sockfd = nil,

        data_sockaddr = memory.alloc(16),
        pasv_sockaddr = memory.alloc(16),
        ctrl_sockaddr = memory.alloc(16),

        pasv_sockaddr_len = memory.alloc(8),
        ctrl_sockaddr_len = memory.alloc(8),

        data_port = nil,

        root_path = "/",
        cur_path = "/",
        conn_type = conn_types.none,
        transfer_type = "I",
        restore_point = -1,
        is_connected = false,
        cur_cmd = nil
    }
}

AF_INET = 2
SOCK_STREAM = 1
INADDR_ANY = 0
SCE_NET_SO_REUSEADDR = 0x00000004
SCE_NET_SOL_SOCKET = 0xFFFF

local shared_st = memory.alloc(128)
local shared_tm = memory.alloc(48)
local shared_dir_buf = memory.alloc(65536)
local shared_io_buf = memory.alloc(8192)
local shared_picked = memory.alloc(16)
local shared_namelen = memory.alloc(8)

function S_ISDIR(m) return bit32.band(m, tonumber("0170000", 8)) == tonumber("0040000", 8) end
function S_ISCHR(m) return bit32.band(m, tonumber("0170000", 8)) == tonumber("0020000", 8) end
function S_ISBLK(m) return bit32.band(m, tonumber("0170000", 8)) == tonumber("0060000", 8) end
function S_ISREG(m) return bit32.band(m, tonumber("0170000", 8)) == tonumber("0100000", 8) end
function S_ISFIFO(m) return bit32.band(m, tonumber("0170000", 8)) == tonumber("0010000", 8) end
function S_ISLNK(m) return bit32.band(m, tonumber("0170000", 8)) == tonumber("0120000", 8) end
function S_ISSOCK(m) return bit32.band(m, tonumber("0170000", 8)) == tonumber("0140000", 8) end
function S_ISWHT(m) return bit32.band(m, tonumber("0170000", 8)) == tonumber("0160000", 8) end

function sceKernelSendDebug(text)
    if FTP_DEBUG_MSG == "on" then
        send_ps_notification(text)
    end
end

function read_u8(addr)
    local f = memory.read_buffer(addr, 1)
    return f:byte(1)
end

function read_u16(addr)
    local f = memory.read_buffer(addr, 2)
    local lo = f:byte(2)
    local hi = f:byte(1)
    return bit32.bor(hi, bit32.lshift(lo, 8))
end

function sceNetRecv(sockfd, buf, len, flags)
    return syscall.recvfrom(sockfd, buf, len, flags, 0, 0):tonumber()
end

function sceNetSend(sockfd, buf, len, flags)
    return syscall.sendto(sockfd, buf, len, flags, 0, 0):tonumber()
end

function sceNetListen(sockfd, backlog)
    return syscall.listen(sockfd, backlog):tonumber()
end

function sceNetBind(sockfd, addr, addrlen)
    return syscall.bind(sockfd, addr, addrlen):tonumber()
end

function sceNetSocket(domain, type, protocol)
    return syscall.socket(domain, type, protocol):tonumber()
end

function sceNetSocketClose(sockfd)
    if not sockfd or sockfd < 0 then return 0 end
    return syscall.close(sockfd):tonumber()
end

function sceNetSetsockopt(sockfd, level, optname, optval, optlen)
    return syscall.setsockopt(sockfd, level, optname, optval, optlen):tonumber()
end

function sceNetHtonl(hostlong)
    return bit32.bor(
        bit32.lshift(bit32.band(hostlong, 0xFF), 24),
        bit32.lshift(bit32.band(hostlong, 0xFF00), 8),
        bit32.rshift(bit32.band(hostlong, 0xFF0000), 8),
        bit32.rshift(bit32.band(hostlong, 0xFF000000), 24)
    )
end

function sceNetHtons(hostshort)
    return bit32.bor(
        bit32.lshift(bit32.band(hostshort, 0xFF), 8),
        bit32.rshift(bit32.band(hostshort, 0xFF00), 8)
    )
end

function sceNetAccept(sockfd, addr, addrlen)
    return syscall.accept(sockfd, addr, addrlen):tonumber()
end

function sceNetConnect(sockfd, addr, addrlen)
    return syscall.connect(sockfd, addr, addrlen):tonumber()
end

function sceNetGetsockname(sockfd, addr, addrlen)
    return syscall.getsockname(sockfd, addr, addrlen):tonumber()
end

function sceStat(path, st)
    return syscall.stat(path, st):tonumber()
end

function sceOpen(path, flags, mode)
    return syscall.open(path, flags, mode):tonumber()
end

function sceRead(fd, buf, len)
    return syscall.read(fd, buf, len):tonumber()
end

function sceWrite(fd, buf, len)
    return syscall.write(fd, buf, len):tonumber()
end

function sceLseek(fd, offset, whence)
    return syscall.lseek(fd, offset, whence):tonumber()
end

function sceGetdents(sck, buf, len)
    return syscall.getdents(sck, buf, len):tonumber()
end

function sceClose(sck)
    if not sck or sck < 0 then return 0 end
    return syscall.close(sck):tonumber()
end

function sceMkdir(path, mode)
    return syscall.mkdir(path, mode):tonumber()
end

function sceRmdir(path)
    return syscall.rmdir(path):tonumber()
end

function sceRename(old, new)
    return syscall.rename(old, new):tonumber()
end

function sceUnlink(path)
    return syscall.unlink(path):tonumber()
end

function sceChmod(path, mode)
    return syscall.chmod(path, mode):tonumber()
end

function sceFileExists(path)
    return sceStat(path, shared_st) >= 0
end

function sceNetInetPton(addr)
    local a, b, c, d = addr:match("(%d+)%.(%d+)%.(%d+)%.(%d+)")
    a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
    local ip_binary = (a * 256 ^ 3) + (b * 256 ^ 2) + (c * 256) + d
    local f0 = bit32.band(bit32.rshift(ip_binary, 24), 0xFF)
    local f1 = bit32.band(bit32.rshift(ip_binary, 8), 0xFF00)
    local f2 = bit32.band(bit32.lshift(ip_binary, 8), 0xFF0000)
    local f3 = bit32.band(bit32.lshift(ip_binary, 24), 0xFF000000)
    return bit32.bor(f0, f1, f2, f3)
end

function ftp_open_data_conn()
    if ftp.client.conn_type == conn_types.active then
        sceNetConnect(ftp.client.data_sockfd, ftp.client.data_sockaddr, 16)
    else
        memory.write_dword(ftp.client.pasv_sockaddr_len, 16)
        ftp.client.pasv_sockfd = sceNetAccept(ftp.client.data_sockfd, ftp.client.pasv_sockaddr,
            ftp.client.pasv_sockaddr_len)
    end
end

function ftp_close_data_conn()
    if ftp.client.data_sockfd then
        sceNetSocketClose(ftp.client.data_sockfd)
        ftp.client.data_sockfd = nil
    end
    if ftp.client.conn_type == conn_types.passive and ftp.client.pasv_sockfd then
        sceNetSocketClose(ftp.client.pasv_sockfd)
        ftp.client.pasv_sockfd = nil
    end
    ftp.client.conn_type = conn_types.none
end

function ftp_send_data_msg(str)
    if ftp.client.conn_type == conn_types.active then
        sceNetSend(ftp.client.data_sockfd, str, #str, 0)
    else
        sceNetSend(ftp.client.pasv_sockfd, str, #str, 0)
    end
end

function ftp_send_ctrl_msg(str)
    sceNetSend(ftp.client.ctrl_sockfd, str, #str, 0)
end

function ftp_send_welcome()
    ftp_send_ctrl_msg("220 LuaK1t FTP Server\r\n")
end

function resolve_ftp_path(base, target)
    if not target or target == "" then return base end
    local combined = target:sub(1, 1) == "/" and target or (base == "/" and ("/" .. target) or (base .. "/" .. target))
    local parts = {}
    for part in combined:gmatch("[^/]+") do
        if part == ".." then
            table.remove(parts)
        elseif part ~= "." then
            table.insert(parts, part)
        end
    end
    return "/" .. table.concat(parts, "/")
end

function sanitize_path(from, to)
    return resolve_ftp_path(from, to)
end

function dir_up(path)
    return resolve_ftp_path(path, "..")
end

function file_type_char(mode)
    if S_ISDIR(mode) then return 'd' end
    if S_ISREG(mode) then return '-' end
    if S_ISLNK(mode) then return 'l' end
    if S_ISCHR(mode) then return 'c' end
    if S_ISBLK(mode) then return 'b' end
    if S_ISFIFO(mode) then return 'p' end
    if S_ISSOCK(mode) then return 's' end
    if S_ISWHT(mode) then return 'w' end
    return '-'
end

function list_args(mode)
    local f = file_type_char(mode)
    f = f .. (bit32.band(mode, tonumber("0400", 8)) > 0 and "r" or "-")
    f = f .. (bit32.band(mode, tonumber("0200", 8)) > 0 and "w" or "-")
    f = f .. (bit32.band(mode, tonumber("0100", 8)) > 0 and (S_ISDIR(mode) and "s" or "x") or (S_ISDIR(mode) and "S" or "-"))
    f = f .. (bit32.band(mode, tonumber("0040", 8)) > 0 and "r" or "-")
    f = f .. (bit32.band(mode, tonumber("0020", 8)) > 0 and "w" or "-")
    f = f .. (bit32.band(mode, tonumber("0010", 8)) > 0 and (S_ISDIR(mode) and "s" or "x") or (S_ISDIR(mode) and "S" or "-"))
    f = f .. (bit32.band(mode, tonumber("0004", 8)) > 0 and "r" or "-")
    f = f .. (bit32.band(mode, tonumber("0002", 8)) > 0 and "w" or "-")
    f = f .. (bit32.band(mode, tonumber("0001", 8)) > 0 and (S_ISDIR(mode) and "s" or "x") or (S_ISDIR(mode) and "S" or "-"))
    return f
end

function ftp_send_size()
    local arg = ftp.client.cur_cmd:match("^SIZE%s+(.+)")
    local dir = arg and resolve_ftp_path(ftp.client.cur_path, arg) or ftp.client.cur_path
    if sceStat(dir, shared_st) < 0 then
        ftp_send_ctrl_msg("550 The file doesn't exist\r\n")
        return
    end
    local file_size = memory.read_qword(shared_st + 72):tonumber()
    ftp_send_ctrl_msg(string.format("213 %d\r\n", file_size))
end

function ftp_send_list()
    local arg = ftp.client.cur_cmd:match("^LIST%s+(.+)")
    if arg then
        arg = arg:gsub("^%-[aAlL]+%s*", "")
    end
    local target_dir = (arg and arg ~= "") and resolve_ftp_path(ftp.client.cur_path, arg) or ftp.client.cur_path

    if sceStat(target_dir, shared_st) < 0 then
        ftp_send_ctrl_msg(string.format("550 Invalid directory. Got %s\r\n", target_dir))
        return
    end

    local fd = sceOpen(target_dir, 0, 0)
    if fd < 0 then
        ftp_send_ctrl_msg(string.format("550 Invalid directory. Got %s\r\n", target_dir))
        return
    end

    local months = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" }

    ftp_send_ctrl_msg("150 Opening ASCII mode data transfer for LIST.\r\n")
    ftp_open_data_conn()

    while true do
        local nread = sceGetdents(fd, shared_dir_buf, 65536)
        if nread <= 0 then break end

        local entry = shared_dir_buf
        local end_ptr = shared_dir_buf + nread

        while entry < end_ptr do
            local length = read_u16(entry + 0x4)
            if length == 0 then break end

            local namlen = read_u8(entry + 0x7)
            local name = memory.read_buffer(entry + 0x8, namlen)

            if name ~= "." and name ~= ".." then
                local full_path = (target_dir == "/" and "" or target_dir) .. "/" .. name
                if sceStat(full_path, shared_st) >= 0 then
                    local file_mode = read_u16(shared_st + 8)
                    local file_size = memory.read_qword(shared_st + 72):tonumber()

                    gmtime_s(shared_st + 40, shared_tm)
                    local n_hour = memory.read_dword(shared_tm + 8):tonumber()
                    local n_mins = memory.read_dword(shared_tm + 4):tonumber()
                    local n_mday = memory.read_dword(shared_tm + 12):tonumber()
                    local n_mon = memory.read_dword(shared_tm + 16):tonumber()

                    ftp_send_data_msg(string.format("%s 1 ps5 ps5 %d %s %2d %02d:%02d %s\r\n",
                        list_args(file_mode),
                        file_size,
                        months[(n_mon % 12) + 1] or "Jan",
                        n_mday > 0 and n_mday or 1,
                        n_hour,
                        n_mins,
                        name))
                end
            end

            entry = entry + length
        end
    end

    sceClose(fd)
    ftp_close_data_conn()
    ftp_send_ctrl_msg("226 Transfer complete\r\n")
end

function ftp_send_type()
    local requested_type = ftp.client.cur_cmd:match("^TYPE%s+(.+)")
    if requested_type == "I" or requested_type == "L 8" then
        ftp.client.transfer_type = "I"
        ftp_send_ctrl_msg("200 Switching to Binary mode\r\n")
    elseif requested_type == "A" or requested_type == "A N" then
        ftp.client.transfer_type = "A"
        ftp_send_ctrl_msg("200 Switching to ASCII mode\r\n")
    else
        ftp_send_ctrl_msg("504 Command not implemented for that parameter\r\n")
    end
end

function ftp_send_pasv()
    ftp_close_data_conn()
    local a, b, c, d = ftp.server.ip:match("(%d+)%.(%d+)%.(%d+)%.(%d+)")
    a, b, c, d = tonumber(a) or 127, tonumber(b) or 0, tonumber(c) or 0, tonumber(d) or 1
    ftp.client.data_sockfd = sceNetSocket(AF_INET, SOCK_STREAM, 0)

    memory.write_byte(ftp.client.data_sockaddr + 1, AF_INET)
    memory.write_word(ftp.client.data_sockaddr + 2, 0)
    memory.write_dword(ftp.client.data_sockaddr + 4, 0)

    sceNetBind(ftp.client.data_sockfd, ftp.client.data_sockaddr, 16)
    sceNetListen(ftp.client.data_sockfd, 128)

    memory.write_dword(shared_namelen, 16)
    sceNetGetsockname(ftp.client.data_sockfd, shared_picked, shared_namelen)

    local port_buf = memory.read_buffer(shared_picked + 2, 2)
    local p_hi, p_lo = string.byte(port_buf, 1), string.byte(port_buf, 2)

    local cmd = string.format("227 Entering Passive Mode (%d,%d,%d,%d,%d,%d)\r\n", a, b, c, d, p_hi, p_lo)
    ftp_send_ctrl_msg(cmd)
    ftp.client.conn_type = conn_types.passive
end

function ftp_send_cwd()
    local new_path = ftp.client.cur_cmd:match("^CWD%s+(.+)")
    sceKernelSendDebug(ftp.client.cur_cmd)

    if not new_path then
        ftp_send_ctrl_msg("500 Syntax error, command unrecognized.\r\n")
        return
    end

    local tmp_path = resolve_ftp_path(ftp.client.cur_path, new_path)
    if sceStat(tmp_path, shared_st) < 0 or not S_ISDIR(read_u16(shared_st + 8)) then
        ftp_send_ctrl_msg("550 Invalid directory.\r\n")
        return
    end

    ftp.client.cur_path = tmp_path
    ftp_send_ctrl_msg("250 Requested file action okay, completed.\r\n")
end

function ftp_send_port()
    ftp_close_data_conn()
    local ip1, ip2, ip3, ip4, port_hi, port_lo = ftp.client.cur_cmd:match("^PORT%s+(%d+),(%d+),(%d+),(%d+),(%d+),(%d+)")
    if not ip1 or not port_hi then
        ftp_send_ctrl_msg("501 Invalid PORT syntax\r\n")
        return
    end

    local data_port = tonumber(port_lo) + tonumber(port_hi) * 256
    if not data_port then
        ftp_send_ctrl_msg("501 Invalid PORT number\r\n")
        return
    end

    ftp.client.data_sockfd = sceNetSocket(AF_INET, SOCK_STREAM, 0)
    if ftp.client.data_sockfd < 0 then
        ftp_send_ctrl_msg("425 Cannot open data socket\r\n")
        return
    end

    local ip_bin = sceNetInetPton(string.format("%d.%d.%d.%d", ip1, ip2, ip3, ip4))

    memory.write_byte(ftp.client.data_sockaddr + 1, AF_INET)
    memory.write_word(ftp.client.data_sockaddr + 2, sceNetHtons(data_port))
    memory.write_dword(ftp.client.data_sockaddr + 4, ip_bin)

    ftp.client.conn_type = conn_types.active
    ftp_send_ctrl_msg("200 PORT command ok\r\n")
end

function ftp_send_syst()
    ftp_send_ctrl_msg("215 UNIX Type: L8\r\n")
end

function ftp_send_feat()
    ftp_send_ctrl_msg("211-extensions\r\n REST STREAM\r\n SIZE\r\n UTF8\r\n211 end\r\n")
end

function ftp_send_cdup()
    ftp.client.cur_path = dir_up(ftp.client.cur_path or "/")
    ftp_send_ctrl_msg("200 Command okay\r\n")
end

function ftp_send_data_raw(buf, len)
    if ftp.client.conn_type == conn_types.active then
        sceNetSend(ftp.client.data_sockfd, buf, len, 0)
    else
        sceNetSend(ftp.client.pasv_sockfd, buf, len, 0)
    end
end

function ftp_recv_data_raw(buf, len)
    if ftp.client.conn_type == conn_types.active then
        return sceNetRecv(ftp.client.data_sockfd, buf, len, 0)
    else
        return sceNetRecv(ftp.client.pasv_sockfd, buf, len, 0)
    end
end

function ftp_send_file(path)
    local fd = sceOpen(path, 0, 0)
    if fd < 0 then
        ftp_send_ctrl_msg("550 File not found\r\n")
        return
    end

    if ftp.client.restore_point and ftp.client.restore_point > 0 then
        sceLseek(fd, ftp.client.restore_point, 0)
    end
    ftp.client.restore_point = -1

    if sceStat(path, shared_st) < 0 then
        sceClose(fd)
        ftp_send_ctrl_msg("550 File not found\r\n")
        return
    end

    local file_size = memory.read_qword(shared_st + 72):tonumber()
    local chunk_size = 8192
    local bytes_sent = 0
    ftp_open_data_conn()
    ftp_send_ctrl_msg("150 Opening Image mode data transfer\r\n")

    while bytes_sent < file_size do
        local bytes_to_read = math.min(chunk_size, file_size - bytes_sent)
        local n_recv = sceRead(fd, shared_io_buf, bytes_to_read)

        if n_recv <= 0 then break end
        ftp_send_data_raw(shared_io_buf, n_recv)
        bytes_sent = bytes_sent + n_recv
    end

    sceClose(fd)
    ftp_close_data_conn()
    ftp_send_ctrl_msg("226 Transfer completed\r\n")
end

function ftp_recv_file(path)
    local O_CREATE = 0x0200
    local O_RDWR = 0x0002
    local O_APPEND = 0x0008
    local O_TRUNC = 0x0400

    local mode = bit32.bor(O_CREATE, O_RDWR)

    if ftp.client.restore_point and ftp.client.restore_point >= 0 then
        mode = bit32.bor(mode, O_APPEND)
    else
        mode = bit32.bor(mode, O_TRUNC)
    end
    ftp.client.restore_point = -1

    local fd = sceOpen(path, mode, tonumber("0777", 8))
    if fd < 0 then
        ftp_send_ctrl_msg("550 Error opening file\r\n")
        return
    end

    ftp_open_data_conn()
    ftp_send_ctrl_msg("150 Opening Image mode data transfer\r\n")

    local chunk_size = 8192

    while true do
        local n_recv = ftp_recv_data_raw(shared_io_buf, chunk_size)
        if n_recv <= 0 then break end

        local n_written = sceWrite(fd, shared_io_buf, n_recv)
        if n_written < n_recv then
            ftp_send_ctrl_msg("550 File write error\r\n")
            break
        end
    end

    ftp_close_data_conn()
    sceClose(fd)
    ftp_send_ctrl_msg("226 Transfer completed\r\n")
end

function ftp_send_retr()
    local path = ftp.client.cur_cmd:match("^RETR%s+(.+)")
    local dir = sanitize_path(ftp.client.cur_path, path)
    sceKernelSendDebug("Requested (RETR): " .. dir)
    ftp_send_file(dir)
end

function ftp_send_stor()
    local path = ftp.client.cur_cmd:match("^STOR%s+(.+)")
    local dir = sanitize_path(ftp.client.cur_path, path)
    sceKernelSendDebug("Requested (STOR): " .. dir)
    ftp_recv_file(dir)
end

function ftp_send_appe()
    local path = ftp.client.cur_cmd:match("^APPE%s+(.+)")
    local dir = sanitize_path(ftp.client.cur_path, path)
    sceKernelSendDebug("Requested (APPE): " .. dir)
    ftp.client.restore_point = 0
    ftp_recv_file(dir)
end

function ftp_send_rest()
    local rest = ftp.client.cur_cmd:match("^REST%s+(%d+)")
    ftp.client.restore_point = tonumber(rest) or -1
    sceKernelSendDebug("Requested (REST): " .. tostring(rest))
    ftp_send_ctrl_msg(string.format("350 Resuming at %d\r\n", ftp.client.restore_point))
end

function ftp_send_mkd()
    local path = ftp.client.cur_cmd:match("^MKD%s+(.+)")
    local dir = sanitize_path(ftp.client.cur_path, path)

    sceKernelSendDebug("Requested (MKD): " .. dir)
    local fd = sceOpen(dir, 0, 0)
    if fd >= 0 then
        sceClose(fd)
        ftp_send_ctrl_msg("550 Requested action not taken. Folder already exists.\r\n")
    else
        if sceMkdir(dir, tonumber("0755", 8)) < 0 then
            ftp_send_ctrl_msg("550 Permission denied.\r\n")
        else
            ftp_send_ctrl_msg(string.format("257 \"%s\" created.\r\n", path))
        end
    end
end

function ftp_send_rmd()
    local path = ftp.client.cur_cmd:match("^RMD%s+(.+)")
    local dir = sanitize_path(ftp.client.cur_path, path)

    sceKernelSendDebug("Requested (RMD): " .. dir)
    if sceRmdir(dir) < 0 then
        ftp_send_ctrl_msg("550 Directory not found or permission denied\r\n")
    else
        ftp_send_ctrl_msg(string.format("250 \"%s\" has been removed\r\n", path))
    end
end

function ftp_send_dele()
    local path = ftp.client.cur_cmd:match("^DELE%s+(.+)")
    local dir = sanitize_path(ftp.client.cur_path, path)

    sceKernelSendDebug("Requested (DELE): " .. dir)
    if sceUnlink(dir) < 0 then
        ftp_send_ctrl_msg("550 Could not delete the file\r\n")
    else
        ftp_send_ctrl_msg("250 File deleted\r\n")
    end
end

function ftp_send_rnfr()
    local path = ftp.client.cur_cmd:match("^RNFR%s+(.+)")
    local dir = sanitize_path(ftp.client.cur_path, path)

    sceKernelSendDebug("Requested (RNFR): " .. dir)
    if sceFileExists(dir) then
        ftp.server.rname = dir
        ftp_send_ctrl_msg("350 Remembered filename\r\n")
        return
    end
    ftp_send_ctrl_msg("550 The file doesn't exist\r\n")
end

function ftp_send_rnto()
    local path = ftp.client.cur_cmd:match("^RNTO%s+(.+)")
    local dir_old = ftp.server.rname
    local dir_new = sanitize_path(ftp.client.cur_path, path)

    sceKernelSendDebug("Requested (RNTO): " .. dir_old .. " -> " .. dir_new)
    if sceRename(dir_old, dir_new) < 0 then
        ftp_send_ctrl_msg("550 Error renaming file\r\n")
    else
        ftp_send_ctrl_msg("250 Renamed file\r\n")
    end
end

function ftp_send_site()
    local arg = ftp.client.cur_cmd:match("^SITE%s+(.+)")
    if arg and arg:upper() == "STOP" then
        ftp.server.stopped = true
        ftp_send_ctrl_msg("221 FTP server stopping\r\n")
        return true
    end
    local action, rule, path = ftp.client.cur_cmd:match("^SITE%s+(%S+)%s+(%d+)%s+(.+)")
    if action and action:upper() == "CHMOD" then
        local dir = sanitize_path(ftp.client.cur_path, path)
        if syscall.chmod(dir, tonumber(string.format("%04d", tonumber(rule)), 8)):tonumber() < 0 then
            ftp_send_ctrl_msg("550 Permission denied\r\n")
        else
            ftp_send_ctrl_msg("200 OK\r\n")
        end
    else
        ftp_send_ctrl_msg("500 Syntax error, command unrecognized\r\n")
    end
end

local command_handlers = {
    USER = function()
        ftp_send_ctrl_msg("331 Anonymous login accepted, send your email as password\r\n")
    end,
    NOOP = function()
        ftp_send_ctrl_msg("200 No operation\r\n")
    end,
    PASS = function()
        ftp_send_ctrl_msg("230 User logged in\r\n")
    end,
    PWD = function()
        ftp_send_ctrl_msg(string.format("257 \"%s\" is the current directory\r\n", ftp.client.cur_path))
    end,
    XPWD = function()
        ftp_send_ctrl_msg(string.format("257 \"%s\" is the current directory\r\n", ftp.client.cur_path))
    end,
    OPTS = function()
        ftp_send_ctrl_msg("200 UTF8 enabled\r\n")
    end,
    TYPE = ftp_send_type,
    PASV = ftp_send_pasv,
    LIST = ftp_send_list,
    CWD = ftp_send_cwd,
    CDUP = ftp_send_cdup,
    XCUP = ftp_send_cdup,
    PORT = ftp_send_port,
    SYST = ftp_send_syst,
    FEAT = ftp_send_feat,
    MKD = ftp_send_mkd,
    XMKD = ftp_send_mkd,
    RMD = ftp_send_rmd,
    XRMD = ftp_send_rmd,
    SIZE = ftp_send_size,
    DELE = ftp_send_dele,
    RNFR = ftp_send_rnfr,
    RNTO = ftp_send_rnto,
    RETR = ftp_send_retr,
    STOR = ftp_send_stor,
    APPE = ftp_send_appe,
    REST = ftp_send_rest,
    SITE = ftp_send_site,
    QUIT = function()
        ftp_send_ctrl_msg("221 Goodbye\r\n")
        return true
    end
}

local function default_handler()
    ftp_send_ctrl_msg("502 Command not implemented.\r\n")
    sceKernelSendDebug("Requested: " .. tostring(ftp.client.cur_cmd) .. ", not implemented.")
end

local function cleanup_ftp()
    ftp_close_data_conn()
    if ftp.client.ctrl_sockfd then
        sceClose(ftp.client.ctrl_sockfd)
        ftp.client.ctrl_sockfd = nil
    end
    if ftp.server.server_sockfd then
        sceClose(ftp.server.server_sockfd)
        ftp.server.server_sockfd = nil
    end
    send_ps_notification("FTP Server closed")
end

function ftp_client_th()
    local recv_buffer = memory.alloc(512)
    ftp_send_welcome()

    while true do
        local recv_len = sceNetRecv(ftp.client.ctrl_sockfd, recv_buffer, 512, 0)
        if recv_len <= 0 then break end

        local raw = memory.read_buffer(recv_buffer, recv_len)
        for line in raw:gmatch("[^\r\n]+") do
            local command = line:match("^(%S+)")
            if command then
                ftp.client.cur_cmd = line
                local handler = command_handlers[command:upper()] or default_handler
                if handler() then
                    memory.free(recv_buffer)
                    cleanup_ftp()
                    return
                end
            end
        end
    end
    memory.free(recv_buffer)
    cleanup_ftp()
end

function ftp_init()
    ftp.client.cur_path = ftp.client.root_path
    ftp.server.server_sockfd = sceNetSocket(AF_INET, SOCK_STREAM, 0)
    if ftp.server.server_sockfd < 0 then
        errorf("sceNetSocket() error: " .. get_error_string())
        return
    end

    local enable = memory.alloc(4)
    memory.write_dword(enable, 1)
    if sceNetSetsockopt(ftp.server.server_sockfd, SCE_NET_SOL_SOCKET, SCE_NET_SO_REUSEADDR, enable, 4) < 0 then
        memory.free(enable)
        sceClose(ftp.server.server_sockfd)
        errorf("sceNetSetsockopt() error: " .. get_error_string())
        return
    end
    memory.free(enable)

    memory.write_byte(ftp.server.server_sockaddr + 1, AF_INET)
    memory.write_word(ftp.server.server_sockaddr + 2, sceNetHtons(ftp.server.port))
    memory.write_dword(ftp.server.server_sockaddr + 4, sceNetHtonl(INADDR_ANY))

    if sceNetBind(ftp.server.server_sockfd, ftp.server.server_sockaddr, 16) < 0 then
        sceClose(ftp.server.server_sockfd)
        errorf("sceNetBind() error: " .. get_error_string())
        return
    end

    if sceNetListen(ftp.server.server_sockfd, 128) < 0 then
        sceClose(ftp.server.server_sockfd)
        errorf("sceNetListen() error: " .. get_error_string())
        return
    end

    send_ps_notification(string.format("FTP Server listening on %s:%d", ftp.server.ip, ftp.server.port))

    memory.write_dword(ftp.client.ctrl_sockaddr_len, 16)
    ftp.client.ctrl_sockfd = sceNetAccept(ftp.server.server_sockfd, ftp.client.ctrl_sockaddr, ftp.client.ctrl_sockaddr_len)
    if ftp.client.ctrl_sockfd < 0 then
        cleanup_ftp()
        errorf("sceNetAccept() timed out or failed")
        return
    end
    ftp.client.is_connected = true
    send_ps_notification("FTP client connected")
    ftp_client_th()
end

function main()
    syscall.resolve({
        open = 5,
        unlink = 10,
        chmod = 15,
        recvfrom = 29,
        getsockname = 32,
        connect = 98,
        rename = 128,
        sendto = 133,
        mkdir = 136,
        rmdir = 137,
        stat = 188,
        getdents = 272,
        lseek = 478
    })

    ftp_init()
end

main()
