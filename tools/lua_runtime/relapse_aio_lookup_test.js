const assert = require('node:assert/strict');
const fs = require('node:fs');
const {lua, lauxlib, lualib, to_luastring: str, to_jsstring} = require('fengari');

const root = __dirname + '/../..';
const source = fs.readFileSync(root + '/payloads/lua/relapse.lua', 'utf8');
const start = source.indexOf('lookup_aio_group = function(');
const end = source.indexOf('\nend\n\ndefuse_aio_groups', start);
assert(start >= 0 && end > start, 'lookup_aio_group function not found');
const lookup = source.slice(start, end + 4);
const blockStart = source.indexOf('local function group_read_block(');
const blockEnd = source.indexOf('\nend\n\nlocal function group_write32', blockStart);
assert(blockStart >= 0 && blockEnd > blockStart, 'group_read_block function not found');
const readBlock = source.slice(blockStart, blockEnd + 4);
const writeStart = source.indexOf('local function group_write64(');
const writeEnd = source.indexOf('\nend\n\nlocal function group_read_pointer', writeStart);
assert(writeStart >= 0 && writeEnd > writeStart, 'group_write64 function not found');
const write64 = source.slice(writeStart, writeEnd + 4);
const defuseStart = source.indexOf('defuse_aio_groups = function()');
const defuseEnd = source.indexOf('\nend\n\n-- shellcode', defuseStart);
assert(defuseStart >= 0 && defuseEnd > defuseStart, 'defuse_aio_groups function not found');
const defuse = source.slice(defuseStart, defuseEnd + 4);

const setup = `
  local bytes = {}
  local function read32(address)
    local value = 0
    for i = 0, 3 do value = value | ((bytes[address + i] or 0) << (i * 8)) end
    return value
  end
  local function write32(address, value)
    for i = 0, 3 do bytes[address + i] = (value >> (i * 8)) & 0xff end
  end
  local function write64(address, value)
    write32(address, value & 0xffffffff)
    write32(address + 4, (value >> 32) & 0xffffffff)
  end
  local function word(value)
    return setmetatable({value=value}, {__index={tonumber=function(self) return self.value end}})
  end
  local scratch=0x9000
  local scratch_word=0x8f00
  local next_alloc=0x20000
  scratch_group=scratch
  scratch_qword=scratch_word
  local u64_meta={__shl=function(value, shift)
    if shift == 32 then return {l=0,h=value.l} end
    return {l=(value.l << shift) & 0xffffffff,h=(value.h << shift) & 0xffffffff}
  end}
  uint64=function(value)
    if type(value)=='table' then return setmetatable({l=value.l,h=value.h},u64_meta) end
    return setmetatable({l=value & 0xffffffff,h=0},u64_meta)
  end
  memory = {
    alloc=function(size) local p=next_alloc; next_alloc=next_alloc+size+16; return p end,
    read_dword=function(address) return word(read32(address)) end,
    read_qword=function(address)
      if address==scratch+0x50 then return {l=read32(address),h=read32(address+4)} end
      return read32(address) + read32(address + 4) * 4294967296
    end,
    read_buffer=function(address,length)
      local out={}
      for i=0,length-1 do out[#out+1]=string.char(bytes[address+i] or 0) end
      return table.concat(out)
    end,
    write_dword=function(address, value) write32(address, value) end,
    write_qword=function(address, value)
      write32(address, value.l or value)
      write32(address + 4, value.h or 0)
    end,
  }
  bit32 = {
    band=function(a,b) return a & b end,
    bor=function(a,b) return a | b end,
    lshift=function(a,b) return (a << b) & 0xffffffff end,
    rshift=function(a,b) return (a & 0xffffffff) >> b end,
  }
  off = {
    proc={aioInfo=0x100},
    pipe={count=0,size=0x0c,buffer=0x10},
    aio={idTable={pages=0x220, slotStride=0x30, entryType=0x160},
      group={num=0,state=8,waiters=0x50}},
  }
  local batch_mode=false
  syscall={read={syscall_no=3},write={syscall_no=4}}
  ropchain=function()
    if not batch_mode then return {ops_only=false} end
    local chain={ops_only=true,ops={}}
    function chain:push_write_qword_memory(address,value)
      self.ops[#self.ops+1]={kind='write64',addr=address,val=value}
    end
    function chain:push_syscall(number,...)
      self.ops[#self.ops+1]={kind='syscall',num=number.syscall_no,args={...}}
    end
    function chain:execute_through_coroutine()
      local target
      for _,op in ipairs(self.ops) do
        if op.kind=='write64' then
          memory.write_qword(op.addr,op.val)
        else
          local fd, buffer, length=op.args[1],op.args[2],op.args[3]
          local result
          if op.num==4 and fd==master.write_fd then
            target=memory.read_qword(aim_buffer+off.pipe.buffer)
            result=0x18
          elseif op.num==3 and fd==master.read_fd then
            result=0x18
          elseif op.num==4 and fd==victim.write_fd then
            for i=0,length-1 do bytes[target+i]=bytes[buffer+i] or 0 end
            result=length
          elseif op.num==3 and fd==victim.read_fd then
            for i=0,length-1 do bytes[buffer+i]=bytes[target+i] or 0 end
            result=length
          else
            error('unexpected batched syscall')
          end
          memory.write_qword(op.ret_addr,result)
        end
      end
      return true
    end
    return chain
  end
  fast_stage_profile={}
  crossed = true
  local page_reads, block_calls, block_bytes, scalar_reads = 0, 0, 0, 0
  local write_calls, write_bytes = 0, 0
  local function is_kernel_pointer(value) return type(value)=='number' and value > 0 end
  local function group_read32(address)
    scalar_reads=scalar_reads+1
    return 0, read32(address)
  end
  local function group_read64(address)
    if address==0x6050 then return 0, {l=read32(address),h=read32(address+4)} end
    return 0, memory.read_qword(address)
  end
  local function group_read_pointer(address)
    page_reads=page_reads+1
    local _, pointer=group_read64(address)
    if is_kernel_pointer(pointer) then return pointer end
  end
  local function group_write32(address,value) write32(address,value); return 0 end
  local function report() end
  function kread_fast(address,length,dest)
    block_calls=block_calls+1; block_bytes=block_bytes+length
    for i=0,length-1 do bytes[dest+i]=bytes[address+i] or 0 end
    return length
  end
  function kwrite_fast(address,length,src)
    write_calls=write_calls+1; write_bytes=write_bytes+length
    for i=0,length-1 do bytes[address+i]=bytes[src+i] or 0 end
    return length
  end
  local id_table=off.aio.idTable
  local table_addr, page = 0x1000, 0x2000
  local function add_id(id, group)
    local slot=page + (id & 0x7f) * id_table.slotStride
    write64(slot + 0x10, group)
    write32(slot + 0x20, id_table.entryType)
    write32(slot + 0x24, 0x30000)
    write32(slot + 0x28, 0)
  end
  write32(table_addr + id_table.pages, 1)
  write64(table_addr, page)
  add_id(5, 0x4000)
  add_id(6, 0x5000)
  local page_cache={}
  ${readBlock}
  ${write64}
  ${lookup}
  assert(lookup_aio_group(table_addr, 5, 1, page_cache, scratch) == 0x4000)
  assert(lookup_aio_group(table_addr, 6, 1, page_cache, scratch) == 0x5000)
  assert(page_reads == 1, 'page pointer reads=' .. page_reads)
  assert(block_calls == 1 and block_bytes == 0x1800, 'one cached page read should cover both slots')
  assert(scalar_reads == 0, 'cached page count and packed slot path should avoid scalar reads')

  local fallback_cache={}
  crossed = false
  assert(lookup_aio_group(table_addr, 5, 1, fallback_cache, scratch) == 0x4000)
  assert(block_calls == 1, 'slow fallback should keep using scalar reads')
  assert(scalar_reads == 3, 'slow fallback should read generation, state, and type individually')

  crossed = true
  off.pipe={count=0,size=0x0c,buffer=0x10,defaultSize=0x4000}
  master={read_fd=11,write_fd=10}
  victim={read_fd=13,write_fd=12}
  aim_buffer=0xa000
  drain_buffer=0xa100
  pipe_size=0x4000
  write64(0x900, table_addr)
  write64(0x4010, 0x6000)
  write32(0x6000, 1)
  write32(0x6008, 2)
  write64(0x6050, 0x7777)
  curproc=0x800
  armed_groups={{5}}
  defused=false
  ${defuse}
  assert(defuse_aio_groups() == true, 'valid AIO group should clear successfully')
  assert(defused == true, 'cleanup should mark groups defused')
  assert(read32(0x6050) == 0 and read32(0x6054) == 0, 'waiter pointer should be cleared')
  assert(write_calls == 1 and write_bytes == 8, 'waiter pointer should clear with one qword write')
  assert(fast_stage_profile.aio_cleanup_counts.total == 1)
  assert(fast_stage_profile.aio_cleanup_counts.cleared == 1)

  write64(0x6050, 0x8888)
  defused=false
  fast_stage_profile={}
  batch_mode=true
  assert(defuse_aio_groups() == true, 'batched AIO clear should clear successfully')
  assert(defused == true, 'batched cleanup should mark groups defused')
  assert(read32(0x6050) == 0 and read32(0x6054) == 0, 'batched waiter pointer should be cleared')
  assert(fast_stage_profile.aio_clear_batches == 1 and fast_stage_profile.aio_clear_batch_ids == 1)
  assert(fast_stage_profile.aio_cleanup_counts.cleared == 1)
  return true
`;

const L = lauxlib.luaL_newstate();
lualib.luaL_openlibs(L);
const status = lauxlib.luaL_loadbufferx(L, str(setup), setup.length, str('=aio-lookup-test'), str('t'));
assert.equal(status, lua.LUA_OK, status ? to_jsstring(lua.lua_tostring(L, -1)) : '');
const callStatus = lua.lua_pcall(L, 0, 1, 0);
assert.equal(callStatus, lua.LUA_OK, callStatus ? to_jsstring(lua.lua_tostring(L, -1)) : '');
assert.equal(lua.lua_toboolean(L, -1), true);
lua.lua_close(L);
console.log('Relapse AIO lookup bulk-read tests passed');
