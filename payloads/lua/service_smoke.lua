--!lua
-- Run with service=1 and compat=remote_lua_loader. Bounded service-policy check.
syscall.resolve({select=93})
local timeout=memory.alloc(16)
for i=1,3 do
    printf("service tick %d, pid %d",i,syscall.getpid():tonumber())
    -- select with no descriptors waits for this timeval (one second).
    memory.write_qword(timeout,1)
    memory.write_qword(timeout+8,0)
    local result=syscall.select(0,nil,nil,nil,timeout)
    assert(result:tonumber()==0,"select wait failed")
end
print("service smoke test complete")
