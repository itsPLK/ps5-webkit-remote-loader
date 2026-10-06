// Assembly corresponding to the bounded helper in payloads/ftp_server.js.
// System V args: syscall number, arg1, arg2, arg3, arg4.
// Returns a nonnegative result on success, or negative kernel errno on error.
// No library/TLS calls and no credential or syscall-policy changes.
.intel_syntax noprefix
.text
.global ftp_raw_syscall
ftp_raw_syscall:
    mov rax, rdi
    mov rdi, rsi
    mov rsi, rdx
    mov rdx, rcx
    mov r10, r8
    syscall
    jnc done
    neg rax
done:
    ret
