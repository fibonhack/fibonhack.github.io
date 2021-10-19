---
ctf_name: "reply ctf 2021"
title: "WANNA PLAY A GAME?"
date:	2021-10-18
author: "NicolaVV, drw0if"
category: "rev"
---

## Program description
An elf file file is giveng along with a connection endpoint and a password `gamebox3.reply.it 45241 ultr4s3cr3tP455`.

The endpoint prompt:
```bash
~ nc gamebox3.reply.it 45241
Password? ultr4s3cr3tP455
Welcome! Your SID is LBkIOklftFgVHjx
 - - - - - - -
 - - - - - - -
 - - - - - - -
 - - - - - - -
 - - - - - - -
 - - - - - - -

```

That's a weird prompt indeed! Maybe it's time to look at the given binary.

First things first, let's strings the binary:
```bash
strings reply2021-bin300
DCBA
Z2FtZWJveDMucmVwbHkuaXQ6Mzg0NTE6enVwcGFsdXBwYQ==
.text
.maps
tracepoint/syscalls/sys_enter_open
tracepoint/syscalls/sys_enter_lseek
debug
tracepoint/syscalls/sys_enter_execve
license
tracepoint/syscalls/sys_enter_tee
.strtab
tracepoint/syscalls/sys_enter_dup3
```

If you have some experience with encodings, you can guess that the second string is a base64 thing, if you are not experienced you can use the magic tool offered by [cyberchef](https://gchq.github.io/CyberChef/#recipe=Magic(3,false,false,'')&input=WjJGdFpXSnZlRE11Y21Wd2JIa3VhWFE2TXpnME5URTZlblZ3Y0dGc2RYQndZUT09) which yields `gamebox3.reply.it:38451:zuppaluppa`.

Let's poke the second endpoint:
```bash
~ nc gamebox3.reply.it 38451
Password? zuppaluppa
SID? 123
Welcome to our (amd64) shellcode-execution service!
Input format: LEN (1 byte) + SHELLCODE (LEN bytes)

What do you wanna run today?
```
So it seems that we have to provide some kind of shellcode (Spoiler execve /bin/sh doesn't work).

It's time to find out what kind of binary we are dealing with:
```bash
file reply2021-bin300
reply2021-bin300: ELF 64-bit LSB relocatable, eBPF, version 1 (SYSV), stripped
```

Oh it's a 64-bit ELF for the eBPF architecture. Basically it is a binary which is gonna be executed in kernel land. It can be used to do a lot of cool stuffs, for example network packet filtering and syscall hooking.
You can find a nice overview of what eBPF is [here](https://www.graplsecurity.com/post/kernel-pwning-with-ebpf-a-love-story).

Thankfully [ghidra can understand this elf file](https://github.com/Nalen98/eBPF-for-Ghidra), so it should not be that hard to reverse this elf.

![Nothing]({{ "/assets/images/reply2021-bin300/ghidra-ebpf-nothing.png" | absolute_url}})

Well that's not optimal, let's try to disassemble the section `.text` by pressing `D` and create a function with `F`

![Something]({{ "/assets/images/reply2021-bin300/ghidra-ebpf-disassembleAndCreateFunction.png" | absolute_url}})


Seems like something is working, if you disassemble and create function for all the .text section you should obtain those functions:
```
FUN_ram_00100000
FUN_ram_001000c8
FUN_ram_001001e0
FUN_ram_00100348
FUN_ram_00100448
FUN_ram_001005d8
```

We can expect that those functions are hooks for those syscalls:
```
tracepoint/syscalls/sys_enter_open
tracepoint/syscalls/sys_enter_lseek
tracepoint/syscalls/sys_enter_execve
tracepoint/syscalls/sys_enter_tee
tracepoint/syscalls/sys_enter_dup3
```

How can we find out which syscall is associated with which function? 

Before trying to read the documentation of ebpf's elf (which btw is the sane way to do it), we can give a try to XREFs. 

XREFs for FUN_ram_001005d8:
![FunctionXREFs]({{ "/assets/images/reply2021-bin300/ghidra-ebpf-functionXREFs.png" | absolute_url}})

Following the xref yields to the shdr array:
![ElfShdrArray]({{ "/assets/images/reply2021-bin300/ghidra-ebpf-shdrTracepoint.png" | absolute_url}})

So with those information we can associate every tracepoint to the corresponding function.


```C
SEC("tracepoint/syscalls/sys_enter_lseek")
void FUN_ram_001005d8(longlong param_1);
```