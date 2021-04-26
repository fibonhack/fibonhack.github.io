---
layout: page
title: "pwn"
---

# Common pitfalls in exploit development
What is this about? Mainly it is about questions like that: `Why my exploit is popping a shell in local but is crashing in remote?`. Spoiler the answer most of the time is not `Because some bit got flipped through the journey to the remote server`. Dont laugh, this is actually a thing: [lol](https://resources.bishopfox.com/files/slides/2019/Kaspersky%20SAS-Ghost-in-the-Browser-Broad-Scale-Espionage-with-Bitsquatting-10Apr2019-%20Slides.pdf).

## How to: Develop the exploit in local with the same(~ish) environment

What does that mean? By simplifying a lot: we are going to execute `./chall.` with the same `libc.so.6` the remote server is using.

What do you need:
- `chall`
- `libc.so.6`: should be possible to get? [this link should help](https://book.hacktricks.xyz/exploiting/linux-exploiting-basic-esp/rop-leaking-libc-address)
- `ld.so`: basically, it is the program responsible to load all the dinamically linkd libraries. Refer to [man ld.so](https://man7.org/linux/man-pages/man8/ld.so.8.html) if you want to know more.

### Method 1: patchelf + LD_PRELOAD
We are going to patch the binary in order to change the interpeter path.

How to see the interpeter path? From
```sh
$ file chall
chall: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=c108eced55038588d5b1a6579bd72b9e0c7fd01b, not stripped
```
-> the intepreter path is /lib64/ld-linux-x86-64.so.2, note this is an absolute path!

How to patch the binary? There are tons of way, you could do it by hand but for the sake of simplicity you can use [patchelf](https://github.com/NixOS/patchelf)
```sh
cp ./ld.so /tmp/ld.so
# dont put a long filename, using /tmp/something should be good
# assert(len(your_interpreter_path) <= len(chall_interpreter_path))
patchelf --set-interpreter /tmp/ld.so ./chall # this command patch the binary
```

- Then if you want to run from shell do this:
```sh
LD_PRELOAD=./libc.so.6 ./test
```

- Or if you want to run from your pwntools script do this:
```py
io = process(["./chall"], env={"LD_PRELOAD":"/path/to/libc.so"})
```

### Method 2: only LD_PRELOAD
Warning: with this method you might not be able to see debug symbols of `chall`, so i would not recommend this way if you want to attach to the process and debug it!

- From shell:
```sh
LD_PRELOAD=./libc.so.6 ./ld.so ./chall
```

- From pwntools script:
```py
io = process(["/path/to/ld.so", "./chall"], env={"LD_PRELOAD":"/path/to/libc.so"})
```

### Method X: Qemu
With qemu-user you can emulate any userspace programs written for a different architecture (e.g. ARM, MIPS, ...), without emulating an entire operating systems. And you can also debug it.

For example, execute an arm64 program for linux, with a custom libc
`qemu-aarch64 -L <your LD_PREFIX> -E LD_PRELOAD=/path/to/libc.so ./chall`


### Method XXX: Docker
Using docker enforces isolation of the processes, and it is not required, the methods above work well. If you still want a sandbox environment to mess up with (if you delete the libc in your system, *YOU WILL HAVE A REALLY BAD TIME*). I suggest using the following alias to use a suitable docker

```bash

pwndocker() {
    if [[ $# -ne 1 ]] ; then
        echo "pwndocker <dockername>"
        return 1;
    fi
    docker run -d -h "$1" --name "$1" -v $PWD:/ctf/work --cap-add=SYS_PTRACE --security-opt seccomp=unconfined skysider/pwndocker
}

```

## I don't want to use the remote libc, but my exploit is still working only in local
99% of the times, the remote environment has Ubuntu LTS. The libc built for Ubuntu has been built with some flags that are not shared among all linux distros. One of this flags enforces a runtime check: every time you enter a function, the stack has to be aligned at 0x10 bytes (64 bits). If this is not the situation, the program will be killed via `SIGSEGV`.

How to solve? If you are in this situation, you are very likely building a ROP. This means that you need to jump to that function only when the stack is properly aligned. How can you align the stack if it is not? Simply ad a NOP gadget (a gadget that includes only a `ret` instruction).

## How to: Debug programs without losing your mental sanity

First of all, if the binary is stripped, aka you have no functions names, readd them to the binary so gdb can will be less PITA.

Example of a `chall` binary which is stripped
```sh
$ file chall
chall: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=c108eced55038588d5b1a6579bd72b9e0c7fd01b, stripped <-- this is stripped
```

There are a lot of ways to do so, but i usually use ghidra.

### Add symbols to any elf file using ghidra

- Put those scripts in ~/ghidra_scripts: https://github.com/nick0ve/syms2elf
- In ghidra:
    - go to the Script Manager
    - search for syms2elf.py
    - execute it
- chmod +x chall.sym.elf
- ./chall.sym.elf
- profit?

Note: If you want to export symbols for a PIE executable, you have to modify the base address to 0x0. (Yes I'm too lazy to fix this). To do it goto: Window -> Memory map -> Set Image Base (image of the home). You can go [there](https://guidedhacking.com/threads/how-to-rebase-a-module-in-ghidra-ida-pro.16511/) for a graphical walkthrough.
Note: If you don't know how to reach the script manager, take a look at https://www.shogunlab.com/blog/2019/12/22/here-be-dragons-ghidra-1.html

### Add symbols to elf files, other methods
I'm not gonna explain how to use those scripts, but they could be very useful by time to time, so I'm gonna stick 'em there.
- https://github.com/wapiflapi/wsym
- https://github.com/cesena/ghidra2dwarf
- https://github.com/sciencemanx/dress


## How to: Run a program with ASLR disabled

- The don't ever do it method: `echo 0 | sudo tee /proc/sys/kernel/randomize_va_space` <- this is gonna disable aslr for every process which will be executed after that command, which is something you dont really want.

- The right method: Run a shell with aslr disabled, and every command that you will execute in that shell will keep aslr disabled: `setarch $(uname -m) -R /bin/bash`, or if you want to execute only the challenge binary with no aslr: `setarch $(uname -m) -R /path/to/chall`

## How to: attach to a running process with gdb

After running the process, let it wait for your input. For instance if you are developing an exploit with pwntools, and you want to be able to debug it, you would modify your script from this:

```py
io = start()
payload = flat(
    right_number_of_As,
    ropchain
)
io.send(payload)
```
to:
```py
io = start()
payload = flat(
    right_number_of_As,
    ropchain
)
ui.pause() # from pwn import ui
io.send(payload)
```

Then open two terminals.

In T1 execute the exploit:
```sh
./exp.py LOCAL
```

In T2 attach to the process:
```sh
gdb -p $(pidof chall) -ex "break vulnerable_function" -ex "continue"
```

--> Profit.


## How to: avoid alarm signal

In most of the pwn challs, to avoid stuck connections the program will be killed with a `SIGALRM` after a small amount of time. Obv, it is recommended to avoid this restriction while you are debugging. Fortunately, gdb can help, not only with `SIGALRM` but with most of linux signals.

Attaching to the process with gdb (for example with `gdb -p $(pidof chall)` will automatically catch all the `SIGALRM` sent to the `chall` process and it will not forward them to the child process (by default). Inside gdb you can also stop other signals, for example

```
handle SIGWINCH nopass
```

You can also set a catchpoint inside gdb

```
catch signal SIGALRM
```

# Other tricks that you might find useful

### How to know if my shellcode is being executed before the crash?
Put a breakpoint in your shellcode and see if a SIGTRAP is triggered:
```py
shellcode = b'\xcc' + shellcode
```
What is 0xcc? int3 instruction. Basically is is an instruction is an instruction specifically used to support debugging, and its corresponding machine code is 0xCC. When the CPU executes this instruction, it will generate an exception and call the corresponding exception handler (interrupt 3) for further processing. [source there](https://www.programmersought.com/article/55404064361/)

Always remember to delete this extra byte before running your exploit on a process that is not being traced by gdb, for example the remote server, or this process will generate the exception and be killed!



### Broken shellcode

The first thing to check when your shellcode (or ROP chain, what you want), is the integrity of your shellcode. Always remember that not all the input functions in `C` will forgive you like `read(fd, buf, size)`. Even the terrible `gets` will stop to receive your input at the first `0xa` byte found, namely `\n`. I always suggest to print your shellcode in a nice form and check that the corrupted memory of the program is exactly what you want before messing around with other possible problems.