---
ctf_name: "m0lecon 2020 Teaser"
title:	"cryptogolf"
date:	2020-05-25
author: "lorenz, marcog" 
category: "crypto"
---

The server start generating a random string, chall. This chall is encrypted and sent, our purpose is to decrypt this chall given the oracle that encrypt what we give. But using less than 128 requests of encryption for the first flag, and 45 for the second flag.


Analysing the encryption process we found that is a kind of ARX cipher with a permutation matrix where the input can be viewed as split in 6 parts of 128 bits. The permutation matrix is applied on the single parts. In the end we obtainend the following form.

```
c0 = p^4 * e5 + p^3 * e0 + p^2 * e1 + p  *  e2    +    e3
c1 = p^5 * e5 + p^4 * e0 + p^3 * e1 + p^2 * e2 + p  *  e3    +    e4
c2 = p^6 * e5 + p^5 * e0 + p^4 * e1 + p^3 * e2 + p^2 * e3 + p  *  e4 + e5
c3 = p^7 * e5 + p^6 * e0 + p^5 * e1 + p^4 * e2 + p^3 * e3 + p^2 * e4 + e0
c4 = p^8 * e5 + p^7 * e0 + p^6 * e1 + p^5 * e2 + p^4 * e3 + p^3 * e4 + p^2 * e5 + e1
c5 = p^9 * e5 + p^8 * e0 + p^7 * e1 + p^6 * e2 + p^5 * e3 + p^4 * e4 + p^2 * e0 + e2
```

Where c0,c1,...,c5 is the result of the encryption, e0,e1,...,e5 is the input and p is the permutation matrix.

Observing the equations we found that if e2=1 and e0,e1,e3,e4,e5 are all 0 the resulting c0 is the permutation of the 1. Meaning that we could dechiper the matrix in 128 steps with this method.

Improving the method, we observe that under the same condition c1 is the result of the permutation applied 2 times, c2 three times, c3 four times, c4 five times. c5 is 6 time the permutation summed with the original bit.

Using this method is possible to obtain the permutation matrix in under 45 attempts.

Finally we must invert the encryption function knowing the permutation matrix.

This is the final script. Beware that this is not the theoretical but very close (around 38 attempts).

```python
#!/usr/bin/env python
from pwn import *
import binascii
import hashlib

host = args.HOST or 'challs.m0lecon.it'
port = int(args.PORT or 11000)

io = connect(host, port)
secret = [-1 for i in range(128)]

def apply_secret(c):
    r = bin(c)[2:].rjust(128,'0')
    return int(''.join([str(r[i]) for i in secret]), 2)

def decrypt(s):  
    to_decrypt = int(s, 16)
    for ll in range(9):
        x = apply_secret((to_decrypt >> (640-128)) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
        reappear = ((to_decrypt >> 640) ^ x) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
        to_decrypt = to_decrypt << 128 | reappear
        to_decrypt = to_decrypt % 2**(128*6)
    return hex(to_decrypt)[2:]

def solve(chall):
    io.recvuntil("2. Give me the decrypted challenge")
    io.sendline("2")
    ris = decrypt(chall)
    ris = binascii.unhexlify(ris)
    io.sendline(ris)
    return io.recvuntil("\n")

def pad32(s):
    m = 32 - len(s)
    return "0"*m + s

def send_enc(val):
    io.recvuntil("2. Give me the decrypted challenge")
    io.sendline("1")
    io.recvuntil("Give me something to encrypt (hex):\n")
    io.sendline(val)
    return io.recvuntil("\n")

def attempt(e):
    val = [pad32(hex(es)[2:]) for es in e]
    vals = int(send_enc("".join(val)),16)
    
    ret = []

    for i in range(6):
        ret.append(vals & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
        vals = vals >> 128
    return ret

#PoW
io.recvuntil("sha256sum ends in ")
check = io.recvuntil(".",drop=True)
chk = ""
for i in range(1000000000000):
    if hashlib.sha256(str(i).encode('ascii')).hexdigest()[-6:] == check:
        print(hashlib.sha256(str(i).encode('ascii')).hexdigest()[-6:])
        print(check)
        chk = str(i)
        break
print(chk)

io.sendline(chk)

#start challlenge
print(io.recvuntil("Encrypted challenge (hex):\n"))
chall = io.recvuntil("\n")

#obtaining the secret permutation matrix
for req in range(128):
    if req in secret:
        continue
    val = 2**(127-req)
    vals = attempt([0,0,0,val,0,0])

    old = req
    #removing e2 from c5 = p**6 * e2 + e2
    vals[5] = vals[5]^val
    #compute the 6 permutations
    for i in range(6):
        pos = 128-len(bin(vals[i])[2:])
        secret[pos] = old
        old = pos

#decrypt and send
solve(chall)

io.interactive()
```