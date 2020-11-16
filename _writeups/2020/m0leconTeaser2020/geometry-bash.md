---
ctf_name: "m0lecon 2020 Teaser"
title:	"geometry bash"
date:	        2020-05-24
category:       "misc"
author:         "OrsoBruno96"
---

The mathematical problem looks difficult. Maybe it's a well known
computational problem. Where can I find a possible solution? Obv, codeforces.

Google Fu: "codeforces projection on line". First result is
[https://codeforces.com/problemset/problem/886/F](https://codeforces.com/problemset/problem/886/F)
That is exactly the same problem given here.

[https://codeforces.com/contest/886/submission/79754745](https://codeforces.com/contest/886/submission/79754745)
This submission is actually from the same person who wrote
this challenge. I didn't find it during the competition,
I found another one: [https://codeforces.com/problemset/submission/886/35605367](https://codeforces.com/problemset/submission/886/35605367)
Download that, compile it, done.


```python
from pwn import remote, process, log
import hashlib

remotehost = ("challs.m0lecon.it", 10001)

def PoW():
    """Proof of work
    """
    io.recvuntil("ends in ")
    res = io.recvline().strip().replace(b".", b"").decode()
    log.info(f"Requested hash {res}")
    for i in range(100000000):
        if i % 1000000 == 0:
            log.info(f"Iteration {i}")
        if hashlib.sha256(str(i).encode('ascii')).hexdigest()[-6:] == res:
            log.info(hashlib.sha256(str(i).encode('ascii')).hexdigest()[-6:])
            log.info(res)
            chk = str(i)
            break
    io.sendline(chk)
    return chk

def handle_lines():
    log.info(io.recvuntil(b"begin!"))
    io.sendline("A")
    for i in range(0, 20):
        log.info(f"Iteration {i + 1}/20")
        N = int(io.recvline().strip())
        log.info(f"N: {N}")
        payload = f"{N}" + "\n"
        for i in range(0, N):
            payload += io.recvline().decode()
        cusumano = process(["./codeforces"])
        cusumano.sendline(payload)
        ans = cusumano.recv().strip()
        cusumano.close()
        log.info(f"Stolen answer: {ans.decode()}")
        io.sendline(ans)
        result = io.recvline()
        if b"Nope" in result:
            log.error("Failed???")
        log.info("Correct! Now next!")

if __name__ == "__main__":
    io = remote(*remotehost)
    PoW()
    handle_lines()
    io.interactive()
```