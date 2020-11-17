---
ctf_name: "m0lecon 2020"
layout: writeup
title:	"escr"
date:	2020-11-16
category: "crypto"
author: "lorenz"
---

### The chall

We are given the code for a custom hash function and we have to create 10 collisions in a row, let's have a look at the actual code.

```python
def rotl(x, n):
    return ((x << n) & 0xffffffffffffffff) | x >> (64 - n)

def rotr(x,n):
    return rotl(x, 64 - n)

class ToyHash(object):
    def __init__(self):
        self.state = [ 0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B,
                       0x510E527FADE682D1, 0x9B05688C2B3E6C1F, 0x1F83D9ABFB41BD6B,
                       0x243F6A8885A308D3, 0x13198A2E03707344, 0xA4093822299F31D0]
        self.rounds = 91
        self.mod = 2**64

    def R(self, a, b, c, m1, m2, m3):
        self.state[a] = (self.state[a] + self.state[b] + m1) % self.mod
        self.state[b] = rotl(self.state[b]^self.state[c]^m2,16)
        self.state[c] = (self.state[b] + self.state[c] + m3) % self.mod
        self.state[a] = (self.state[a] + self.state[b] + m1) % self.mod
        self.state[b] = rotr(self.state[b]^self.state[c]^m2,48)
        self.state[c] = (self.state[b] + self.state[c] + m3) % self.mod

    def compress(self, block):
        mini_blocks = [int(block[64*i:64*i+64], 2) for i in range(9)]
        for _ in range(self.rounds):
            self.R(0, 3, 6, mini_blocks[0],mini_blocks[1],mini_blocks[2])
            self.R(1, 4, 7, mini_blocks[3],mini_blocks[4],mini_blocks[5])
            self.R(2, 5, 8, mini_blocks[6],mini_blocks[7],mini_blocks[8])

    def hash(self, m):
        bm = bin(bytes_to_long(m))[2:]
        l = len(bm) % 0x7ff
        bm = bm + '0'*((576-len(bm))%576) + '0'*564 + '1' + bin(l)[2:].rjust(11, '0')
        blocks = [bm[576*i:576*i+576] for i in range(len(bm)//576)]
        for b in blocks:
            self.compress(b)
        h = [self.state[i]^self.state[i+3]^self.state[i+6] for i in range(3)]
        return ''.join(hex(n)[2:].ljust(16, 'f') for n in h).encode()
```
Basically the message is splitted in blocks of length 576 bits (padded with 0's if necessay ) and another block with the length of the message is appended at the end, then each block is passed to the `compress` function that updates the internal state. The final hash is calculated from the internal state.

The idea is to find a block `b'` different from `b` but that satisfies `compress(b') = compress(b)`, so that we can create a second message different from the first, but that updates the inernal state in the same way and therefore has the same hash.

### The exploit

Since `rotl(x, 16)` and `rotr(x, 48)` are actually the same we can simplify the function `R` like so (and we need to double the number of `rounds`):
```python
def R(self, a, b, c, m1, m2, m3):
    self.state[a] = (self.state[a] + self.state[b] + m1) % self.mod
    self.state[b] = rotl(self.state[b]^self.state[c]^m2,16)
    self.state[c] = (self.state[b] + self.state[c] + m3) % self.mod
```

We can observe that a change in `m1` has effect **ONLY** on `state[a]`, in particular if we call 2*`rounds` times the function `R` the `state[a]` will change like so:  `newState[a] = ( something_that_dosent_depend_on_m1 + 2*rounds*m1 ) % mod`.

Since `gcd(2*rounds, mod) = 2` there exists another value `m1'` different from `m1` that satisfies `2*rounds*m1' = 2*rounds*m1 (mod n)`. In particular that value is `m1' = ( m1 + mod/2 ) % mod`. ( in this case is the same as flipping the most significant bit: `m1' = m1 ^ (1<<63)`)

### Putting everything together

So we want to modify the value of either `mini_blocks[0]`, `mini_blocks[3]`, `mini_blocks[6]` as described above. If we study how the message is splitted into mini_blocks we see that `mini_blocks[0]` corresponds to the first 64 bits of the message, that means that the most significant bit will always be one, and it also means that if we flip it we will obtain a new message that is shorter than the original, no good. Thats not a big deal, we can flip the first bit of `mini_blocks[3]`.

Since each block is 64 bits long we'll have to flip the 193-th bit of the message (counting from one), that is easy enough and can be done for example like so:
```python
def gencoll(plain):
    plain = bytes_to_long(plain)    
    coll = plain ^ (1<<(plain.bit_length() - 64*3 - 1))
    return  long_to_bytes(coll)
```