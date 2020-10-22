---
ctf_name: "m0lecon 2020 Teaser"
title:	"king exchange"
date:	2020-05-24
category: "crypto"
author: "trenta3"
---

## Initial thoughts

We were presented with the source code of `server.py`, which is the script used for encryption.

```python
# Other imports removed
from secret import flag, p

def add_points(P, Q):
    return ((P[0]*Q[0]-P[1]*Q[1]) % p, (P[0]*Q[1]+P[1]*Q[0]) % p)

def multiply(P, n):
    Q = (1, 0)
    while n > 0:
        if n % 2 == 1:
            Q = add_points(Q, P)
        P = add_points(P, P)
        n = n//2
    return Q
```

As we can see it first defines an operation between points (written as tuples).
By seeing the operation to add points, and doing a little math, we recognize that the operation is the group operation on the conic $$X^2 + Y^2 = 1$$.
Equivalently, the operation on the conic is complex multiplication when we encode the point $$(x, y)$$ as $$x + iy$$, so we are effectively operating on gaussian integers.

```python
def gen_key():
    g = (0x43bf9535b2c484b67c68cb98bace14ae9526d955732e2e30ac0895ab6ba, 0x4a9f13a6bd7bb39158cc785e05688d8138b05af9f1e13e01aaef7c0ab94)
    sk = random.randint(0, 2**256)
    pk = multiply(g, sk)
    return sk, pk

a, A = gen_key()
b, B = gen_key()
print(A)
print(B)

shared = multiply(A, b)[0]
key = sha256(long_to_bytes(shared)).digest()
aes = AES.new(key, AES.MODE_ECB)
ciphertext = aes.encrypt(pad(flag.encode(), AES.block_size))
print(ciphertext.hex())
```

## Plan of attack

We can then see that we are given a generator of the group, and a diffie-hellman exchange is done, but we are only provided the public keys. The flag is then encrypted using the secret.
So our goal is to break the encryption to recover the shared secret.

We first recover the prime modulus p which is needed for the calculations: we notice that A[0]\*\*2 + A[1]\*\*2 - 1, B[0]\*\*2 + B[1]\*\*2 - 1 and g[0]\*\*2 + g[1]\*\*2 - 1 are all divisible by the prime modulus, so that we take their gcd to get our possible candidate P, and check that it is prime by fourty rounds of miller-rabin primality test.

We notice that the prime $$p$$ is congruent to three modulo four, which remains a prime also inside of gaussian integers (while prime $$\equiv 3 \ (\mod 4)$$ do split).
Therefore $$\frac{\mathbb{Z}[i]}p$$ is a field which is finite, so that it is isomorphic (as field) to $$\mathbb{F}_{p^2}$$, therefore its multiplicative order is $$p^2 - 1$$ (Interested readers can see [this reference](https://kconrad.math.uconn.edu/blurbs/ugradnumthy/Zinotes.pdf)).

Factorizing the order, we notice that its greater factor is 480231246962542657532393144857, which is quite small, so we try to attack it via the chinese remainder theorem, which requires us to just solve the discrete logarithm problem inside subgroups.
After coding the small-steps giant-steps algorithm for the discrete logarithm, and trying not to loose our mind in the correct way to apply the chinese remainder theorem, we recovered the exponent of A, and obtained the shared key.

## Putting all together

```python
g = (0x43bf9535b2c484b67c68cb98bace14ae9526d955732e2e30ac0895ab6ba, 0x4a9f13a6bd7bb39158cc785e05688d8138b05af9f1e13e01aaef7c0ab94)
A = (70584838528566138057920558091160583247156394376694509226477175997005624, 47208562635669790449305203114934717034939475647594168392271311241505021)
B = (28274152596231079767179933954556001021066477327209843622539706192176128, 99565893173481261433550089673695177934890207483997197067732588009694082)
cipher = b"aaa21dce78ef99d23aaa70e5d263719de9245f33b8a9e2a0a63c8847dba61296c5a1f56154b062d3a347faa31b8d8030"

# The curve with that addition law is x^2 + y^2 = 1.
# Find plausible p's as divisors of g_1^2 + g^2 - 1.
bign = g[0]**2 + g[1]**2 - 1
biga = A[0]**2 + A[1]**2 - 1
bigb = B[0]**2 + B[1]**2 - 1

def hcfnaive(a,b):
    "Naively computes the GCD"
    if(b==0):
        return a 
    else:
        return hcfnaive(b,a%b) 

p = hcfnaive(bign, biga)
p = hcfnaive(p, bigb)
print(f"Final P: {p}")
    
from factordb.factordb import FactorDB
def factors(n):
    f = FactorDB(n)
    f.connect()
    return f.get_factor_list()

# The right one is the biggest one, the others are too small to contain A and B
print(f"Factors: {factors(p)}")

from random import randrange
def miller_rabin(n, k=10):
	if n == 2:
		return True
	if not n & 1:
		return False

	def check(a, s, d, n):
		x = pow(a, d, n)
		if x == 1:
			return True
		for i in range(s - 1):
			if x == n - 1:
				return True
			x = pow(x, 2, n)
		return x == n - 1

	s = 0
	d = n - 1

	while d % 2 == 0:
		d >>= 1
		s += 1

	for i in range(k):
		a = randrange(2, n - 1)
		if not check(a, s, d, n):
			return False
	return True

assert miller_rabin(17, k=20)
assert miller_rabin(37, k=20)
assert miller_rabin(p, k=40)

assert p % 4 == 3
# Therefore Z[i]/p is a field, and we know that its order is p**2 - 1, since it is
# isomorphic to F_{p^2}.
# See also https://kconrad.math.uconn.edu/blurbs/ugradnumthy/Zinotes.pdf

# Now we decompose the order, and try to see if we can lower the difficulty of the problem.

def add_points(P, Q):
    return ((P[0]*Q[0]-P[1]*Q[1]) % p, (P[0]*Q[1]+P[1]*Q[0]) % p)

def multiply(P, n):
    Q = (1, 0)
    while n > 0:
        if n % 2 == 1:
            Q = add_points(Q, P)
        P = add_points(P, P)
        n = n//2
    return Q

order_factors = factors(p**2 - 1)
print(f"Factors: {order_factors}")

ghalf = (p**2 - 1) / 2
assert multiply(g, p**2 - 1) == (1, 0)
assert multiply(g, ghalf) != (1, 0)

import math
def baby_steps_giant_steps(Q, G, group_order):
    if Q == (1, 0):
        return 0
    N = 1 + int(math.sqrt(group_order))

    baby_steps = {}
    baby_step = Q
    for r in range(N+1):
        baby_steps[baby_step] = r
        baby_step = add_points(baby_step, G)

    H = multiply(G, N)
    giant_step = H
    for q in range(N+1):
        if giant_step in baby_steps:
            return (q + 1) * N - baby_steps[giant_step]
        giant_step = add_points(giant_step, H)
    return None

def discrete_logarithm(Q, G, group_order):
    return baby_steps_giant_steps(Q, G, group_order)
    if group_order <= 10000:
        naive = naive_discrete_logarithm(Q, G)
        print(naive, result)
        assert naive == result
        
def prime_powers(n):
    lst = factors(n)
    dct = {}
    for el in lst:
        if el not in dct:
            dct[el] = 0
        dct[el] += 1
        if el > 3:
            assert miller_rabin(el, k=40)
    return dct

from sympy.ntheory.modular import crt

# Get exponent of A in group generate by G which is of order n
def get_exponent_of(A, G, n):
    expon = {}
    powers = prime_powers(n)
    for prime, power in powers.items():
        # print(f"Processing {prime}^{power}")
        expon[prime**power] = discrete_logarithm(multiply(A, n // (prime ** power)), multiply(G, n // (prime ** power)), prime**power)
        # print(f"Expon: {expon[prime**power]}")
    moduli = [prime_power for prime_power, _ in expon.items()]
    v = [order_pp for _, order_pp in expon.items()]
    return crt(moduli, v, symmetric=True)

# Just one is needed, but we double check everything
exponA = int(get_exponent_of(A, g, p**2-1)[0])
print(f"exponA: {exponA}")
assert multiply(g, exponA) == A

exponB = int(get_exponent_of(B, g, p**2-1)[0])
print(f"exponB: {exponB}")
assert multiply(g, exponB) == B

sharedB = multiply(B, exponA)
sharedA = multiply(A, exponB)
assert sharedA == sharedB
shared = sharedA[0]
print(f"Shared: {shared}")

from Crypto.Util.number import long_to_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import random
from hashlib import sha256

key = sha256(long_to_bytes(shared)).digest()
aes = AES.new(key, AES.MODE_ECB)
from binascii import unhexlify
cleantext = aes.decrypt(unhexlify(cipher))
print(f"Flag: {cleantext}")
```