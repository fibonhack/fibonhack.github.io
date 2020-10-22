---
ctf_name: "m0lecon 2020 Teaser"
layout: writeup
title:	"kid exchange"
date:	2020-05-24
category: "crypto"
author: "lorenz, marcog" 
---

We are given two python scripts, alice.py and bob.py, and a pcap file. The two scripts implement a very custom DH key exchange and then Alice send to Bob the flag encripted with the shared key.

`alice.py` (the code for bob is very similar)
```python
n = 128
m = 2**n

x = [int.from_bytes(os.urandom(n//8),'big') for _ in range(4)] #private key
e1 = (x[0] * x[1]) % m
e2 = (x[2]**2 + 3 * x[3]) % m
p1 = (e1**2 - 2 * e1 * e2 + 2 * e2**2) % m
p2 = (e1 * e2) % m
conn.sendall(str(p1).encode()+b'\n')
conn.sendall(str(p2).encode())
r = ''
while True:
	c = conn.recv(1).decode()
	if c != '\n':
		r += c
	else:
		break
p3 = int(r)
p4 = int(conn.recv(1024).decode())
e3 = (p3 + 4 * p4) % m
e4 = pow(3, p3 * e3, m)
e5 = pow(e1, 4, m)
e6 = pow(e2, 4, m)
e7 = (e5 + 4 * e6) % m
k = pow(e4, e7, m)
key = int.to_bytes(k, 16, 'big')

cipher = AES.new(key, AES.MODE_ECB)
flag = open('flag.txt', 'rb').read()
c = cipher.encrypt(pad(flag))
conn.sendall(c)
conn.close()
```

The code is a bit messy, basically we have $$e_1$$, $$e_2$$ that is the private key, $$p_1$$ and $$p_2$$ is the public key and is calculated as follow (all operation are modulo $$m$$):

$$p_1 = e_1^2 - 2 \cdot e_1 \cdot e_2 + 2 \cdot e_2^2$$

$$p_2 = e_1 \cdot e_2$$

Let's call bob public key $$p_3$$ and $$p_4$$, then the secret is calculated like so: 

$$k = 3^{p_3(p_3 + 4p_4)(e_1^4 + 4e_2^4)}$$

If you take a minute to expand $$p_1(p_1 + 4p_2)$$ you will find that it is equal to $$e_1^4 + 4e_2^4$$, and obviously also $$p_3(p_3 + 4p_4) = e_3^4 + 4e_4^4$$ (This is actually a famous identity, see [Sophie Germain's identity](https://en.wikipedia.org/wiki/Sophie_Germain#Honors_in_number_theory), but we didn't know at the time of solving the problem).

That means that the shared secret is actually $$k = 3^{p_3(p_3 + 4p_4) \cdot p_1(p_1 + 4p_2)}$$ so recovering the flag is pretty straightforward.

```python
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes

m = 2**128

p1 = 273788890796601263265245594347262103880
p2 = 258572069890864811747964868343405266432

p3 = 26837497238457670050499535274845058824
p4 = 40856090470940388713344411229977259912

ciphertext = '0132d9...'.decode('hex')

k = pow(3, p3*(p3+4*p4) * p1*(p1+4*p2), m)

key = long_to_bytes(k).ljust(16, '\x00')

print AES.new(key, AES.MODE_ECB).decrypt(ciphertext)
```