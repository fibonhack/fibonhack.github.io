---
ctf_name: "hitcon 2020"
layout: writeup
title:	"another secret note"
date:	2020-12-2
category: "crypto"
author: "marcog" 
---

We are given a python script that represent a remote server:

$$prob.py$$
```python
#!/usr/bin/env python3
from Crypto.Cipher import AES
import base64,random,hashlib,json,string
import time
from secret import *

class MyRandom:
    def __init__(self):
        self.mask = (1<<64)-1
        self.offset = 0
        self.magic = random.getrandbits(64)
        self.state = random.getrandbits(64)

    def __iter__(self):
        return self

    def __next__(self):
        self.state = (self.state * self.state) & self.mask
        self.offset = (self.offset + self.magic) & self.mask
        self.state = (self.state + self.offset) & self.mask
        self.state = ((self.state << 32) | (self.state >> 32)) & self.mask
        return self.state >> 32


def get_random(my_random, b):
    b //= 4
    lst = [next(my_random) for i in range(b)]
    byte_lst = []
    for v in lst:
        byte_lst.append(v%256)
        byte_lst.append((v>>8)%256)
        byte_lst.append((v>>16)%256)
        byte_lst.append((v>>24)%256)
    return bytes(byte_lst)

def pad(s):
    pad_len = 16-len(s)%16
    return s+chr(pad_len)*pad_len

def unpad(s):
    v = ord(s[-1])
    assert(s[-v:] == chr(v)*v)
    return s[:-v]

def proof_of_work():
    proof = ''.join([random.choice(string.ascii_letters+string.digits) for _ in range(20)])
    digest = hashlib.sha256(proof.encode()).hexdigest()
    print("SHA256(XXXX+%s) == %s" % (proof[4:],digest))
    x = input('Give me XXXX:')
    if len(x)!=4 or hashlib.sha256((x+proof[4:]).encode()).hexdigest() != digest: 
        exit()

if __name__ == '__main__':
    key = open('key','rb').read()
    flag = user_secret+admin_secret
    assert(flag.startswith('hitcon{'))
    assert(flag.endswith('}'))
    assert(len(user_secret)==16)
    assert(len(admin_secret)==16)
    proof_of_work()
    my_random = MyRandom()
    iv =  get_random(my_random, 16)
    note = {}
    while True:
        try:
            msg = input("cmd: ")
            if msg == "register":
                name = input("name: ")
                if name == 'admin':
                    print('no! I dont believe that')
                    exit()
                data = {'secret': user_secret, 'who': 'user', "name": name}
                string = json.dumps(data)
                cipher = AES.new(key, AES.MODE_CBC, iv)
                encrypted = cipher.encrypt(pad(string).encode()).hex()
                send_data = {"cipher": encrypted}
                print("token: ",base64.b64encode(json.dumps(send_data).encode()).decode())
            elif msg == "login":
                recv_data = json.loads(base64.b64decode(input("token: ").encode()).decode())
                if 'iv' in recv_data:
                    iv = bytes.fromhex(recv_data['iv'])
                encrypted = bytes.fromhex(recv_data['cipher'])
                cipher = AES.new(key, AES.MODE_CBC, iv)
                string = unpad(cipher.decrypt(encrypted).decode())
                data = json.loads(string)
                if 'cmd' in data:
                    if data['cmd'] == 'get_secret':
                        if "who" in data and data["who"] == "admin" and data["name"] == 'admin':
                            data["secret"] = admin_secret
                    elif data['cmd'] == 'get_time':
                        data['time'] = str(time.time())
                    elif data['cmd'] == 'note':
                        note_name = get_random(my_random, 4).hex() 
                        note[note_name] = data['note']
                        data['note_name'] = note_name
                    elif data['cmd'] == 'read_note':
                        note_name = data['note_name'] 
                        data['note'] = note[note_name]
                string = json.dumps(data)
                cipher = AES.new(key, AES.MODE_CBC, iv)
                encrypted = cipher.encrypt(pad(string).encode()).hex()
                send_data = {"cipher": encrypted}
                print("token: ",base64.b64encode(json.dumps(send_data).encode()).decode())
        except Exception as e:
            exit()
```

Essentially we have the flag 32 byte long, divided in 2 parts $$user_secret$$ and $$admin_secret$$, and 2 function $$register$$ and $$login$$. 

In $$register$$ we can ask to encrypt a json that contains our username in the format:
```python
{"secret": user_secret, "who": "user", "name": user}
```
This json is encrypted and encoded in base64 and inserted inside a json:
```python
{"cipher": encrypted}
```
Inside $$login$$ we can input a json in the same format as above and we can also input a IV for the decryption of the ciphertext.

The objective of this challenge is to recover the two half of the flag, is possible to recover the first half with an orable attack on the decryption (more on the next part), instead, the second part is recoverable only sending a ciphertext to the login function with a json:
```python
{"secret": "", "cmd": "get_secret", "who": "admin", "user": "admin"}
```
Then the returned ciphertext contains the admin_secret in the first 3 block.

The encryption/decryption is done using AES-CBC with a random IV and the same key every session.

When decrypting the $$login$$ function check if the decrypted plaintext is padded correctly and then it load the the string into a json. If an exception is thrown the program terminate. Now, the second block of the ciphertext after the $$login$$ is always the encryption of:
```
on{123456789", "
```
Xorred with the first block of the ciphertext. 123456789 are the last 9 characters of the user secret (as the flag start with `hitcon{` and terminate with `}`). So we can input as IV the first block of ciphertext and the second block alone as ciphertext. The decryption should get the original plaintext incorrecly padded as it terminate with " and the json should throw an exception.

<img style="background-color:white" src="/assets/files/CBC_decryption.png" alt="AES CBC"/>

Using this schema we can calculate the new IV to use to obtain a target text knowing the original plaintext: ($$P$$ is the old plaintext and $$T$$ is the target plaintext after the decryption)

$$NEWIV_i = IV_i \oplus P_i \oplus T_i$$

This because the first make the decryption all zeros, instead the second make the result equals to the target $$T$$. Not knowing the original plaintext we can try to decode 1 character at a time. We start by trying to obtain the target $$T$$:
```python
'{ "12345678":3}'+'\x01'
```
So that the unpadding pass and is a correct json string. To do that we need to know the ninth character ninth unknown character of the flag, but we can try all the possible printable character to recover that. Next whe can continue to decode the plaintext by guessing the eight character as `'{ "1234567" :3}'+'\x01'` etc...

Possible Script for the first part:
```python
def do_pow():
    if args.LOCAL:
        return
    io.recvuntil("SHA256(XXXX+")
    first = io.recvuntil(") == ",drop=True).decode()
    digest = io.recvuntil("\n", drop=True).decode()
    print(first,digest)
    for combo in product(string.ascii_letters+string.digits,repeat=4):
        x = ''.join(combo)
        if hashlib.sha256((x+first).encode()).hexdigest() == digest: 
            print("found")
            break
    io.recvuntil("Give me XXXX:")
    io.sendline(x)

def change(vals,orig,result):
    ret = []
    for v,o,r in zip(vals,orig,result):
        a = v^ord(o)^ord(r)
        ret.append(a)
    return bytes(ret)

do_pow()
io.recvuntil("cmd: ")
io.sendline("register")
io.recvuntil("name: ")
io.sendline("user12345")
if args.LOCAL:
    print(io.recvuntil("}").decode())
io.recvuntil("token: ")
token = io.recvuntil("\n",drop=True)
token = json.loads(base64.b64decode(token).decode())
print(token)
iv = bytes.fromhex(token["cipher"][:32])

dup = token.copy()
elements = string.digits+"_-"+string.ascii_letters
key = ""
for i in range(9-len(key)):
    found = False
    for c in elements:
        try:
            io = start()
            do_pow()
            cut = -5-len(key)
            ivchange = change(iv[:3], 'on{' ,'{ "')+iv[3:cut]+change(iv[cut:], c+key+'", "' ,    '"'+' '*len(key)+':3}'+"\x01"*1)
            dup["iv"] = ivchange.hex()
            dup["cipher"] = token["cipher"][32:64]
            send_data = base64.b64encode(json.dumps(dup).encode()).decode()
            print(dup)
            io.sendline("login")
            io.recvuntil("token: ")
            print("send %s"%c)
            io.sendline(send_data)
            io.recvuntil("cmd:")
            found = True
            break
        except:
            import time
            time.sleep(0.1)
            continue
    if not found:
        print("ERROR")
        break
    key = c+key
    for i in range(5):
        print(key)
```

At the end (after many minutes as every guess need a new connection and a new PoW) we obtain `hitcon{JSON_is_5`.

To continue the challenge I found an unintended way, unintended because it does not use the random number generator, nor the note commands.

If we need to make the $$login$$ function decrypt more blocks than 1 we can try to first set the second block as we want and use the old schema to make it decrypt as we want, changing the first ciphertext block instead of the $$IV$$. The problem now is that we do not know the plaintext of the first block to set the $$IV$$ correctly to decrypt to the target plaintext as we generated it to match what we wanted. Obviously this does not work.

Instead, to make it work, we can change our schema as follows:
<img src="/assets/files/CBC-schema2.png" alt="CBC Schema"/>

In Red the first block is xorred with the plain text to obtain the immediate state in green. When decrypting the immediate state in green is xorred with the $$IV$$ in black obtaining the target plain text in yellow. If we find (using the $$register$$ function to generate long usernames) two blocks (red and black) such that $$P1_i = T1_i \oplus C0_i \oplus C0_2_i$$ (where $$T$$ is the target plaintext, $$C0_2$$ and $$C0$$ are the two blocks) and $$P_i$$ are all printable characters inside a json string (only printable characters and no " and other escaped characters).
We can obtain the plaintext necessary for obtaining the target plaintext $$T1$$ by passing to the $$regiter$$ function the same string to generate $$C0_2$$ and another block $$P1$$ obtained before. The result of the encryption contains the ciphtertext in pink (let's call it $$C1$$) of such block that passed to the $$login$$ function as second block, as first block  $$C0$$ found before and as IV the necessary IV to decrypt the first block as $$T0$$. As the plaintext of every block is known we can do that. Obviously we need a correct padding and correct json string as target.

To continue concatenating block we can search for another ciphertext $$C1_2$$ that satisfy the previous condition: $$P2_i = T2_i \oplus C1_2_i \oplus C1_i$$ and $$P2$$ is printable and json escaped as before. Now we can generate the ciphertext $$C2$$ relative to $$P2$$ by generating using the same string inside the $$register$$ and appending $$P2$$ after the plaintext of $$C1_2$$. After that we have now 3 blocks that we can use to generate whatever string we want inside the json, we can continue and search for a forth block by searching $$C2_2$$ such that $$P3_i = T2_i \oplus C2_2_i \oplus C2_i$$ and $$P3$$ is printable and json escaped etc...

If you are worried about how much time is needed to find a match do not worry, the first match is found in less than 5 seconds, the next ones in less than a minute, so is very fast, just use username of 160000 of characters :)

Now we can put inside the ciphertext the json:
```python
{"secret": "", "cmd": "get_secret", "who": "admin", "user": "admin"}
```
This request would return the $$admin_secret$$ inside the first 2 blocks of the ciphertext returned:
```python
{"secret": "123456789012345}", "cmd": "get_secret", "who": "admin", "user": "admin"}
```
We can recover with first method by guessing a character at a time from the end. Starting from the 15th character:
```python
'{"secret": "12345678901234} "}'+'\x02\x02'
```
and continuing by guessing the 14th...
```python
'{"secret": "1234567890123}  "}'+'\x02\x02'
```