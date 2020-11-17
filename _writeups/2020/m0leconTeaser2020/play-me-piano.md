---
ctf_name: "m0lecon 2020 Teaser"
title:	"play me piano"
date:	2020-05-24
category: "reverse"
author: "NicolaVV, AvengerF12, lorenz"
---

### Description

Do you feel sleepy? [Let me play](https://challs.m0lecon.it:8005/) you something before bed.

### The Challenge

It was given a link to a webpage where you could play piano notes and the 
page responded with 3 different outputs:

- zzz... // Nice note
- what's this? // Bad note
- thx ...zzzzzz... // nice sequence of notes, go grab the flag (maybe)

The logic of the webpage was implemented in the html file as follows:

- Initialize wasm module to call a `review` function
- onMouseDown of a certain note
  - get pressed note
  - set $(".review").text = review(note))
  - if mouse holding: set $(".review").text = review('-')

### Wasm module reversing

There are lot of ways to reverse engineering a wasm file, I'm gonna enumerate some of them for the sake of completeness:

- [JEB](https://www.pnfsoftware.com/)
- [ghidra_wasm](https://github.com/andr3colonel/ghidra_wasm)
- [wasmdec](https://github.com/wwwg/wasmdec)
- [wabt](https://github.com/WebAssembly/wabt)
- [idawasm](https://www.fireeye.com/blog/threat-research/2018/10/reverse-engineering-webassembly-modules-using-the-idawasm-ida-pro-plugin.html)

With a bit of reversing you could came out with something like that:

```python
MEM = bytearray([42, 57, 103, 126, 113, 45, 33, 33, 114, 67, 65, 58, 9, 12, 4, 5, 82, 66, 64, 25, 10, 119, 81, 66, 5, 35, 54, 91, 12, 103, 102, 34, 0, 75, 39, 56, 71, 114, 110, 91, 117, 43, 44, 50, 94, 83, 71, 90, 34, 112, 116, 109, 123, 0, 119, 104, 97, 116, 39, 115, 32, 116, 104, 105, 115, 63, 0, 122, 122, 122, 46, 46, 46, 0, 0, 0, 0, 0, 0, 0, 116, 104, 120, 32, 46, 46, 46, 122, 122, 122, 122, 122, 122, 46, 46, 46, 0, 42])

flag_idx = 0
prev = 0x2a

def review(p):
    global flag_idx, prev
    flag_idx += 1
    prev = MEM[flag_idx] ^ p ^ prev
    # check if flag starts with ptm{
    if flag_idx <= 4 and prev == MEM[49 + flag_idx - 1]:
        return 'zzz...'
    else:
        if prev < 128: # check if it's an ascii
            if flag_idx == 47 and prev == ord('}'): 
                return 'thx ...zzzzzz...'
            elif flag_idx < 47:
                return 'zzz...'
        else:
            return "what's this?"
```

As one can see, there are too many notes wich satisfies those constrains, but the first
ones remains constant: ccggaa.
By searching on google images: `ccggaa english notes` you could find this image:

![Twinkle_Twinkle_Little_Star](https://upload.wikimedia.org/wikipedia/commons/1/16/Twinkle_Twinkle_Little_Star.png)

which, if played on the site, printed `thx ...zzzzzz...`

### Getting the flag

```python
sol = ["c", "c", "g", "g", "a", "a", "g", "-", "f", "f", "e", "e", "d", "d", "c", "-", "g", "g", "f", "f", "e", "e", "d", "-", "g", "g", "f", "f", "e", "e", "d", "-", "c", "c", "g", "g", "a", "a", "g", "-", "f", "f", "e", "e", "d", "d", "c", "-"]

for note in sol:
    review(ord(note))
    print (chr(prev), end='')

# ptm{7w1nKl3_7W1NkL3_My_w3b_574r_w3lL_Pl4y3d_hKr}
```
