---
ctf_name: "m0lecon 2020 Teaser"
title:	"NT master"
date:	        2020-05-24
category:       "misc"
author:         "OrsoBruno96"
---

This is the prompt of the challenge:

```
$ nc challs.m0lecon.it 10000
Hello!
I'll give you a positive integer N, can you give me two positive integers a,b
such that a>b and gcd(a,b)+lcm(a,b)=N? You must send the values of a and b
separated by a space.
You have 1 second for each of the 10 tests.
```

We can observe that `a = N-1, b = 1` always satisfy `gcd(a,b)+lcm(a,b)=N`
