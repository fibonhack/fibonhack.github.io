---
ctf_name: "m0lecon 2020 Teaser"
layout: writeup
title:	"andry"
date:	2020-05-24
category: "reverse"
author: "AvengerF12, NicolaVV"
---
### Tools
- Ghidra
- Jadx
- dex2jar

### Analyzing the apk
We started the analysis by opening the apk with jadx and exploring the file's structure.

Our target was clearly marked as MainActivity, located in the com.andry directory.
If there were any doubt a quick look inside AndroidManifest.xml would have made it clear that the execution flow starts from MainActivity.

After taking a quick look at the code we noticed the use of multiple native functions inside the password_check() function.
The first step was therefore to find the password.

### Getting the password
In android native functions are located inside shared libraries located in the Resources/lib path, in there we found libandry-lib.so, we chose the x86_64 version for ease of use with Ghidra.
By decompiling the library and exporting it as C/C++, we retrieved everything we needed to get the password:

```c
int results[] = {6326,2259,455,1848,275400,745,1714,1076,12645,2120,153664,10371,37453,203640,691092,36288,753,2011,59949,18082,538,12420,2529,1130,6076,11702,47217,1056,207,11315,2676,261};

int c1(int arg) {
  return (arg + 7) * 0x50 + 6;
}

    ...

int c32(int arg) {
  return arg + 0x13;
}

void (*c[])(int) = {c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16, c17, c18, c19, c20, c21, c22, c23, c24, c25, c26, c27, c28, c29, c30, c31, c32};

int main(int argc, char ** argv) {
  for (int i = 0; i < 32; ++i) {
    for (int ch = 0; ch <= 0xff; ++ch) {
      if (c[i](ch) == results[i]) {
        printf("%02x", ch);
        break;
      }
    }
  }
}
```

Output: `48bb6e862e54f2a795ffc4e541caed4d0bf985de4d3d7c5df73cf960638b4bf2`

### There and back again
Following the execution flow inside the onClick() function we ended up inside the DynamicLoaderService class.

The application uses an intent to pass the password to handleActionFoo() which then xors it with the contents of Resources/assets/enc_payload.
Even though the xor function is not implemented a simple python script did the trick.

The result of this operation is a valid dex file containing the second unimplemented cryptographic function, in order to read it however we need to first convert it to jar using dex2jar.

Finally, we reimplemented the new decrypt() function in python and used it with the argument "EASYPEASY", as shown in DynamicLoaderService, to obtain the flag.

```python
def decrypt(string):
    i = 0
    upperCase = "NUKRPFUFALOXYLJUDYRDJMXHMWQW"
    str2 = ""
    i2 = 0
    while (True):
        i3 = i
        if (i3 >= len(upperCase)):
            return str2

        str2 = str2 + (chr(((((ord(upperCase[i3]) - ord(string[i2])) + 26) % 26) + 65)))
        i2 = (i2 + 1) % len(string)
        i = i3 + 1

print(decrypt("EASYPEASY"))
```

Flag: `ptm{JUSTABUNCHOFAWFULANDROIDMESS}`
