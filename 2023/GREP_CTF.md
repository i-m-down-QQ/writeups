# GREP CTF
###### tags: `CTF`

## Crypto
### Blind

https://zh.wikipedia.org/zh-tw/盲文

the flag is t00_bl1nd_t0_s33

`grepCTF{t00_bl1nd_t0_s33}`

### CaeX0R

```python
import string
c=['162', '177', '188', '169', '136', '187', '138', '145', '172', '187', '138', '145', '172', '190', '152', '156', '187', '195', '177', '142']

for k in range(256):
    flag = bytes([int(char)^k for char in c])
    if(all([chr(f) in string.printable for f in flag])):
        print(flag)
```

get `QBOZ{Hyb_Hyb_MkoH0B}`

caesar with key = 10

`GREP{Xor_Xor_CaeX0R}`

### Birdseed

```python
import random

# rand_seed = random.randint(0, 999)
for rand_seed in range(1000):
    random.seed(rand_seed)
    encrypted = ''

    for enc in bytes.fromhex("a282b415279f5aa08cd4649515268910b8968a1eabda7c1bb2898c"):
        encrypted += chr(enc ^ random.randint(0, 255))

    if ("grep" in encrypted):
        print(encrypted)
```

`grepCTF{n3v3r_tru1y_r4nd0m}`

### Uneasy Alliance

brute force the seed

```python
from random import Random
from Crypto.Util.number import *

ct = 9898717456951148133749957106576029659879736707349710770560950848503614119828

for seed in range(1680365354, 1672502400, -1):
    rnd = Random(seed)
    rand_fn = lambda n: long_to_bytes(rnd.getrandbits(n))
    p = getPrime(128, randfunc=rand_fn)
    q = getPrime(128, randfunc=rand_fn)
    if(p == q):
        continue
    e = 65537
    n = p * q
    d = pow(e, -1, (p-1)*(q-1))
    pt = long_to_bytes(pow(ct, d, n))
    if(b"GREP" in pt):
        print(seed, pt)
    if(seed % 1000000 == 0):
        print(seed)
```

seed is `1680353499`

`GREP{Brut3D_M3!_f0r_l1f3}`

### CaeX0R 2

nearly same script as `CaeX0R 1`

```python
import string
c=['313', '296', '295', '304', '274', '280', '263', '280', '263', '310', '315', '310', '316', '345', '268', '263', '310', '302', '345', '296', '276']

for k in range(256):
    flag = bytes([(int(char)^k)&0xff for char in c])
    if(all([chr(f) in string.printable for f in flag])):
        print(flag)
```

found `PANY{qnqn_R_U0en_G0A}`

caesar cipher found shift is 9

`GREP{hehe_I_L0ve_X0R}`

### NOT 13

https://www.dcode.fr/monoalphabetic-substitution

fixing with table:

```
abcdefghijklmnopqrstuvwxyz
GNJSYQEDUCVRIHWLPFKBOXATMZ
```

```!
lorem ipsum dolor sit amet, consectetur adipiscing elit. morVi sceleriskue, nulla Bitae luctus tincidunt, mi turpis BestiVulum tellus, ut congue turpis kuam kuis augue. proin ultricies luctus risus, eget Barius risus interdum sed. nunc id tincidunt ipsum. the flag is its not always rot, in lower case, with underscores instead of spaces. fusce dictum nulla erat, tincidunt tempus lectus ultricies Bel.
```

`grepCTF{its_not_always_rot}`

### DOGE DOGE DOGE

xor with `grepCTF{` first

found xor key is `DOGE`

`grepCTF{pl4y1ng_w1th_x0r_is_fun}`

### Derailed

read the line 378 (75th prime - 1)

rail fence with key 41, found `TERC{N_Irel_ONQ_cNFfjBeq}`

caesar with key 13 (rot 13)

`GREP{A_Very_BAD_pASswOrd}`

## Reverse
### Simple rev

```bash
strings outfile | grep "grep"
```

`grepCTF{4p0g33_h1vem1nd_g3n3s1s}`

### EXORcist

```python
bytes([i^s for i,s in enumerate(b"gsgsGQ@|9gn8tRy>c\"Mk$gk")])
```

`grepCTF{1nd3x_w1s3_x0r}`

### Worst encoding

unzip jar to get class file

logic as below
```
enc = 1
prime = 2
flag = flag.toCharArray()
for(f in flag):
    enc *= pow(prime, f)
    prime = nextPrime(prime+1)
print(enc)
```

```python
from sage.all import factor

with open("./hint.txt") as fh:
    data = fh.readline()

num = list(factor(int(data)))
flag = []
for a,b in num:
    flag.append(b)
print(bytes(flag))
```

`GREP{who_would_encode_like_this?_c1caad3482259933bdf988ade3c073e6}`

## PWN
### A lot of files

```bash
strace ./release_file_opener
```

ignore `.*\.flag` files opening

`GREP{that_was_easy_1aa9e759139a09f73618689fa0b3287a4ce81b00472d894ff518fe1d189e2858}`

### (X) Infinite sleep (Level I)

[ref](https://medium.com/@0xEpitome/grep-ctf-writeups-bf457f3fcc4c#:~:text=Infinite)

use `LD_PRELOAD` bypass sleep function

[ref](https://jasonblog.github.io/note/fcamel/04.html)

mylib.c
```clike
unsigned int sleep(unsigned int seconds)
{
    return 0;
}
```

```bash
gcc -shared -o mylib.o mylib.c
LD_PRELOAD=./mylib.o ./release_sleeper_level1
```

`GREP{Sleep_Thr1ll$_BUt_K1ll$_bb003ebe87e4c02c9eb57e5c2c97ca782a6c6bcab77308e4c2b18b3f9e0c6523}`

## Forensics
### Monke

```bash
strings monke.jpg
```

found a strange string `Z3JlcENURntyM2ozY3RfaHVtNG4xdHlfZzBfYjRja190MF9tMG5rM30K`

base64 -d

`grepCTF{r3j3ct_hum4n1ty_g0_b4ck_t0_m0nk3}`

### R36

mmsstv

![](https://i.imgur.com/cgua7It.jpg)

`grepCTF{psych3d3l1c_fr0g}`

### Doctored image

copy byte 0x0 ~ 0x9 from a normal jpg to corrupted

`grepCTF{m00n_kn1ght}`

### Royal Steg

stegseek find steghide password `cuteessort37`

extract a zip

zip2john + john found zip password `jesuslove`

`grepCTF{tw0_l3v3ls_0f_st3g}`

### NGGYU

audacity frequency map

`grepCTF{r1ck_4stl3y_g1v1ng_m3_up}`

### IronMan

```bash
zsteg -o ALL ironman.png
```

`grepCTF{i_d0n't_f3el_s0_g00d}`

### Missing Kitty

stegseek found password `kitty123`

extract `secret.txt`

replace `m` to `0`, `e` to `1`

binary to text

`GREP{steghide,Sw33t_l1ttle_k1tt3n}`

## OSINT

reverse image search

found [John GBA Lite](https://play.google.com/store/apps/details?id=com.johnemulators.johngbalite&hl=zh_HK&gl=RO)

`GREP{john}`

### Sherlock Exhausted

use new Bing found that the subject of the lyrics is 甘蔗汁 (`sugarcane juice`)

use google map finding around the BITS campus, found a store called `Bhagirath Redi`, and the comment said that it is the place famous for sugarcane juice

https://goo.gl/maps/MbDsdUirPFsxnMAN8

`GREP{bhagirath_redi}`

## Misc
### Consensual Non Consent

gcode

https://ncviewer.com/

`grepCTF{w0rksh0p_pract1ce_b3st_c0urs3}`

### esoF*ck

replace `f#ck` to empty

throw it to browser development tool and found an error

follow the error

`grepCTF{3sot3r1c_l4ngu4g3s_ftw}`

### esoF*ck 2

brainfuck -> ook -> text

https://www.cachesleuth.com/bfook.html

`grepCTF{3sot3r1c_l4ngu4g3s_4r3_0k!}`

### Approved !

https://ctftime.org/ctf/918

`GREP{W3lc0me_t0_GR3P_CTF}`

### Lost Card

vertically reverse image

https://www.dcode.fr/luhn-algorithm

`GREP{5388110365956729}`

### Layouts

https://awsm-tools.com/keyboard-layout

`grepCTF{r4pg0d_em1n3m_3256gd62}`

### (X) Stormborn

[ref](https://github.com/de-upayan/ctf-writeups/blob/main/GREP%20CTF%20(BITS%20Pilani)/stormborn.md)

Quick Reload -> QR code

```python
import matplotlib.pyplot as plt
import numpy as np

with open("stormborn.txt") as fh:
    data = fh.readlines()

mat = np.zeros((100,100))

for i,d in enumerate(data):
    mat[i//100][i%100] = int(d[0])

plt.imshow(mat)
plt.show()
```

`grepCTF{m0th3r_of_dr4g0n5}`