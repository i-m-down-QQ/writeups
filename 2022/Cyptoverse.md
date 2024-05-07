# Cryptoverse
###### tags: `CTF`

## Crypto
### Warmup 1

`echo "cGlwZ3N7cG5yZm5lXzY0X3Nnan0=" |base64 -d|rot13`


### Warmup 2

![](https://i.imgur.com/a08nC0s.png)
flag : `cvctf{m0r53isn0t50fun}`

### Warmup 3

![](https://i.imgur.com/UXzWNtX.png)

flag : `cvctf{vigenere_is_too_guessy_without_the_key?}`

### Substitution

[Guballa Solver](https://www.guballa.de/substitution-solver)
很好用的工具

解出
'''
Capture the Flag is a special kind of information security competitions. There are three common types, Weopardy, Attack Defence and mixed.
If you have figured out the above message, here is your flag, please add curly brackets before submission: cvctfaverysimplesubstitution
'''
flag : `cvctf{averysimplesubstitution}`

### RSA1
```
n = 0x7c05a45d02649367ebf6f472663119777ce5f9b3f2283c7b03471e9feb1714a3ce9fa31460eebd9cd5aca7620ecdb52693a736e2fcc83d7909130c6038813fd16ef50c5ca6f491b4a8571289e6ef710536c4615604f8e7aeea606d4b5f59d7adbec935df23dc2bbc2adebbee07c05beb7fa68065805d8c8f0e86b5c3f654e651
e = 0x10001
ct = 0x35b63f7513dbb828800a6bcd708d87a6c9f33af634b8006d7a94b7e3ba62e6b9a1732a58dc35a8df9f7554e1168bfe3de1cb64792332fc8e5c9d5db1e49e86deb650ee0313aae53b227c75e40779a150ddb521f3c80f139e26b2a8880f0869f755965346cd28b7ddb132cf8d8dcc31c6b1befc83e21d8c452bcce8b9207ab76e
```

簡單的 RSA
n 已經在 factordb  裡面了

:::spoiler solve script
```python
#!/usr/bin/python3

from factordb.factordb import FactorDB
from Crypto.Util.number import long_to_bytes , inverse
from chal import n , e , ct

f = FactorDB(n)
f.connect()
p , q = f.get_factor_list()

phi = (p - 1) * (q - 1)
d = inverse(e , phi)
m = pow(ct , d , n)
print(long_to_bytes(m).decode())
```
:::

### RSA2
![](https://i.imgur.com/5hnLntd.png)

:::spoiler chall.py
```python=
from Crypto.Util.number import inverse, bytes_to_long, getPrime, isPrime
from math import gcd
from secret import flag

PBITS = 512
e = 0x10001

def stage_one(data: bytes):
    m = bytes_to_long(data)
    p = getPrime(PBITS)
    q = getPrime(PBITS)
    b = 7
    n = p**b * q
    print(f"p = {p}")
    print(f"e = {e}")
    print(f"dp = {inverse(e, p-1)}")
    print(f"b = {b}")
    print(f"ct = {pow(m, e, n)}\n")

def stage_two(data: bytes):
    m = bytes_to_long(data)
    p = getPrime(PBITS)
    q = p + 2
    while not isPrime(q):
        q += 2
    n = p * q
    print(f"n = {n}")
    print(f"e = {e}")
    print(f"ct = {pow(m, e, n)}\n")

print("=== Stage 1 ===")
stage_one(flag[:len(flag)//2])
print("=== Stage 2 ===")
stage_two(flag[len(flag)//2:])
```
:::

這題有 2 個部分要解

第一個部分的解法是利用模除的特性

$a\ \%\ (b \times c) = (a\ \%\ b) + b \times (\lfloor \frac{a}{b} \rfloor\ \%\ c)$

且由於 $ct = m^e\ \%\ n = m^e\ \%\ (p^7 \times q) = (m^e\ \%\ p^7) + p^7 \times (\lfloor \frac{m^e}{p^7} \rfloor\ \%\ q)$

因此可透過公式推得較小的 $m^e\ \%\ p^7$ 以避掉 q 未知的情況，即 $ct\ \%\ p^7$

而接下來及可假設新 $n = p^7$，新 $\phi(n) = p^6 \times (p-1)$，而 $d = e^{-1}\ \%\ \phi(n)$，使用一般的 RSA 公式 $m = ct^d\ \%\ n$ 即可獲得 m

```python
temp = ct % (p**7)
d = pow(e, -1, p**6 * (p-1))
m = pow(temp, d, p**7)
print(long_to_bytes(m))
```

得出 `cvctf{Hensel_Takagi_Lifti`

第二個部分可以利用 Fermat’s Factorization 來解

https://www.geeksforgeeks.org/fermats-factorization-method/

得到 `ng,but_Fermat_is_better?}`

拼起來就是完整的 flag 了

cvctf{Hensel_Takagi_Lifting,but_Fermat_is_better?}

### Big Rabin
![](https://i.imgur.com/N3gV2uc.png)

:::spoiler chall.py
```python=
from Crypto.Util.number import *
from secret import flag
import os, functools

primes = []
e = 2

for _ in range(10):
    primes.append(getPrime(1024))

n = functools.reduce((lambda x, y: x * y), primes)
m = bytes_to_long(os.urandom(256) + flag)
c = pow(m,e,n)

print(primes)
print(c)
```
:::

基本上可以看到，e 極小且 n 極大，所以可以嘗試對密文加很多次 n 算 iroot 的值，如果恰巧是可開根號則就會得到明文

solve.py
```python=
from Crypto.Util.number import *
from gmpy2 import iroot
import functools

with open("out.txt") as fh:
	data = fh.readlines()

exec(f"primes = {data[0].strip()}")
exec(f"c = {data[1].strip()}")

n = functools.reduce((lambda x, y: x * y), primes)

i = 0
while(True):
	num, is_sqrt = iroot(c + i * n,2)
	if(is_sqrt):
		print(i)
		print(long_to_bytes(num))
	i += 1
	break
```

其實恰巧這題的 n 太大了，只要加一次的 n 即可獲得 flag

cvctf{r4b1n_Cryp70_K1nd4_c0mpL1C4t3d?}

## misc
### Survey

填問卷

cvctf{7hx_4_p14y1ng_CVCTF!}

### iKUN 1
![](https://i.imgur.com/dPDqa9b.png)

題目的 yt 連結不重要，直接去 github 找 `CryptoverseCTF` 這個 user

只有找到唯一一個 user，且只有一個 repo
https://github.com/CryptoverseCTF

![](https://i.imgur.com/lQnupzf.png =500x)

確實是這個 repo，翻看舊紀錄有沒有神奇的東西

在 `Removed unnecessary comments in Chinese` 紀錄中，看到了 flag 的紀錄

![](https://i.imgur.com/IfB11u8.png =450x)

![](https://i.imgur.com/tKJb9oY.png)

cvctf{git_reveals_everything}

### Not Georainbolt
![](https://i.imgur.com/ybolQKW.png)

給 IP 或經緯度，要找 city，只要正確率一半以上就行

參考 [Get the city, state, and country names from latitude and longitude using Python](https://www.geeksforgeeks.org/get-the-city-state-and-country-names-from-latitude-and-longitude-using-python/) 和 [How to Get Location Information of an IP Address Using Python](https://www.freecodecamp.org/news/how-to-get-location-information-of-ip-address-using-python/) 這兩篇文章，寫出了一個 bot

solve.py
```python=
from geopy.geocoders import Nominatim
from pwn import *
import requests
context.log_level = "debug"

geolocator = Nominatim(user_agent="geoapiExercises")

conn = remote("137.184.215.151", 22606)

for i in range(50):
	conn.recvuntil(b"wrong.\n")
	aline = conn.recvline()
	city = b""
	if (b"IP" in aline):
		data = aline.split(b": ")[1].strip()
		data = data.decode()
		city = requests.get(f'https://ipapi.co/{data}/json/').json().get("city", '').encode()
	elif(b"Coordinate" in aline):
		data = aline.split(b": ")[1]
		Latitude, Longitude = data.split(b", ")
		Latitude, Longitude = Latitude.decode(), Longitude.decode()
		city = geolocator.reverse(f"{Latitude.strip()},{Longitude.strip()}", language="en").raw['address'].get('city', '').encode()

	conn.sendlineafter(b"City: ", city)

conn.interactive()
```

其中要注意的一點是 `geolocator.reverse` 要帶 language，不然會拿到奇怪的語言，另外如果沒成功就多跑幾次試試看

最終拿到 27 correct 23 wrong，算是低空飛過

![](https://i.imgur.com/30KWktw.png)

cvctf{4r3_y0u_4_R34L_Ge@r41nB0L7?}

### (X) Baby Maths
![](https://i.imgur.com/AGUpgf0.png)

題目如下
![](https://i.imgur.com/LxfZizn.png)

此題未完成，此部分參考[別人的解法](https://github.com/sahuang/my-ctf-challenges/tree/main/cryptoversectf-2022/Misc/Baby%20Maths)

由題目可知，點 $O$ 為 $\Delta ABC$ 的外接圓圓心，且 $\vec{AO} = \vec{AB} + 4 \times \vec{AC}$，要求得 $sin(\angle BAC)$ 的值

敘述如下圖所示，三角形為橘色部分，而輔助線為綠色虛線部分且等長 (外接圓心至多邊形頂點街等長)，而 $\vec{OB} = 4 \times \vec{AC}$
![](https://i.imgur.com/qPVKdPx.png)

由於 $\vec{OB} = 4 \times \vec{AC}$，所以代表 $\vec{OB}$ 與 $\vec{AC}$ 同方向，換言之，二者平行

所以，$\angle CAO = \angle AOB$

在此先進行一些假設，設 $\vec{AC} = x$、$\angle CAO = \alpha$

因 $\vec{OB} = 4 \times \vec{AC}$，所以 $\overline{OB} = 4 \times \overline{AC} = 4 \times x$，又 $\overline{OB} = \overline{OA} = \overline{OC} = 4 \times x$

而 $\angle CAO = \angle AOB = \alpha$，且由於 $\overline{OB} = \overline{OA} = \overline{OC}$ 故 $\Delta ABO$ 和 $\Delta ACO$ 皆為等腰三角形，因此 $\angle CAO = \angle ACO = \alpha$，$\angle OAB = \angle OBA = \frac{180 - \alpha}{2} = 90 - \frac{\alpha}{2}$

以上整理如下圖
![](https://i.imgur.com/Ar9osya.png)

因此可看到，我們要求的是 $sin(\angle CAB)$，也就是 $sin(\alpha + 90 - \frac{\alpha}{2}) = sin(90 + \frac{\alpha}{2})$

根據和角公式 $sin(a+b) = sin(a)cos(b) + sin(b)cos(a)$，所以上面公式可拆成 $sin(90)cos(\frac{\alpha}{2}) + sin(\frac{\alpha}{2})cos(90) = 1 \times cos(\frac{\alpha}{2}) + sin(\frac{\alpha}{2}) \times 0 = cos(\frac{\alpha}{2})$

而至於 $cos(\frac{\alpha}{2})$ 要怎麼算，可以透過左邊的等腰三角形 $\Delta ACO$ 的相關邊長算出 $cos(\alpha) = \frac{\frac{x}{2}}{4x} = \frac{1}{8}$，再利用半角公式 $cos(\frac{a}{2}) = \pm \sqrt{\frac{1+cos(a)}{2}}$ 求得 $cos(\alpha) = \pm \sqrt{\frac{1+cos(\alpha)}{2}} = \pm \sqrt{\frac{1+\frac{1}{8}}{2}} = \pm \sqrt{\frac{9}{16}} = \pm \frac{3}{4}$，而因 $\alpha < 90^{\circ}$，故 $cos(\alpha)$ 為正，為 $\frac{3}{4} = 0.75$

題目要求求到小數後五位，故為 0.75000

cvctf{0.75000}

以下是前面繪圖時的參數，採用 desmos 繪製
```
A=\left(0,0\right)
B=\left(2\sqrt{7},0\right)
C=\left(-\frac{\sqrt{7}}{4},\frac{3}{4}\right)
O=\left(\sqrt{7},3\right)
\left(x-O.x\right)^{2}+\left(y-O.y\right)^{2}=16
```
![](https://i.imgur.com/BKGrGSl.png)

## Reverse
### Baby Reverse
![](https://i.imgur.com/Fso7Ri9.png)

strings 一下就出來了
![](https://i.imgur.com/0n1j0vh.png)

cvctf{r3v3r53_15_4w350m3}

### Basic Transforms
![](https://i.imgur.com/7uvc9np.png)

這題弄了好久，不知道為什麼 node js 的 vigenere 怪怪的

:::spoiler app.js
```javascript=
var readline = require('readline');
var Crypto = require('vigenere');

var rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    terminal: false
});

rl.on('line', function(line){
    if (line.length == 20 && line.startsWith("cvctf{") && line.endsWith("}")) {
        var cat = Crypto.encode(line.substring(6, line.length - 1), "nodejsisfun").split('').map(function(c) {
            return String.fromCharCode(c.charCodeAt(0) + 1);
        }).join('');
        if (Buffer.from(cat.split("").reverse().join("")).toString('base64') == "QUlgNGoxT2A2empxMQ==") {
            console.log("Correct!");
        }
    }
});
```
:::

可以看到，會吃一條 flag 輸入進來，確認長度及開頭等是否正確後對其做 vigenere cipher 並用 `nodejsisfun` 加密，並做一次的 shift，接著就會做 reverse 及算 base64 並比對字串是否相同

因此可從字串反推回原文

如果要到 correct，cat 的值為 "1qjz6\`O1j4\`IA"，由於 vigenere cipher 的結果怪怪的，因此慢慢調整輸入即可

cvctf{0bfu5_N0d3_H@}

### French
![](https://i.imgur.com/Myimhkr.png)

main 函式如下
![](https://i.imgur.com/rmZNecY.png)

可以看到，程式會先對裡面存放的字串進行 RC4 的加密，並比對加密後的結果是否與輸入相同

由於加密後的結果也嘿被存放進記憶體當中，所以可以用動態分析方式直接拿到加密後的結果，如下圖的 0048

![](https://i.imgur.com/twdkbmI.png)

cvctf{rC4<->3nC0d3d>-<}

### World Cup Predictions
![](https://i.imgur.com/WIKEZUi.png)

逆向後 main 函式分解如下

![](https://i.imgur.com/23NXgUa.png)

第一關會要求要輸入進入 8 強的隊伍

同時在 FUN_001012fb 中會檢查是否是存在程式中的特定字串，不是的話會將 local_148 減 1

![](https://i.imgur.com/EICHHGX.png =400x)
![](https://i.imgur.com/6A2BdY1.png =400x)

回到 main 函式的部分，接著當輸入完之後會檢查每一行輸入是否在特定位置符合特定的字母

![](https://i.imgur.com/lqmOHI6.png =400x)
![](https://i.imgur.com/AwQ7iF9.png =400x)

且在最後會將結果做計算，基本上如果有任何一項不符合就不通過

在檢查的部分 ghidra 翻得不是很好，查看組語後發現會檢查當前字串 index = 0, 1, 0, 1, 0, 0, 2, 0 的位置 (即圖中當 `ADD RAX, RBP` 的下一行為 `SUB 0x130` 時就是 index 0， `SUB 0x12f` 即為 index 1，以此類推)

![](https://i.imgur.com/uaBHjGI.png =400x)
![](https://i.imgur.com/PaxcBO5.png =400x)

因此在符合程式內資料及特定字詞的規則之下，我這邊找出的是
```
Group A: Netherlands
Group B: England
Group C: Argentina
Group D: Mexico
Group E: Japan
Group F: Belgium
Group G: Ghana
Group H: USA
```

當然，解法不只一種

當通過第一關後，第二關為判斷獲勝隊伍，基本上就檢查是否在程式資料中且開頭是否為 `Arg`

![](https://i.imgur.com/RCcSX3T.png)

翻一下資料，應該就只有 `Argentina` 符合

解完後就能拿到 flag

cvctf{Arg3nt1n4_PLS_W1N_Th3_W0rld_Cup,M3551}

### Super Guesser
![](https://i.imgur.com/JTFwAgo.png)

拿到了一個 pyc，但不知道為什麼好像壞掉了 uncompyle6 逆向失敗

查看解出來的部分 code，看起來好像是要破 hash

首先程式 import 了 hashlib 和 re，並提供了 hashes
```
import hashlib, re
hashes = [
 'd.0.....f5...5.6.7.1.30.6c.d9..0',
 '1b.8.1.c........09.30.....64aa9.',
 'c.d.1.53..66.4.43bd.......59...8',
 '.d.d.076........eae.3.6.85.a2...']
```

在 main 的 L14 部分，要求進行輸入
```
L.  14        20  LOAD_GLOBAL              input
               22  LOAD_STR                 'Guess: '
               24  CALL_FUNCTION_1       1  ''
               26  STORE_FAST               'guess'
```

隨後在 L15 進行判斷，確認輸入長度為 5 的字元且為 [a-z] 的範圍
```
L.  15        28  LOAD_GLOBAL              len
               30  LOAD_FAST                'guess'
               32  CALL_FUNCTION_1       1  ''
               34  LOAD_CONST               4
               36  COMPARE_OP               <=
               38  POP_JUMP_IF_TRUE     64  'to 64'
               40  LOAD_GLOBAL              len
               42  LOAD_FAST                'guess'
               44  CALL_FUNCTION_1       1  ''
               46  LOAD_CONST               6
               48  COMPARE_OP               >=
               50  POP_JUMP_IF_TRUE     64  'to 64'
               52  LOAD_GLOBAL              re
               54  LOAD_METHOD              match
               56  LOAD_STR                 '^[a-z]+$'
               58  LOAD_FAST                'guess'
               60  CALL_METHOD_2         2  ''
               62  POP_JUMP_IF_TRUE     72  'to 72'
             64_0  COME_FROM            50  '50'
             64_1  COME_FROM            38  '38'
```

在 L17 中，使用到 hashlib.md5 計算 hash
```
 98  LOAD_GLOBAL              hashlib
100  LOAD_METHOD              md5
102  LOAD_FAST                'guess'
104  LOAD_METHOD              encode
106  CALL_METHOD_0         0  ''
108  CALL_METHOD_1         1  ''
110  LOAD_METHOD              hexdigest
112  CALL_METHOD_0         0  ''
114  CALL_METHOD_2         2  ''
```

由此推斷，應該是要讓輸入符合宣告的 hashes 其中之一，而 hashes 的 `.` 是任意 [a-z] 字元

寫了一個腳本來猜 hash
```python=
import hashlib
import string
import itertools

hashes = [
 'd.0.....f5...5.6.7.1.30.6c.d9..0',
 '1b.8.1.c........09.30.....64aa9.',
 'c.d.1.53..66.4.43bd.......59...8',
 '.d.d.076........eae.3.6.85.a2...']

wl = string.ascii_lowercase

words = [None for _ in range(len(hashes))]

p = itertools.product(wl, repeat=5)
for word in p:
	word = ''.join(word)
	hash = hashlib.md5(word.encode()).hexdigest()
	for i,h in enumerate(hashes):
		found = True
		for a,b in zip(hash, h):
			if (b != '.' and a != b):
				found = False
				break
		if(found):
			words[i] = word
			print(i, "is", word)

print(words)
```

算出來為 `['cvctf', 'hashi', 'snotg', 'uessy']`，照 flag 格式拼起來就可以了

cvctf{hashisnotguessy}