# SECCON CTF
###### tags: `CTF`

## Welcome
### welcome
![](https://i.imgur.com/yfe4WCo.png)

discord -> announcement -> 第一條訊息

![](https://i.imgur.com/eYMSdfT.png)

SECCON{JPY's_drop_makes_it_a_good_deal_to_go_to_the_Finals}

## Misc
### (X) find flag
![](https://i.imgur.com/lkmDGMM.png)

:::spoiler server.py
```python=
#!/usr/bin/env python3.9
import os

FLAG = os.getenv("FLAG", "FAKECON{*** REDUCTED ***}").encode()

def check():
    try:
        filename = input("filename: ")
        if open(filename, "rb").read(len(FLAG)) == FLAG:
            return True
    except FileNotFoundError:
        print("[-] missing")
    except IsADirectoryError:
        print("[-] seems wrong")
    except PermissionError:
        print("[-] not mine")
    except OSError:
        print("[-] hurting my eyes")
    except KeyboardInterrupt:
        print("[-] gone")
    return False

if __name__ == '__main__':
    try:
        check = check()
    except:
        print("[-] something went wrong")
        exit(1)
    finally:
        if check:
            print("[+] congrats!")
            print(FLAG.decode())

```
:::

可以看到，在這題中會要求輸入檔案路徑，並會嘗試讀取檔案，並比對檔案內容是否是 flag 的內容

不過，查看提供的 docker 相關設定檔，沒有看到有 mount 其他檔案，所以應該沒有其他檔案有 flag 的內容

以下是其他人的解法

![](https://i.imgur.com/AE2VwEQ.png)

可以看到，當發生其他特別的錯誤時，會在 main 中進入到 except 區塊並輸出一些提示字後執行 `exit(1)` 的指令，而從一些外部資料可知 python 中的 `exit()` 並非強制程式停止，而是產生 `SystemExit` exception

![](https://i.imgur.com/fgQaKEB.png)

[參考文章](https://stackoverflow.com/questions/65492548/python-function-exit-does-not-work-why)

![](https://i.imgur.com/22lXMRj.png)

[參考文章](https://docs.python.org/3/library/exceptions.html#SystemExit)

而因為 python finally 的特性，當在 try 或 except 中發生的 exception 沒有被 handle 時，會在**執行完** finally 後才被 raise

![](https://i.imgur.com/uzQUmdH.png)
[參考文章](https://docs.python.org/3/tutorial/errors.html#defining-clean-up-actions)

![](https://i.imgur.com/Ub1qVHZ.png)

因此，我們這邊的 exit 不會馬上被執行，而會在執行完 finally 進行檢查並印出提示文字及 flag 資訊後才執行

另外還有一些問題，要怎麼產生 exception 並被 raise 出來，以及當 raise 出來要怎麼通過檢查

第一個問題，可以看到因為 `FileNotFoundError`、`IsADirectoryError`、 ... 等都已經在 check 中被 handle 住，無法使用這些 exception，在經過嘗試後發現當檔案名稱是 Null byte 時會 raise 出 ValueError，不會被 handle 住

![](https://i.imgur.com/HXL982v.png)

而第二個問題，可以發現程式中 main 的部分有變數名稱重用的問題，也就是 `check = check()` 這行，因此檢查時檢查的變數為 `check`，而由於在 check 函式中發生了 exception，導致在 `check = check()` 這行不會進行賦值，而 python 中有奇怪特性是當 `x` 是一個 function 時， `x != true` 但 `if(x)` 能成功

因此在輸入 filename 為 null byte 的情況下，會發生 exception 且 `check = check()` 不會進行賦值，此時的 `check` 變數型態為 function，因此 `if(check)` 成功進入，拿到 flag

![](https://i.imgur.com/qNN3xVo.png)

SECCON{exit_1n_Pyth0n_d0es_n0t_c4ll_exit_sysc4ll}

## Web
### (X)skipinx
![](https://i.imgur.com/5ZZGTrY.png)

:::spoiler index.js
```javascript=
const app = require("express")();

const FLAG = process.env.FLAG ?? "SECCON{dummy}";
const PORT = 3000;

app.get("/", (req, res) => {
  console.log(req.query);
  req.query.proxy.includes("nginx")
    ? res.status(400).send("Access here directly, not via nginx :(")
    : res.send(`Congratz! You got a flag: ${FLAG}`);
});

app.listen({ port: PORT, host: "0.0.0.0" }, () => {
  console.log(`Server listening at ${PORT}`);
});

```
:::

:::spoiler default.conf
```nginx=
server {
  listen 8080 default_server;
  server_name nginx;

  location / {
    set $args "${args}&proxy=nginx";
    proxy_pass http://web:3000;
  }
}

```
:::

可以看到，當使用 nginx 進入時，會自動帶上 `proxy=nginx` 的參數，而程式中會判斷是否有這一項參數，如果沒有的話就會吐出 flag

以下是別人的解法:
![](https://i.imgur.com/PmMnOMd.png)

經測試發現，似乎當參數超過 1000 個的時候，後面剩下的參數就會被忽略

查詢文件後，發現是 `express` 框架中預設使用 `qs` 模組作為 query string 的 parser，而其預設限制即為 1000 個參數

![](https://i.imgur.com/TR77sSo.png)

[參考資料](https://expressjs.com/en/api.html)

![](https://i.imgur.com/ozezng0.png)

[參考資料](https://www.npmjs.com/package/qs)

因此，透過以下程式，即可獲得 flag

```python=
requests.get('http://skipinx.seccon.games:8080/?proxy=' + 'a=3&'*1000).text
```

![](https://i.imgur.com/7EdOcqY.png)

SECCON{sometimes_deFault_options_are_useful_to_bypa55}

## Crypto
### (X) pqpq
![](https://i.imgur.com/FUYHATm.png)

:::spoiler problem.py
```python=
from Crypto.Util.number import *
from Crypto.Random import *
from flag import flag

p = getPrime(512)
q = getPrime(512)
r = getPrime(512)
n = p * q * r
e = 2 * 65537

assert n.bit_length() // 8 - len(flag) > 0
padding = get_random_bytes(n.bit_length() // 8 - len(flag))
m = bytes_to_long(padding + flag)

assert m < n

c1p = pow(p, e, n)
c1q = pow(q, e, n)
cm = pow(m, e, n)
c1 = (c1p - c1q) % n
c2 = pow(p - q, e, n)

print(f"e = {e}")
print(f"n = {n}")
# p^e - q^e mod n
print(f"c1 = {c1}")
# (p-q)^e mod n
print(f"c2 = {c2}")
# m^e mod n
print(f"cm = {cm}")
```
:::

已知 `e`, `n`, `c1`, `c2`, `cm`，關係式如下

$e = 2 \times 65537$
$n = p \times q \times r$
$c1 \equiv p^e - q^e \ (mod\ n)$
$c2 \equiv (p-q)^e\ (mod\ n)$
$cm \equiv m^e (mod\ n)$

要求得 `p`, `q`，可觀察 `c1` 和 `c2` 的式子，發現以下關係

$\begin{aligned}
c2 - c1 &\equiv (p-q)^e - (p^e - q^e) \\
    & \equiv (p^e - {e \choose 1} p^{e-1} q + {e \choose 2} p^{e-2} q^2 - ... - {e \choose e-1} p q^{e-1} + q^e) - (p^e - q^e) \\
    & \equiv - {e \choose 1} p^{e-1} q + {e \choose 2} p^{e-2} q^2 - ... - {e \choose e-1} p q^{e-1} + q^e + q^e \\
    & \equiv k_1 \times q
\end{aligned}$

$\begin{aligned}
c2 + c1 &\equiv (p-q)^e + (p^e - q^e) \\
    & \equiv (p^e - {e \choose 1} p^{e-1} q + {e \choose 2} p^{e-2} q^2 - ... - {e \choose e-1} p q^{e-1} + q^e) + (p^e - q^e) \\
    & \equiv p^e - {e \choose 1} p^{e-1} q + {e \choose 2} p^{e-2} q^2 - ... - {e \choose e-1} p q^{e-1} + p^e \\
    & \equiv k_2 \times p
\end{aligned}$

其中，$k_1$ 和 $k_2$ 皆為一常數

因此可透過 GCD 的方式得出 `p` 和 `q`，即 
$p = GCD(n, (c2+c1)\%n)$
$q = GCD(n, (c2-c1)\%n)$

而 `r` 值亦可知，參數如下:

```python=
p = 7572427786695057270624844967644562609112132599800420296747189080920032359205995588384031542287784540006438555802994008688795974493684400576592403320929717
q = 8609258896430210586523688955272794335561428099377427081622836355194006054569349679983850344916908011330202034512905353365631416251631307084038768336538857
r = 9018251874561850467651399512661829039310834429345808807288228370045576292997274498659156953954383290793552486677903139680704353709352146165598701061994853
```

進一步亦可得出 $\phi (n)$ 值

不過此題的 $e$ 與 $\phi (n)$ 非互質，無法輕易找出模反元素

以下參考別人的解法
![](https://i.imgur.com/EkVCRl1.png)

參考[此文章](https://tttang.com/archive/1504/#toc_1)，先將 $m^e$ 降為 $m^t$，而發現 $t = 2$，即獲得 $m^2\ (mod\ n)$

此外，亦可計算 $m^2\ (mod\ p)$, $m^2\ (mod\ q)$, $m^2\ (mod\ r)$

而在數學上有名為 [Quadratic residue](https://zh.wikipedia.org/wiki/%E4%BA%8C%E6%AC%A1%E5%89%A9%E4%BD%99) 的特性，當模數 $p$ 為質數且 $p \equiv 3\ (mod\ 4)$ 時，可直接計算 $m = \pm n^{\frac{p+1}{4}}\ (mod\ p)$

不過此題的 $p$, $q$, $r$ 皆在模 4 的情況下為 1，無法直接應用上面的特性，不過仍可以透過 [Tonelli–Shanks algorithm](https://en.wikipedia.org/wiki/Tonelli%E2%80%93Shanks_algorithm) 的演算法來求出 $m$ (在模 p, q ,r)

而現在有了 $m\ (mod\ p)$, $m\ (mod\ q)$, $m\ (mod\ r)$，可透過 CRT 的方式重組回 $m\ (mod\ p \times q \times r) = m\ (mod\ n)$

完整腳本如下:
```python=
import Crypto.Util.number as cn
from sage.all import *

with open("output.txt") as fh:
	data = fh.readlines()

for d in data:
	exec(d)

q = cn.GCD(c2-c1, n)
p = cn.GCD(c2+c1, n)

assert (pow(p, e, n) - pow(q, e, n))%n == c1
assert pow(p-q, e, n) == c2

r = n // p // q

assert (p * q * r) == n
assert cn.GCD(p, q) == 1 and cn.GCD(p, r) == 1 and cn.GCD(r, q) == 1

phi = (p-1) * (q-1) * (r-1)

# not invertable :(
# GCD(e, phi) != 1
# https://tttang.com/archive/1504/

t = cn.GCD(e, phi)
assert t == 2
e_bar = e // t
d_bar = pow(e_bar, -1, phi)

m_t = pow(cm, d_bar, n)

# m_t = m^2 % n
# m_t_p = m_t % p = m^2 % p
# m_t_q = m_t % q = m^2 % q
# m_t_r = m_t % r = m^2 % r

m_t_p = m_t % p
m_t_q = m_t % q
m_t_r = m_t % r

# m_p = Tonelli-shanks(m_t_p, p)
# m_q = Tonelli-shanks(m_t_q, q)
# m_r = Tonelli-shanks(m_t_r, r)

def Tonelli_Shanks(n, p):
	assert cn.isPrime(p)
	assert pow(n, (p-1)//2, p) == 1
	if (p % 4 == 3):
		return pow(n, (p+1)//4, p)
	assert (p % 4) == 1
	S = 0
	Q = p-1
	while (Q % 2 == 0):
		Q //= 2
		S += 1
	z = 2
	while(pow(z, (p-1)//2, p) != p-1):
		z += 1
	M = S
	c = pow(z, Q, p)
	t = pow(n, Q, p)
	R = pow(n, (Q+1)//2, p)
	r = 0
	while(True):
		if(t == 0):
			return 0
		elif(t == 1):
			return R
		else:
			i = 1
			t2 = pow(t, 2, p)
			for i in range(1, M):
				if((t2-1) % p == 0):
					break
				t2 = pow(t2, 2, p)
			b = pow(c, pow(2, M-i-1), p)
			M = i
			c = pow(b, 2, p)
			t = (t * c) % p
			R = (R * b) % p

m_p = Tonelli_Shanks(m_t_p, p)
m_q = Tonelli_Shanks(m_t_q, q)
m_r = Tonelli_Shanks(m_t_r, r)

for i in range(2**3):
	mm_p,mm_q,mm_r = m_p,m_q,m_r
	if(i % 2 == 1):
		mm_p = (-mm_p)%p
	if((i >> 1) % 2 == 1):
		mm_q = (-mm_q)%q
	if((i >> 2) % 2 == 1):
		mm_r = (-mm_r)%r
	flag = CRT([mm_p,mm_q,mm_r],[p,q,r])

	print(cn.long_to_bytes(flag))
```

SECCON{being_able_to_s0lve_this_1s_great!}

另一個[類似的解法](https://github.com/rkm0959/Cryptography_Writeups/blob/main/2022/SECCON/PQPQ/solve.py) (使用 sage 自動解 $x^2 \equiv n\ (mod\ p)$)

```python=
import Crypto.Util.number as cn
from sage.all import *

with open("output.txt") as fh:
	data = fh.readlines()

for d in data:
	exec(d)

q = cn.GCD(c2-c1, n)
p = cn.GCD(c2+c1, n)

assert (pow(p, e, n) - pow(q, e, n))%n == c1
assert pow(p-q, e, n) == c2

r = n // p // q

assert (p * q * r) == n
assert cn.GCD(p, q) == 1 and cn.GCD(p, r) == 1 and cn.GCD(r, q) == 1

phi = (p-1) * (q-1) * (r-1)

# not invertable :(
# GCD(e, phi) != 1
# https://tttang.com/archive/1504/

t = cn.GCD(e, phi)
assert t == 2
e_bar = e // t
d_bar = pow(e_bar, -1, phi)

m_t = pow(cm, d_bar, n)

# m_t = m^2 % n
POLp = PolynomialRing(GF(p), 'pp')
POLq = PolynomialRing(GF(q), 'qq')
POLr = PolynomialRing(GF(r), 'rr')
pp = POLp.gen()
qq = POLq.gen()
rr = POLr.gen()

f_p = pp**2 - m_t # pp^2 = m_t
f_q = qq**2 - m_t # qq^2 = m_t
f_r = rr**2 - m_t # rr^2 = m_t

pps = f_p.roots()
qqs = f_q.roots()
rrs = f_r.roots()

for i in range(len(pps)):
	for j in range(len(qqs)):
		for k in range(len(rrs)):
			flag = CRT([int(pps[i][0]), int(qqs[j][0]), int(rrs[k][0])], [p, q, r])
			print(cn.long_to_bytes(flag))
```

<!-- 目前腳本:
```python=
import Crypto.Util.number as cn
from sage.all import *

with open("output.txt") as fh:
	data = fh.readlines()

for d in data:
	exec(d)

q = cn.GCD(c2-c1, n)
p = cn.GCD(c2+c1, n)

assert (pow(p, e, n) - pow(q, e, n))%n == c1
assert pow(p-q, e, n) == c2

r = n // p // q

assert (p * q * r) == n
assert cn.GCD(p, q) == 1 and cn.GCD(p, r) == 1 and cn.GCD(r, q) == 1

phi = (p-1) * (q-1) * (r-1)

# not invertable :(
# GCD(e, phi) != 1
```

雖有發現此[文章](https://tttang.com/archive/1504/#toc_2)，不過他的 code 無法使用，期待 sixkwnp 大大能幫忙解出來

使用文章內解法仍無法解出，使用[這個](https://blog.csdn.net/m0_62506844/article/details/122580164)仍無法
<!--花了三小時--> -->

## Reverse
### babycmp
![](https://i.imgur.com/ey6ZSCG.png)

首先丟到 ghidra 翻譯，翻出來的 code 很噁心，不過可以看出是會將輸入字串與一些數字運算做 xor 後最終進行比對

![](https://i.imgur.com/Kp4T5Jy.png)

稍微看了一下 asm 後，發現 xor 的 key 在指令 0x001250 (在 gdb 上對應的位置是 0x555555555250) 時的 AL 可以看到，直接使用動態分析方式 break 在那邊查看 key

![](https://i.imgur.com/MZ4aY2C.png)

發現 key 是 `Welcome to SECCON 2022`

解密腳本：
```python=
# 591E2320202F2004 2B2D3675357F1A44 0736506D035A1711 362B470401093C15 380a41

enc = b"\x04\x20\x2f\x20" +  b"\x20\x23\x1e\x59" + \
	b"\x44\x1a\x7f\x35" + b"\x75\x36\x2d\x2b" + \
	b"\x11\x17\x5a\x03" + b"\x6d\x50\x36\x07" + \
	b"\x15\x3c\x09\x01" + b"\x04\x47\x2b\x36" + \
	b"\x41\x0a\x38"

key = b"Welcome to SECCON 2022"

flag = [0 for _ in range(len(enc))]
for i,e in enumerate(enc):
	flag[i] = e ^ key[i%len(key)]

flag = [f for f in flag]
print(bytes(flag))
```

SECCON{y0u_f0und_7h3_baby_flag_YaY}
### (X)eguite
這題蠻有趣的，思路應該是解掉一個函式就好了
> eguite::Crackme::onclick::hb69201652eb2ef3b

應該可以用推的推出來Licence或跳轉到輸出Flag的地方，不過時間不夠沒解出來。

幫補個找到的 [writeup](https://fantac.at/posts/secconctf2022-writeup/)

input[19] == '-' and input[26] == '-' and input[33] == '-'

```python
from z3 import *

x, y, z, w = BitVecs('x y z w', 64)
solve(x + y == 0x8B228BF35F6A, y + z == 15172161, z + w == 4199291551, w + x == 0x8B238557F7C8, y ^ z ^ w == 4184371021)
```

<!-- z3 太神啦 -->

SECCON{8b228b98e458-5a7b12-8d072f-f9bf1370}