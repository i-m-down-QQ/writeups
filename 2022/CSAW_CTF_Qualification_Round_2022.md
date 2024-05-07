# CSAW CTF Qualification Round 2022
###### tags: `CTF`

<!--先去睡ㄌ 明天有空上[name=sixkwnp]-->

## Misc
### Welcome

![](https://i.imgur.com/Fz0Zd8m.png)

加入 discord 後，在 announce 頻道即可看到 flag

![](https://i.imgur.com/qotYVwQ.png)

flag{c54w_f1n4l5_15_1n_p3r50n_y4y}

### Beta Survey

![](https://i.imgur.com/FJ38elT.png)

![](https://i.imgur.com/UIYU3VV.png)

flag{h0p3_7h47_y0u_h4d_fun_pl4y1n6!}

### CatTheFlag

![](https://i.imgur.com/RdVD6oY.png)

要 train 一個 NN model

給了 3 個 pkl 檔案，但基本上只有用到 X.pkl 和 y.pkl 而已 (因為 X_test.pkl 沒有標籤 (雖然也可以搞 semi-supervise learning 啦但我不想))

個別維度如下
![](https://i.imgur.com/m2srqwS.png)

X 的部分看起來像是影像
![](https://i.imgur.com/QdVGCML.png)

y (標籤) 的部分看起來只有 0 和 1，算是 binary classification
![](https://i.imgur.com/KgI2Jwg.png)

網路架構如下:
![](https://i.imgur.com/LlHvUUO.png)

基本上是參考 [Simple MNIST convnet](https://keras.io/examples/vision/mnist_convnet/) 和 [Image classification from scratch](https://keras.io/examples/vision/image_classification_from_scratch/) 這兩篇來改的

參數部分如下:
```
optimizer: keras.optimizers.Adam(1e-3)
loss: binary crossentropy
epochs: 50
```

暴力硬算後的結果在 training set 上為 `loss: 0.1563`, `accuracy: 0.9645`

完整的 code: https://colab.research.google.com/drive/1pSqilx5ia65ypdHPVcYu25VPdawTdeVQ?usp=sharing

原本一直卡在上傳不上去，後來在 discord 的公告發現要傳 zip
![](https://i.imgur.com/kTrI849.png)

上傳結果
![](https://i.imgur.com/gPuhiEV.png)

flag{!ts_r4In!Ng_C47$_AnD_D09z!}

## forensic
### Our Spy In New Terrain (OSINT)
1. 08/2022
2. spyduhman
3. log.txt
4. canada
5. TDOMCATTTOR
6. 

commit log
bit.ly/evilevilinfo

morse code
![](https://i.imgur.com/l7bhJpv.png)

bit.ly/osintsec

卡在這不知道怎麼解 6. 題
![](https://i.imgur.com/wyteUOJ.jpg)


:::warning
[被找到ㄉFlag 改掉ㄌQQ](https://github.com/elh313/somethin/blob/8213a297e5fec48279c9d6eae8112d0aa1974d1d/server.py)
:::

<!--我先解別題 這題快解完ㄌ--!>
<!-- ok -->

### Android x86

https://medium.com/@frank1314168/%E7%A1%AC%E7%A2%9F%E9%91%91%E8%AD%98%E5%B7%A5%E5%85%B7-tsk-toolkit-%E7%B0%A1%E6%98%93%E6%95%99%E5%AD%B8-%E4%BB%A5-picoctf-2022-%E9%A1%8C%E7%9B%AE-sleuthkit-apprentice-%E7%82%BA%E4%BE%8B-2fc98e195fc7
```
img_stat android_forensics_easy.dd
mmls android_forensics_easy.dd
fsstat -o 63 android_forensics_easy.dd
mmls android_forensics_easy.dd
fls 63 android_forensics_easy.dd
fls -o 63 android_forensics_easy.dd
fls -o 63 android_forensics_easy.dd 81921
fls -o 63 android_forensics_easy.dd 90113
fls -o 63 android_forensics_easy.dd 90115
fls -o 63 android_forensics_easy.dd 172034
fls -o 63 android_forensics_easy.dd 172037
fls -o 63 android_forensics_easy.dd 180226
fls -o 63 android_forensics_easy.dd 98305
fls -o 63 android_forensics_easy.dd 98307
tsk_recover -o 63 -d 98307 android_forensics_easy.dd .
ls
tsk_recover -o 63 -d 81921 android_forensics_easy.dd ./android_extract
 ```

## Web
### Word Wide Web

![](https://i.imgur.com/61zJzcS.png)

點進去後發現有很多連結
![](https://i.imgur.com/l4DeaiF.png)

但發現其實只有一個是有效的連結
![](https://i.imgur.com/9KXTQ3r.png)

推測是要一直點選連結直到最後

~~檢視頁面來源 and ctrl+f `<a ` 找有連結的東西~~

連結太多，使用程式來處理

要注意的地方是，網頁有使用 cookie 來記錄，要處理一下

```python=
import requests
import re

url = "http://web.chal.csaw.io:5010/"
visited = []
last = ''
solChain = ''

while True:
    headers = {'Cookie': f"solChain={solChain};"}
    res = requests.get(url+last, headers=headers)
    regex = re.search('<a href=\\"(.*)\\">', res.text)
    try:
        reloc = regex.group(0)[10:-2]
    except:
        print(res.text)
        break
    last = reloc
    visited.append(reloc)
    if(solChain == ''):
        solChain = reloc
    else:
        solChain += '%20' + reloc
    print(reloc)

print(solChain)
print(visited)
```

最後的 cookie
```!
stuff%20threw%20label%20explain%20chapter%20canal%20piece%20course%20plastic%20grown%20gulf%20shirt%20manner%20gravity%20ice%20enjoy%20skill%20foreign%20ago%20found%20hope%20introduced%20nothing%20fellow%20gasoline%20string%20step%20growth%20nation%20oldest%20exact%20opposite%20manufacturing%20describe%20fresh%20youth%20strip%20arm%20parent%20everyone%20rock%20compound%20said%20massage%20by%20coach%20charge%20reach%20ants%20finish%20activity%20cave%20test%20queen%20past%20love%20bet%20observe%20bank%20exciting%20catch%20whether%20importance%20wagon%20sent%20calm%20dog%20substance%20repeat%20national%20port%20trade%20diagram%20support%20meant%20studied%20flight%20rest%20full%20loose%20flies%20although%20voyage%20practice%20went%20drop%20develop%20point%20nest%20instant%20light%20should%20parallel%20industrial%20planning%20ahead%20desk%20best
```

![](https://i.imgur.com/85qZ3JR.png)

CTF{w0rdS_4R3_4mAz1nG_r1ght}

## Reverse
### DockREleakage
史上最水的題目

藏在 .json檔 裡的 base64 Encode
![](https://i.imgur.com/qwpPWGd.png)

跟 tar 解壓縮後的 txt
![](https://i.imgur.com/7232aVn.png)

flag{n3v3r_l34v3_53n5171v3_1nf0rm4710n_unpr073c73d_w17h1n_7h3_d0ck3rf1l3}

### Anya Gacha

flag可以參考用 Ghidra 開 .app看看

~~放這個4什麼意思~~
![](https://i.imgur.com/mHtS8cI.png)

## Pwn
### ezROP

蓋 120 個垃圾即可操控 rip

有 NX，無法使用 shellcode
有 GOT 且可蓋，但目前想不到哪裡可以控制覆蓋位置
可使用 ROPgadget，但目前找不到可利用的 ROP chain (沒有 system 或 open 或 int 80 之類的，但可控制 rdi 及 rsi)

```
0000000000401000 <_init>:
0000000000401020 <.plt>:
00000000004010a0 <puts@plt>:
00000000004010b0 <fclose@plt>:
00000000004010c0 <printf@plt>:
00000000004010d0 <memset@plt>:
00000000004010e0 <read@plt>:
00000000004010f0 <setvbuf@plt>:
0000000000401100 <exit@plt>:
0000000000401110 <__ctype_b_loc@plt>:
0000000000401120 <_start>:
0000000000401150 <_dl_relocate_static_pie>:
0000000000401160 <deregister_tm_clones>:
0000000000401190 <register_tm_clones>:
00000000004011d0 <__do_global_dtors_aux>:
0000000000401200 <frame_dummy>:
0000000000401206 <init>:
000000000040125c <check>:
0000000000401304 <readn>:
0000000000401343 <vul>:
000000000040150b <main>:
0000000000401540 <__libc_csu_init>:
00000000004015b0 <__libc_csu_fini>:
00000000004015b8 <_fini>:
```

## crypto
### Gotta Crack Them All
![](https://i.imgur.com/EicreMf.png)

以下是 encrypt.py 的內容
```python=
with open('key.txt','rb') as f:
        key = f.read()

def encrypt(plain):
        return b''.join((ord(x) ^ y).to_bytes(1,'big') for (x,y) in zip(plain,key))
```
可以看到是使用基本的 xor 進行加密

且已知有一組明文，可使用加密服務獲得密文，xor 後可以拿到密鑰
![](https://i.imgur.com/YD6AxhM.png)

但嘗試對整包進行解密時，發現有些密文解密出來怪怪的，推測這邊的密鑰只是一小部分

![](https://i.imgur.com/bS2WNzq.png)

觀察後，發現可以使用猜字的方式猜出未解密的明文內容，即可繼續獲得更長的密鑰

最終解密程式如下:
```python=
plain = b"Cacturne-Grass-Dark"
leak = b'kz\xc6\xb9\xd9Du\xcb\x8a\x9e\xe0\x9d\xbeo\xee\x03\xcf\xddd'
passwd = [p^l for p,l in zip(plain, leak)] + [
    ord('n')^int('fb',16),
    ord('g')^int('eb',16),
    ord('d')^int('df',16),
    ord('n')^int('a7',16),
    ord('g')^int('9c',16),
    ]
print(passwd)

with open('encrypted_passwords.txt', 'rb') as fh:
    enc = fh.readlines()

enc = [e[:-1] for e in enc]

def xor(e, p):
    ret = []
    for i in range(len(e)):
        ret.append(e[i] ^ p[i%len(p)])
    return ret

for e in enc:
    print(e, bytes(xor(e, passwd)))
```

解密結果
![](https://i.imgur.com/vpRCOIp.png)

發現其中有一組不一樣的字串 `1n53cu2357234mc1ph32`

且發現這組字串在加密服務上無法使用，推測是 admin 的密碼
![](https://i.imgur.com/Zy6GNXD.png)

flag 就是這組密碼

1n53cu2357234mc1ph32

### Phi Too Much In Common
![](https://i.imgur.com/k2z21ao.png)

連進去後，會出現以下畫面

![](https://i.imgur.com/hqFlB2C.png)

首先選 1 後，發現會給 rsa 的 `N`, `e`, `c`，推測是要破密

但是可以一直嘗試生成參數 (這邊假定密文都是固定的)，並發現會有可能發生 N 一樣的情況，可嘗試使用共模攻擊

![](https://i.imgur.com/3TKlktr.png)

數學推導如下:

$\begin{aligned}
c_1 &\equiv m^{e_1}\ (mod\ N) \\
c_2 &\equiv m^{e_2}\ (mod\ N) \\
(c_1)^x \times (c_2)^y &\equiv m^{e_1 \times x + e_2 \times y}\ (mod\ N)\ \leftarrow [e_1 \times x + e_2 \times y = 1]\\
&\equiv m^1\ (mod\ N)
\end{aligned}$

腳本如下 (相關參數依據實際狀況填寫):
```python=
from Crypto.Util.number import long_to_bytes

# from GeeksforGeeks
def gcdExtended(a, b):
	if a == 0:
		return b, 0, 1
	gcd, x1, y1 = gcdExtended(b % a, a)
	x = y1 - (b//a) * x1
	y = x1
	return gcd, x, y

e1 = ...
e2 = ...
c1 = ...
c2 = ...
n1 = ...
n2 = ...

assert n1 == n2

_, x, y = gcdExtend(e1, e2)
m = (pow(c1, x, n1) * pow(c2, y, n2)) % n1
print(long_to_bytes(m))
```

密文為 `d0nt_reUs3_c0mm0n_m0duLus_iN_RSA`

輸入後，發現還有下一關

![](https://i.imgur.com/SxT4vmK.png)

這關會提供 `N`, `e`, `d` 參數，要求要輸入 phi

一樣，多刷幾次就會發現有出現一樣的 N，可以用數學推導出

$\begin{aligned}
e_1 \times d_1 &\equiv 1\ (mod\ \phi(N)) \\
e_2 \times d_2 &\equiv 1\ (mod\ \phi(N))
\end{aligned}$

$\begin{aligned}
e_1 \times d_1 - 1 &= k \times \phi(N) \\
e_2 \times d_2 - 1 &= q \times \phi(N)
\end{aligned}$


$GCD(e_1 \times d_1 - 1, e_2 \times d_2 - 1) = GCD(k \times \phi(N), q \times \phi(N)) = \phi(N)$

腳本如下:
```python=
# from GeeksforGeeks
def gcdExtended(a, b):
	if a == 0:
		return b, 0, 1
	gcd, x1, y1 = gcdExtended(b % a, a)
	x = y1 - (b//a) * x1
	y = x1
	return gcd, x, y

e1 = ...
e2 = ...
d1 = ...
d2 = ...
n1 = ...
n2 = ...

assert n1 == n2
g, _, _ = gcdExtend(e1*d1 - 1, e2*d2 - 1)
print(g)
```

提交後，得到 flag

![](https://i.imgur.com/SgPFyk0.png)

flag{aR3nT_U_tH3_RSA_ninJA}