# DownUnderCTF 2022
###### tags: `CTF`

## misc
### discord
![](https://i.imgur.com/EcS8Au7.png)

discord -> general -> memes -> Nosurf

![](https://i.imgur.com/upWd4E7.png)

DUCTF{G'day_mates_this'll_be_a_cracka}

### twitter
![](https://i.imgur.com/jxFqdxw.png)

https://twitter.com/DownUnderCTF

![](https://i.imgur.com/1o02AVs.png)

DUCTF{the-mascot-on-the-ductf-hoodie-is-named-ducky}

## OSINT
### Honk Honk
![](https://i.imgur.com/Z2lLPyE.png)

找車的註冊資料

找到一個網址 https://free-rego-check.service.nsw.gov.au/ ，輸入資料後即可得到以下結果

![](https://i.imgur.com/raKt8Wd.png)

flag 是到期日
 
DUCTF{19/07/2023}

### Bridget Returns!
![](https://i.imgur.com/0RPAKap.png)

從題目敘述可知是 3 word location，位置如下

https://what3words.com/download.pausing.counterparts

flag 是橋的名稱

TedSmoutMemorialBridge

### Bird's eye view!
![](https://i.imgur.com/TUjmkJG.png)

GEOSINT

![](https://i.imgur.com/wyAkuKb.jpg)

打開圖片，找不到太特別的東西，用 google 相片來找也沒看到一個特定地方

用 exiftool，發現有 GPS 資訊

![](https://i.imgur.com/rRK8AAe.png)

![](https://i.imgur.com/ImQStzG.png)

flag 就是旁邊的 Hoop Pine

HoopPine

### (?) Pre-Kebab Competition
google 圖片找到似乎是 The Epping Club，但flag 不對

## DFIR
### doxme
![](https://i.imgur.com/gJDPLTz.png)

題目提示是 microsoft word，將檔案附檔名調整成 .docx，發現內嵌有一張圖片，是一半的 flag

![](https://i.imgur.com/54Ko5e8.png)

已知 word 其實是一個壓縮檔，解壓縮之後找找看有沒有特別的東西

在 word/media 發現了兩張圖片，其中一張是嵌入的圖片，另一張是剩下的 flag

![](https://i.imgur.com/n6xvbHE.png)
![](https://i.imgur.com/SuilHnT.png)

DUCTF{WOrd_D0Cs_Ar3_R34L1Y_W3ird}

### Shop-Setup&Disclaimer
![](https://i.imgur.com/xRTwMU6.png)

說明題，flag 在題目裡

IAgreeToTheTeasAndTheSeas

### Shop-Knock Knock Knock
![](https://i.imgur.com/VRHDKqE.png)

使用 log 分析工具 [cloudvyzor LogPad](https://cloudvyzor.com/)

從題目敘述看起來是要找 bruteforce 的 IP，搜尋看看 login，發現有奇怪的 IP 58.164.62.91 一直在用 curl 戳主機

![](https://i.imgur.com/Z30acj7.png)

丟 ip 到 whois365，找到 ISP 的 email

![](https://i.imgur.com/fvazNij.png)

flag 是 email

abuse@telstra.net

### Shop-I'm just looking!
![](https://i.imgur.com/U6HR2CW.png)

在 log 中翻到奇怪的 nuclei.php 字樣，搜尋後發現是一個 vulnerabilities scanning tool

https://github.com/projectdiscovery/nuclei-templates

flag 就是工具名稱

nuclei

## web
### helicoptering
![](https://i.imgur.com/iczntUK.png)

進入後，可以看到有兩個檔案要讀，但是其中一個有限制 HTTP_HOST 要是 localhost，而另外一個限制 THE_REQUEST 不能是 flag

![](https://i.imgur.com/0WND3VS.png)

第一個的限制可以透過修改 HTTP 中的 Host，即可 bypass

![](https://i.imgur.com/EZQ3CCv.png)

第二個的限制可以透過 url encoding 的方式 bypass

![](https://i.imgur.com/h8mgZF4.png)

組合起來就是 flag

DUCTF{thats_it_next_time_im_using_nginx}

## crypto
### babyarx
![](https://i.imgur.com/3wYBgoN.png)

原始碼如下:
```python=
class baby_arx():
    def __init__(self, key):
        assert len(key) == 64
        self.state = list(key)

    def b(self):
        b1 = self.state[0]
        b2 = self.state[1]
        b1 = (b1 ^ ((b1 << 1) | (b1 & 1))) & 0xff
        b2 = (b2 ^ ((b2 >> 5) | (b2 << 3))) & 0xff
        b = (b1 + b2) % 256
        self.state = self.state[1:] + [b]
        return b

    def stream(self, n):
        return bytes([self.b() for _ in range(n)])


FLAG = open('./flag.txt', 'rb').read().strip()
cipher = baby_arx(FLAG)
out = cipher.stream(64).hex()
print(out)

# cb57ba706aae5f275d6d8941b7c7706fe261b7c74d3384390b691c3d982941ac4931c6a4394a1a7b7a336bc3662fd0edab3ff8b31b96d112a026f93fff07e61b
```

加密概念圖如下，下方圈圈為輸出部分:
![](https://i.imgur.com/qyqFR1O.png)

由於已可知第一個 `O` 的值及 63 和 O 做運算的結果，因此可用逆推的方式求出 63，而已知 63 和及 62 和 63 做運算的結果，因此也可逆推出 62，一值逆推下去即可獲得全部的值

解密腳本:
```python=
def solver(b=None, c=None):
        b1 = (b ^ ((b >> 5) | (b << 3))) & 0xff
        a1 = (c - b1) % 256
        a = [0 for _ in range(8)]
        a[0] = 0
        for i in range(1,8):
                a[i] = ((a1 >> (8-i)) & 0x1) ^ a[i-1]
        a = int(''.join([str(aa) for aa in a]), 2)
        return a

cipher = bytes.fromhex('cb57ba706aae5f275d6d8941b7c7706fe261b7c74d3384390b691c3d982941ac4931c6a4394a1a7b7a336bc3662fd0edab3ff8b31b96d112a026f93fff07e61b')

ans = [None for _ in range(64)]

ans[-1] = solver(b=cipher[0],c=cipher[-1])
for i in range(62, -1, -1):
        ans[i] = solver(b=ans[i+1], c=cipher[i])

ans = ''.join([chr(a) for a in ans])
print(ans)
```

DUCTF{i_d0nt_th1nk_th4ts_h0w_1t_w0rks_actu4lly_92f45fb961ecf420}

## blockchain
### Solve Me
![](https://i.imgur.com/rpmRAIn.png)

合約如下:
```solidity=
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/**
 * @title SolveMe
 * @author BlueAlder duc.tf
 */
contract SolveMe {
    bool public isSolved = false;

    function solveChallenge() external {
        isSolved = true;
    }

}
```

簡單的來說，要 call solveChallenge 即可完成挑戰

相關資訊:
```json=
{
    "player_wallet":
    {
        "address": "0x1C3101Df12B2A0a0ce9e4e8e86a4fA654426de73",
        "private_key": "0xf1aafae36ce55c5756c4c589774e93bc9f51c2a5cd5010b93a14dfffc033a54a",
        "balance": "2 ETH"
    },
    "contract_address":
    [
        {
            "address": "0x6E4198C61C75D1B4D1cbcd00707aAC7d76867cF8",
            "name": "SolveMe.sol"
        }
    ]
}
```

研究了一下 web3.js 後，寫出的腳本如下，ABI 部分為 remix 編譯:

```javascript=
var Web3 = require('web3');
var web3 = new Web3('https://blockchain-solveme-687ec80889e4af40-eth.2022.ductf.dev/');

var myaddr = "0x1C3101Df12B2A0a0ce9e4e8e86a4fA654426de73";
var mypriv = "0xf1aafae36ce55c5756c4c589774e93bc9f51c2a5cd5010b93a14dfffc033a54a";
var contractaddr = "0x6E4198C61C75D1B4D1cbcd00707aAC7d76867cF8";

const ABI = [
    {
        "inputs": [],
        "name": "isSolved",
        "outputs": [
            {
                "internalType": "bool",
                "name": "",
                "type": "bool"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "solveChallenge",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    }
];

var mycontract = new web3.eth.Contract(ABI, contractaddr);

web3.eth.accounts.wallet.add(mypriv);
mycontract.methods.solveChallenge().send({from: myaddr, gas: 100000}).then(console.log);
mycontract.methods.isSolved().call().then(console.log);
```

前往 `/challenge/solve` 即可看到 flag

DUCTF{muM_1_did_a_blonkchain!}

## rev
### source provided
![](https://i.imgur.com/hK8ihk3.png)

題目提供了 chall 的 assembly，節錄如下
```=
SECTION .data
c db 0xc4, 0xda, 0xc5, 0xdb, 0xce, 0x80, 0xf8, 0x3e, 0x82, 0xe8, 0xf7, 0x82, 0xef, 0xc0, 0xf3, 0x86, 0x89, 0xf0, 0xc7, 0xf9, 0xf7, 0x92, 0xca, 0x8c, 0xfb, 0xfc, 0xff, 0x89, 0xff, 0x93, 0xd1, 0xd7, 0x84, 0x80, 0x87, 0x9a, 0x9b, 0xd8, 0x97, 0x89, 0x94, 0xa6, 0x89, 0x9d, 0xdd, 0x94, 0x9a, 0xa7, 0xf3, 0xb2

l:
    movzx r11, byte [rsp + r10]
    movzx r12, byte [c + r10]
    add r11, r10
    add r11, 0x42
    xor r11, 0x42
    and r11, 0xff
    cmp r11, r12
```

大致上會每次讀取後，會先加上當前的 index，然後加上 0x42 後跟 0x42 做 xor，並與 data 區段做比較，相等即會正常返回 0 否則返回錯誤 1

解碼腳本如下

```python=
data = [
        0xc4, 0xda, 0xc5, 0xdb, 0xce, 0x80, 0xf8, 0x3e, 0x82, 0xe8, 0xf7, 0x82, 0xef, 0xc0, 0xf3, 0x86, 0x89, 0xf0, 0xc7, 0xf9, 0xf7, 0x92, 0xca, 0x8c, 0xfb, 0xfc, 0xff, 0x89, 0xff, 0x93, 0xd1, 0xd7, 0x84, 0x80, 0x87, 0x9a, 0x9b, 0xd8, 0x97, 0x89, 0x94, 0xa6, 0x89, 0x9d, 0xdd, 0x94, 0x9a, 0xa7, 0xf3, 0xb2
]

for i, d in enumerate(data):
        d = d ^ 0x42
        d -= 0x42
        d -= i
        print(chr(d), end='')
print()
```

出來的就是 flag

DUCTF{r3v_is_3asy_1f_y0u_can_r34d_ass3mbly_r1ght?}

## pwn
### babyp(y)wn
![](https://i.imgur.com/XwJ7b0A.png)

程式內容如下:
```python=
#!/usr/bin/env python3

from ctypes import CDLL, c_buffer
libc = CDLL('/lib/x86_64-linux-gnu/libc.so.6')
buf1 = c_buffer(512)
buf2 = c_buffer(512)
libc.gets(buf1)
if b'DUCTF' in bytes(buf2):
    print(open('./flag.txt', 'r').read())
```

看的出來，只要隨便塞超過 512 bytes 的資料即可塞到 buf2，所以塞 `'A'*512+'DUCTF'` 即可

![](https://i.imgur.com/FXFtyPg.png)

DUCTF{C_is_n0t_s0_f0r31gn_f0r_incr3d1bl3_pwn3rs}

## survey
### survey
填問卷

DUCTF{thx_4_playing_DUCTF_2022}