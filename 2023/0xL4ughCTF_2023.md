# 0xL4ughCTF 2023
###### tags: `CTF`

## Misc
### Welcome
```
Welcome to our ctf hope you enjoy. find your flag here

https://discord.gg/invite/JyCGhgDnCq
```

rules -> 公告

`0xL4ugh{W3LC0ME_T0_0UR_C7F_FREE_PALESTINE}`

### Detected
```
Can you be undetected ?

link
```
[link](http://20.121.121.120:8000/)
附件: `misc.php`

這題很詭異，一進去網站就拿到 flag 了 :thinking_face: 

以下是 `misc.php`

:::spoiler misc.php
```php
<?php
session_start();
$servername = "localhost";
$username = "root";
$dbname = "ctf_test";
$password = "";
// Create connection
$conn = new mysqli($servername, $username, $password,$dbname);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

$session=mysqli_real_escape_string($conn,$_COOKIE['PHPSESSID']);
$ip=$_SERVER['REMOTE_ADDR'];

$conn->query("INSERT into misc (ip,phpsess)values('$ip','$session')");

if($conn->query("select Distinct ip from misc where phpsess='$session'")->num_rows >20)
{
    echo "Flag{here}";
}
else
{
    echo "Still Not 20 ip yet :D";
}

?>
```
:::

推測是我進去的時候的 cookie 有被其他人使用過 (或是題目哪邊出包了)，所以在判斷式中直接通過檢查，拿到 flag

`0xL4ugh{Youuu_R_a_real_Haqqqqqqeer}`

## Osint
### Cat
```
i lost my cat a while ago , and recently i found a photo of it can you help me track my cat by getting the location of this image.

flag is in the format: 0xL4ugh{Latitude,Longitude}. Use the 6 digits after the decimal point. (ex: 112.1234567 --> 112.123456)
```
附件: `10472912333_57c751743a_w.jpg`

圖片如下

![](https://i.imgur.com/Zhnn2ei.jpg)

可以看到，左下角有一串英文，推測可能是攝影師帳號之類的

搜尋這個名字後找到以下圖片，看起來就是這一張

[flicker](https://www.flickr.com/photos/95789140@N05/10472912333/)

在右側的地圖點下去後，找到地點的網址:
https://www.flickr.com/map/?fLat=29.386886&fLon=47.977166&zl=13&everyone_nearby=1&photo=10472912333

所以 Latitude = 29.386886, Longitude = 47.977166

拼成 flag 格式，繳交

`0xL4ugh{29.386886,47.977166}`

## Forensics
### ATT IP
```
This is a trojan , Can u identify the C2 server IP and the port?

Flag format: 0xL4ugh{IP_PORT}
```
附件: `AttIP.zip`

附件解壓後得到 `AttIP.pcap`

根據題目敘述，這是一個木馬程式的封包，需要我們找到 C2 server 的 IP 和 port

首先看 protocol hierarchy，看到有一些 HTTP 和 tcp data 的東西

![](https://i.imgur.com/w3v7xUj.png =500x)

首先看 HTTP，看到似乎是在做 whois 的查詢，而查看相關 ip 沒有看到特別的東西

![](https://i.imgur.com/QqPjb3K.png =500x)

而看到 data 區塊，看到是 192.168.100.145 與 91.243.59.76 的溝通紀錄，而中間開始有ㄧ些奇怪的東西，像是說在封包 75 開始有一些列舉文件的行為，而封包 83 開始似乎就開始傳送 png 圖片

![](https://i.imgur.com/QkLJR3Z.png =500x)

![](https://i.imgur.com/hDH8Rg9.png =500x)

看起來十分可疑，所以我就推測 ip 91.243.59.76 與其對應的 port 23927 是 c2 server，繳交成功

`0xL4ugh{91.243.59.76_23927}`

### PVE 1
```!
An attacker attacked our server. we got a dump so can you investigate it for us?

Q1: What is the operating system and kernal version of the dump

Download: https://drive.google.com/file/d/1IV95rb5VH8K2PD27zN-K53HC8NNL8njE/view?usp=sharing

Flag format: 0xL4ugh{OsName_theFullKernalVersion}
```

記憶體鑑識題，首先要問 OS 與更細節的版本

首先嘗試使用 volatility3 的 `windows.info`，但不知道為什麼會跳出下面錯誤，無法執行

```
Volatility 3 Framework 2.4.1
Progress:  100.00               PDB scanning finished
Unsatisfied requirement plugins.VerInfo.kernel.layer_name:
Unsatisfied requirement plugins.VerInfo.kernel.symbol_table_name:

A translation layer requirement was not fulfilled.  Please verify that:
        A file was provided to create this layer (by -f, --single-location or by config)
        The file exists and is readable
        The file is a valid memory image and was acquired cleanly

A symbol table requirement was not fulfilled.  Please verify that:
        The associated translation layer requirement was fulfilled
        You have the correct symbol file for the requirement
        The symbol file is under the correct directory or zip file
        The symbol file is named appropriately or contains the correct banner

Unable to validate the plugin requirements: ['plugins.VerInfo.kernel.layer_name', 'plugins.VerInfo.kernel.symbol_table_name']
```

後來想說猜猜看是 linux 系統，然後 volatility 中有一個 `banner` plugin 可以看 linux 的 banner 資訊，然後就得到了以下東東

```
Volatility 3 Framework 2.4.1
Progress:  100.00               PDB scanning finished
Offset  Banner

0x1a00180       Linux version 4.4.0-186-generic (buildd@lcy01-amd64-002) (gcc version 5.4.0 20160609 (Ubuntu 5.4.0-6ubuntu1~16.04.12) ) #216-Ubuntu SMP Wed Jul 1 05:34:05 UTC 2020 (Ubuntu 4.4.0-186.216-generic 4.4.228)
0x211e6a4       Linux version 4.4.0-186-generic (buildd@lcy01-amd64-002) (gcc version 5.4.0 20160609 (Ubuntu 5.4.0-6ubuntu1~16.04.12) ) #216-Ubuntu SMP Wed Jul 1 05:34:05 UTC 2020 (Ubuntu 4.4.0-186.216-generic 4.4.228)
0x1aaf7338      Linux version 4.4.0-186-generic (buildd@lcy01-amd64-002) (gcc version 5.4.0 20160609 (Ubuntu 5.4.0-6ubuntu1~16.04.12) ) #216-Ubuntu SMP Wed Jul 1 05:34:05 UTC 2020 (Ubuntu 4.4.0-186.216-generic 4.4.228)
0x1fde00a8      Linux version 4.4.0-186-generic (buildd@lcy01-amd64-002) (gcc version 5.4.0 20160609 (Ubuntu 5.4.0-6ubuntu1~16.04.12) ) #216-Ubuntu SMP Wed Jul 1 05:34:05 UTC 2020 (Ubuntu 4.4.0-186.216-generic 4.4.228)
```

所以 OS 是 `Ubuntu`，kernel 是 `4.4.0-186.216-generic`

`0xL4ugh{Ubuntu_4.4.0-186-generic}`

### PVE 2
```!
Q2: What is the version of the apache server?

Files: Same as PVE 1 flag format : 0xL4ugh{..*}
```

這次要來找 apache 的版本

由於前面遇到 volatility 不能動的問題，所以我使用 strings + grep 篩選出與 `apache` 有關的字串後，使用 more 慢慢讀，看有沒有版本資訊出來

```bash
strings PVE.vmem | grep apache | more
```
```
[10dsudo apt-get install apache2=2.2.14-5ubuntu16.04.7
[11dsudo apt-get install apache=2.2.14-5ubuntu16.04.7
[12dsudo apt-get install apache
[13dsudo apt-get install apache2
[14dsudo apt-get install apache=2.2.14-5ubuntu16.04.7
...
```
幸運的是，一開始就看到 server 在安裝 apache 的紀錄，版本為 `2.2.14`

`0xL4ugh{2.2.14}`

### PVE 3
```!
Q3: We think that there was a suspicious process can you look what is it and reterive the flag ?

Files: Same As PVE 1
```

這次要找特別的 process，根據題目敘述，flag 在裡面

同前面問題，使用 strings + grep 來找與 `L4ugh` 有關的字串

```bash
strings PVE.vmem | grep L4ugh
```
```
[23dsudo echo "0xL4ugh{S4D_Y0U_G07_M3}" > flag.txt
    char flag[] = "0xL4ugh{H1DD3N_1N_PR0CE$$}";
0xL4ugh{H
0xL4ugh{H1DD3N_1N_PR0CE$$}
sudo echo "0xL4ugh{S4D_Y0U_G07_M3}" > flag.txt
echo "0xL4ugh{S4D_Y0U_G07_M3}" > flag.txt
0xL4ugh{H
    char flag[] = "0xL4ugh{H1DD3N_1N_PR0CE$$}";
    char flag[] = "0xL4ugh{H1DD3N_1N_PR0CE$$}";
0xL4ugh{H
sudo echo "0xL4ugh{S4D_Y0U_G07_M3}" > flag.txt
[23dsudo echo "0xL4ugh{S4D_Y0U_G07_M3}" > flag.txt
    char flag[] = "0xL4ugh{H1DD3N_1N_PR0CE$$}";
L4ugh{S4D_Y0U_G07_M3}" > flag.txt
echo "0xL4ugh{S4D_Y0U_G07_M3}" > flag.txt
echo "0xL4ugh{S4D_Y0U_G07_M3}" > flag.txt
echo "0xL4ugh{S4D_Y0U_G07_M3}" > flag.txt
sudo echo "0xL4ugh{S4D_Y0U_G07_M3}" > flag.txt
sudo echo "0xL4ugh{S4D_Y0U_G07_M3}" > flag.txt
sudo echo "0xL4ugh{S4D_Y0U_G07_M3}" > flag.txt
0xL4ugh{H
0xL4ugh{H
0xL4ugh{H
```

找到了 `0xL4ugh{S4D_Y0U_G07_M3}` 和 `0xL4ugh{H1DD3N_1N_PR0CE$$}`，看來也順便把後面題目的 flag 找出來了

反正兩個都丟看看，而後者是這題的 flag

`0xL4ugh{H1DD3N_1N_PR0CE$$}`

### PVE 4
```!
Q4: There is something hidden in somewhere but can you find where ?

Files: Same as PVE 1
```

丟前一題找到的 flag

`0xL4ugh{S4D_Y0U_G07_M3}`

### PVE 5
```
Q5: The attack got the password of the user but can you?

Files: Same as PVE 1
```

這題需要找使用者的密碼

跟前面依樣因為沒辦法用 volatility 的原因，所以必須使用 strings 大法

首先先找出可能的使用者名稱，首先使用 strings + grep 篩選出有關 `/home` 的資料，因為通常使用者帳號的家目錄會在裡面

```bash
strings PVE.vmem | grep "/home" | more
```
```
/home/mrx
/home/mrx
HOME=/home/mrx
/home/mrx
cwd="/home" cmd="su" terminal=tty1 res=success
/home/mrx
/home/mrx/.local/share/systemd/user
/home/mrx
/home/mrx
...
```

可以看到使用者名稱可能為 `mrx`，可以用來做進一步篩選

由於我們知道 linux 中使用者的密碼 hash 存放在 `/etc/shadow` 下，而格式如下

```
username:$hashid$salt$hash:18759:0:99999:7:::
```

所以我們可以利用此格式，篩選出有關於 `mrx:$` 的 pattern 來進一步取得 hash (注意在 linux 中的 `$` 符號有特殊意義，所以篩選時的 pattern 記得要加 `\` 做 excape )

```bash
strings PVE.vmem | grep 'mrx:\$'
```
```
mrx:$6$AkhWkiSy$MV4YekoydUoqhdnoJYWTHFpSWSsSTe53cTvuGNJLrE7FVMrKgDIEyyQio3ZPtnEX6524nSCenk2fYYV8mxwkL0:19404:0:99999:7:::
```

得到 hash 為 `$6$AkhWkiSy$MV4YekoydUoqhdnoJYWTHFpSWSsSTe53cTvuGNJLrE7FVMrKgDIEyyQio3ZPtnEX6524nSCenk2fYYV8mxwkL0`

接著丟到 john 搭配 rockyou.txt 慢慢爆密碼

![](https://i.imgur.com/2fWqDr4.png)

可以看到我花了約 37 分鐘才爆出來，得到密碼為 `08041632890804163289`

`0xL4ugh{08041632890804163289}`

### GetTheparts
```
what if we group the atmoics ? we get a cool shape
```
附件: `EzPz.zip`

附件解壓後得到 `EzPz.pcap`

在 wireshark 打開後，發現幾乎都是 TCP Retransission package，但發現 TCP Payload 有資料

![](https://i.imgur.com/6nms4lh.png =400x)

![](https://i.imgur.com/UBvS31n.png =400x)
![](https://i.imgur.com/33MEVdp.png =400x)
![](https://i.imgur.com/QY7AJOc.png =400x)
![](https://i.imgur.com/YeOjV6h.png =400x)

就我通靈這麼多場的經驗來看，`89 50 4e 47` 是 png 的固定開頭 (magin number)，因此每個封包應該就是 png 的每個 byte

於是我寫了一個程式來自動擷取成 png

:::spoiler solve.py
```python
import pyshark

caps = pyshark.FileCapture("EzPz.pcap")

data = b""
for cap in caps:
    payload = bytes.fromhex(cap.tcp.payload.raw_value)
    if(len(payload) > 4):
        continue
    payload_hex = payload.decode()[2:]
    data += bytes.fromhex(payload_hex.rjust(2,"0"))

with open("out.png", "wb") as fh:
    fh.write(data)
```
:::

得出以下圖片

![](https://i.imgur.com/orxMKWg.png =400x)

`0xL4ugh{By735_3verywh3r3_WE3333}`

## Steganography
### Uraa
```
I love Urahara. he keeps hiding the secrets.
```
附件: `Uraa.zip`

附件解壓後得到 `Uraa.jpg`

根據題目敘述，這張圖片似乎是被用什麼密碼來藏秘密，而從副檔名的 jpg 來猜測使用 steghide 工具

使用題目敘述中的 `Urahara` 來嘗試解密，但是沒有解出來

後來使用 stegseek 自動破密工具，成功找出密碼 `urahara1`，並且提取出 `flag.txt`

```
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: "urahara1"
[i] Original filename: "flag.txt".
[i] Extracting to "Uraa.jpg.out".
```

打開此文件即是密碼

`0xL4ugh{W4RM_UP_STE94N0_G0OD_J0B}`

### Weirdoooo
```
Too many numbers but i guess you know what you should do.
```
附件: `Weirdoooo.zip`

附件解壓後得到 `Weirdoooo.txt`

直接查看 `Weirdoooo.txt` 後，發現裡面有一堆的數字，看起來很可能是灰階圖的數值

![](https://i.imgur.com/H24TnfI.png =600x)

所以我寫了一個程式輔助來轉換成圖片

:::spoiler solve.py
```python
from PIL import Image
import numpy as np

with open("./Weirdoooo.txt") as fh:
    data = fh.readlines()

data = [d.strip().split(" ") for d in data]

for i,d in enumerate(data):
    for j,dd in enumerate(d):
        data[i][j] = int(dd)

im = Image.fromarray(np.array(data, np.uint8))
im.save("./out.png")
```
:::

圖片如下

![](https://i.imgur.com/jY9RKiT.png =500x)

`0xL4ugh{N07_JU$T_NUM63R5}`

### Colorful
```
This is really colorful but what does that mean ?

Flag Format: 0xL4ugh{word1_word2}
```
附件: `Colorful.zip`

附件解壓後得到 `Colorful.png`，如下

![](https://i.imgur.com/cw72xLs.png)

上網搜尋有關 `color cryptography` 之類的東西，找到一個叫做 hexahue code 的東西

https://www.boxentriq.com/code-breaking/hexahue

照著 decode 得到以下字串

```
0XL4UGH TH1S 15 H3X4HU3 C0D3
```

拼起來得到 flag

`0xL4ugh{TH1S_15_H3X4HU3_C0D3}`

### Bloody
```

```
附件: `Bloody.zip`

附件解壓後得到 `Bloody.png`，如下

![](https://i.imgur.com/74hI8Xv.png)

可以看到基本上是兩條紅色線，而其他地方是透明的

因此我們可以嘗試讀取有顏色的部分，而另外由於顏色範圍是 0 ~ 255，所以有可能每個紅色的紅色值就會是文字，所以我們順便讀取出來

以下是程式的部分

:::spoiler solve.py
```python
from PIL import Image
im = Image.open("./Bloody.png")

flag = b""
x,y = im.size
for i in range(y):
    for j in range(x):
        pixel = im.getpixel((j,i))
        if(pixel[3] != 0):
            flag += bytes([pixel[0]])
print(flag)
```
:::

輸出文字如下，基本上就是 flag 一直循環而已

```!
b'00xxLL44uugghh{{RR__GG__BB__FFOORR__TTHH33__WW11NN}}0xL4ugh{R_G_B_FOR_TH3_W1N}0xL4ugh{R_G_B_FOR_TH3_W1N}0xL4ugh{R_G_B_FOR_TH3_W1N}0xL4ugh{R_G_B_FOR_TH3_W1N}0xL4ugh{R_G_B_FOR_TH3_W1N}0xL4ugh{R_G_B_FOR_TH3_W1N}0xL4ugh{R_G_B_FOR_TH3_W1N}0xL4ugh{R_G_B_FOR_TH3_W1N}0xL4ugh{R_G_B_FOR_TH3_W1N}0xL4ugh{R_G_B_FOR_TH3_W1N}0xL4ugh{R_G_B_FOR_TH3_W1N}0xL4ugh{R_G_B_FOR_TH3_W1N}0xL4ugh{R_G_B_FOR_TH3_W1N}0xL4ugh{R_G_B_FOR_TH3_W1N}0xL4ugh{R_G_B_FOR_TH3_W1N}0xL4ugh{R_G_B_FOR_TH3_W1N}0xL4ugh{R_G_B_FOR_TH3_W1N}0xL4ugh{R_G_B_FOR_TH3_W1N}0xL4ugh{R_G_B_FOR_TH3_W1N}0xL4ugh{R_G_B_FOR_TH3_W1N}0xL4ugh{R_G_B_FOR_TH3_W1N}0xL4ugh{R_G_B_FOR_TH3_W1N}0xL4ugh{R_G_B_FOR_TH3_W1N}0xL4ugh{R_G_B_FOR_TH3_W1N}0xL4ugh{R_G_B_FOR_TH3_W1N}'
```

`0xL4ugh{R_G_B_FOR_TH3_W1N}`

## Web
### Bruh (Basic)
```
he is my brother , can he go instead of me ?

link
```
[link](http://20.121.121.120:8080/bruh)
附件: `index.php`

:::spoiler index.php
```php=
<?php

$servername = "127.0.0.1";
$username = "ctf";
$dbname = "login";
$password = "ctf123";

// Create connection
$conn = new mysqli($servername, $username, $password,$dbname);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

if(!empty($_GET['username']) && !empty($_GET['password']))
{
    $username=mysqli_real_escape_string($conn,$_GET['username']);
    $password=mysqli_real_escape_string($conn,$_GET['password']);
    if ($username=="admin" && $_SERVER['REMOTE_ADDR']!=="127.0.0.1")
    {
        die("Admins login are allowed locally only");
    }
    else
    {
        $res=$conn->query("select * from users where username='$username' and password='$password'"); # admin admin
        if($res->num_rows > 0)
        {
            $user=$res->fetch_assoc();
            echo ($user['username']==="admin")?"0xL4ugh{test_flag}":"sorry u r not admin";
        }
        else
        {
            echo "Error : Wrong Creds";
        }

    }
}
else
{
    echo "Please Fill All Fields";
}
?>
```
:::

可以看到，需要給 username 以及 password 的參數給網頁，假如名稱為 `admin` 且 `password` 亦同的話在第 30 行會拿到 flag

但是在第 20 行也可以看到，假如是從外站連線進去且使用 admin 的話就會被擋下來，無法進入 sql 查詢部分

不過這題我有發現兩個可能的漏洞，一個是在第 20 行的 `$username=="admin"` 使用的是 2 個等於而非 3 個等於，因此可能會有型態上面的漏洞

而另一個漏洞是在第 18, 19 行使用的是 `mysqli_real_escape_string` 來取代特殊的字元，但是其實沒辦法檔 mulitbyte 的字元，有可能用來做 sqli

但這題我自己是矇到的，我不確定是否是上面兩個其中的一個漏洞或是其他的，我送的 payload 為 `username=admin%20&password=admin`，也就是 `username` 設定為 `admin(空白)`，這樣子在第 20 行的地方不會被檢查到，但我不懂的是為什麼在後面取值時會取出 `admin` 出來，看看有沒有其他大神能找出原因

總之，得到的 flag 如下

`0xL4ugh{oH_mY_BruuoohH_pLAEStine_iN_our_Hearts}`

### Evil oR nOt
```
am i evil or not ? Link
```
[link](http://172.174.108.207:8080/evil/)

點進去後可以看到，這是一個 php eval 的工具，但是有一些黑名單限制，不能出現 `system`,`exec`,`eval`,`passthru`,`file`,`open`,`php`,`include`,`require`,`show`,`get_all_headers`,`curl` 這其中任一個，包含大小寫

![](https://i.imgur.com/a0jnbaf.png)

因為這題黑名單機制是當全部字符合時才會被匹配到，而我們可以利用字串串接的方式來規避這一點

另外在 php 中有一個奇怪的行為是，當使用字串作為函式名稱呼叫時等同於一般的函式呼叫，即 `"system"('ls') == system('ls')`，這一點我們等下也會用到

這邊我的 payload 如下
```
('sys'.'tem')('ls');
```

亦即先使用字串串接的方式將 `sys` 和 `tem` 拼起來成 `system` 來使用並規避黑名單，再利用前面提到的字串函式呼叫特性當成正常的 system 呼叫，即可達到 RCE

經過一般搜尋後，在 `/` 的目錄下找到 `flag_43243204320.txt` 檔案，接著直接 cat 出來即可

`0xL4ugh{Ev!l_!5_Alw@ys_Evill}`

### 403 Bypass ( Basic )
```!
Some one reported to our Bug Bounty Program that he found a secret page that discloses some senstive information and we forbidden any access to it link
```
[link](http://20.121.121.120/secret.php)

點進去後可以看到網頁只會寫一個 `You are forbidden!`，沒有其他資訊了

嘗試了一些方法如改 HTTP method, phps, robots.txt, cookie, GET param, HTTP version, ... 等，皆沒有辦法

在參考 [hacktricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/403-and-401-bypasses) 的時候，看到有使用 backwaymachine 的建議，試了一下發現的確有一個存檔點

![](https://i.imgur.com/0uOTkqv.png)

點進去後 flag 就出來了

https://web.archive.org/web/20230217010631/http://20.121.121.120/secret.php

`0xL4ugh{All_The_W@@y_Up_Fr33_Palestine}`

## Reverse
### Snake
```!
Sssslippery ssslimy flag

https://drive.google.com/file/d/1riE7acg2PVrcIkmoNI6F9Xb_tKj6qIhd/view?usp=sharing
```

點進去連結後可以看到是一個 python bytecode，內容如下

:::spoiler
```
  2           0 LOAD_CONST               1 (0)
              2 LOAD_CONST               0 (None)
              4 IMPORT_NAME              0 (base64)
              6 STORE_FAST               0 (base64)

  3           8 LOAD_CONST               1 (0)
             10 LOAD_CONST               2 (('Fernet',))
             12 IMPORT_NAME              1 (cryptography.fernet)
             14 IMPORT_FROM              2 (Fernet)
             16 STORE_FAST               1 (Fernet)
             18 POP_TOP

  4          20 LOAD_CONST               3 (b'gAAAAABj7Xd90ySo11DSFyX8t-9QIQvAPmU40mWQfpq856jFl1rpwvm1kyE1w23fyyAAd9riXt-JJA9v6BEcsq6LNroZTnjExjFur_tEp0OLJv0c_8BD3bg=')
             22 STORE_FAST               2 (encMessage)

  5          24 LOAD_FAST                0 (base64)
             26 LOAD_METHOD              3 (b64decode)
             28 LOAD_CONST               4 (b'7PXy9PSZmf/r5pXB79LW1cj/7JT6ltPEmfjk8sHljfr6x/LyyfjymNXR5Z0=')
             30 CALL_METHOD              1
             32 STORE_FAST               3 (key_bytes)

  6          34 BUILD_LIST               0
             36 STORE_FAST               4 (key)

  7          38 LOAD_FAST                3 (key_bytes)
             40 GET_ITER
        >>   42 FOR_ITER                 9 (to 62)
             44 STORE_FAST               5 (k_b)

  8          46 LOAD_FAST                4 (key)
             48 LOAD_METHOD              4 (append)
             50 LOAD_FAST                5 (k_b)
             52 LOAD_CONST               5 (160)
             54 BINARY_XOR
             56 CALL_METHOD              1
             58 POP_TOP
             60 JUMP_ABSOLUTE           21 (to 42)

 10     >>   62 LOAD_GLOBAL              5 (bytes)
             64 LOAD_FAST                4 (key)
             66 CALL_FUNCTION            1
             68 STORE_FAST               4 (key)

 11          70 LOAD_FAST                1 (Fernet)
             72 LOAD_FAST                4 (key)
             74 CALL_FUNCTION            1
             76 STORE_FAST               6 (fernet)

 12          78 LOAD_FAST                6 (fernet)
             80 LOAD_METHOD              6 (decrypt)
             82 LOAD_FAST                2 (encMessage)
             84 CALL_METHOD              1
             86 LOAD_METHOD              7 (decode)
             88 CALL_METHOD              0
             90 STORE_FAST               7 (decMessage)

 13          92 LOAD_GLOBAL              8 (print)
             94 LOAD_FAST                7 (decMessage)
             96 CALL_FUNCTION            1
             98 POP_TOP
            100 LOAD_CONST               0 (None)
            102 RETURN_VALUE
None

```
:::

反正就邊看邊寫 python 出來就可以ㄌ

:::spoiler solve.py
```python
import base64
from cryptography.fernet import Fernet

encMessage = b'gAAAAABj7Xd90ySo11DSFyX8t-9QIQvAPmU40mWQfpq856jFl1rpwvm1kyE1w23fyyAAd9riXt-JJA9v6BEcsq6LNroZTnjExjFur_tEp0OLJv0c_8BD3bg='
key_bytes = base64.b64decode(b'7PXy9PSZmf/r5pXB79LW1cj/7JT6ltPEmfjk8sHljfr6x/LyyfjymNXR5Z0=')

key = []
for k_b in key_bytes:
    key.append(k_b ^ 160)

key = bytes(key)
fernet = Fernet(key)
decMessage = fernet.decrypt(encMessage).decode()
print(decMessage)
```
:::

`FLAG{FLY_L1k3_0xR4V3N}`

### Easy-Peasy
```
This should be a walk in the PPark

https://drive.google.com/file/d/1xzSA6notubOIPDbEtR2BZvkMfVJTS9Ba/view?usp=sharing

format : 0xL4ugh{}
```

拿到一個 exe，丟進 ghidra，進入 entry，看到以下這坨大便

![](https://i.imgur.com/ae2jU9F.png =400x)

根據經驗，關鍵函式在下面這邊

![](https://i.imgur.com/8tAB3qW.png =400x)

以下是反編譯出來的東西

:::spoiler
```clike
  local_58 = 0x7414c464;
  local_54 = 0x50534b7;
  local_50 = 0xf53513f5;
  local_4c = 0xc6030334;
  local_48 = 0x534323f5;
  local_44 = 0x53437323;
  local_40 = 0xd763;
  local_3e = 0;
  lVar6 = 0;
  local_20 = 0;
  local_18 = 0xf;
  local_30._0_1_ = '\0';
  FUN_140001350((longlong **)&local_30,param_2,(longlong *)0x0);
  FUN_1400015d0((longlong *)cout_exref,"Enter The Flag: ");
  FUN_140001a50((longlong *)cin_exref,(void **)&local_30);
  if (local_20 == 0x1a) {
    do {
      puVar4 = (undefined *)&local_30;
      if (0xf < local_18) {
        puVar4 = (undefined *)CONCAT71(local_30._1_7_,(char)local_30);
      }
      puVar2 = (undefined *)&local_30;
      if (0xf < local_18) {
        puVar2 = (undefined *)CONCAT71(local_30._1_7_,(char)local_30);
      }
      if ((uint)*(byte *)((longlong)&local_58 + lVar6) !=
          (((int)(char)puVar2[lVar6] & 0xfU) << 4 | (int)(char)puVar4[lVar6] >> 4))
      goto LAB_140001268;
      lVar6 = lVar6 + 1;
    } while (lVar6 < 0x1a);
    plVar3 = FUN_1400015d0((longlong *)cout_exref,"The Flag is: ");
    pcVar5 = (char *)&local_30;
    if (0xf < local_18) {
      pcVar5 = (char *)CONCAT71(local_30._1_7_,(char)local_30);
    }
    FUN_140001c50(plVar3,pcVar5,local_20);
  }
  else {
LAB_140001268:
    plVar3 = FUN_1400015d0((longlong *)cout_exref,"This will not work");
    std::basic_ostream<char,struct_std::char_traits<char>_>::operator<<
              ((basic_ostream<char,struct_std::char_traits<char>_> *)plVar3,
               (FuncDef0 *)&LAB_1400017a0);
  }
```
:::

可以看到，首先會先印出 `Enter The Flag: `，接著會檢查輸入長度使否為 0x1a，是的話會進入裡面的 for loop 將每個字元做前 4 bit 後 4 bit 交換後檢查是否等同於 local_58 開始的那一串東東，是的話繼續不是的話跳走，假如都輸入正確的話就會印出 `The Flag is: ...`，否則前任一檢查失敗皆會印出 `This will not work`

搞懂邏輯後，以下是解密的程式

:::spoiler solve.py
```python

data = bytes.fromhex("7414c464")[::-1]
data += bytes.fromhex("050534b7")[::-1]
data += bytes.fromhex("f53513f5")[::-1]
data += bytes.fromhex("c6030334")[::-1]
data += bytes.fromhex("534323f5")[::-1]
data += bytes.fromhex("53437323")[::-1]
data += bytes.fromhex("d763")[::-1]

flag = b""
for d in data:
    flag += bytes([((d>>4) | (d<<4)) & 0xff])
print(flag)
```
:::

輸出 flag，確認後上傳成功

`0xL4ugh{CPP_1S_C00l_24527456}`

### Let's Go
```!
Focus on the essential, avoid getting lost in details.

https://drive.google.com/file/d/15PZhj2RN-tzV8r-AuPJ27am6t8WIxXbO/view?usp=sharing
```

根據題目名稱，推測是 golang 的 reverse 題

進入關鍵的 main.main 函式，反組譯結果如下

:::spoiler
```clike
  fmt.Fprint(1,1,&DAT_00494360,local_18);
  local_50 = (long *)runtime.newobject();
  *local_50 = 0;
  local_28 = CONCAT88(local_50,0x4929a0);
  fmt.Fscanln();
  lVar10 = *local_50;
  lVar2 = local_50[1];
  uVar6 = 0;
  uVar8 = 0;
  lVar9 = 0;
  local_58 = lVar10;
  for (lVar4 = 0; lVar4 < lVar2; lVar4 = lVar4 + 1) {
    bVar1 = *(byte *)(lVar10 + lVar4);
    uVar7 = uVar8;
    lVar5 = lVar9;
    if ((byte)(bVar1 + 0xbf) < 0x1a) {
                    /* A-Z */
      uVar11 = uVar6 + 1;
      if (uVar8 < uVar11) {
        uVar7 = uVar6;
        lVar5 = runtime.growslice(uVar8,uVar11);
        uVar11 = lVar9 + 1;
        lVar10 = local_58;
      }
      *(byte *)(lVar5 + uVar6) = bVar1 + (char)((bVar1 - 0x31 & 0xff) / 0x1a) * -0x1a + '\x10';
      uVar6 = uVar11;
    }
    else if ((byte)(bVar1 + 0x9f) < 0x1a) {
                    /* a-z */
      uVar11 = uVar6 + 1;
      if (uVar8 < uVar11) {
        uVar7 = uVar6;
        lVar5 = runtime.growslice(uVar8,uVar11);
        uVar11 = lVar9 + 1;
        lVar10 = local_58;
      }
      *(byte *)(lVar5 + uVar6) = bVar1 + (char)((bVar1 - 0x51 & 0xff) / 0x1a) * -0x1a + '\x10';
      uVar6 = uVar11;
    }
    else {
      uVar11 = uVar6 + 1;
      if (uVar8 < uVar11) {
        uVar7 = uVar6;
        lVar5 = runtime.growslice(uVar8,uVar11);
        uVar11 = lVar9 + 1;
        lVar10 = local_58;
      }
      *(byte *)(lVar5 + uVar6) = bVar1;
      uVar6 = uVar11;
    }
    uVar8 = uVar7;
    lVar9 = lVar5;
  }
  runtime.slicebytetostring();
  if ((lVar9 == 0x20) && (cVar3 = runtime.memequal(), cVar3 != '\0')) {
    auVar12 = runtime.convTstring();
    local_38 = CONCAT88(SUB168(auVar12,0),0x494360);
    fmt.Fprintf(0x13,local_38,SUB168(auVar12 >> 0x40,0),"Correct:)\nFLAG{%s}\n",1,1);
    return;
  }
  local_48 = CONCAT88(0x4c3f60,0x494360);
  fmt.Fprint(1,1,"Wrong:(\n",local_48);
  return;
}
```
:::

有部分內容可能在反組譯中有所缺漏，不過大致還可以看出邏輯，像是說會要求我們輸入文字，並會一個一個字元進行處理，最後檢查輸入長度是否為 0x20 bytes 且比較結果是否相同，相同則輸出 correct 和 flag

可以看到，前面的 if 部分檢查可分為 3 種，是 A-Z 的、是 a-z 的、其餘的，其餘的部分最簡單，就是輸入 == 輸出，而 A-Z 與 a-z 的邏輯類似，手動測試看看發現基本上就是 caesar cipher 而已

根據測試，這題的 cipher key 是 0x10，也就是 16，因此只要用一些工具解碼即可

```
enc = bytes.fromhex("75 35 30 37 72 76 37 38 71 72 35 74 36 71 39 39 39 34 31 34 32 32 75 75 72 73 76 39 34 34 36 34")
key = 16

plain = b"e507bf78ab5d6a99941422eebcf94464"
```

丟進去檢查通過，輸出 flag，手動將 flag format 搞定即可

`0xL4ugh{e507bf78ab5d6a99941422eebcf94464}`

## Crypto
### Crypto 1

:::spoiler message.txt
`ct = [0, 1, 1, 2, 5, 10, 20, 40, 79, 159, 317, 635, 1269, 2538, 5077, 10154, 20307, 40615, 81229, 162458, 324916, 649832, 1299665, 2599330, 5198659, 10397319, 20794638, 41589276, 83178552, 166357103, 332714207, 665428414, 1330856827, 2661713655, 5323427309, 10646854619, 21293709237, 42587418474, 85174836949, 170349673898, 340699347795, 681398695591, 1362797391181, 2725594782363, 5451189564725, 10902379129451, 21804758258901, 43609516517803, 87219033035605, 174438066071211, 348876132142421, 697752264284843, 1395504528569685, 2791009057139370, 5582018114278740, 11164036228557480, 22328072457114960, 44656144914229920, 89312289828459841, 178624579656919682, 357249159313839363, 714498318627678726, 1428996637255357453, 2857993274510714906, 5715986549021429811, 11431973098042859623, 22863946196085719246, 45727892392171438492, 91455784784342876983, 182911569568685753966, 365823139137371507933, 731646278274743015865, 1463292556549486031730, 2926585113098972063460, 5853170226197944126921, 11706340452395888253841, 23412680904791776507682, 46825361809583553015364, 93650723619167106030728, 187301447238334212061457, 374602894476668424122913, 749205788953336848245827, 1498411577906673696491653, 2996823155813347392983306, 5993646311626694785966613, 11987292623253389571933226, 23974585246506779143866452, 47949170493013558287732903, 95898340986027116575465806, 191796681972054233150931613, 383593363944108466301863225, 767186727888216932603726450, 1534373455776433865207452900, 3068746911552867730414905800, 6137493823105735460829811601, 12274987646211470921659623202, 24549975292422941843319246403, 49099950584845883686638492807, 98199901169691767373276985614, 196399802339383534746553971228, 392799604678767069493107942455, 785599209357534138986215884910, 1571198418715068277972431769821, 3142396837430136555944863539641, 6284793674860273111889727079282, 12569587349720546223779454158564, 25139174699441092447558908317129, 50278349398882184895117816634258, 100556698797764369790235633268515, 201113397595528739580471266537030, 402226795191057479160942533074061, 804453590382114958321885066148122, 1608907180764229916643770132296243, 3217814361528459833287540264592486, 6435628723056919666575080529184973, 12871257446113839333150161058369946, 25742514892227678666300322116739891, 51485029784455357332600644233479783, 102970059568910714665201288466959565, 205940119137821429330402576933919130, 411880238275642858660805153867838260, 823760476551285717321610307735676520, 1647520953102571434643220615471353041, 3295041906205142869286441230942706082, 6590083812410285738572882461885412163, 13180167624820571477145764923770824327, 26360335249641142954291529847541648653, 52720670499282285908583059695083297307, 105441340998564571817166119390166594613, 210882681997129143634332238780333189226, 421765363994258287268664477560666378453, 843530727988516574537328955121332756906, 1687061455977033149074657910242665513811, 3374122911954066298149315820485331027622, 6748245823908132596298631640970662055244, 13496491647816265192597263281941324110489, 26992983295632530385194526563882648220977, 53985966591265060770389053127765296441955, 107971933182530121540778106255530592883909, 215943866365060243081556212511061185767818, 431887732730120486163112425022122371535637, 863775465460240972326224850044244743071274, 1727550930920481944652449700088489486142548, 3455101861840963889304899400176978972285095, 6910203723681927778609798800353957944570190, 13820407447363855557219597600707915889140381, 27640814894727711114439195201415831778280761, 55281629789455422228878390402831663556561522, 110563259578910844457756780805663327113123044, 221126519157821688915513561611326654226246089, 442253038315643377831027123222653308452492178, 884506076631286755662054246445306616904984356, 1769012153262573511324108492890613233809968711, 3538024306525147022648216985781226467619937423, 7076048613050294045296433971562452935239874845, 14152097226100588090592867943124905870479749691, 28304194452201176181185735886249811740959499382, 56608388904402352362371471772499623481918998764, 113216777808804704724742943544999246963837997528, 226433555617609409449485887089998493927675995056, 452867111235218818898971774179996987855351990111, 905734222470437637797943548359993975710703980222, 1811468444940875275595887096719987951421407960445, 3622936889881750551191774193439975902842815920890, 7245873779763501102383548386879951805685631841779, 14491747559527002204767096773759903611371263683559, 28983495119054004409534193547519807222742527367117, 57966990238108008819068387095039614445485054734235, 115933980476216017638136774190079228890970109468469, 231867960952432035276273548380158457781940218936938, 463735921904864070552547096760316915563880437873877, 927471843809728141105094193520633831127760875747754, 1854943687619456282210188387041267662255521751495507, 3709887375238912564420376774082535324511043502991014, 7419774750477825128840753548165070649022087005982029, 14839549500955650257681507096330141298044174011964058, 29679099001911300515363014192660282596088348023928115, 59358198003822601030726028385320565192176696047856231, 118716396007645202061452056770641130384353392095712461, 237432792015290404122904113541282260768706784191424923, 474865584030580808245808227082564521537413568382849845, 949731168061161616491616454165129043074827136765699690, 1899462336122323232983232908330258086149654273531399380, 3798924672244646465966465816660516172299308547062798761, 7597849344489292931932931633321032344598617094125597521, 15195698688978585863865863266642064689197234188251195043, 30391397377957171727731726533284129378394468376502390085, 60782794755914343455463453066568258756788936753004780171, 121565589511828686910926906133136517513577873506009560341, 243131179023657373821853812266273035027155747012019120683, 486262358047314747643707624532546070054311494024038241365, 972524716094629495287415249065092140108622988048076482731, 1945049432189258990574830498130184280217245976096152965461, 3890098864378517981149660996260368560434491952192305930922, 7780197728757035962299321992520737120868983904384611861845, 15560395457514071924598643985041474241737967808769223723690, 31120790915028143849197287970082948483475935617538447447379, 62241581830056287698394575940165896966951871235076894894758, 124483163660112575396789151880331793933903742470153789789517, 248966327320225150793578303760663587867807484940307579579034, 497932654640450301587156607521327175735614969880615159158067, 995865309280900603174313215042654351471229939761230318316135, 1991730618561801206348626430085308702942459879522460636632269, 3983461237123602412697252860170617405884919759044921273264538, 7966922474247204825394505720341234811769839518089842546529077, 15933844948494409650789011440682469623539679036179685093058154, 31867689896988819301578022881364939247079358072359370186116308, 63735379793977638603156045762729878494158716144718740372232615, 127470759587955277206312091525459756988317432289437480744465230, 254941519175910554412624183050919513976634864578874961488930461, 509883038351821108825248366101839027953269729157749922977860921, 1019766076703642217650496732203678055906539458315499845955721842, 2039532153407284435300993464407356111813078916630999691911443684, 4079064306814568870601986928814712223626157833261999383822887368, 8158128613629137741203973857629424447252315666523998767645774737, 16316257227258275482407947715258848894504631333047997535291549474, 32632514454516550964815895430517697789009262666095995070583098947, 65265028909033101929631790861035395578018525332191990141166197894, 130530057818066203859263581722070791156037050664383980282332395789, 261060115636132407718527163444141582312074101328767960564664791578, 522120231272264815437054326888283164624148202657535921129329583155, 1044240462544529630874108653776566329248296405315071842258659166310, 2088480925089059261748217307553132658496592810630143684517318332621, 4176961850178118523496434615106265316993185621260287369034636665242, 8353923700356237046992869230212530633986371242520574738069273330483, 16707847400712474093985738460425061267972742485041149476138546660967, 33415694801424948187971476920850122535945484970082298952277093321934, 66831389602849896375942953841700245071890969940164597904554186643868, 133662779205699792751885907683400490143781939880329195809108373287736, 267325558411399585503771815366800980287563879760658391618216746575472, 534651116822799171007543630733601960575127759521316783236433493150943, 1069302233645598342015087261467203921150255519042633566472866986301887]`
:::

超爛通靈
全部 long_to_bytes 之後拿最後那段
```
b'\x13\xd4\xd0\xde\xd4\xd5T\x0c\xdc\x88S\x90\xdc\x8c\xcd\rLS\x91\xd7\xcdL\xd4UL\xd3\x90\xcd'
b"'\xa9\xa1\xbd\xa9\xaa\xa8\x19\xb9\x10\xa7!\xb9\x19\x9a\x1a\x98\xa7#\xaf\x9a\x99\xa8\xaa\x99\xa7!\x9a"
b'OSC{SUP3r!NCr3451NG_53QU3NC3'
b'\x9e\xa6\x86\xf6\xa6\xaa\xa0f\xe4B\x9c\x86\xe4fhjb\x9c\x8e\xbejf\xa2\xaaf\x9c\x86g'
```

直接補上 `}` 就好

> flag : `OSC{SUP3r!NCr3451NG_53QU3NC3}`


### Crypto 2
:::spoiler code.py
```python!
from Crypto.Util.number import bytes_to_long, getPrime
from secret import messages


def RSA_encrypt(message):
    m = bytes_to_long(message)
    p = getPrime(1024)
    q = getPrime(1024)
    N = p * q
    e = 3
    c = pow(m, e, N)
    return N, e, c


for m in messages:
    N, e, c = RSA_encrypt(m)
    print(f"n = {N}")
    print(f"e = {e}")
    print(f"c = {c}")
```

給你一堆 n , e = 3 , c 
e 給很小又給很多組 就是 BroadCast Attack 直接用 CRT 推回去就好
經典題型

:::spoiler sol.py
```python!
#!/usr/bin/python3

from output import *
from gmpy2 import invert , iroot
from functools import reduce
from itertools import combinations
from Crypto.Util.number import long_to_bytes

def CRT(r, mod):
    M = reduce(lambda x , y : x * y , mod)

    ans = 0
    
    for i in range(len(r)):
        m = M // mod[i]
        ans += r[i] * m * invert(m , mod[i])
    
    return ans % M

n = [n1 , n2 , n3 , n4 , n5 , n6 , n7 , n8 , n9]
c = [c1 , c2 , c3 , c4 , c5 , c6 , c7 , c8 , c9]

for i in range(1 , 10):
    for j in combinations(range(9) , 3):
        r = [c[k] for k in j]
        mod = [n[k] for k in j]
        m = CRT(r , mod)
        if iroot(m , 3)[1]:
            print(long_to_bytes(iroot(m , 3)[0]))
            exit(1)
```
:::

> flag : `OSC{C0N6r47U14710N5!_Y0U_UND3r574ND_H0W_70_U53_H4574D5_8r04DC457_4774CK_______0xL4ugh}`
