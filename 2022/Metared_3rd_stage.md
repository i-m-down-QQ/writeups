# Metared 3rd stage
###### tags: `CTF`

## Web
### quemada broadcast
![](https://i.imgur.com/EoN5kuG.png)

原本想嘗試偷雞直接進 container 看 flag，但沒辦法 QQ

建好環境並進入 localhost:5000 後，發現網址會自動跳轉到 `/seq/XXXXX....XXXX` 的路徑 (後面 `X` 的部分似乎是隨機的)，並在畫面中顯示了 `~` 符號

![](https://i.imgur.com/JPIH6jS.png)
![](https://i.imgur.com/nL5DM3D.png)


而後多重新整理幾次後，發現會出現 0 或是 1

![](https://i.imgur.com/DCCQrES.png)
![](https://i.imgur.com/MqKG5el.png)


根據題目敘述，推測每一次存取都是單一個 bit，而要以每 7 個為單位成為一個 ascii 單字，所以建造一個腳本來解密

```python=
import requests

url = "http://127.0.0.1:5000/"
res = requests.get(url)

flag_raw = ""

broadcast_url = res.url
while(True):
	res = requests.get(broadcast_url)
	text = res.text
	if (text not in ['0', '1']):
		print(text)
		break
	flag_raw += text

flag = ""
begin = 0
while(begin < len(flag_raw)):
	flag += chr(int(flag_raw[begin:begin+7], 2))
	begin += 7

print(flag)
```

解密結果如下

```
ZmxhZ01YezdCaXRTdGFuZGFyZEhlbHBVc1BsZWFzZX0=
```

看起來像是 base64，丟到解碼器去解即可獲得 flag

flagMX{7BitStandardHelpUsPlease}

## Misc
### La enchilada
![](https://i.imgur.com/JDtiXwL.png)

根據題目敘述，跟明文傳輸有關

在 pcap 中的 statistics -> protocol hierarchy 看到有 telnet 連線，且由於 telnet 是明文傳輸可以直接看到內容，符合本題題旨

![](https://i.imgur.com/RSTOBaU.png)

在封包 4528 ~ 4577，使用者進行登入，輸入帳號為 `enchilada` 以及密碼為 `ench1lada`

而在封包 4581，成功登入

![](https://i.imgur.com/Nr3OhxX.png)

在封包 4614 ~ 4645，使用者下了 `more flag.txt` 的指令

而在封包 4653 印出了 flag.txt  的內容，如下

```
ZmxhZ01Ye0VuY2gxbGFkYVIwamF5VmVyZDN9Cg==
```

看起來像是 base64，丟到解碼器即可獲得 flag

flagMX{Ench1ladaR0jayVerd3}

### Aluxe
![](https://i.imgur.com/lXtcRd0.png)

下載的檔案為 RFC 822 Mail，直接用純文字打開

![](https://i.imgur.com/GeYj6uz.png)

打開後發現有奇怪的 header `x-header-aluxe`，裡面是一大串亂碼，往後一直翻才發現似乎是 base64 的資料

![](https://i.imgur.com/kS170NJ.png)
![](https://i.imgur.com/HgmsKzq.png)

複製出來並用 base64 解碼後，發現是 `data:image/png;base64` 的影像，後面一樣是 base64 字串

一樣將字串複製後解碼，得出一張 png 圖片，flag 在裡面

![](https://i.imgur.com/ADkEzwG.png)

flagMX{A1ux3Tr4v13s0}

### delicious mexicon food
![](https://i.imgur.com/F7iQClK.png)

乍看之下似乎是一些冷門的古典密碼學東東，不過用 dcode.fr 解不出什麼東西

仔細一看，發現 ingredients 的數字似乎可以轉成 ascii，而 method 的部分則是跟順序有關，因此推測需要照著 method 的順序來放 ingredients 的數字

至於 method 最後 2 行我原本以為沒有作用，但根據底下腳本實際執行測試後才發現倒數第二行的功能似乎是要做 reversed order

寫了一個腳本來解碼
```python=
ingredients_text = "81 ml beer 103 cups oil 77 g salt 83 g sugar 88 ml water 123 g chili 99 g cream 82 totopos 101 g guacamole 108 tomatoes 105 g fish 78 g cilantro 102 g chicken 72 ml milk 117 g cinnamon 97 g lard 125 g pepper 95 g honey"
method = "Put pepper into the mixing bowl. Put sugar into the mixing bowl. Put guacamole into the mixing bowl. Put tomatoes into the mixing bowl. Put fish into the mixing bowl. Put cinnamon into the mixing bowl. Put beer into the mixing bowl. Put lard into the mixing bowl. Put tomatoes into the mixing bowl. Put fish into the mixing bowl. Put milk into the mixing bowl. Put cream into the mixing bowl. Put honey into the mixing bowl. Put cilantro into the mixing bowl. Put guacamole into the mixing bowl. Put guacamole into the mixing bowl. Put totopos into the mixing bowl. Put oil into the mixing bowl. Put chili into the mixing bowl. Put water into the mixing bowl. Put salt into the mixing bowl. Put oil into the mixing bowl. Put lard into the mixing bowl. Put tomatoes into the mixing bowl. Put chicken into the mixing bowl"

ingredients_raw = ingredients_text.split()

ingredients = dict()
i = 0
while(i < len(ingredients_raw)):
	try:
		int(ingredients_raw[i+2])
	except ValueError:
		ingredient = ingredients_raw[i+2]
		quentity = int(ingredients_raw[i+0])
		i += 3
	else:
		ingredient = ingredients_raw[i+1]
		quentity = int(ingredients_raw[i+0])
		i += 2
	ingredients[ingredient] = quentity

print(ingredients)

flag = ""
method_lines = method.split('. ')
for line in method_lines:
	words = line.split()
	flag += chr(ingredients[words[1]])

flag = flag[::-1]
print(flag)
```

flagMX{gReeN_cHilaQuileS}

## forensics
### bufa secret
![](https://i.imgur.com/mHWW85x.png)

用 xxd 打開看後，發現似乎是 png 檔案，只是檔案第一行壞掉了

![](https://i.imgur.com/xzRHchr.png)

正常的 png 開頭如下
```
89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52
```

用 hxd 修改成正確的之後，得到圖片，flag 在裡面

![](https://i.imgur.com/GpHSMH3.png)

flagMX{you_found_my_secret_vault}

### Important file
![](https://i.imgur.com/wPeaI2Y.png)

下載後是一個 word 檔案

眾所皆知，word 是一個 zip 壓縮檔，因此使用 unzip 解壓

使用指令 `grep -r "flag" .`，發現 image11.jpg 裡面有 flag 的字串

![](https://i.imgur.com/xF2DWVF.png)

使用 strings 結合 grep，拿到 flag

![](https://i.imgur.com/uhY1Yik.png)

flagMX{M3x1c4n_h41rl355_d0g}

### Forensic analysis
![](https://i.imgur.com/qP4W9Sm.png)

檔案是一個映像檔，使用 tsk toolkit 查看並萃取檔案

老樣子，[工商一下之前寫的文章](https://medium.com/@frank1314168/%E7%A1%AC%E7%A2%9F%E9%91%91%E8%AD%98%E5%B7%A5%E5%85%B7-tsk-toolkit-%E7%B0%A1%E6%98%93%E6%95%99%E5%AD%B8-%E4%BB%A5-picoctf-2022-%E9%A1%8C%E7%9B%AE-sleuthkit-apprentice-%E7%82%BA%E4%BE%8B-2fc98e195fc7)

取出後發現有 word 檔案，直接用 unzip 拆包

在 `word/documnets.xml` 裡發現了神秘的字串，看起來像是 flag 但經過加密

![](https://i.imgur.com/fOc47Nr.png)

看起來很像是 caesar cipher 在 n=7 的情況，解出來就是 flag

![](https://i.imgur.com/iII2Xhz.png)

flagMX{M1m3r0m0l3}

## Obfuscation
### But where?
![](https://i.imgur.com/VGe02G4.png)

拿到 binary 一樣直接丟到 ghidra

在 entry 中，會執行到 `_CorExeMain`，但裡面函式指令解碼出來怪怪的

![](https://i.imgur.com/fqe16CD.png)
![](https://i.imgur.com/wdO2sVb.png)

搜尋後，發現這是 .Net 的函式，改用 dotPeak 反編譯

![](https://i.imgur.com/bDtfXCn.png)

在裡面的 `a` 函式發現，會進行一些輸入輸出之類的，然後最後當輸入值總和 > 100 就會輸出一個特別的結果

![](https://i.imgur.com/rvseenc.png)

執行起來，隨便輸入以確保總和大於 100 後，得出以下結果

![](https://i.imgur.com/Q72zG1f.png)

得到 flag，但直接上傳會錯誤，嘗試把 `'` 和 `"` 之類的修成一般的 ascii 符號即可上傳成功

flagMX{52°30'42"N 13°22'55"E}

### Quite Random
![](https://i.imgur.com/CCBIjS8.png)

下載後，是一張沒辦法掃的 qrcode

![](https://i.imgur.com/yjUeeVm.jpg)

使用 strings，發現有密碼的字串

![](https://i.imgur.com/pEI8D6U.png)

但使用 steghide 沒發現東西 :(

使用 binwalk，找到裡面有藏 rar

![](https://i.imgur.com/VxKBrWn.png)

extract 後，使用前面找到的密碼解密，發現是一張順序圖

![](https://i.imgur.com/X5qSgde.png)

推測是要將 qrcode 切 9 塊照順序排，拼出來如下

![](https://i.imgur.com/ONGiipH.png)

掃描之後就是 flag

flagMX{ug0t1t}

## Network
### Linked to the Taco
![](https://i.imgur.com/BmR1ZY5.png)

![](https://i.imgur.com/IlU3TdE.png)

附件下載下來是一篇 email，裡面有附加檔案 urgent.zip，使用 base64 做 encode

解碼過後 unzip，發現有密碼，使用 MuMu 破出來的 123 進行解密，解密後是一個 vhd

此處用 strings 還能發現 flag 的前面部分

![](https://i.imgur.com/wc574Dm.png)

```
flagMX{Trompowithpineapple_
```

使用 tsk toolkit 來看，[工商一下之前寫的文章](https://medium.com/@frank1314168/%E7%A1%AC%E7%A2%9F%E9%91%91%E8%AD%98%E5%B7%A5%E5%85%B7-tsk-toolkit-%E7%B0%A1%E6%98%93%E6%95%99%E5%AD%B8-%E4%BB%A5-picoctf-2022-%E9%A1%8C%E7%9B%AE-sleuthkit-apprentice-%E7%82%BA%E4%BE%8B-2fc98e195fc7)，取出檔案

![](https://i.imgur.com/DqMdjhF.png)

在 lnvoice2.PDF.lnk 的 strings 中發現了 powershell 的命令，其中有像是 base64 的東西，解密又解密後發現是一個 PE

![](https://i.imgur.com/KPuy9f6.png)

使用 ghidra 逆向，在 main 發現裡面一直做 nslookup

![](https://i.imgur.com/MQjoi6O.png)

subdomain 的字串看起來蠻像 base64 ㄉ，丟到解碼器解出 flag 的後段部分

![](https://i.imgur.com/Xfl6gRD.png)

```
The_Mole_Is_A_Delicious_Dish_In_Mexico_Its_Taste_Is_Amazing}
```

前段加後段就是 flag

flagMX{Trompowithpineapple_The_Mole_Is_A_Delicious_Dish_In_Mexico_Its_Taste_Is_Amazing}

## Crypto
### María’s Art Class
`echo "Vm0weGQxTnRVWGxXYTFwUFZsZG9WRmxVU2xOalJsSlZVMnhPVlUxV2NEQlVWbEpUWVdzeFYxTnNhRmRpVkZaUVZrUktTMUl5VGtsaVJtUk9ZbTFvZVZadE1YcGxSbGw0Vkc1V2FsSnNXazlXYlRWRFYxWmFkR1JIUmxSTlZYQjVWR3hhYjFSc1duTmpSVGxhWWxoU1RGWnNXbUZXVmtaMFVteHdWMkpJUWpaV1ZFa3hWREZhV0ZOclpHcFNWR3hZV1ZSS1VrMUdWWGRYYlVacVZtdHdlbGRyV210VWJGcDFVV3R3VjJGcmJ6QlZla1pYVmpGa2NsWnNTbGRTTTAwMQ=="|base64 -d|base64 -d|base64 -d|base64 -d |base64 -d |base64 -d|base64 -d|base64 -d`
直接 strings 就有了

### Pablito Visits Hubikú

![](https://i.imgur.com/u1MlmFC.png)
超爛 直接找表對表即可

![](https://i.imgur.com/yozGMqw.png)
![](https://i.imgur.com/LcB3W9u.png)

flag : `flagMX{M4YAN5_R0KK5}`

### eden mine
`aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbb....`

其實從重複的長度大概可以猜到她的長度轉成 char 就是 flag

```python
In [1]: f = open("./edenmine.txt" , "r").read()

In [2]: from collections import Counter

In [3]: "".join(list(map(chr , list(Counter(f).values()))))
Out[3]: 'flagMX{I_10v3_fr3qu3ncies_XD}'
```

## Reverse
### caxcan club
![](https://i.imgur.com/E9iHZzq.png)

:::spoiler caxcan-club.py
```python=
def roll(text):
    return text[::-1]

def swoop(text):
    text = list(text)
    for i in range(len(text)):
        if text[i] not in '{}':
            text[i] = chr(ord(text[i]) + (i % 6))
    return ''.join(text)

password = input("Enter the password: ")
if swoop(roll(password)) == "}zudidsbybwxaqaqehxbebimt`jks{XNidpk":
	print("Welcome in!")
else:
    print("Sorry, wrong password.")
```
:::

逆著解回來，沒難度

solve.py
```python=
password = "}zudidsbybwxaqaqehxbebimt`jks{XNidpk"

def unswoop(text):
    text = list(text)
    for i in range(len(text)):
        if text[i] not in '{}':
            text[i] = chr(ord(text[i]) - (i % 6))
    return ''.join(text)

def roll(text):
    return text[::-1]

print(roll(unswoop(password)))
```

flagMX{ohh_the_caxcan_pass_was_easy}

### legends
![](https://i.imgur.com/LAc1zta.png)

main 函式如下
![](https://i.imgur.com/6KgbDCo.png)

基本上就是讀 name 然後送進 verify 函式做驗證

而 verify 函式如下
![](https://i.imgur.com/Dcqt388.png)

... 就醬，沒麼好說的

flagMX{la_llorona_legend_XD}

### The password
![](https://i.imgur.com/Y9cUtMj.png)

使用 ghidra 打開後，發現是 .Net 編譯的，改用 dotPeak 做逆向

![](https://i.imgur.com/Q0fTgNi.png)

打開後，發現裡面的字串很噁心，要透過 b 的函式來解碼

![](https://i.imgur.com/81v9GeJ.png)

b 函式如下

![](https://i.imgur.com/iq6HobY.png)

看起來一樣超噁心的，所以我用 python 改寫了一遍

solve.py
```python=
def b(string: bytes, num: int):
    charArray = list(string)
    num1 = 1289535241 + num + 40 + 70 + 19
    for num2 in range(0, len(charArray), 1):
        num3 = ord(charArray[num2])
        num7 = ((num3 & 0xFF) ^ (num1 + 1)) & 0xff
        num10 = ((num3 >> 8) ^ (num1 + 1)) & 0xff
        num1 += 2
        charArray[num2] = chr((num7 << 8 | num10) & 0xff)
    return "".join(charArray)
```

然後把裡面的噁心字串做解碼之後，發現其中有 flag

![](https://i.imgur.com/QGUPjU2.png)

flagMX{The right way}