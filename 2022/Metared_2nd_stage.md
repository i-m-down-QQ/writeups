# MetaRed 2nd stage
###### tags: `CTF`

## Web
### Country flags
![](https://i.imgur.com/BAgrrxC.png)

在提供的 app.py 節錄如下:
```python=
def create_token(user='guest'):
    return jwt.encode({'user': user}, app.config['SECRET_KEY'], "HS256")


def decode_token(token_):
    return jwt.decode(token_, app.config['SECRET_KEY'], algorithms=["HS256"])


@app.route('/flag', methods=['GET'])
def flag():
    token_ = request.args.get('token')
    if not token_:
        return jsonify({'message': 'You need to provide a token'})

    data = decode_token(token_)
    user = data.get('user')
    if user == 'admin':
        return jsonify({'message': FLAG})

    return jsonify({'message': f'https://countryflagsapi.com/png/{random.choice(flags_iso_2)}'})


@app.route('/token', methods=['GET'])
def token():
    return jsonify({'token': create_token()})


if __name__ == '__main__':
    app.secret_key = str(os.urandom)
    app.run(host=APP_HOST, port=APP_PORT, debug=False)
```

可以看到主要有兩個進入點 `/token` 及 `/flag`，而會輸出 flag 的部分在 `/flag` 中，需要提供 jwt 並在解碼後 user 為 admin 的身分

對於一般 jwt 漏洞如弱密碼、切換加密法等方式似乎無法在這題起作用

其中程式有一個問題，app.secret_key 為 `str(os.urandom)`，此並非正常的使用，實際上的 secret_key 會是 `'<built-in function urandom>'`，並且程式中對於 jwt 會是以這組作為 secret 簽章，因此已知 secret，可任意簽章

使用 `<built-in function urandom>` 作為 secret，user 改為 admin，並傳入 `/flag` 中即可獲得 flag

![](https://i.imgur.com/xkZoRl3.png)

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.yCrm4expxw9Yq1yp99FiFZyMk-5WFGPafT4ARUk3Ns0
```

CTFUA{1866d85a9e54f8850f18e57664da5b62}

## reverse
### 1x02..ware
![](https://i.imgur.com/vbrOZW0.png)

python 檔案最好逆向ㄌ

打開後看到有奇怪的 dict，以及一個神祕的 eval

![](https://i.imgur.com/8EN4yPq.png)

稍微看一下會執行什麼，以策安全

在執行前加入以下程式，並強制讓其中斷

```python=
print(base64.b64decode(b''.join(codes_dict.values())))
assert(1==2)
```

![](https://i.imgur.com/rmU4LL5.png)

發現似乎又包了一層的 base64 及 eval，繼續還原 base64 內容

![](https://i.imgur.com/H72ac7a.png)

發現似乎會是一個加密勒索程式，而其中有一個奇怪的 decrypt，似乎也是 base64 字串

![](https://i.imgur.com/SlmyE8K.png)

再次破解，拿到 flag

![](https://i.imgur.com/FV1g1Jz.png)

CTFUA{r4ns0mw4re_f41led}

### Sneaky
![](https://i.imgur.com/XfAVP0u.png)

打開後，發現確實是一個空白檔案

使用 strings 查看，發現檔案中有一個奇怪的 p 標籤

![](https://i.imgur.com/GBc7R3B.png)

將其內容用 base64 解密，發現是 flag

```
FLAG: CTFUA{reading_is_fun}
```

CTFUA{reading_is_fun}

### Grades
![](https://i.imgur.com/zdYrVS0.png)

打開 xlsx 後，看到的是一堆鬼數字，不過發現有巨集執行

巨集內容如下:
```vb=
Public Sub Magic()
    If i = Empty Then
        i = 1
        a = 875126856
        b = 741258756
        x = 534542575
    End If
    
    For j = 1 To 42
        Cells(1, j).Value = Cells(1, j).Value Xor x
    Next j
    
    i = i + 1
    x = (a * x * b) Mod (2 ^ 32)
    
    alertTime = Now + 1 / (24 * 60 * 60# * 2)
    Application.OnTime alertTime, "Magic"
End Sub
```

看起來內容有和 x 做 xor 加密

解密程式:
```python=
with open("1.csv") as fh:
	data = fh.readlines()

data = [d.strip() for d in data]
data = [d.split(',') for d in data]

a = 875126856
b = 741258756
x = 534542575

new_data = []

for d in data:
	temp = []
	for dd in d:
		temp.append(int(dd) ^ x)
	#x = (a*x*b) % (2**32)
	new_data.append(temp)

for d in new_data:
	print(bytes(d))
```

原本預期換到下一行 x 就會變成 a\*x\*b，但是看起來好像沒有，不確定是不是因為溢位的關係，因此註解掉那一行

![](https://i.imgur.com/8wxbjN5.png)

解密結果中，只有第三行是正確的 flag

CTFUA{d0_y0u_kN0w_tH1s_c0uLd_b3_m4lic10uS}

## Misc
### Fscript
![](https://i.imgur.com/lsvYeEM.png)

打開檔案後，看到一堆 `!`, `[]` 等東西，看起來有點像 jsfuck

使用工具 https://enkhee-osiris.github.io/Decoder-JSFuck/ 解碼，獲得翻譯為
`if (true===1){   console.log('CTFUA{WH4T_TH3_b' + 'a' + + 'a' + 'a_W42_TH4T}') }`

直接在瀏覽器執行中間 console.log 部分後，得到 flag

CTFUA{WH4T_TH3_baNaNa_W42_TH4T}

### Tlpyosgol
![](https://i.imgur.com/bdUclPS.png)

打開來後，發現 doc 檔案似乎有損壞的提示，雖然要硬打開也是可以，但由於 word 檔案基本上是和 zip 差不多，嘗試直接解壓找找看是否有其他東西

![](https://i.imgur.com/ZQOjUxG.png)

除了有一張圖片之外，並沒有太特別的發現

直接硬解開後，發現並沒有這張圖片，可見這張圖應該是一個關鍵

使用 binwalk 查看，發現有隱藏的 ELF 檔案

```
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             JPEG image data, JFIF standard 1.01
3500          0xDAC           ELF, 64-bit LSB shared object, AMD x86-64, version 1 (SYSV)
3763          0xEB3           mcrypt 2.2 encrypted data, algorithm: blowfish-448, mode: CBC, keymode: 8bit
3771          0xEBB           mcrypt 2.2 encrypted data, algorithm: blowfish-448, mode: CBC, keymode: 8bit
```

使用 `binwalk image.jpg --dd=".*"` 萃取所有檔案

打開並分析無危險性後，直接執行，得到 flag

CTFUA{FilesInsideFilesInsideFiles}

### Books
![](https://i.imgur.com/bryggGL.png)

根據題目說明，檔案內為 ISBN，而需要將符合格式的挑出來並相加

參考資料: [ISBN checksum](https://zh.wikipedia.org/wiki/%E5%9B%BD%E9%99%85%E6%A0%87%E5%87%86%E4%B9%A6%E5%8F%B7#10_%E4%BD%8D)

程式:
```python=
def checkISBN(b):
	book = b.replace("-", "")
	assert (len(book) == 10)
	s = 0
	for i in range(9):
		s += (10-i) * int(book[i])
	checksum = ((s // 11 + 1) * 11 - s) % 11
	return checksum == int(book[-1])

with open("numbers.txt") as fh:
	data = fh.readlines()

s = 0
for d in data:
	d = d.strip()
	if(checkISBN(d)):
		d = d.replace("-", "")
		s += int(d)

print("CTFUA{"+f"{s}"+"}")
```

CTFUA{391239994710}

### (?) Infiltrated student

上網搜尋後發現[這篇文章](https://www.vbforums.com/showthread.php?157720-Decode-the-SPAM)，似乎是其他種加密方式

https://www.spammimic.com/decode.shtml

解密後獲得字串
```
My name is Alina Petrov, please see my video to find the key (min 3:19)�
```

目前找不到影片

## forensics
### Catastrophy
![](https://i.imgur.com/OdXlGcd.png)

使用 binwalk，發現藏有其他檔案

```
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             JPEG image data, JFIF standard 1.01
11647         0x2D7F          JPEG image data, JFIF standard 1.01
21648         0x5490          JPEG image data, JFIF standard 1.01
```

執行指令 `binwalk meowmeowmeow.jpg  --dd=".*"`，全部萃取出來

編號為 5490 的檔案即是 flag

![](https://i.imgur.com/Uvt9xDv.jpg)

CTFUA{Cr0ucHinG_h3adEr_H1dd3n_fILe}

### Got it
![](https://i.imgur.com/k2g3j7L.png)

下載後，發現 zip 有密碼，使用　zip2john + rockyou.txt 破解出密碼為 `qwerty`

從提示可知道，這題跟 git 有關，查看是否有特殊的 branch

使用 `git log --all --graph` 用圖像方式查看，發現有另一個 master branch，並且 commit 為 `clean evidences`

![](https://i.imgur.com/nXxw4yK.png)

因此可推測，evidence 在上一個 commit 中，使用 checkout 移動到 `now it is easy`，發現裡面有一個 flag.txt，裡面是 flag

CTFUA{g1t_h00ks_4r3_fun}

## steg
### Lit 101
![](https://i.imgur.com/QW0EXpx.png)

打開後 pdf 後，發現有一些文字有加粗

![](https://i.imgur.com/lShWwUI.png)

推測加粗的部分是 flag

嘗試用眼睛看，但一直失敗

上網搜尋後，發現有一個[神奇的方法](https://stackoverflow.com/questions/70932129/how-to-extract-bold-text-from-pdf-using-python)可以找出 pdf 中加粗的文字

```python=
import pdfplumber
with pdfplumber.open('the_raven.pdf') as pdf: 
    text = pdf.pages[0]
    clean_text = text.filter(lambda obj: obj["object_type"] == "char" and "Bold" in obj["fontname"])
    print(clean_text.extract_text())
```

輸出為
```
CTFUA{
f
i n d
—
m
e
— b
e s t
i e s
```

統整後即為 flag

CTFUA{find-me-besties}

### Magic surfing
![](https://i.imgur.com/EX5SMPA.png)

使用 binwalk，發現圖片中藏著一個 zip

```
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             JPEG image data, JFIF standard 1.01
382           0x17E           Copyright string: "Copyright (c) 1998 Hewlett-Packard Company"
2349480       0x23D9A8        Zip archive data, at least v2.0 to extract, compressed size: 1810925, uncompressed size: 1874423, name: troll.mp3
4160535       0x3F7C17        End of Zip archive, footer length: 22
```

在 zip 中有一個 troll.mp3，裡面播的是百年經典老歌 rickroll

但在播放開始不久，出現有奇怪的聲音，使用 audacity 觀察，確實有一段聲音不同

![](https://i.imgur.com/MrqfDL5.png)

查看波頻圖，發現那一段是 flag

![](https://i.imgur.com/G6wWOO2.png)

CTFUA{d0_y0u_l1k3_w4v3s_s0unD}

## crypto
### Reliable Nifty Advance
![](https://i.imgur.com/O2XOeYg.png)

檔案內容如下:
```
CGG AAC GCC UGU GCC AAC CAU AUA GAU GAA UUU UUA GCC GGG UCA
```

使用 dcode.fr，發現是 Genetic Code

在解密結果中，只有第一個較符合文字訊息

![](https://i.imgur.com/ng6p2Wk.png)

flag 就是第一個

CTFUA{RNACANHIDEFLAGS}

### Caesar++
![](https://i.imgur.com/77VWByv.png)

透過 dcode.fr 分析，輸入關鍵字 casear，發現似乎是一個叫做 Trithemius Cipher 的東西

![](https://i.imgur.com/bxujMXj.png)

解密後，看到第一個結果最符合文字，flag 就是這一個

![](https://i.imgur.com/CcEAioG.png)

CTFUA{THISISPROGRESSIVECAESARCIPHER}

### Tic tac toe
![](https://i.imgur.com/btp13Qm.png)

透過 dcode.fr 分析，發現似乎是 Caesar Box Cipher

使用 brute fouce，發現結果中的 6x6 似乎就是 flag

![](https://i.imgur.com/TTmJxdm.png)

CTFUA{TR4N2P021T10N_12NT_TH4T_24F3}

### Xorcist
![](https://i.imgur.com/uH2kUWc.png)

很明顯的，檔案透過 xor 加密，在已知明文及密文的情況下可以還原出金鑰

不過這題檔案似乎有一些小問題，檔案一直解密有問題，起初解密出的金鑰是 `iUN3DUN3DUN3DUN3DUN3DUN3DUN3DUN3DUN3D`，且解密檔案能看的出來是 png 格式，但無法 render 出來

後來透過比對 png 開頭固定字串後發現金鑰第一位應該要是 `D` 而非 `i`，因此可知金鑰其實是 `DUN3`，也順利解密出來

![](https://i.imgur.com/FqLBLFQ.png)

CTFUA{X0R_4ll_TH3_TH1NG2}

### Empty
![](https://i.imgur.com/iVNwEMb.png)

從題目敘述可知，這是一個被加密的 pdf，嘗試解密

從 [PDF 格式](https://en.wikipedia.org/wiki/PDF#File_format) 可知，PDF 開頭是 `%PDF-1.7`，嘗試使用 xor 解密

![](https://i.imgur.com/KyeR6l0.png)

解密出來的 key 為 `0x16`，嘗試對全部檔案進行破解

```python=
key = 0x16
with open("empty.pdf", "rb") as fh:
	data = fh.read()

data2 = b""
for d in data:
	data2 += bytes([d ^ key])

with open("empty2.pdf", "wb") as fh:
	fh.write(data2)
```

破解出來的 pdf 似乎也有問題，嘗試檢查 `%EOF` 部分是否有問題，不過在檢查時可以看到有 flag 的字樣

![](https://i.imgur.com/Tkbjw2R.png)

CTFUA{16_8s_a_mag8c_number}