# shellctf

## Web
### Choosy
![](https://i.imgur.com/TRl7KHJ.png)

![](https://i.imgur.com/idPkHjW.png)
在題目給的網址中，標題的 X, S 為大寫提示了這題是有關 XSS 或 XSLeak 相關攻擊

先隨便送 payload
![](https://i.imgur.com/Ojvy7y4.png)
可以看到文字是包在 `<h2>` 中

送出 payload 為 `</h2><p style="color:%20red;">aaa</p>`
![](https://i.imgur.com/W1qFa66.png =500x)

可以看到顏色確實有變，代表可以嘗試進行 XSS

嘗試送出 payload: `</h2><script>alert(1)</script>`
![](https://i.imgur.com/ySoFbZw.png)
但發現對於 `script` 字樣似乎有做過濾，嘗試另一種繞法

payload: `</h2><img src="javascript:alert(1)">`
![](https://i.imgur.com/0qiQG4W.png)

shellctf{50oom3_P4yL0aDS_aM0ng_Maaa4nnY}

### Colour Cookie
題目如下:
![](https://i.imgur.com/V0vOFG3.png)

進入網站後，發現主要有一個可以輸入名字的地方，以及一個選顏色的部分
![](https://i.imgur.com/a8LkpMJ.png)
不過經實測在送出時僅有名子部分會變成參數送出，顏色部分不會

根據題目提示，查看他有關CSS、字體等的引用，發現僅有 `./static/base_cookie.css` 是它自己的，其餘皆是引用外部資源
![](https://i.imgur.com/s2FSx3G.png)

查看此 css，發現檔案最下面有 `name="C0loR"` 的提示
http://20.193.247.209:8222/static/base_cookie.css
![](https://i.imgur.com/IqoUYMn.png)

不過在網頁中輸入此名字沒有相關反應

經嘗試後，使用提示大法，提示如下:
![](https://i.imgur.com/D33RmY6.png)

很明顯的，key 就是剛才找到的 `C0loR`，而 value 則是網頁中出現的 `Blue is my favourite colour`，而根據此提示，推測使用 `C0loR=Blue` 作為 GET parameter
http://20.193.247.209:8222/check?C0loR=Blue
![](https://i.imgur.com/zY7g3JT.png)

成功獲得 flag

shellctf{C0ooooK13_W17h_c0ooorr3c7_Parr4m37er...}

### ILLUSION

題目如下:
![](https://i.imgur.com/XgsOr9z.png)

![](https://i.imgur.com/YkFC5Qg.png)

在進入題目的網站後，可以看到主要有一個輸入框

嘗試輸入一些文字，發現有些字可以出現在 `What I see ◔_◔` 的後面有些不能

舉例來說，輸入 `a` 可以看到
http://20.125.142.38:8765/wH4t_Y0u_d1d?inn=a
![](https://i.imgur.com/xViCW6Y.png)

輸入 `b` 則不行
http://20.125.142.38:8765/wH4t_Y0u_d1d?inn=b
![](https://i.imgur.com/vy6UDCs.png)

根據嘗試，基本上只有以下的單字能輸入進去 (及其組成的字串)
```
a c d f g l s t x ; . (不包含空白)
```

然後意外的發現，輸入 `ls` 字串還會被裁掉，如下 payload:
`acdfglstx;.`
http://20.125.142.38:8765/wH4t_Y0u_d1d?inn=acdfglstx%3B.
![](https://i.imgur.com/8sbdqim.png)

推測這邊會擋 ls 輸入的原因是會直接將輸入丟進 command 中，可以嘗試 command injection 的方向

至於會被裁掉，可以嘗試用 `llss` 這樣讓他自動幫我切掉中間的 ls，有點類似 path traversal `../` waf bypass 的作法

payload: `llss .`
http://20.125.142.38:8765/wH4t_Y0u_d1d?inn=llss+.
![](https://i.imgur.com/0LSTGfX.png)
command injection 成功

嘗試尋找 flag 檔案，由能用的單字中判斷檔案名稱應該是 `flag` 相關

而由於不能用 `/` 的關係，無法直接用 `../..` 的方式往上一層，但可以使用 `cd ..; cd ..;` 的方式往上 (實際上的 payload 為 `ccdd ....;` 這樣)

最終在上二層的位置找到可能的檔案 `flag.txt`
payload: `ccdd ....; ccdd ....; llss .`
http://20.125.142.38:8765/wH4t_Y0u_d1d?inn=ccdd+....%3B+ccdd+....%3B+llss+.
![](https://i.imgur.com/EIYTB85.png)

最終的 payload: `ccdd ....; ccdd ....; cat flag.txt`
http://20.125.142.38:8765/wH4t_Y0u_d1d?inn=ccdd+....%3B+ccdd+....%3B+cat+flag.txt
![](https://i.imgur.com/4yTswvC.png)

不知道為什麼 cat 不像其他 command 一樣做截斷，不過沒差

shellctf{F1l73R5_C4n'T_Pr3v3N7_C0mM4nd_1nJeC71on}

### (未完成) RAW Agent
題目如下:
![](https://i.imgur.com/SIbZykf.png)

進入網站後，可看到底下畫面
![](https://i.imgur.com/pGb7ve5.png)
由 `ONLY AGENT VINOD IS ALLOWED` 推測是要改 User-Agent header
![](https://i.imgur.com/bWfbVhk.png)

修改後可看到底下畫面
![](https://i.imgur.com/vdkILbe.png)

推測需要加入 Date header，經嘗試後須修改為當前時間的前三小時左右
![](https://i.imgur.com/FWzdPo4.png)

綜合以上，以下是需要修改的 header
```
User-Agent: Vinod
Date: Sat, 13 Aug 2022 15:40:30 GMT (依當時時間而定)
```

修改後可看到底下畫面
![](https://i.imgur.com/73YdsL3.png)
且最下面有以下圖片
![](https://i.imgur.com/wv0t9Ya.png)

根據[神奇寶貝百科](https://wiki.52poke.com/zh-hant/未知图腾)，這部分解密為 `USSERAGENT`，恰巧符合第一段的 flag

而在檢視原始碼後，看到類似 brainfuck 的東西，如下
![](https://i.imgur.com/gs0RHtx.png)
完整句子如下
```!
+++++++++----------<<<<<<<<<<<<<<]}}]<<<<<<+++++++++

++++++++++[>+>+++>+++++++>++++++++++<<<<-]>>>++++++++++++.>++++.+++++++++++++++++.<++++++++++++++++++.>----------.-.<<++.>----------------.>+.--------.--.+++++++++++.-------.<<.>-------.>.+++.+++.+++++.-----------.------.<<.>.>--.++.+++++.-------.++++++++++++.+++.<<.>+++++++.>+++++++++.-------.<+++++++++++++.>----.++++++.--.+++.--------.<<.>-----------------.>++++++.++++++.<++++++++++++++++++++.>----.<-.++++++++.<.>------------------------------.>----------------.++++++++++++++++++.---.+++.--------.<<.>+++.>--------------.++.+++++.+.+++++++++.---------.++++++++++.++.<<.>---------------.>---------.++++++++.-------------------.+++++++++++++++++.---------.--------.<<.>++++++++++++.>.++++++.+++++++.---------.+++++++++++++++++++++.-----------.-.---------.<<.>+++.<+++++++++++++++++.>>++++++.<<+++.>>--------.<--------.>++++++++++++++++++.<<--------------------.>----.>------------.--------.+++++++++++.-----.------.<<.>+++.>++++++++++++++++++++++++.------------------------.+++++++++++++++++.-----------------.+++.+++++++++++.++++.<<.>---.>-.-----------------.++++++.++++++++.-.-----.+++++++++++.---------------.<<.>+.>.+++++++++++++++++.-----------------..<<.>+++++++.>++++++++++++++++.------------------.<<++++++++++++++++++++.>>+++++++++++++++.<<---.-.----------------.>--------.>-------------.++++++++++.+++++++++.+.------.<<.>++++++++++++++++++++++.+++++++.>---.<+++.>-.++++.<<.>---------------------------------.>-----------.<---------------.>++++++++++.<---.>++++++++.<++++++++++++++++.>--------.<+++.<.>++++++++++++++.>---.+++++.-----.--.<<.>-----------.>------------.+++++++++++++++++.--------------.+.+++++++++++++++++.-------.------.+++++++++.<<.>++++++++++++++.>----.---.+++.<<++++++++++++++++.>++.>.<<----------------.>----------------.<++++++++++++++++.>>----------.++++++++++++++++++++++.<<+.>>--------------.<+++++.<+++.--------------------.>-------.>.-------.--.+++++++++++++++++.--.---.-----------.+.<<.>.>++++++++++++++.----------------.--.+++++++++++++++++++++.---------------------.+++++++++++.---.----.+++++++++++++.<<.>++.>-----------------.+++++++++++++++++.---------------.+++++.+++++++.--.+++.<<.>+++++++++++++++++++.>+++++++++.<+++++++++++++.------.>-------.<+++.+.<.++++++++++++++++++++++++++++++++++.>>------.<----.>++++++++++++++.<++++++++.++.------.+++++++++.<<++++++++++++++++++++++.>+++++.>++++.-------------.+++++++++.-----.+++++.----.---------.
```

第一句無法解析，而第二句解析結果為
```!
Rhydon Togepi Milotic Machamp Tyrantrum Psyduck Mewtwo Pachirisu Altaria Magnezone P1k4cHu Dialga Gyarados Dragonite Eevee Luc4r10 Deoxys Zapdos Ch4r1zArD Rotom Gardevoir Unkn0Wn G0dz1lL4 Electrode Escavalier Garchomp Zygarde Blaziken Greninja
```

有嘗試把上面 P 開頭的三個寶可夢當作第二段 flag，但是繳交失敗

嘗試許久，用了提示大法，提示如下:
![](https://i.imgur.com/SO6QAFk.png)
![](https://i.imgur.com/pDfPHD1.png)
![](https://i.imgur.com/EOPOQIM.png)

根據提示一，目前解到了第三階段，所以還需要再解一個部分
根據提示三，查看有關 cookie 相關，回到第一階段的開頭發現有一個神祕的 cookie: `77686f616d5f695f616d: 55736572`

使用 [cipher-identifier](https://www.dcode.fr/cipher-identifier) 發現這是一個 hex string，解析後 cookie 名稱為 `whoam_i_am` 而現在值為 `User`

嘗試將值改為 `Admin` 的 hex string: `41646d696e`
![](https://i.imgur.com/hffxfsa.jpg)
發現已經到達 Utlimate level，但目前查看原始碼或其他方法皆無法找到 flag 第二部分

別人的解法:
```
ChronosPK — 今天 21:18
change user-agent to vinod
change date to at least 3 hours earlier
-> get image saying USSERAGENT (first part of the flag)
-> get comment in brainfuck -> list of pokemons
decode cookie from hex and replace user with admin (77686f616d5f695f616d=55736572 -> whoam_i_am=User)
-> get another image -> zsteg since it is png -> google link is embeded -> link to a zip file
crack with the list of pokemons as wordlist -> *flag.txt* 
shellctf{USSERAGENT_p4raM37eR_P0llu7iOn}
```

在第四階段的圖片中藏有資料，使用 zsteg 工具找出
![](https://i.imgur.com/kii91ti.png)
可以看到有紅色的部分，似乎是 base64，嘗試解碼
![](https://i.imgur.com/DAupLZ5.png)

解密出來後是一個連結
https://drive.google.com/file/d/1NllVrmrHdLHRgX6sV539L1ZzbnRGCvdr/view?usp=sharing
![](https://i.imgur.com/lgKk27M.png)
發現裡面似乎就是 flag 的檔案

不過在解壓縮時有密碼的部分
![](https://i.imgur.com/RHDHXFf.png)
嘗試使用前面 brainfuck 出來的寶可夢名字做解碼

最終，使用名稱 `Luc4r10` 成功解出
![](https://i.imgur.com/LczyuLQ.png)

檔案內容為第二段的字串
```
_p4raM37eR_P0llu7iOn
```

shellctf{USSERAGENT_p4raM37eR_P0llu7iOn}

### More ILLUSION
題目如下:
![](https://i.imgur.com/npDYIpo.png)
![](https://i.imgur.com/bhuP577.png)

反正類似前面的 ILLUSION 那題，然後輸入 command 時會需要 double encode 過，在 GET 參數名稱 (`Th1nK_Tw1c3`) 就有提示

http://20.125.142.38:8499/wH4t_Y0u_d1d?Th1nK_Tw1c3=a

不過這題網頁架構不太一樣，在上一層目錄會看到有很多 flag 相關的資料夾，如下:
payload: `ccdd ....; llss`
http://20.125.142.38:8499/wH4t_Y0u_d1d?Th1nK_Tw1c3=ccdd+....%3B+llss
![](https://i.imgur.com/Y1tNoIp.png)

而題目說明也有提示要用 `du`，查看 manual 及 flag 格式提示後發現主要要關注以下的選項
```!
-a, --all
    write counts for all files, not just directories

--apparent-size
    print  apparent  sizes,  rather  than  disk  usage;  although  the apparent size is usually smaller, it may be larger due to holes in ('sparse') files, internal fragmentation, indirect blocks, and the like

-h, --human-readable
    print sizes in human readable format (e.g., 1K 234M 2G)
```

`-a` 選項是選擇檢視資料夾外也要檢視檔案，`-h` 選項是選擇輸出 human friendly 的字串，`--apparent-size` 選項是選擇看檔案實際大小

payload: `ccdd ....; dduu --apparent-size -ah`
http://20.125.142.38:8499/wH4t_Y0u_d1d?Th1nK_Tw1c3=ccdd+....%3B+dduu+--apparent-size+-ah
![](https://i.imgur.com/2ZpTfr9.png)

將這些文字複製後，我們的作法是使用 c 的 printf 將字串做 formating 以方便觀看，並搭配 grep 篩選出 .txt 檔案

結果整理如下:
```
23  ./flag=/flag/flag/flag/flag/flag.txt
663 ./injection/requirements.txt
23  ./flag--------------------/flag/flag/flag/flag/flag.txt
23  ./flag-------------------/flag/flag/flag/flag/flag.txt
23  ./flag------------------/flag/flag/flag/flag/flag.txt
23  ./flag-----------------/flag/flag/flag/flag/flag.txt
23  ./flag----------------/flag/flag/flag/flag/flag.txt
23  ./flag---------------/flag/flag/flag/flag/flag.txt
23  ./flag--------------/flag/flag/flag/flag/flag.txt
38  ./flag-------------/flag/flag/flag/flag/flag.txt
23  ./flag------------/flag/flag/flag/flag/flag.txt
23  ./flag-----------/flag/flag/flag/flag/flag.txt
23  ./flag----------/flag/flag/flag/flag/flag.txt
23  ./flag---------/flag/flag/flag/flag/flag.txt
23  ./flag--------/flag/flag/flag/flag/flag.txt
23  ./flag-------/flag/flag/flag/flag/flag.txt
23  ./flag------/flag/flag/flag/flag/flag.txt
23  ./flag-----/flag/flag/flag/flag/flag.txt
23  ./flag----/flag/flag/flag/flag/flag.txt
23  ./flag---/flag/flag/flag/flag/flag.txt
23  ./flag--/flag/flag/flag/flag/flag.txt
23  ./flag-/flag/flag/flag/flag/flag.txt
23  ./flag/flag/flag/flag/flag/flag.txt
23  ./flag===========================/flag/flag/flag/flag/flag.txt
23  ./flag==========================/flag/flag/flag/flag/flag.txt
23  ./flag=========================/flag/flag/flag/flag/flag.txt
23  ./flag========================/flag/flag/flag/flag/flag.txt
23  ./flag=======================/flag/flag/flag/flag/flag.txt
23  ./flag======================/flag/flag/flag/flag/flag.txt
23  ./flag=====================/flag/flag/flag/flag/flag.txt
23  ./flag====================/flag/flag/flag/flag/flag.txt
23  ./flag===================/flag/flag/flag/flag/flag.txt
23  ./flag==================/flag/flag/flag/flag/flag.txt
23  ./flag=================/flag/flag/flag/flag/flag.txt
23  ./flag================/flag/flag/flag/flag/flag.txt
23  ./flag===============/flag/flag/flag/flag/flag.txt
23  ./flag==============/flag/flag/flag/flag/flag.txt
23  ./flag=============/flag/flag/flag/flag/flag.txt
23  ./flag============/flag/flag/flag/flag/flag.txt
23  ./flag===========/flag/flag/flag/flag/flag.txt
23  ./flag==========/flag/flag/flag/flag/flag.txt
23  ./flag=========/flag/flag/flag/flag/flag.txt
23  ./flag========/flag/flag/flag/flag/flag.txt
23  ./flag=======/flag/flag/flag/flag/flag.txt
23  ./flag======/flag/flag/flag/flag/flag.txt
23  ./flag=====/flag/flag/flag/flag/flag.txt
23  ./flag====/flag/flag/flag/flag/flag.txt
23  ./flag===/flag/flag/flag/flag/flag.txt
23  ./flag==/flag/flag/flag/flag/flag.txt
```

可以看到其中有一個檔案大小為 38，與其它不同，推測我們要的 flag 在這裡

payload: `ccdd ....; ccdd flag-------------; ccdd flag; ccdd flag; ccdd flag; ccdd flag; cat flag.txt`
http://20.125.142.38:8499/wH4t_Y0u_d1d?Th1nK_Tw1c3=ccdd+....%3B+ccdd+flag-------------%3B+ccdd+flag%3B+ccdd+flag%3B+ccdd+flag%3B+ccdd+flag%3B+cat+flag.txt
![](https://i.imgur.com/38wOsbn.png)

根據題目敘述，完整的 flag 如下:

shellctf{H0p3_4ny0N3_No7_n071c3_SiZe_D1fF3reNc3_du_apparent-size_ah}

## Reversing
### Keygen
打開程式先看 main

![](https://i.imgur.com/ctlshCA.png)
發現前面會先做一些檢查後，印出 `Access Granted!` 和 `getString` 出來的東西，看一下 `getString` 是什麼

![](https://i.imgur.com/6UBkGl4.png)
發現是一些奇怪的 hex 組成的字，嘗試解譯這些 hex

![](https://i.imgur.com/OvLHU33.png)
發現其實就是 flag 了

SHELLCTF{k3ygen_1s_c0oL}

### How to defeat a dragon
1. Reverse發現所求code為69420
![](https://i.imgur.com/sbTrbon.png)

2. 得到
![](https://i.imgur.com/qHYFUWj.png)
SHELLCTF{5348454c4c4354467b31355f523376337235316e675f333473793f7d}
3. 假flag值為hex，轉ascii
![](https://i.imgur.com/NBdps9X.png)
SHELLCTF{15_R3v3r51ng_34sy?}

### Pulling the strings
有點偷懶ㄟ
![](https://i.imgur.com/Lon04Hi.png)
SHELLCTF{Th4nks_f0r_the_food}

### Warmup
1. flag以此一形式儲存
![](https://i.imgur.com/zCYcUFE.png)
2. 程式檢查時，將各值右移兩位後與輸入值比對，故可將各值/4之後轉換為ascii
![](https://i.imgur.com/LGISvrF.png)
3. 應該可以寫程式解，但想說好麻煩就直接手幹，對表對到眼睛脫窗
![](https://i.imgur.com/irOFjwW.png)
shellctf{b1tWi5e_0p3rAt0rS}

> ![](https://i.imgur.com/K8e43TJ.png)
> from AIS3 pre-exam 2021

### tea
打開程式看 main
![](https://i.imgur.com/NNynmlo.png)
可以看到主要有 5 個函式－`boilWater`, `addSugar`, `addTea`, `addMilk`, `strainAndServe`

![](https://i.imgur.com/AWRo5bC.png)
boilWater 函式主要是提示並讀取使用者輸入，並存到 `pwd` 變數中，沒什麼特別的

![](https://i.imgur.com/Xtrgz0O.png)
在 addSugar 函式部分，會將輸入的 `pwd` 根據 index 分奇偶，打散順序
舉例來說，`0 1 2 3 4 ...` 會變成 `1 3 5 7 ... 0 2 4 6 ...`

![](https://i.imgur.com/ygWqlzj.png)
在 addTea 部分會改變字元，在前半部分會將字元加上 `-3 * (index // 2)`，後半部分則會加上 `(index // 6)`

![](https://i.imgur.com/TULa7l6.png)
在 addMilk 中，會再次打亂順序，會將字串分成三部分－遇到第一個 '5' 之前、第一個 '5' 到第一個 'R' 之間、第一個 'R' 之後，並再重新排列

排列方式:
```
........5........R.........
區塊一     區塊二     區塊三
=> R............5......
   區塊三  區塊一  區塊二
```

![](https://i.imgur.com/KmJiI95.png)
而 strainAndServe 函式則是比對最終的字串是否等於指定的字串

這邊我們的解法是使用倒推法，從指定字串倒推回可能的輸入

由於在 addMilk 輸出部分的區塊一及區塊三無法切分，所以必須一個一個嘗試切割的位置

另外由於指定字串中有 2 個 '5'，無法直接知道哪個是區塊二的開頭，不過我們推斷因為當較前者為開頭時區塊二的範圍較大，較不平均，所以暫時假設後者為區塊開頭 (不過假設失敗再更改也影響不大)

以下是解密程式:

```python=
password = "R;crc75ihl`cNYe`]m%50gYhugow~34i"

section1_start = 7
section2_start = 19

DEBUG = False
if(DEBUG):
        print("[DEBUG]", password)

for i in range(section1_start, section2_start):
        # remove milk
        possible_passwd = password[i:] + password[:i]
        if(DEBUG):
                print('[DEBUG]', possible_passwd)

        temp_passwd = ""
        # remove tea
        for j in range(len(possible_passwd)):
                if j < len(possible_passwd) // 2:
                        temp_passwd += chr(ord(possible_passwd[j]) + (j // 2) * 3)
                else:
                        temp_passwd += chr(ord(possible_passwd[j]) - (j // 6))
        possible_passwd = temp_passwd
        if(DEBUG):
                print('[DEBUG]', possible_passwd)

        # remove sugar
        section_odd = possible_passwd[:len(possible_passwd) // 2]
        section_even = possible_passwd[len(possible_passwd) // 2:]
        possible_passwd = ""
        for a,b in zip(section_odd, section_even):
                possible_passwd += b + a

        print(i, bytes(possible_passwd, encoding="utf8"))

#print(password[0:section1_start], password[section1_start:section2_start], password[section2_start:])
```

解密結果如下:
![](https://i.imgur.com/pySltpo.png)
可以看到僅當區塊一三切割點在 index 8 時才比較符合 flag 格式，因此推斷這是這一題的 flag

shellctf{T0_1nfiNi7y_4nD_B3y0nd}

### (待完成) swift
![](https://i.imgur.com/RXh0jOI.png)

func 為 `exponential` function，故 output.txt 的數字可反推為
```
-2 -1 1 2 -3 0 5 -1 -1 1 3 5
```

## Misc
### Sanity Check
![](https://i.imgur.com/CXxpsTE.png)

直接在他們 discord 的 announcement 即可找到 flag
![](https://i.imgur.com/ZaJZmvV.png)

SHELLCTF{W3lc0me_2_SHELLCTF2022}


### World's Greatest Detective

![](https://i.imgur.com/4uAycdY.png)
[source](https://www.reddit.com/r/marvelstudios/comments/nac1c1/on_the_wakandan_written_language/)

SHELLCTF{W4kandA_F0rev3r}

> 太神了吧這你也找的到 [name=陳彥瑋]
>> 檔名直接寫XD [name=范綱佑]
>> ![](https://i.imgur.com/uLfWGPb.png)


## Forensic
### Alien Communication
waveform
![](https://i.imgur.com/inoCJPC.png)
shell{y0u_g07_7h3_f1ag}

### (未完成) Secret Document
[別人的解法](https://infern0o.medium.com/shell-ctf-2022-forensics-writeup-258c9d7dbd8#:~:text=Secret%20Document)

題目如下:
![](https://i.imgur.com/ODrACkw.png)

題目給了一個 .dat 檔案，且內容無法閱讀，且根據題目推測是有做過加密

從題目敘述的 `xorry` 推測是使用 xor 做加密，且 key 為 `shell`

使用 [ciberchef](https://gchq.github.io/CyberChef/) 嘗試解密
![](https://i.imgur.com/5R2xTMw.png)
可以看到解密出來為 png 影像

打開後如下:
![](https://i.imgur.com/T6Tepz8.png)

shell{y0u_c4n_s33_th3_h1dd3n}

### Heaven

給了一張圖
提示如下
`"I was in the seventh heaven painted red green and blue"`
用神器 stegsolve 的 Data extract 功能
題目有 Heaven Flag 就放在頂部
![](https://i.imgur.com/LshCzif.png)
SHELL{man1pul4t1ng_w1th_31ts_15_3A5y}

> 難怪我解不開，原來是因為我是從 0 和 1 那邊開始勾 [name=陳彥瑋]
> > 我剛剛看到提示才發現 [name=sixkwnp]

### GO deep!
題目給了一段音頻
而音檔為一段叫 Go Higher 的 Audio

既然題目叫 Go deep 就用 notepad++ 開到最底
![](https://i.imgur.com/RWkQHUm.png)
目前懷疑音頻裡有藏資料

使用Deepsound解
![](https://i.imgur.com/n3IoVdg.png)

extract 後得到解
SHELL{y0u_w3r3_7h1nk1ng_R3ally_D33p}

## Crypto
### (未完成) Tweeeet
[別人的解法](https://github.com/samari-k/shellctf2022-writeup/blob/main/challenges/Tweeeet.md)

題目給了一張鳥圖
![](https://i.imgur.com/0SUqHcj.jpg)

經過搜尋，找到了 Birds on a wire code
![](https://i.imgur.com/dH18hn0.png)

使用工具解密
![](https://i.imgur.com/cypMxEZ.png)
解密結果為 `WELOVESINGING`

SHELL{WELOVESINGING}

> 這題目太鳥了吧 [name=陳彥瑋]

### (未完成) Tring Tring....

[別人的解法](https://github.com/samari-k/shellctf2022-writeup/blob/main/challenges/Tring%20Tring.md)

題目如下:
![](https://i.imgur.com/bp2Mgtc.png)

看起來就是一副 morse code 的樣子，使用工具解密
![](https://i.imgur.com/k71AZuw.png)
解密結果為: `999 666 88 222 2 66 777 33 2 3 6 999 7777 6 7777`

根據題目提示，與舊型手機的按鍵方式有關
![](https://i.imgur.com/VMSbahQ.png)
解密出來為 `youcanreadmysms`

SHELL{youcanreadmysms}

### (未完成) MALBORNE

別人的解法:
```
Lil Supa — 今天 20:38
malbolge code
https://malbolge.doleczek.pl/
```

題目給了這一坨大便:
```
'&%$#">~6;438765.Rsrqponmlkjihgfedcba`_^]\[ZYXWVUTSRQPONMLKJIHGFEDCBA@?>=<RQ
VOTSRQPINMFj-,+*)('&%$#"!~}|{zyxwvutsrqponm+*)('&%$#cb~`=^]\[ZYXWVUTSRQPONMi
hJfedcba`_X|?>ZYXWVUT6RKoONGFj-CHAF?c&%$#"!~}|{zyxwvutsrqponmlk)i'&%$#z!xwv<
]\[ZYXWVUTSRQPONMLKJ`_dcba`Y^W\Uy<RQPUNMqQPON0Fj-,+*)('&%$#"!~}|{zyxwvutsrqp
onmlkjihgfedcba`_^]\[ZYXWVUTSRQPONMLKJIHGFEDCBA]V[ZYXWPOTMLp3OHGFj-,+*)('&%$
#"!~}|{zyxwvutsrqponmlkjihgfedcba`_^]\[ZYXWVUTponPlejihafe^$ED`_AW\[ZYRQu87S
RQ3ONMLKDh+*)('&%$@?!7<;:9810Tutsrqponmlkjihgfedcba`_^]\[ZYXWVUTSRQPONMLKJIH
GFEDCBA@?>=<;:9876543210/.-CHA@EDCBA@98\}|{zyxwvutsrqponmlkjihgfedcba`_^]\[Z
YXWVUTSRQPONMLKJIHGFEDCBA@?>=<;:9876RQJONGLKJIHA@d'&%$#"!~}|{zyxwvutsrqponml
kjihgfedcba`_^]\[ZYXWVUTSRQPONMLKJIHGFEDCBA@?>=<;:98TSRQ3ONMLKDCBf)('&%$#"!~
}|{zyxwvutsrqponmlkjihgfedcba`_^]\[ZYXWVUTSRQPONMLKJf_dcba`Y^WV[Tx;:9OTSRQPO
NGkK-CHG@?c=BA:^!7<54Xyxwvutsrqponmlkjihgfedcba`_^]\[ZYXWVUTSRQPONMLKJIHGFED
CBA@?>=<;:98765432N0FKJIHGFED=<`#"!~}|{zyxwvutsrqponmlkjih&f|#"!~}|uts9ZYXWV
UTSoQgfkjihg`_%FEDCBA@?>=<;:9876543210/.-,+*)('&%$#"!~}|{zyxwvutsrqponmlkjih
gfedcba`_^]\[ZYXWVUTSRQPONMLKJIHGFEDCBA@?>=<;:9876543210/.-,+*)('&%$#"!~}|{z
yxwvutsrqpon,+*)('&%${cbx`=^]\[ZYXWVUTSRQPONMihJfedcba`_X|?>=<;:9876543210/.
-CHAFEDCBA@9]=<5:92Vwvutsrqponmlkjihgfedcba`_^]\[ZYXWVUTSRQPONMLKJIHGFEDCBA@
?>=<;:9876543210FKDCHGFEDCB;:^!~}|{zyxwvutsrqponmlkjih&f|#"y~}|{ts9ZYXWVUTSR
QPONMLKJIHGFEDCBA@?>=<;:9876543210/.-,+*)('&%$#"!~}|{zyxwvutsrqponmlkjihgfed
cba`_^]\[ZYXWVUTSRQPONMLKJIHGFEDCBA@?>=<;:9876543210/.-,+*)('&%$#"!~}|{zyxwv
utsrqponmlkjihgfedcba`_^]\[ZYXWVUTSRQPONMLKJIHGFEDCBA@?>=<;:9UTSRQ3IHMLEJCBf
)('&%$#"!~}|{zyxwvutsrqponmlkjihgfedcba`_^]\[ZYXWVUTSRQPONMLKJf_dcba`Y^WV[Tx
;:9OTSRQPONGk.-,+*)('&%$#"!~}|{zyxwvutsrqponmlkjihgfedcba`_^]\[ZYXWVrqponmlk
jLhg`&GFb[`Y^]\[ZSwWPUTMqKPINGFjJIHGFE>b%$#"!~}|{zyxwvutsrqponmlkjihgfedcba`
_^]\[ZYXWVUTSRQPONMLKJIHGFEDCBA@?>=<;:9876543210/.-,+*)('&%$#"!~}|{zyxwvutsr
qponmlkjihgfedcba`_^]\[ZYXWVUTSRQPONMLKJIHGFEDCBA@?>=<;:98TSRQ3ONMLEDIHAe('&
%$#?!=65:9876/Stsrqpon&%$)('~%${Aba`_^]\[ZYXWVUTSRQPONMLKJI_dc\a`_^]VUTx;:98
76543210/.-,+*)('&%$#"!~}|{zyxwvutsrqponmlkjihgfedcy~}v{zyxwvun4UTponmlkjiba
'&dcE[`YX|?Uy<;:9876543210/.-,+*)E'CB;@?>=6;4Xyx654t210/.'KJkjihgfedcba`_^]\
[ZYXWsrqponmlkjLb(IHGcb[`_^]VUy<XWVOTMqQPIHlLKJIH*F?c&<A@?>=<5Y3210Tutsrqpon
mlkjihgfedcba`_^]\[ZYXWVUTSRQPONMLKJIHGFEDCBA@?>=<;:9876543210/.-CHA@EDCBA@9
8\}|{92765432+Oponmlk)('~}${z!~w=^]sxwvutsrqj0ng-Ndcba`&GFEDCBA@V[ZYXWVUTMLp
3OHGFj-,+*)('CBA@?>=<;4Xyxwvutsrqponmlkjihgfedcba`_^]\[ZYXWVUTSRQPONMLKJIHGF
EDCBAW\[ZYXWVOTSLp3INMLEiCHAF?c&<;@?>=<5Yzyxwvutsrqponmlkjihgfedcba`_^]\[ZYX
WVUTSRQPONMLKJIHGFEDCBA@?[ZYXWPUTSRKPIm0/.-,+*)('&%$#"!~};{987054321*Nonmlkj
ihgfedcba`_^]\[ZvutsrqponPOe+LKJIHGFED`Y^]\[ZYRQuOTMqQ3INGkK-CHA@d'&%$#"!~}|
{zyxwvut2r0)(-,+*)(!Efedcba`_^]\[ZYXWVUqponPledihg`&q
```

通靈出是 [Malbolge](https://zh.wikipedia.org/zh-tw/Malbolge) 這個大便程式語言

使用 [線上執行器](https://malbolge.doleczek.pl/) 執行
![](https://i.imgur.com/VAKlHUy.png)

SHELL{m41b01g3_15_my_n3w_l4ngu4g3}

> 馬的糞題 [name=陳彥瑋]

### OX9OR2
題目僅有給一個檔案及 python 檔

encrypt.py:
```
def xor(msg, key):
    o = ''
    for i in range(len(msg)):
        o += chr(ord(msg[i]) ^ ord(key[i % len(key)]))
    return o

with open('message', 'r') as f:
    msg = ''.join(f.readlines()).rstrip('\n')

with open('key', 'r') as k:
    key = ''.join(k.readlines()).rstrip('\n')

assert key.isalnum() and (len(key) == 9)
assert 'SHELL' in msg

with open('encrypted', 'w') as fo:
    fo.write(xor(msg, key))
```

可以看到 key 和 message 是使用 xor 做加密，且已知 key 長度為 9 且僅有字母及數字，而 message 包含 `SHELL` 字串

encrypted 檔案:
```
00000000: 0b07 1705 1f38 177f 1e07 7e01 1601 7019  .....8....~...p.
00000010: 2a1e 6d7e 1005 603e                      *.m~..`>
```

由於 a XOR b XOR a = b，所以可以使用已知明文攻擊猜出 key

先使用 `SHELL` 當作 key
![](https://i.imgur.com/rf16LrF.png)
找出 key 的開頭是 `XORIS`

而更進一步，假設 flag 開頭為 `SHELL{`
![](https://i.imgur.com/dnjwLt8.png)
則可推出 key 開頭為 `XORISC`

而剩下字母可以直接用~~寫腳本~~通靈的方式直接通靈，猜測 key= `XORISCOOL`
![](https://i.imgur.com/SDxhK9L.png)
成功獲得 flag

![](https://i.imgur.com/5NkNxx2.png)

SHELL{X0R_1S_R3VeR51BL3}

> ciberchef 好用 [name=陳彥瑋]