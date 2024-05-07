# T3N4CI0US writeup

###### tags: `CTF`

## Pwnable

### Check Check Check

題目如下:

```
mic test one, two, three!!!

IP : 34.64.203.138
Port : 10009
```

![](https://i.imgur.com/vPxSrke.png)

nc 連上後，發現是直接給 shell

嘗試尋找 flag 檔案

![](https://i.imgur.com/IXIPlWI.png)

發現在 home 目錄下有一個 flag 檔案，嘗試讀取

![](https://i.imgur.com/UL5bzI1.png)

T3N4CI0US{ZG9yb3Jvbmc/ZG9uZz9kaW5nPw}

## OSINT

### G0

題目:
```
What is the name of the electronic store around the place in the picture?

Please mark the space with _
```

![](https://i.imgur.com/ZzUrVzf.png)

通靈出位置在秋葉原，通過搜尋 sega 一號館，找出位置是在 `35°41'55.2"N 139°46'16.5"E` 附近

根據題目，找尋附近店家，最後找到題目要的應該是這個位置

![](https://i.imgur.com/4xD6L1g.png)

T3N4CI0US{Tokyo_Radio_Department_Store_Shops}

### [?] Airplane

~~目前只確認出飛機為 `JA224J` ，目的地未知~~

~~國家確定是JPN 試過{JA224J_JPN} {JA224J_Japan}{JA224J_Hanamaki}{JA224J_HNA}都暫時Incorrect~~

![](https://i.imgur.com/H4LqlJb.png)

修正航班為 `JA213J`

### Japen Travel

找下方圖片景點的名字

![](https://i.imgur.com/cLEWg9T.jpg)
用中文的魔力 應該先比其他隊伍先找到名字叫 

“成田山 深川不動堂”

![](https://i.imgur.com/bAj7Pjb.png)

英文是 "Fukagawa Fudodo"
不過 Type 進 {Fukagawa_Fudodo} 報錯誤
所以目前不確定是格式還是找不夠深

## MISC

### Find me
此題是要輸入`dolpari`的`URL`
不過 [Twitter](https://twitter.com/dodododolpari), [CTFtime](https://ctftime.org/team/178366/), [Github](https://github.com/Dolpari) 和[他們自架的網站](https://dolpari-is-come.tistory.com)都試過一遍發現都不行
索性開一個 Hint
Hint 1 為`SNS Site`
而 Github 皆有附 SNS Site 但目前不確定是哪個

開了第二個提示，結果是他的 IG :(

T3N4CI0US{https://www.instagram.com/dolpari_05/}

### Find us

使用提示，為: `site URL`

直覺是他們官方網站的 member 區塊

T3N4CI0US{https://t3n4ci0us.kr/member/}

## Crypto

### french

題目如下:
```
French Ciper

V3Y4GK0FW{EccrEsXpvtjIcdc}
```

不過在賽中的 discord 更正題目為

![](https://i.imgur.com/dXDaUDo.png)

使用 [Cipher Identifier](https://www.dcode.fr/cipher-identifier) 辨認，認為可能是 Vigenere Cipher，且符合題目與法國有關

由於 flag 開頭為 `T3N4CI0US`，嘗試破解 key

key = `CLE`，解密出來的是flag

T3N4CI0US{CrypTo_Verry_Easy}

## Reversing

### Swood

![](https://i.imgur.com/fMLXD7L.png)

在 main function 中，可以看到它是直接將密碼寫死在 code 中

![](https://i.imgur.com/4fSGYKX.png)

直接使用 ascii tool 解碼，要注意上面的是 little endian 所以需要反過來

![](https://i.imgur.com/oBbreCH.png)

T3N4CI0US{da39a3ee5e6b4b0d3255bfef95601890afd80709}

## Forensic

## Web

### Rosin
題目如下

`[!] The flag.txt is located in the flag folder.`

Dirsearch 後基本上沒找到有用的東西
![](https://i.imgur.com/yMRmGFx.png)


![](https://i.imgur.com/4k082PT.png)

看到 url 參數，推測是 LFI 題目

嘗試使用 `file://` 協定，讀取 `/etc/passwd`

http://34.125.194.164:49157/index.php?url=file:///etc/passwd

![](https://i.imgur.com/Pr6qNX6.png)

發現確實能夠讀取

根據題目提示，讀取 `/flag/flag.txt`

http://34.125.194.164:49157/index.php?url=file:///flag/flag.txt

![](https://i.imgur.com/RvFDzNt.png)

### World
題目給出
`IP : 34.125.194.164`
`Port : 49153`

一進入網頁 Output 出
- `Welcome To Find Secret`

所以就在 url 輸入 /secret
- `Tell me your secret.I will encrypt it so others can't see`

可以在此頁面給 GET 參數 secret=???

### Viska

進入並檢視原始碼後，發現有一長串的東西

![](https://i.imgur.com/shUWBHk.png)

![](https://i.imgur.com/v1MP976.png)

根據格式，推測是 base64，嘗試進行 decode

![](https://i.imgur.com/xp0xTvA.png)

decode 後的字串看起來也是 base64，嘗試繼續 decode

在一直 decode 的情況下，最終出現了 flag

![](https://i.imgur.com/QIOZR6Z.png)

T3N4CI0US{d79fa6_2bc60_db3_5_da5512c3d_8896b7_0_2796d6_0cd}