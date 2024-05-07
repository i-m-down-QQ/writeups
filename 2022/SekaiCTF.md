# SekaiCTF
###### tags: `CTF`

## Misc
### ▶ Sanity Check
![](https://i.imgur.com/D2T2frM.png)

在 discord -> announcement -> 公告

![](https://i.imgur.com/Dp5eLCr.png)

SEKAI{w31c0m3_t0_th3_w0r1d!}

### Console Port
![](https://i.imgur.com/pAanCc1.png)

直接連線上去，發現是 Keep Talking and Nobody Explodes 的遊戲，基本上只有基本的 section 1 module，有大概 300 多秒 5 道題，但只有一次失敗機會

![](https://i.imgur.com/mstzA1u.png)

成功後就得到 flag

SEKAI{SenkouToTomoniHibikuBakuon!}

### ▻ Survey
![](https://i.imgur.com/thhvbxR.png)

問卷時間

SEKAI{thx_for_playing_SekaiCTF_2022}

## PPC
### Let’s Play Osu!Mania
![](https://i.imgur.com/XnRsTj6.png)

題目輸入為一個譜面，譜面固定 4 格寬，其中有兩種按壓－點壓及長壓，以下是輸入範例

```
13
|-- -|
| #  |
| #- |
| #  |
| - -|
|-   |
| - -|
|    |
|  --|
|- # |
| -# |
|  # |
|  - |
```

第一行為譜面長度，在此例中為 13 行
第二行之後為譜面內容，譜面左右固定為 `|` 邊界符號，譜面中單純一個 `-` 而上下無 `#` 符號代表此一為點擊，而 `-` 上或下有 `#` 則為長壓，`#` 為長壓的中段部分，長壓固定一定會有兩個 `-` 包含至少一個 `#` 在其中

輸出為一整數，為要按壓的次數 (長壓算一次)，在此範例中為 12 次

code:
```python
line = int(input())

beatmap = []
for _ in range(line):
	aline = input()
	temp = []
	for i in range(1,5):
		dd = aline[i]
		if dd == '-':
			temp.append(1)
		elif dd == '#':
			temp.append(2)
		elif dd == ' ':
			temp.append(0)
	beatmap.append(temp)

inhold = [0,0,0,0]
total = 0
for i in range(line-1,-1,-1):
	temp = beatmap[i]
	for j in range(4):
		d = temp[j]
		if d == 1:
			if(inhold[j]):
				inhold[j] = 0
			else:
				total += 1
		if d == 2:
			inhold[j] = 1

print(total)
```

全部測資通過即可獲得 flag

SEKAI{wysi_Wh3n_y0u_fuxx1ng_C_727727}

## Cryptography
### Time Capsule
![](https://i.imgur.com/eRdn3K1.png)

chall.py 如下:
```python
import time
import os
import random

from SECRET import flag

def encrypt_stage_one(message, key):
    u = [s for s in sorted(zip(key, range(len(key))))]
    res = ''

    for i in u:
        for j in range(i[1], len(message), len(key)):
            res += message[j]

    return res

def encrypt_stage_two(message):
    now = str(time.time()).encode('utf-8')
    now = now + "".join("0" for _ in range(len(now), 18)).encode('utf-8')

    random.seed(now)
    key = [random.randrange(256) for _ in message]

    return [m ^ k for (m,k) in zip(message + now, key + [0x42]*len(now))]

rand_nums = []
while len(rand_nums) != 8:
    tmp = int.from_bytes(os.urandom(1), "big")
    if tmp not in rand_nums:
        rand_nums.append(tmp)

for _ in range(42):
    flag = encrypt_stage_one(flag, rand_nums)

res = encrypt_stage_two(flag.encode('utf-8'))

with open("flag.enc", "wb") as f:
    f.write(bytes(res))
f.close()
```

可以看到，其中有做 2 次的加密方法，第一個會根據預先求出的 8 個 urandom 出來的大小順序為起點，每次 index 增加 8 之後的值串接新的 flag，接著換成下一個起點，有點類似柵欄加密法

在第一個加密中，會執行 42 次

第二個加密會讀取當前時間，並根據時間產生隨機金鑰，並將原文與金鑰 xor 產生新密碼，而其中也會串接當前時間 xor 0x42 的值

在第二個加密中，由於當前時間也被包含在輸出中，所以可以根據格式逆向出來，並且也能依據這個時間做為種子產生一樣的隨機金鑰即可獲得原文

而第一個加密，由於順序無法逆向出來，可以嘗試爆破出來

解密腳本
```python
import random
import itertools

def decrypt_stage_two(message):
	now = bytes([m^0x42 for m in message[-18:]])
	print(now)

	random.seed(now)
	key = [random.randrange(256) for _ in message[:-18]]
	return bytes([m ^ k for (m,k) in zip(message[:-18], key)])

def decrypt_stage_one(message):
	print(len(message))
	bgen = itertools.permutations(range(8),8)
	for begins in bgen:
		tmp = message
		new_message = [None for _ in range(len(message))]
		for _ in range(42):
			bi = 0
			count = begins[bi]
			for i,m in enumerate(tmp):
				new_message[count] = m
				count += 8
				if(count >= len(tmp)):
					bi += 1
					if(bi < 8):
						count = begins[bi]
			tmp = bytes(new_message)
			new_message = [None for _ in range(len(message))]
		if(b'SEKAI' in tmp):
			print(begins, tmp)


with open("flag.enc", "rb") as fh:
	res = fh.read()

flag1 = decrypt_stage_two(res)
print(flag1)

decrypt_stage_one(flag1)
```

對於第一個的順序，破解出來為 `6, 3, 7, 4, 2, 1, 0, 5`，解密出來的即是 flag

SEKAI{T1m3_15_pr3C10u5_s0_Enj0y_ur_L1F5!!!}

## Reverse
### Matrix Lab 1
![](https://i.imgur.com/DZDT7SD.png)

java reverse 挑戰

使用工具 ghidra 外加 [javadecompilers](http://www.javadecompilers.com/) 輔助

翻譯如下:

Sekai.main
```java=
public static void main(final String[] array) {
    if (input.length() != 43) {
        return;
    }
    if (input.substring(0, 6).equals("SEKAI{") && input.substring(input.length() - 1).equals("}")) {
        assert input.substring(6, input.length() - 1).length() == 6 * 6;
        if (solve(input.substring(6, input.length() - 1))) {
            System.out.println("Congratulations, you got the flag!");
        }
    }
}
```

可以看到，首先會檢查輸入的開頭結尾部分是否為 flag 格式，是的話會進入 solve 函式
此外，也可知 flag 中間部分長度為 36

Sekai.solve
```java=
public static boolean solve(final String s) {
    final char[][] transform = transform(s.toCharArray(), 6);
    for (int i = 0; i <= 3; ++i) {
        for (int j = 0; j < 5 - 2 * i; ++j) {
            final char c = transform[i][i + j];
            transform[i][i + j] = transform[5 - i - j][i];
            transform[5 - i - j][i] = transform[5 - i][5 - i - j];
            transform[5 - i][5 - i - j] = transform[i + j][5 - i];
            transform[i + j][5 - i] = c;
        }
    }
    
    objectRef = "oz]{R]3l]]B#50es6O4tL23Etr3c10_F4TD2";
    pcVar3 = Sekai.getArray(transform,0,5);
    pSVar4 = Sekai.encrypt(pcVar3,2);
    pcVar3 = Sekai.getArray(transform,1,4);
    pSVar5 = Sekai.encrypt(pcVar3,1);
    pcVar3 = Sekai.getArray(transform,2,3);
    pSVar6 = Sekai.encrypt(pcVar3,0);
    pSVar4 = makeConcatWithConstants(pSVar4,pSVar5,pSVar6);
    return objectRef.equals(pSVar4);
}
```

首先，會將輸入部分做 transform 轉換，接著會將轉換後字串做重新排列，再來就會進行 getarray 及 encrypt，最後組合後會檢查是否等於 objectRef 所存的字串

Sekai.transform, Sekai.getArray, Sekai.encrypt:
```java=
public static String encrypt(final char[] array, final int n) {
    final char[] data = new char[12];
    int n2 = 5;
    int length = 6;
    for (int i = 0; i < 12; ++i, ++i) {
        data[i] = array[n2--];
        data[i + 1] = array[length++];
    }
    for (int j = 0; j < 12; ++j) {
        data[j] ^= (char)n;
    }
    return String.valueOf(data);
}

public static char[] getArray(final char[][] array, final int n, final int n2) {
    final char[] array2 = new char[12];
    int n3 = 0;
    for (int i = 0; i < 6; ++i) {
        array2[n3] = array[n][i];
        ++n3;
    }
    for (int j = 0; j < 6; ++j) {
        array2[n3] = array[n2][5 - j];
        ++n3;
    }
    return array2;
}

public static char[][] transform(final char[] array, final int n) {
    final char[][] array2 = new char[n][n];
    for (int i = 0; i < n * n; ++i) {
        array2[i / n][i % n] = array[i];
    }
    return array2;
}
```

基本上，每一步都是可逆的，可用以下腳本破解

```python=

def decrypt(string, num):
	str2 = bytes([ord(c)^num for c in string])
	dec = [None for _ in range(12)]
	for i in range(6):
		dec[5-i] = str2[2*i]
		dec[6+i] = str2[2*i+1]
	return dec

def notgetarray(arr1, arr2, arr3):
	oriarr = [[None for __ in range(6)] for _ in range(6)]
	arr = [arr1, arr2, arr3]
	for i in range(3):
		aarr = arr[i]
		for j in range(6):
			oriarr[i][j] = aarr[j]
		for j in range(6):
			oriarr[5-i][5-j] = aarr[j+6]
	return oriarr

def backtotransform(arr):
	for i in range(3, -1, -1):
		for j in range(4 - 2*i, -1, -1):
			c = arr[i+j][5-i]
			arr[i+j][5-i] = arr[5-i][5-i-j]
			arr[5-i][5-i-j] = arr[5-i-j][i]
			arr[5-i-j][i] = arr[i][i+j]
			arr[i][i+j] = c
	return arr

def untransform(arr):
	newarr = [None for _ in range(6*6)]
	for i in range(6*6):
		newarr[i] = arr[i//6][i%6]
	return newarr

midpart_enc = "oz]{R]3l]]B#50es6O4tL23Etr3c10_F4TD2"
assert len(midpart_enc) == 12 * 3

psvar4 = midpart_enc[:12]
psvar5 = midpart_enc[12:24]
psvar6 = midpart_enc[24:]

pcvar2_1 = decrypt(psvar4, 2)
pcvar2_2 = decrypt(psvar5, 1)
pcvar2_3 = decrypt(psvar6, 0)

oriarr = notgetarray(pcvar2_1, pcvar2_2, pcvar2_3)
oriarr2 = backtotransform(oriarr)
flag = untransform(oriarr2)

print(b"SEKAI{" + bytes(flag) + b"}")
```

SEKAI{m4tr1x_d3cryP710N_15_Fun_M4T3_@2D2D!}