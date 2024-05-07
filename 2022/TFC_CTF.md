# TFC CTF
###### tags: `CTF`

# Crypto
## MAFIOSO

![](https://i.imgur.com/59O2eLM.png)

通靈出是 SHA 類型的

丟到 [CrackStation](https://crackstation.net/) 解

![](https://i.imgur.com/Z1gGi8p.png)

TFCCTF{snitchesgetstitches}

## BASIC

![](https://i.imgur.com/aVsFPtM.png)

- 丟到 dcode.fr 的 [cipher identifier](https://www.dcode.fr/cipher-identifier) 分析可能的加密方式。

    ![](https://i.imgur.com/3LlyqrY.png)

- 丟 Base91 就解出來了。

    ![](https://i.imgur.com/KENjxST.png)

## OBSUCRE

![](https://i.imgur.com/Z6vLchq.png)

反白肉眼看囉

![](https://i.imgur.com/kLPCem9.png)

# Foresics
## BBBBBBBBBB

查看 strings，發現有很多 10 個 `B` 的字串，跟題目名稱一樣，猜測是要移除這些字串

```bash=
strings chell.jpg | grep BBBBBBBBBB
```

![](https://i.imgur.com/llOVPrc.png)

使用 sed 處理

```bash=
sed -i 's/BBBBBBBBBB//g' chell_new.jpg
```

用圖片瀏覽器查看，看到 flag

![](https://i.imgur.com/QGRfybZ.png)

TFCCTF{the_fl4g_1s_th3_w4y}

# Reverse
## SOURCE
直接丟到IDA或Ghidra Dissemble就有Flag了(puts func)
![](https://i.imgur.com/qvuBPsp.png)
![](https://i.imgur.com/9mwU0Dk.png)
TFC{3v3ryth1ng_1s_0p3n_5ourc3_1f_y0u try_h4rd_3n0ugh}

## COLORS



### The app connects to a server to upload the data. What is the URL?

用 7zip 解開 color.ipa
到 `Payload\colors.app\color`，這是 ios 會執行的 binary

![](https://i.imgur.com/rCmyoFD.png)

format: Mac OS X Mach-O
language: AARCH64:LE:64:AppleSilicon

在 defined string 可以找到一個 URL，推測是這題的解

![](https://i.imgur.com/LBymKcq.png)



# Misc
## Rules
![](https://i.imgur.com/6WFaP3i.png)

plain sight
![](https://i.imgur.com/TgUdDY5.png)

## DISCORD SHENANIGANS V2
1. bot提示要從私訊觸發

    ![](https://i.imgur.com/k6Va8qj.png)
Look, I'm not supposed to help you. But, what you need to do is to exfiltrate the flag

2. `#announcement` 有一張看起來一臉很可疑的圖片

    ![](https://i.imgur.com/XwdYuEO.png)

3. 將它base64 encode 再 decode
    - base64 預設 encode 會每 76 個字元做 wrapping，中間會加空格，所以要保持原始資料的內容做 encode 要加 `-w0`
    - [exfiltrate介紹](https://book.hacktricks.xyz/generic-methodologies-and-resources/exfiltration#copy-and-paste-base64)

    ![](https://i.imgur.com/UiMczFI.png)

    ![](https://i.imgur.com/71iBPZK.png)
TFCCTF{h1dd3n_1n_pl4in_br3ad!...1_m3an_s1gh7}



# Web
## ROBOTS AND MUSIC
- 很明顯是要你看 robots.txt(?

    ![](https://i.imgur.com/PaWnPT7.png)

- 可以發現 Disallow 的 path。

    ![](https://i.imgur.com/MSb9dCz.png)

- 連進去就拿到 FLAG 了~

    ![](https://i.imgur.com/ENjQ9eH.png)

## PONG
- 簡單的 cmd injection。

    ![](https://i.imgur.com/KbDmozZ.png)

    ![](https://i.imgur.com/6VS5rag.png)

## ARE YOU THE ADMIN?
- 這題看起來小複雜，但其實超簡單。
- index.tsx 重點是 render 那邊，可以看到 input username 後按下 create 按鈕會 call create 那個 async function，然後會 POST 一個 Json object 到 api/auth。
- 要拿到 flag 的條件就是 isAdmin 判斷為 ture。
```react=
const Home: NextPage<Props> = ({ users }) => {
  const [username, setUsername] = useState("");

  const router = useRouter();

  const create = async () => {
    await fetch("/api/auth", {
      headers: {
        "Content-Type": "application/json",
      },
      method: "POST",
      body: JSON.stringify({
        username,
      }),
    });
    await router.replace(router.asPath);
  };

  return (
    <div>
      <div>Create user:</div>
      <input
        value={username}
        onChange={(event) => setUsername(event.target.value)}
      />
      <button onClick={create}>Create</button>
      <div>Users:</div>
      {users.map((user) => (
        <div key={user.id}>
          <div>Username: {user.username}</div>
          <div>Is admin? {user.isAdmin ? "yes" : "no"}</div>
          {user.isAdmin && <div>{user.flag}</div>}
        </div>
      ))}
    </div>
  );
};
```
- auth.ts 可以看到他就是直接抓 req.body，也就是我們前面按下 create 按鈕丟出的 Json object，然後用 prisma 這個 [ORM db](https://ithelp.ithome.com.tw/articles/10234820) 在 user table create 一筆 user 資料。
```react=
import { NextApiRequest, NextApiResponse } from "next";
import { prisma } from "../../globals/prisma";

export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse
) {
  const body = req.body;
  await prisma.user.create({
    data: body,
  });
  return res.status(200).end();
}
```
- db schema 長這樣。
```react=
generator client {
  provider = "prisma-client-js"
}

datasource db {
  provider = "sqlite"
  url      = "file:./app.db"
}

model User {
  id       String  @id @default(uuid())
  username String
  isAdmin  Boolean @default(false)
}
```

- 所以很明顯就是在 index.txs 在 call api/auth 送出 Json object 時多加一個 isAdmin:true 的 attribute，就可以在 db create 一筆 {uuid, \<username\>, true} 的資料，就可以拿到 flag 了。

    ![](https://i.imgur.com/8slbD5i.png)
    
    ![](https://i.imgur.com/wfyTZG0.png)


## DEEPLINKS

dirsearch 掃一遍

![](https://i.imgur.com/1zo3KUy.png)

找到 `.well-known/apple-app-site-association` 路徑

http://01.linux.challenges.ctf.thefewchosen.com:60610/.well-known/apple-app-site-association

打開後就是 flag

![](https://i.imgur.com/PapaAuG.png)

TFCCTF{4ppl3_4pp_51t3_4550c14t10n}

# PWN

## Random

![](https://i.imgur.com/eITHrQ7.png)

if insert 1->normal function
else if insert 1337->FLAG!

![](https://i.imgur.com/NVcC6AA.png)


TFCCTF{Th3r3_w3r3_m0r3_0pt10n5_4ft3r_4ll!}

