---
title: CakeCTF Writeup
tags: Writeup , CTF , Security
---

# Crypto
## Frozen cake

:::spoiler task.py
```python
from Crypto.Util.number import getPrime
import os

flag = os.getenv("FLAG", "FakeCTF{warmup_a_frozen_cake}")
m = int(flag.encode().hex(), 16)

p = getPrime(512)
q = getPrime(512)

n = p*q

print("n =", n)
print("a =", pow(m, p, n))
print("b =", pow(m, q, n))
print("c =", pow(m, n, n))
```
:::

:::info
Known $m^{n},\ m^{p},\ m^{q},\ n$
:::

Given :
$a = m^{p}\ mod\ n$
$b = m^{q}\ mod\ n$
$c = m^{n}\ mod\ n$

$$
\displaystyle{
m^{n} \\
\equiv m^{n - \phi(n)}\ mod\ n\ \equiv m^{n - (\underline{n - (p + q) + 1})_{\phi(n)}}\\
\equiv m^{(p + q) - 1}\\
\rightarrow \frac{m^{n}}{m^{p} * m^{q}} \equiv m^{-1}}
$$


```python
from gmpy2 import invert
from Crypto.Util.number import long_to_bytes

exec(open("./output.txt" , "r").read())

print(long_to_bytes(invert(c * invert(a * b , n) , n)))
```


## Brand New Crypto
:::spoiler task.py
```python
from Crypto.Util.number import getPrime, getRandomRange, inverse, GCD
import os

flag = os.getenv("FLAG", "FakeCTF{sushi_no_ue_nimo_sunshine}").encode()

def keygen():
    p = getPrime(512)
    q = getPrime(512)

    n = p * q
    phi = (p-1)*(q-1)

    while True:
        a = getRandomRange(0, phi)
        b = phi + 1 - a

        s = getRandomRange(0, phi)
        t = -s*a * inverse(b, phi) % phi

        if GCD(b, phi) == 1:
            break
    return (s, t, n), (a, b, n)

def enc(m, k):
    s, t, n = k
    r = getRandomRange(0, n)

    c1, c2 = m * pow(r, s, n) % n, m * pow(r, t, n) % n
    assert (c1 * inverse(m, n) % n) * inverse(c2 * inverse(m, n) % n, n) % n == pow(r, s - t, n)
    assert pow(r, s -t ,n) == c1 * inverse(c2, n) % n
    return m * pow(r, s, n) % n, m * pow(r, t, n) % n

def dec(c1, c2, k):
    a, b, n = k
    return pow(c1, a, n) * pow(c2, b, n) % n

pubkey, privkey = keygen()
c = []
for m in flag:
    c1, c2 = enc(m, pubkey)
    assert dec(c1, c2, privkey)

    c.append((c1, c2))

print(pubkey)
print(c)
```
:::


:::info
Known : $c_1 ,\ c_2 ,\ s ,\ t ,\ n$
:::

$c_1 = m * r^{s}\ mod\ n$
$c_2 = m * r^{t}\ mod\ n$

As $r$ is a random number , we should use some formula to eliminate $r$

$$
\displaystyle{\\
c_1^{t} = m^{t} * r^{st}\ mod\ n\\
c_2^{s} = m^{s} * r^{st}\ mod\ n\\
\frac{c_1^{t}}{c_2^{s}} \equiv m ^{s - t}\ (mod\ n)\\}
$$

Then we can write the solve script
```python
#!/usr/bin/python3

from Crypto.Util.number import getRandomRange , long_to_bytes , inverse
from output import *

def enc(m, k):
    s, t, n = k
    r = getRandomRange(0, n)

    c1, c2 = m * pow(r, s, n) % n, m * pow(r, t, n) % n
    assert (c1 * inverse(m, n) % n) * inverse(c2 * inverse(m, n) % n, n) % n == pow(r, s - t, n)
    assert pow(r, s -t ,n) == c1 * inverse(c2, n) % n
    return m * pow(r, s, n) % n, m * pow(r, t, n) % n

c1 = [i[0] for i in c]
c2 = [i[1] for i in c]
s , t , n = pubkey

res = ""
for i in range(len(c)):
    c2s = pow(c2[i] , s , n)
    c1t = pow(c1[i] , t , n)
    mst = c2s * inverse(c1t , n) % n
    for m in range(0x20 , 0x80):
        if mst == pow(m , s , n) * inverse(pow(m , t , n) , n) % n:
            res += chr(m)
            print(res)
            break
```

# Reverse

# Web
## CakeGEAR

:::spoiler index.php
```php
<?php
session_start();
$_SESSION = array();
define('ADMIN_PASSWORD', 'f365691b6e7d8bc4e043ff1b75dc660708c1040e');

/* Router login API */
$req = @json_decode(file_get_contents("php://input"));
if (isset($req->username) && isset($req->password)) {
    if ($req->username === 'godmode'
        && !in_array($_SERVER['REMOTE_ADDR'], ['127.0.0.1', '::1'])) {
        /* Debug mode is not allowed from outside the router */
        $req->username = 'nobody';
    }

    switch ($req->username) {
        case 'godmode':
            /* No password is required in god mode */
            $_SESSION['login'] = true;
            $_SESSION['admin'] = true;
            break;

        case 'admin':
            /* Secret password is required in admin mode */
            if (sha1($req->password) === ADMIN_PASSWORD) {
                $_SESSION['login'] = true;
                $_SESSION['admin'] = true;
            }
            break;

        case 'guest':
            /* Guest mode (low privilege) */
            if ($req->password === 'guest') {
                $_SESSION['login'] = true;
                $_SESSION['admin'] = false;
            }
            break;
    }

    /* Return response */
    if (isset($_SESSION['login']) && $_SESSION['login'] === true) {
        echo json_encode(array('status'=>'success'));
        exit;
    } else {
        echo json_encode(array('status'=>'error'));
        exit;
    }
}
?>

...

        <script>
         function login() {
             let error = document.getElementById('error-msg');
             let username = document.getElementById('username').value;
             let password = document.getElementById('password').value;
             let xhr = new XMLHttpRequest();
             xhr.addEventListener('load', function() {
                 let res = JSON.parse(this.response);
                 if (res.status === 'success') {
                     window.location.href = "/admin.php";
                 } else {
                     error.innerHTML = "Invalid credential";
                 }
             }, false);
             xhr.withCredentials = true;
             xhr.open('post', '/');
             xhr.send(JSON.stringify({ username, password }));
         }
        </script>
```
:::


We will notice either in localhost and login as godmode or login as admin with a password that known hash if you want to make `$_SESSION['admin']` true.
But we can't actually get the origin password through rainbow table.

But there is a cool feature in PHP about switch case
As we know PHP's low comparison is weird as what switch case using.
So if we send a true to comparison with string then it will return true.

```php
>>> true == "123"
=> true
```

```php
#!/usr/bin/php
<?php

$test = True;

switch($test){
    case "godmode":
        echo "You are god" . PHP_EOL;
        break;
    case "testmode":
        echo "You are a test" . PHP_EOL;
        break;
}
```

Result is echo "You are god"

So we just need to send a json like `{"username" : true , "password" : "123"}`

BTW we can't just use curl or Firefox resend packet to solve this challenge :(


