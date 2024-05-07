# Maple CTF 2023
###### tags: `祈求CTF大神maple請讓這次INFRA完全不會爆掉:place_of_worship: `

## Rev
### JaVieScript

:::spoiler checker.js
```javascript=
var flag = "maple{";
var honk = {};

async function hash(string) {
	const utf8 = new TextEncoder().encode(string);
	const hashBuffer = await crypto.subtle.digest('SHA-256', utf8);
	const hashArray = Array.from(new Uint8Array(hashBuffer));
	const hashHex = hashArray
	  .map((bytes) => bytes.toString(16).padStart(2, '0'))
	  .join('');
	return hashHex;
  }

async function constructflag() {
	const urlParams = new URLSearchParams(window.location.search);
	var fleg = "maple{";
	for (const pair of urlParams.entries()) {
		honk[pair[0]] = JSON.parse(pair[1]); 
	}

	if (honk.toString() === {}.toString()) {
		fleg += honk.toString()[9];
	}

	if (Object.keys(honk).length === 0) {
		const test = eval(honk.one);
		if (typeof test === 'number' && test * test + '' == test + '' && !/\d/.test(test)) {
			fleg += 'a' + test.toString()[0];
		}

		const quack = honk.two;

		if (quack.toString().length === 0 & quack.length === 1) {
			fleg += 'a' + (quack[0] + '')[0].repeat(4) + 'as';
		}

		const hiss = honk.three;

		if (hiss === "_are_a_mId_FruiT}") {
			fleg += hiss;
		}
	}
	if (await hash(fleg) == "bfe06d1e92942a0eca51881a879a0a9aef3fe75acaece04877eb0a26ceb8710d") {
		console.log(fleg);
	}
}

constructflag();

```
:::

As in the checker code, it read the input from `window.location.search` and parsing to dictionary object. Then it will read the value of `one`, `two`, `three` and do some check. If the check pass, it will add some string into the `fleg` variable, and it will check the hash of the variable will meet the constant value.

So, we can guess that we need to pass all the checks and the concatnated string is the flag we want. Also, it will satisified the hash check.

for the third check, which is the most easiest, it will check the value of `three` is `_are_a_mId_FruiT}`. So the value of `three` must be `_are_a_mId_FruiT}`

Then, the second most easiest, which is the first check. It will assume it is a number type, and it is not satisified the `/\d/` regex. This seems wierd, so it must not a normal number but some cool stuff in JS. After I do some guess and found there is a `NaN` in javascript. It means `Not a Number` but it's type is a number. Also it is sure that it doesn't meet the `/\d/` regex. So this is the thing we want.

For the second check, I have do some test and can't find a thing that satisified this check. So I decided to bruteforce the character it will add into the fleg.

Before the bruteforcing, That's calculate the known flag we have. First, the fleg will be `maple{` in L16. Then in L22, it will add the character of `honk.toString()[9]`, which is `{}.toString()[9]` = `'[object Object]'[9]` = `b`. And in the first check, the flag will add the character of `'a' + test.toString()[0]` = `'a' + 'NaN'[0]` = `aN`

In the second check, the flag will add the character of `'a' + (quack[0] + '')[0].repeat(4) + 'as'` = `a????as`. The `?` is the character we will bruteforce later

In the third check, the flag will add `_are_a_mId_FruiT}`

So, we have the `fleg` as `maple{baNa????as_are_a_mId_FruiT}` and need to bruteforce the `?`

Here is the script:

:::spoiler bruteforce.py
```python
from hashlib import sha256
from tqdm import trange

hash = "bfe06d1e92942a0eca51881a879a0a9aef3fe75acaece04877eb0a26ceb8710d"

for quack in trange(256):
    flag = "maple{baNa" + chr(quack)*4 + "as_are_a_mId_FruiT}"
    if(sha256(flag.encode()).hexdigest() == hash):
        print(flag)
        exit()
print("ERROR")
```
:::

we found the `?` is `n`

`maple{baNannnnas_are_a_mId_FruiT}`

### Actually Baby Rev

After discompiling in ghidra and reading it. It can clean up as following

In the main function it will do 3 checks. If all 3 check pass, it will print the check.

:::spoiler main
```clike
undefined8 main(void)

{
  // initialize variable
  
  init();
  puts(".....");
  printf("> ");
  iVar1 = check1();
    
  if (iVar1 == 1) {
    puts(".....");
    printf("> ");
    iVar1 = check2();
      
    if (iVar1 == 1) {
      puts(".....");
      printf("> ");
      iVar1 = check3();
        
      if (iVar1 == 1) {
        printf("oops you forgot to burp the baby, the baby begins to burp: ");
        print_flag();
        puts(". What a strange choice of a baby\'s first word you wonder...");
        return 0;
      }
    }
  }
  return -1;
}
```
:::

In the check 1, it will read up to 30 characters. And it will do var_add5 or var_add4 according to the input. In this check, the var need to be 127.

:::spoiler check1
```clike
undefined8 check1(void)
{
  // initialize variable
  
  pcVar1 = fgets(local_38,30,stdin);
  if (pcVar1 == (char *)0x0) return -1;
  local_3c = 0;
  sVar3 = strcspn(local_38,"\n");
  local_38[sVar3] = '\0';

  for (i = 0; local_38[i] != '\0'; i = i + 1) {
    ppuVar4 = __ctype_b_loc();
    if (((*ppuVar4)[local_38[i]] & 0x800) == 0) {
      puts("....");
      return -1;
    }
      
    local_10 = local_38[i] + -0x30;
    if (local_10 == 5) {
      var_add5(&local_3c);
    }
    else {
      if (local_10 != 9) {
        puts("...");
        return 0;
      }
      var_add4(&local_3c);
    }
  }
  if (local_3c == 127) return 1;
  return 0;
}
```
:::

So do some math and check one-by-one, it can found that $4*18+5*11 = 127$. So in this check we need to input `9` 18 times and `5` 11 times

In the check2, which is similar to check1. It will read 6 character and do var_add6 or var_add13 according to the input. But in the var value check, it will check var is 1 in mod 3 and mod 5, also, it will check `uVar1 = (uint)(local_1c >> 0x1f) >> 0x1e, (local_1c + uVar1 & 3) - uVar1 == 3`

After reading the assembly of `uVar1 = (uint)(local_1c >> 0x1f) >> 0x1e, (local_1c + uVar1 & 3) - uVar1 == 3`, It can found that it is just checking the last 2 bit of var is `0b11`, which means it will check var is 3 in mod 4

By CRT method, we can know that the var must be in the range of $31 + 60*n$

:::spoiler check2
```clike
undefined8 check2(void)
{
  // initialize variable
  
  pcVar2 = fgets(local_16,6,stdin);
  if (pcVar2 == (char *)0x0) return -1;

  local_1c = 0;
  sVar4 = strcspn(local_16,"\n");
  local_16[sVar4] = '\0';
    
  for (local_c = 0; local_16[local_c] != '\0'; local_c = local_c + 1) {
    ppuVar5 = __ctype_b_loc();
    if (((*ppuVar5)[local_16[local_c]] & 0x800) == 0) {
      puts("The baby did not like that.");
      return 0xffffffff;
    }
    local_10 = local_16[local_c] + -0x30;
    if (local_10 == 4) {
      var_add6(&local_1c);
    }
    else {
      if (4 < local_10) {
  LAB_00401726:
        puts("...");
        return 0;
      }
      if (local_10 == 1) {
        end();
        return 0;
      }
      if (local_10 != 2) goto LAB_00401726;
      var_add13(&local_1c);
    }
  }
    
  if (((local_1c % 3 == 1) &&
      (uVar1 = (uint)(local_1c >> 0x1f) >> 0x1e, (local_1c + uVar1 & 3) - uVar1 == 3)) &&
     (local_1c % 5 == 1)) {
    return 1;
  }
  return 0;
}
```
:::

Same, after do some math stuff, we can found that $13*1+6*3 = 31$, so we need to input `2444` in this check

For check3, which is similar as check1 and check2. It will read 6 character input and do the operating according to the input. But in this time, the var_AtimesB will check whether the var is A. If it isn't, it will return 0 immediately.

:::spoiler check3
```clike
undefined8 check3(void)
{
  // initialize variable
  
    pcVar2 = fgets(local_16,6,stdin);
    if (pcVar2 == (char *)0x0) return -1;
    local_1c = 1;
    sVar4 = strcspn(local_16,"\n");
    local_16[sVar4] = '\0';
    
    for (local_c = 0; local_16[local_c] != '\0'; local_c = local_c + 1) {
      ppuVar5 = __ctype_b_loc();
      if (((*ppuVar5)[local_16[local_c]] & 0x800) == 0) {
        puts("....");
        return -1;
      }
      local_10 = local_16[local_c] + -0x30;
      switch(local_10) {
      case 0:
        iVar1 = var_3times7(&local_1c);
        if (iVar1 == 0) {
          return 0;
        }
        break;
      default:
        puts("....");
        return 0;
      case 3:
        iVar1 = var_1155times2(&local_1c);
        if (iVar1 == 0) {
          return 0;
        }
        break;
      case 6:
        iVar1 = var_21times5(&local_1c);
        if (iVar1 == 0) {
          return 0;
        }
        break;
      case 7:
        iVar1 = var_105times11(&local_1c);
        if (iVar1 == 0) {
          return 0;
        }
        break;
      case 8:
        iVar1 = var_become_3(&local_1c);
        if (iVar1 == 0) {
          return 0;
        }
      }
    }
    if (local_1c == 2310) {
      return 1;
    }
    return 0;
}
```
:::

Because the var_AtimesB has a static sequence, so we just follow it. We will need to input `80673` in this check

So, in summary, we need to input `99999999999999999955555555555` in first check and `2444` in second check. Then, input `80673` in third check.

`maple{th3_b4by_cry1ng_1s_w0rs3_th4n_th1s_r3v3r51ng}`

## Crypto
### Pen and Paper

Really hard working stuff

In this challenge, it generate a 13-digits-long base key as the character space of keystream. Then in the encrypt part, it generate the keystream and add some shift to the plaintext.

:::spoiler source.py
```python
import string
import random

ALPHABET = string.ascii_uppercase


def generate_key():
    return [random.randint(0, 26) for _ in range(13)]


def generate_keystream(key, length):
    keystream = []
    while len(keystream) < length:
        keystream.extend(key)
        key = key[1:] + key[:1]
    return keystream


def encrypt(message, key):
    indices = [ALPHABET.index(c) if c in ALPHABET else c for c in message.upper()]
    keystream = generate_keystream(key, len(message))
    encrypted = []

    for i in range(len(indices)):
        if isinstance(indices[i], int):
            encrypted.append(ALPHABET[(keystream[i] + indices[i]) % 26])
        else:
            encrypted.append(indices[i])

    return "".join(encrypted)


with open("plaintext.txt", "r") as f:
    plaintext = f.read()

key = generate_key()
ciphertext = encrypt(plaintext, key)

with open("ciphertext.txt", "w") as f:
    f.write(ciphertext)

```
:::

So if we get the base key, we can generate the same keystream and do inverse side shift to recover the flag.

To get the base key, we can use [frequency analysis](https://www3.nd.edu/~busiforc/handouts/cryptography/cryptography%20hints.html) and guess some common word and do a known-plaintext attack. As we can get the subkey at the position we cracked, we can mapping to a pre-calculate keystream map which map the current position to the index of base key. So we can found all the base key eventually.

For the frequency analysis part I do it by hand, so there is no any code to demonstrate. But in the flag recovery part, the code will as below

:::spoiler solve.py
```python
# x = generate_keystream([i for i in range(13)], 1984)
# x[pos]
# 214 M -> 9 -> I or A -> 756 -> A
# 320 T -> 6 -> I or A -> 41 -> A
# 515 P -> 8 -> I or A -> 756 -> A
# 691 T -> 3 -> I or A -> 51 -> A
# 982 I -> 4 -> I or A -> 680 -> A
# 1607 V -> 1 -> I or A -> 1583 -> A
# 41 BH -> 5,6 -> ?W (T->I) or ?O (T->A) -> ?O -> 536 -> TO
# 51 IV -> 2,3 -> ?K (T->I) or ?C (T->A) -> 1590 -> AK (T->I) or AC (T->A) -> 0 -> AC
# 74 JN -> 1,2 -> W? (V->I) or O? (V->A) -> 1583 -> O? -> 1590 -> OF
# 125 BW -> 4,5 -> B? (I->I) or T? (I->A) -> 536,680 -> TO
# 155 HZ -> 10,11 -> 1590 -> IJ
# 188 LG -> 7,8 -> ?R (P->I) or ?Z (P->A) -> 756 -> ?R -> OR
# 211 BK -> 6,7 -> I? -> 188 -> IN
# 238 FN -> 9,10 -> B? (M->I) or T? (M->A) -> 756,1590 -> TO
# 337 ER -> 11, 12 -> 1590 -> O? ->
# 351 VB -> 1,2 -> I? (V->I) or A? (V->A) -> 1583 -> A? -> 1590 -> AT
# 364 WY -> 2,3 -> ?N (T->I) or ?F (T->A) -> 1590 -> ON (T->I) or OF (T->A)-> 0 -> OF
# 536 WY -> 5,6 -> ?F -> IF or OF -> 41,125 -> OF
# 680 QV -> 4,5 -> QN (I->I) or IN (I->A) -> IN
# 756 IA -> 8,9 -> BW (PM->II), BO (PM->IA), TW (PM->AI), TO (PM->AA) -> TO
# 906 AA -> 0,1 -> ?N (V->I) or ?F (V->A) -> 1583 -> ?F -> 0 -> OF
# 1038 MZ -> 12,0 -> 0 -> ?N -> 
# 1132 HD -> 10,11 -> 1590 -> IN
# 1196 JZ -> 1,2 -> W? (V->I) or O? (V->A) -> 1583,1590 -> OR
# 1583 DV -> 1,2 -> Q? (V->I) or I? (V->A) -> I? -> 1590 -> IN
# 1590 QMT -> 9,10,11 -> E?? -> 1583,1586 -> I? THE E?? -> IN THE END
# 1737 YZ -> 11,12 -> I? ->
# 13 VVW -> 1,2,3 -> AND
# 0 OJUIMBBQXAMI -> 0-11 -> ?OM?ETITIONS -> COMPETITIONS
# 17 KKVEFNWDMXAG -> 5,6,7,8,9,10,11,12,0,2,3,4 -> CRYPTOG?APHY -> CRYPTOGRAPHY

# wierd 11 known 0,1,2,3,4,5,6,7,8,9,10 guess unknown 12
key = [
    (ord('O')-ord('C'))%26, (ord('V')-ord('A'))%26, (ord('V')-ord('N'))%26, 
    (ord('I')-ord('P'))%26, (ord('I')-ord('A'))%26, (ord('W')-ord('O'))%26, 
    (ord('T')-ord('A'))%26, (ord('L')-ord('O'))%26, (ord('P')-ord('A'))%26, 
    (ord('M')-ord('A'))%26, (ord('M')-ord('N'))%26, (ord('T')-ord('D'))%26, 
    (ord('D')-ord('R'))%26]

# recovery
# chr(((ord(enc_char)-ord('A')) - key[i])%26 + ord('A'))
import string

ALPHABET = string.ascii_uppercase
def generate_keystream(key, length):
    keystream = []
    while len(keystream) < length:
        keystream.extend(key)
        key = key[1:] + key[:1]
    return keystream

def decrypt(message, key):
    indices = [ALPHABET.index(c) if c in ALPHABET else c for c in message.upper()]
    keystream = generate_keystream(key, len(message))
    encrypted = []

    for i in range(len(indices)):
        if isinstance(indices[i], int):
            encrypted.append(ALPHABET[(indices[i] - keystream[i]) % 26])
        else:
            encrypted.append(indices[i])

    return "".join(encrypted)

ciphertext = open("ciphertext.txt").read()
plaintext = decrypt(ciphertext, key)
print(plaintext)
```
:::

The plaintext will tell us `THE FLAG YOU ARE LOOKING FOR IS VIGENEREWITHATWIST.`. Just packing it to the flag format.

`maple{VIGENEREWITHATWIST}`

## Misc
### Feedback Survey

`maple{Baple_Macon}`