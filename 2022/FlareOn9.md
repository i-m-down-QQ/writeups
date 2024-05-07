# FlareOn9
###### tags: `CTF`

## 01 - Flaredle
![](https://i.imgur.com/xXjQuwT.png)

打開來後，發現是一個猜字的網頁

查看程式碼的 script.js，發現當猜的字和 `rightGuessString` 相同時就會給出 flag

```javascript=
if (guessString === rightGuessString) {
    let flag = rightGuessString + '@flare-on.com';
    toastr.options.timeOut = 0;
    toastr.options.onclick = function() {alert(flag);}
    toastr.success('You guessed right! The flag is ' + flag);

    guessesRemaining = 0
    return
}
```

而 rightGuessString 是 words 的 index 57

```javascript=
import { WORDS } from "./words.js";

const NUMBER_OF_GUESSES = 6;
const WORD_LENGTH = 21;
const CORRECT_GUESS = 57;
let guessesRemaining = NUMBER_OF_GUESSES;
let currentGuess = [];
let nextLetter = 0;
let rightGuessString = WORDS[CORRECT_GUESS];
```

將 word 陣列丟到瀏覽器上執行後，取 index 57，得到 `flareonisallaboutcats`

![](https://i.imgur.com/uHghbCb.png)

正確，拿 flag

![](https://i.imgur.com/Mjdt1oO.png)

flareonisallaboutcats@flare-on.com

## 02 - Pixel Poker
![](https://i.imgur.com/YuteOxj.png)

根據題目說明，裡面是一個點 pixel 的遊戲，只要點中指定的 pixel 即可獲得 flag，有 10 次機會，失敗會獲得以下字串並結束視窗

![](https://i.imgur.com/dlIk0vl.jpg)

因此可以透過找輸出字串的方式找到處理的函數

defined string -> Womp Womp -> reference -> show reference to address，可以找到 00401457 的位置

![](https://i.imgur.com/MIPy7V7.png)

因此就可以找到 FUN_004012c0 這個函數，看起來是判斷一些選單的函式，應該也有判斷點到的位置的相關處理程式

看起來是在 74 行這個判斷函式

![](https://i.imgur.com/Kpcd3T8.png)

由於位置一般來說不容易點到，因此嘗試將其對應的 JNZ 改成 JZ，就可以變成當沒有點到特定位置時就能拿到 flag

![](https://i.imgur.com/w5MnuPL.png)

![](https://i.imgur.com/pC0Hw0C.png)

執行後隨便點，即可拿到 flag

![](https://i.imgur.com/1HqfuPy.png)

w1nN3r_W!NneR_cHick3n_d1nNer@flare-on.com

