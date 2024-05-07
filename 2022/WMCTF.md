# WMCTF 2022 writeup
###### tags: `CTF`

## PWN/Ubuntu
![](https://i.imgur.com/GmO6y3i.png)

解開後的檔案中有一個 `start.sh`，內容如下
```bash=
#!/bin/sh

qemu-system-x86_64  \
 -m 512M \
-cpu kvm64,+smep,+smap \
-smp 4 \
-kernel ./bzImage \
-append "console=ttyS0 nokaslr quiet" \
-initrd rootfs.img \
-monitor /dev/null \
 -nographic\
```

可以看到有使用到 `bzImage` 和 `rootfs.img` 檔案，先查看 `rootfs.img` 中有什麼檔案

![](https://i.imgur.com/SCiBlbM.png)

可以看到其中有一個 `flag` 檔案，嘗試直接讀取看內容

![](https://i.imgur.com/Hn9SOtN.png)

看起來這題應該是要用 buffer overflow 之類的方式解，但題目沒設計好，所以能直接看到 flag

flag{WTF_stack0verf1ow_in_2022}

## MISC/Checkin
![](https://i.imgur.com/LuY6NXW.png)

簽到題

WMCTF{Welcode_wmctf_2022!!!!have_fun!!}