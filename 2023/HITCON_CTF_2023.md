# HITCON CTF 2023
###### tags: `CTF`

## Welcome

`hitcon{welcome to hitcon ctf 2023}`

## Misc
### (X) HITOJ - Level 1

題目給了一個 sandbox 的 OJ，要 RCE

而根據提供的 github 的 [seccomp](https://github.com/QingdaoU/Judger/blob/newnew/src/rules/general.c)，可以得知有一些 syscall 被擋住了，但是沒有擋讀檔案 (一般來說應該也不能擋)，因此可以嘗試讀取 `getflag` 的 binary，並可以看到它有嘗試做網路連線去其他 server 取資料

後來一直想不到怎麼繞過去，因此到比賽結束後參考別人的 writeup 發現其實裡面的 seccomp 設定與 github 上的不同，沒有阻擋 socket 的 syscall

因此可以依 `getflag` 的邏輯改成 python，即可取得 flag

:::spoiler
```python
import socket

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('0.0.0.0', 321))
    host = socket.gethostbyname('172.12.34.56')
    s.connect((host, 1337))
    s.sendto(b'\x00' * 0x100, (host, 1337))
    data,_ = s.recvfrom(0x100)
    print(data)

try:
    main()
except Exception as e:
    print(e)
```
:::

`hitcon{level1__i_should_not_have_used_whitelist_seccomp:(}`

## forensics
### Not Just usbpcap

[writeup](https://github.com/t510599/My-CTF-Challenges/tree/master/HITCON%20CTF/2023/Not%20Just%20usbpcap)

