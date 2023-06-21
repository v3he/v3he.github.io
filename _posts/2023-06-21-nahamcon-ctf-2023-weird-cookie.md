---
title: NahamCon CTF 2023 - Weird Cookie
date: 2023-06-21 09:00:00 +0800
categories: [NahamCon CTF 2023, Binary Exploitation]
tags: [binary-exploitation, pwn, buffer-overflow, gdb]
img_path: /assets/img/ctfs/nahamcon2023/weird-cookie/
image:
  path: weird-cookie.jpeg
---

## Info

| Name                                                                               | Difficulty   | Author        |
|------------------------------------------------------------------------------------|--------------|:--------------|
| [Weird Cookie](https://github.com/v3he/ctfs/tree/master/nahamcon2023/weird-cookie) | Medium       | @M_alpha#3534 |

> Something's a little off about this stack cookie...
{: .prompt-info }

## Analysis

For this challenge we are provided with two files:

- `weird_cookie` is the application that we have to breach
- `libc-2.27.so` is the exact version of libc that the host is using

We will start by looking at the security of the binary, for this we will make use of `checksec`, which you can download directly or use it if you have [pwntools](https://github.com/Gallopsled/pwntools) installed.

```bash
$ pwn checksec weird_cookie
[*] '/home/kali/ctf/nahamcon2023/weird-cookie/weird_cookie'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
{: .nolineno }

The main thing about the above information is the `NX` entry. NX stands for No eXecute. This is a security feature used by the operating system to prevent certain areas of memory from being executed. When NX is enabled, it means the stack memory is non-executable, which can help to prevent the execution of injected shellcode during a buffer overflow attack.

`ASLR (Address Space Layout Randomization)` is also enabled, so it looks like we have to do some kind of `ret2libc` technique to get remote execution on the machine.

> A ret2libc (return to libc, or return to the C library) attack is one in which the attacker does not require any shellcode to take control of a target, vulnerable process.
{: .prompt-info }

## Adjusting the Binary

As we know that the binary uses the libc version that is provided with the challenge, what we are going to do first is to adjust the binary to use this libc version instead of the one that our machine has, this way, at the time of the exploitation and debugging we will have the correct offsets since they will be the same as the version that runs on the server. We are currently using `/lib/x86_64-linux-gnu/libc.so.6`

```bash
$ ldd weird_cookie 
        linux-vdso.so.1 (0x00007fff1b1f1000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fd67e826000)
        /lib64/ld-linux-x86-64.so.2 (0x00007fd67ea2a000)
```
{: .nolineno }

We are going to make use of [pwninit](https://github.com/io12/pwninit), a very useful tool that will give us all the base we need to start the exploit, all we have to do is download it and have in the current folder the binary and the libc file.

```bash
$ pwninit                  
bin: ./weird_cookie
libc: ./libc-2.27.so

fetching linker
https://launchpad.net/ubuntu/+archive/primary/+files//libc6_2.27-3ubuntu1.6_amd64.deb
unstripping libc
https://launchpad.net/ubuntu/+archive/primary/+files//libc6-dbg_2.27-3ubuntu1.6_amd64.deb
warning: failed unstripping libc: failed running eu-unstrip, please install elfutils: No such file or directory (os error 2)
setting ./ld-2.27.so executable
symlinking ./libc.so.6 -> libc-2.27.so
copying ./weird_cookie to ./weird_cookie_patched
running patchelf on ./weird_cookie_patched
writing solve.py stub
                                                                                                                                                                  
$ ls -l
total 2208
-rwxr-xr-x 1 kali kali  179152 Jun 21 10:07 ld-2.27.so
-rwxr-xr-x 1 kali kali 2030928 Jun 21 10:06 libc-2.27.so
lrwxrwxrwx 1 kali kali      12 Jun 21 10:07 libc.so.6 -> libc-2.27.so
-rwxr-xr-x 1 kali kali     443 Jun 21 10:07 solve.py
-rwxr-xr-x 1 kali kali   17000 Jun 21 10:06 weird_cookie
-rwxr-xr-x 1 kali kali   21616 Jun 21 10:07 weird_cookie_patched
```
{: .nolineno }

We see that a lot of files have been created. Our new target binary is `weird_cookie_patched`, which is the version that has been adjusted to use libc 2.27, as we can see if we now run the `ldd` command again.

```bash
$ ldd weird_cookie_patched
        linux-vdso.so.1 (0x00007fff1ecb5000)
        libc.so.6 => ./libc.so.6 (0x00007f63b5000000)
        ./ld-2.27.so => /lib64/ld-linux-x86-64.so.2 (0x00007f63b5420000)
```
{: .nolineno }

## Execution

Now that we have the binary to work with, let's run it and see what it does.

```bash
$ ./weird_cookie_patched 
Do you think you can overflow me?
im sure
im sure

Are you sure you overflowed it right? Try again.
share the blog
```
{: .nolineno }

It seems quite simple, it asks for a text input and then returns it to the screen, asks again for another text input and that's the end of the execution.
Let's see what happens if we try to send `100 characters` in the input requests.

```bash
$ ./weird_cookie_patched
Do you think you can overflow me?
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Are you sure you overflowed it right? Try again.
Nope. :(
```
{: .nolineno }

Well, it seems that he didn't like it, this time when sending the input he sent me back a lower amount than the one I sent him, besides he didn't ask for input again, just automatically put `Nope. :(` and close.

```bash
$ echo -n AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA | wc -c                         
64
```
{: .nolineno }

Returned exactly 64 characters, which is probably the buffer size.

## Disassembly With IDA

Now that we have an idea of what the program does, it is time to analyze it statically to see in more depth what it is doing.

In my case I am going to use [IDA Free](https://hex-rays.com/ida-free/) but you can use any other like [Ghidra](https://github.com/NationalSecurityAgency/ghidra), [Binary Ninja](https://binary.ninja/) etc. The free version of `IDA` does not allow to see the decompiled code, so maybe with `Ghidra` you would see it easier.

Let's take a quick look from the top and then I'll go deeper into each part.

![IDA Graph Main Function](weird-cookie-ida-graph.png)

It is not very long, but let's go little by little, I will put comments along the code so you can see better what is happening.

### Canary Creation

```bash
mov     rax, cs:printf_ptr          # address of printf
mov     rdx, rax
mov     rax, 123456789ABCDEF1h      # hardcoded value
xor     rax, rdx                    # xor the harcoded value with the address of prinft
mov     [rbp+var_8], rax            # save the result in a variable
mov     rax, [rbp+var_8]
mov     cs:saved_canary, rax        # save the result in saved_canary
```
{: .nolineno }

> Stack Canaries are very simple - at the beginning of the function, a random value is placed on the stack. Before the program executes `ret`, the current value of that variable is compared to the initial: if they are the same, no buffer overflow has occurred.
{: .prompt-info }

It seems that some kind of protection is being implemented imitating what would be a `canary`, for this it uses a hardcoded string xored with the printf address to generate a string that we will see below is used to validate the integrity of the binary.

### First Input

```bash
lea     rax, [rbp+s]                 # [rbp+s] is the buffer where our input is going to be stored
mov     edx, 28h ; '('  ; n          # 28h is 40 in decimal
mov     esi, 0          ; c
mov     rdi, rax        ; s
call    _memset                      # clears the first 40 characters of our buffer
lea     rdi, s          ; "Do you think you can overflow me?"
call    _puts                        # prints the string above to the user
lea     rax, [rbp+s]                 # [rbp+s] is the buffer where our input is going to be stored
mov     edx, 40h ; '@'  ; nbytes     # 40h is 64 in decimal
mov     rsi, rax        ; buf
mov     edi, 0          ; fd
call    _read                        # stores 64 bytes of our input into the buffer
lea     rax, [rbp+s]
mov     rdi, rax        ; s
call    _puts                        # prints our input again to the console
```
{: .nolineno }

It is clearly seen that originally `40 characters` are cleared in the buffer but then when the user input is requested, `60` are stored! It looks like an `buffer overlow` but very limited in size.

I'm going to give you a little sneak peak of what we'll see later when we debug the program. This is what the memory looks like when we enter `40` characters as input.

![First Input Stack](first-input-stack.png)

