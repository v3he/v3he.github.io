---
title: HackTheBox - Backend
date: 2022-08-15 21:00:00 +0800
categories: [HackTheBox]
tags: [api]
img_path: /assets/img/machine/backend/
---

![Backend Machine Info](backend-machine-card.png)

# Port Scan

> script scanning (`-sC`), version scanning (`-sV`), output all formats (`-oA`)
{: .prompt-info }

```bash
$ nmap -sC -sV -oA nmap/backend 10.129.227.148
Nmap scan report for 10.129.227.148
Host is up (0.051s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ea:84:21:a3:22:4a:7d:f9:b5:25:51:79:83:a4:f5:f2 (RSA)
|   256 b8:39:9e:f4:88:be:aa:01:73:2d:10:fb:44:7f:84:61 (ECDSA)
|_  256 22:21:e9:f4:85:90:87:45:16:1f:73:36:41:ee:3b:32 (ED25519)
80/tcp open  http    uvicorn
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     date: Tue, 16 Aug 2022 00:26:46 GMT
|     server: uvicorn
|     content-length: 29
|     content-type: application/json
|     Connection: close
|     {"msg":"UHC API Version 1.0"}
|   HTTPOptions: 
|_http-title: Site doesn't have a title (application/json).
|_http-server-header: uvicorn
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
{: .nolineno }

We can see that you have two ports open, running `ssh` and `http`. We can also see that the http port is running using `uvicorn`
so we can assume that the backend of the application is made with Python.

> Uvicorn is an ASGI web server implementation for Python.
{: .prompt-info }

# Web enumeration

Knowing that it is a web application the first thing we are going to do is to run `gobuster` to see what is the first thing we come across.

```bash
$ gobuster dir -u http://10.129.227.148/ -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt                   
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.227.148/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
[...] Starting gobuster in directory enumeration mode
===============================================================
/docs                 (Status: 401) [Size: 30]
/api                  (Status: 200) [Size: 20]
Progress: 1236 / 220561 (0.56%)
===============================================================
[...] Finished
===============================================================
```
{: .nolineno }

```bash
$ curl http://10.129.227.148/docs
{"detail":"Not authenticated"}

$ curl http://10.129.227.148/api 
{"endpoints":["v1"]}

$ curl http://10.129.227.148/api/v1
{"endpoints":["user","admin"]}

$ curl http://10.129.227.148/api/v1/user/   
{"detail":"Not Found"}

$ curl http://10.129.227.148/api/v1/admin/
{"detail":"Not authenticated"}
```
{: .nolineno }

We can see that for the admin endpoint we need authentication, but the user endpoint simply says not found. Let's launch `feroxbuster` to see if it is possible to enumerate within these endpoints.

> ignore status codes (`-C`), ignore response size (`-S`), methods (`-m`)
{: .prompt-info }

```bash
$ feroxbuster -u http://10.129.227.148/api/v1/user -C 404,405 -m GET,POST -S 4,104

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.129.227.148/api/v1/user
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 [...]
──────────────────────────────────────────────────
200      GET        1l        1w      141c http://10.129.227.148/api/v1/user/1
422     POST        1l        3w      172c http://10.129.227.148/api/v1/user/login
422     POST        1l        2w       81c http://10.129.227.148/api/v1/user/signup
```
{: .nolineno }

```bash
$ feroxbuster -u http://10.129.227.148/api/v1/admin -C 404,405 -m GET,POST -S 4,104

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.129.227.148/api/v1/admin
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 [...]
───────────────────────────┴──────────────────────
401     POST        1l        2w       30c http://10.129.227.148/api/v1/admin/file
```
{: .nolineno }