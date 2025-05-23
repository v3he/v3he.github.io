---
title: NahamCon CTF 2023 - Fetch
date: 2023-06-19 09:00:00 +0800
categories: [NahamCon CTF 2023, Forensics]
tags: [wim, pecmd, forensics]
media_subpath: /assets/img/ctfs/nahamcon2023/fetch/
image:
  path: fetch.jpg
---

## Info

| Name                                                                 | Difficulty | Author                                          |
|----------------------------------------------------------------------|------------|:------------------------------------------------|
| [Fetch](https://github.com/v3he/ctfs/tree/master/nahamcon2023/fetch) | Easy       | [JohnHammond](https://twitter.com/_johnhammond) |

> "Gretchen, stop trying to make fetch happen! It's not going to happen!" - Regina George
{: .prompt-info }

## Recon

For this challenge we are provided with a file called `fetch.7z`, the first thing to do is to open it, for this we use the 7z utility.

```bash
$ 7z x fetch.7z 

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,32 CPUs Intel(R) Core(TM) i7-7700K CPU @ 4.20GHz (906E9),ASM,AES-NI)

Scanning the drive for archives:
1 file, 6090097 bytes (5948 KiB)

Extracting archive: fetch.7z
--
Path = fetch.7z
Type = 7z
Physical Size = 6090097
Headers Size = 114
Method = LZMA2:6m
Solid = -
Blocks = 1

Everything is Ok

Size:       6144852
Compressed: 6090097
```
{: .nolineno }

## Extraction

When we extract it, we find a new file called fetch, if we analyze it, we see that it is a `Windows imaging (WIM)`.

> A Windows Imaging (WIM) image is a file-based disk image format used by Microsoft to encapsulate the contents of a Windows installation, including files, folders, and system configurations.
{: .prompt-info }

```bash
$ file fetch
fetch: Windows imaging (WIM) image v1.13, XPRESS compressed, reparse point fixup
```
{: .nolineno }

We can mount the WIM image, or we can use 7z again to directly extract the contents.

```bash
$ 7z x fetch   

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,32 CPUs Intel(R) Core(TM) i7-7700K CPU @ 4.20GHz (906E9),ASM,AES-NI)

Scanning the drive for archives:
1 file, 6144852 bytes (6001 KiB)

Extracting archive: fetch
--       
[...]
Everything is Ok

Folders: 1
Files: 272
Size:       7337140
Compressed: 6144852
```
{: .nolineno }

This extracts a lot of files, mostly `.pf`, now the question is what we do with this, how we look for the flag here.

### PECmd

For this part we have to move to a Windows machine, since we are going to make use of [PECmd](https://github.com/EricZimmerman/PECmd). So we extract the `WIM` again in a directory called `fetch` and execute the following:

```console
C:\Users\batman\Downloads>PECmd.exe -d fetch > output
```
{: .nolineno }

Once we have the complete output, we search the file to see if the string `FLAG` exists.
The search is case sensitive, so it is necessary to capitalize it, otherwise no results will be returned.

```console
C:\Users\batman\Downloads>type output | findstr /c:"FLAG"
61: \VOLUME{01d89fa75d2a9f57-245d3454}\USERS\LOCAL_ADMIN\DESKTOP\FLAG{97F33C9783C21DF85D79D613B0B258BD}
```
{: .nolineno }

## Final Thoughts

An interesting challenge, it is true that I have been a while trying to understand what to do with the files extracted from the WIM and I have been a little frustrated, but anyways a different and entertaining challenge.