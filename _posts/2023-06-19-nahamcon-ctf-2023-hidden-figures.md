---
title: NahamCon CTF 2023 - Hidden Figures
date: 2023-06-19 09:00:00 +0800
categories: [NahamCon CTF 2023, Web]
tags: [web, cyber-chef, steganography, binwalk]
media_subpath: /assets/img/ctfs/nahamcon2023/hidden-figures/
image:
  path: hidden-figures.jpeg
---

## Info

| Name                                                                                   | Difficulty | Author                                          |
|----------------------------------------------------------------------------------------|------------|:------------------------------------------------|
| [Hidden Figures](https://github.com/v3he/ctfs/tree/master/nahamcon2023/hidden-figures) | Easy       | [JohnHammond](https://twitter.com/_johnhammond) |

> Look at this fan page I made for the Hidden Figures movie and website! Not everything is what it seems!
{: .prompt-info }

## Recon

When we enter the page we find a static page with nothing but images, text and a weird javascript file.

![Main Page](main-page.png)

The most striking thing is that all the images are loaded through a bunch of base64 code.

![Base64 Source Code](base64.png)

## Extracting the Flag

### CyberChef

After looking around and not seeing anything else suspicious apart from the base64, let's see if we can extract anything from it using [CyberChef](https://gchq.github.io/CyberChef/).

![CyberChef Flag](cyber-chef.png)

Perfect! one of the images contained the flag.

### Binwalk

Before trying the extraction with CyberChef, I tried with binwalk -e without any result, so far I am not sure why it could be, maybe the embedded file might be fragmented or stored in a non-contiguous manner within the input file.

But with this other way of using binwalk, we can successfully extract the flag just like with CyberChef.

```bash
$ binwalk -D=".*" image.jpeg       

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             JPEG image data, JFIF standard 1.01
15486         0x3C7E          PNG image, 1851 x 174, 8-bit/color RGB, non-interlaced
15527         0x3CA7          Zlib compressed data, default compression

$ file 3C7E 
3C7E: PNG image data, 1851 x 174, 8-bit/color RGB, non-interlaced
```
{: .nolineno }

## Final Thoughts

It was not a bad challenge, but I was expecting something more web, it was really a steganography challenge, but I learned more binwalk options and how to extract files with CyberChef.