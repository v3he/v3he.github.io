---
pin: true
title: "Zero to Reentrancy: Day 1 of My Smart Contract Hacking Journey"
date: 2025-05-24 12:00:00 +0200
categories: [Smart Contract Security]
tags: [web3, smart-contracts, solidity, ctf]
media_subpath: /assets/img/smart-contracts/day-1/
description: "From pwning boxes to draining contracts — this post kicks off my transition from traditional cybersecurity to smart contract hacking."
image:
  path: zero-to-reentrancy.jpg
---

## Introduction

It’s been years since I first got into security. I still remember watching *geohot* streaming *OverTheWire* — and I couldn’t understand a single thing on the screen. That moment led me to discover Hack The Box, and from there, I spent countless hours trying to understand things I didn’t even know existed.

I started out in software development, treating security as a side hobby — until I had the chance to go full-time. I specialized in web app security, mostly because CTFs I loved (web and pwn) felt familiar.

All that time, I kept hearing about Bitcoin — this “digital currency” no one really understood. Then came Ethereum, NFTs, and smart contracts… and I never touched any of it.

That changed recently after I read a blog post by [Zellic](https://www.zellic.io/): [The Auditooor Grindset](https://www.zellic.io/blog/the-auditooor-grindset).  
It hit hard. Just like I grew up watching *geohot*, I had also spent years watching [LiveOverflow](https://x.com/LiveOverflow) and [Luna Tong](https://x.com/gf_256) (Zellic’s co-founder). Reading that post — paired with my burnout from repetitive web vulns at work — was the final push.

After a bunch of false starts, I’m finally doing it: diving into smart contract security and documenting the whole journey.

![Here we go](https://media2.giphy.com/media/v1.Y2lkPTc5MGI3NjExc2Zyd2lmM3V5cGlyNm14cGswMmpkeXZxbGUxam92aDg1Z3dpNXhmdyZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/RrVzUOXldFe8M/giphy.gif){: w="300" }

## Where I’m Starting From

I’m not new to hacking, but I’m definitely new to Web3.

Right now, I barely know the basics of Solidity — I’ve skimmed a few contracts, watched some YouTube videos, and poked around with forge. I’ve heard the word *reentrancy* a thousand times, and I know flash loans are a thing… but that’s about it.

I’ve never deployed a contract. I’ve never written a full exploit. I’ve never used Foundry or Hardhat seriously. Most of the tooling is still unfamiliar to me.

So yeah — I’m starting from the very beginning.

Also, let’s be real: I’m not a genius. I learn fast sometimes, but I also get stuck on simple things. Maybe you’ll read this and think, “how did he not get that sooner?” And that’s fine. I’m probably closer to an average learner than a 10x one.

To keep myself accountable (and make this useful for others), I’ll be tracking everything I learn:
- Each vulnerable contract I analyze or exploit
- Each concept I break down (like storage layout, call stack, etc.)
- Tools I test out
- Mistakes I make and how I fix them

This blog is my public notebook — each post builds on the last, and whether it helps one person or a hundred, it’ll be worth it.

## What I’m Aiming For

To be honest, I don’t expect much from this.

I’m not doing this to pivot my career, land a job in Web3, or chase bug bounties (at least not for now). I’m doing this because I want to understand how this stuff works — and because it’s fun to explore something that still feels like magic.

I don’t know where this path will lead, and I’m not chasing any specific end goal.  

That’s it. Curiosity first, everything else later.

![Money](https://media1.giphy.com/media/v1.Y2lkPTc5MGI3NjExNjZjajRtbnR6YjFzdnRnc3BmdTlnN2F4ZmIwY2dwY3JlNm1lZ2x5ayZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/67ThRZlYBvibtdF9JH/giphy.gif){: w="300" }

## The Plan

Alright, here we go — what’s the plan?

Following the advice from [The Auditooor Grindset](https://www.zellic.io/blog/the-auditooor-grindset), the first step is simple: do CTFs. Not just skimming or solving them with writeups, but really digging in and figuring things out by myself.

The first stop is [Damn Vulnerable DeFi V4](https://www.damnvulnerabledefi.xyz/).

No writeups, no spoilers. I won’t be looking at solutions unless I absolutely hit a dead end — and even then, it’ll be for learning, not copying.  

That said, I’m not doing this alone. Like any security researcher in 2025, I’ll be making full use of **ChatGPT (especially GPT-4o)** as a sidekick. But not as a walkthrough machine — it’s here to help me break down concepts, clarify confusion, and explain things I don’t yet understand.

And yes, I’ve explicitly set the rule: **no direct solutions**, even if it “knows” them. The goal is to build understanding, not to collect flags.

I’ll go step-by-step through every challenge, documenting:
- What the contract does
- How I approached breaking it
- What I learned along the way

Let’s see how deep the rabbit hole goes.

## Setup

I’m doing everything on **Windows 11**, but through **WSL** with **Ubuntu 24.04**.

The first steps were simple:

```bash
git clone https://github.com/theredguild/damn-vulnerable-defi
cd damn-vulnerable-defi
```

From there, I just followed the instructions in the [DVDF Readme](https://github.com/theredguild/damn-vulnerable-defi/) to install **Foundry** — the framework used to build and test all the challenges.

If you’re starting from scratch, the setup guide is solid and gets you running with `forge` quickly.

No issues so far, and everything worked out of the box on a fresh WSL setup.

## Tracking Progress

As much as I can, I’ll try to keep track of the time I spend actively working on this — meaning, actual time in front of the computer reading code, writing, debugging, and experimenting.

I won’t be counting the late-night scrolls through audit reports in bed or passive content consumption. This is about focused, hands-on learning — and I want to stay honest with how much time that really takes.

Time itself doesn’t mean much — everyone learns at a different pace. But for me, it’s just a way to stay aware of the effort I’m putting in.  
And who knows — maybe it’ll be useful to you too, if you ever decide to go down the same path.

```js
total_hours_wasted_here = 0.5 // +30 min for setup — let’s go 😎
```

---

That’s it for the intro chapter. If you’ve made it this far — thanks. The next post will dive into the first real challenge: [**Unstoppable**](https://www.damnvulnerabledefi.xyz/challenges/unstoppable/).

Let’s get to it.
