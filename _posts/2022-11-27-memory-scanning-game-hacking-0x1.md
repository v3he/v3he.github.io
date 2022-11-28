---
title: Memory Scanning & EXP/Gold Hacking [0x1]
date: 2022-11-27 11:00:00 +0800
categories: [Game Hacking, Tutorials]
tags: [cheat-engine, game-hacking, sekiro]
img_path: /assets/img/game-hacking/101/
---

In this game hacking series, I'm going to try to fulfill the dream of every kid when he was little, "HACK A GAME!".

![Hackerman](https://media.giphy.com/media/3knKct3fGqxhK/giphy.gif)

## Introduction

> Disclaimer: The material on this site is purely educational, under no circumstances use hacks when you can influence the gameplay of other people, always do it at your own risk and in offline and single player games.
{: .prompt-info }

Ok, so what is the plan, first of all I will say that in order to follow this tutorial, as basic as it is, it is necessary to have a basic knowledge about [Assembly](https://en.wikipedia.org/wiki/Assembly_language) mostly.

For the first posts we will make use of [Cheat Engine](https://www.cheatengine.org/) to manipulate the game memory and do whatever we want with it. Once we advance we will use a technique called [DLL Injection](https://en.wikipedia.org/wiki/DLL_injection) to manipulate the memory with the data that we extract from Cheat Engine.

Without further ado, let's get started! and the game we are going to use as target is [Sekiro: Shadows Die Twice](https://www.sekirothegame.com/es) in its 1.05 version, although it doesn't really matter the version other than that certain memory addresses may change.

Let's open Sekiro and Cheat Engine to start!

![Sekiro](https://media.giphy.com/media/1UUZxXPoguNdaD6P8B/giphy.gif)

## Process Attach

Move around a bit, explore the game, feel comfortable with the mechanics and everything the game has to offer. Once you think it's time, open Cheat Engine and click the computer icon on the top left corner and select `sekiro.exe` in the process explorer window.

![Process Selector](process-selector.png)

Well now that we have the process selected, before continuing we are going to make sure that we have the debugger options configured correctly, for this we go to `Edit -> Settings`, select `Debugger Options` and check `Use VEH Debugger`.

![Debugger Options](debugger-options.png)

## Infinite Money 💰

Let's start with simple things, such as changing the amount of gold that our character has so that from the beginning of the game we can buy everything we want.

![Rich](https://media.giphy.com/media/SsTcO55LJDBsI/giphy.gif)

After advancing the initial part of the game and killing a few enemies, I start in my case with a total of `100 gold`.

![Current Gold](initial-gold.png)

The first thing we have to do to modify the gold, is to know where the game is storing this value in memory. For this, the Cheat Engine's memory search engine comes into play. To make things easier I advance you that Sekiro saves the gold in a variable of type `4 Bytes`, this can vary in each game and it is necessary to take it into account at the time of looking for the values.

What we have to do is to enter the data we know, first, we indicate in the `Value` field the current value of gold, in the `Scan Type` we must indicate `Exact Value`, since we will always control the amount of gold we have, so the search is faster. And finally, as I said, we will indicate `4 Bytes` in the `Value Type` field. Then click `First Scan`.

(When you are asked to activate the debugger simply click yes)

![First Scan](initial-scan.png)

The first search shows a lot of results, so we will kill some more enemies and get some more gold to do another search.

Well, let's do the scan again but changing the previous `Value` field by the updated amount of gold, in my case 111 and click on `Next Scan`! very important not to click on New Scan or we would start the process again.

![Second Scan](second-scan.png)

Great! this time the number of results is minimal and we can now manually look at which of these addresses has the current value of our gold.

> If your results are still too many perform the same process over and over again until you narrow down the list to a manageable number.
{: .prompt-info }

Select all addresses and `Right Click -> Add selected addresses to the address list`.

Once all the addresses are in our addresslist, what we have to do is to check the `Active` checkbox one by one, with this what we do is to freeze the value of this one, so if when we kill an enemy and looting it we do not get more money and it has remained as it was, it means that this is the address that contains the real money. The others are labels of the graphical interface, like the pause menu, the buy menu... those are places where the money is shown but is not modified.

![Gold Address](gold-address.png)

In my case, almost the last of the addresses was the one that contained the real value of the gold, so I rename it by double clicking on the description field and indicate that it is the address that holds the gold value.

To modify the value as well as the name, just double click on the `Value` column and change the value to `20000` for example.

![Gold Updated Cheat Engine](gold-updated-cheat-engine.png)
![Gold Updated Sekiro Game](gold-updated-sekiro.png)

Great! by opening and closing the menu we can see that the gold counter has been updated and now shows `20000` as expected! Easy right?

> Holds signed 32-bit (4-byte) integers that range in value from -2,147,483,648 through 2,147,483,647
{: .prompt-info }

Do not go crazy when setting gold, as I said before the value is stored in a variable of type 4 Bytes. The maximum value that the variable can store is `2,147,483,647` so if you go too far you can end up with a negative number of money!

## Infinite EXP 🆙
