---
layout: post
title: BlackHat MEA 2025 - Multiverse
description: My writeup for a chalenge from BlackHat MEA 2025
tags: [BlackHat MEA 2025, Forensic, Writeup, Blue Team, Autopsy, rclone]
---

Hi guys, I was known about BlackHat MEA 2025 from my brother from PTIT and since I did not register, my brother sent me sample in onder to solve. After solving this is 
my solution.

![image](https://github.com/user-attachments/assets/97658df8-7741-44a3-8f8a-abe13d86a59b)

First, I had a sample which contains some files and directories inside a Windows system, so I opened it on Autopsy:

![image](https://github.com/user-attachments/assets/460d6329-85f5-4d2b-a042-36b509aa7b47)

Based on the sample, I checked in Recent first since I could know which file and how many file were opened: 

![image](https://github.com/user-attachments/assets/1929c064-cca3-40fd-b7cf-4498dca3e8d1)

I scrolled down and I found a zip file which name was in base64 format:

![image](https://github.com/user-attachments/assets/8d8b6878-3bbe-4bf7-8e08-b099ab156bef)

Decoded it and I got the first part of the flag:

![image](https://github.com/user-attachments/assets/015bed44-6905-4e3a-903f-1f9fe69613db)

Next, in the Email field I found a suspicious email: **cattheflag@gmail.com**, I clicked on to see where the email was from and I found inside MFT file there was a 
config file for **rclone**:

![image](https://github.com/user-attachments/assets/30dddbbf-7fd6-45d5-9572-66e4b2baea88)

In short, **rclone** is an open-source command-line program to manage cloud storages and if you want to manage any type of cloud storage, you just create a config file 
like this:

![image](https://github.com/user-attachments/assets/251a443e-d4cb-4b69-8773-27d58039812d)

And in our case it will be like this:

![image](https://github.com/user-attachments/assets/02891172-3bb0-4c08-9837-683ac1954b05)

And when you have **rclone.conf** you can access cloud storage remotely, however in this challenge the connection was corrupted by somehow. My intended solution is 
accessing cloud storage, investigate to find out whether there has any file or not, but after read other solutions I knew this is a guessy challenge 💀. OK so it will be 
like this: the rclone password always be encrypted and to reveal the original password, it's so simple that we use this command: **rclone reveal**:

![image](https://github.com/user-attachments/assets/3617e444-7960-41e0-9200-a037635944c5)

Decode from base64 and you get another part:

![image](https://github.com/user-attachments/assets/d0f3395f-5132-4312-a844-af1c41969d57)

Combine with the part we found before, decrypt from RC4 and you get the flag 💀💀💀 (it's even more guessy than FUSecathon 2025 💀):

![image](https://github.com/user-attachments/assets/66468f0e-fc68-4fd6-be01-7d06e59742d7)

In my opinion, if they can fix the mega connection, then this challenge will be very great but sadly, they failed. Thank you for reading this article, bye! 





