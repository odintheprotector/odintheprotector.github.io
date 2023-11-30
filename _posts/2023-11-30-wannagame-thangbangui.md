---
layout: post
title: WannaGame - Ngau Hung 
description: Browser history forensic
tags: [WannaGame, Writeup, Powershell, Wireshark ]
---

Hi everyone, after a long time I've not done anything in my blog, now I will share you a challenge that I think it's very interesting and very fun for anyone who want to become an incident responder or just want to learn new things. OK, so let's start!

Link challenge: https://drive.google.com/drive/folders/1vlr_l_4v-KXZORsj5HPfCIVGfpa_kD4x

All we have are two files: network captured file and dump file. I start with dump file, as the name of link challenge: HISTORY IN MEMORY, I've guessed that this is the key to solve this challenge. Not waiting, I've checked all files related to browser history:

And now we have a file started with "Session...", this is a file containing browser histories, and I've found a suspicious link

That link redirected me to a [minecraft website](https://hackeverythingssg.id.vn){:target="_blank"}{:rel="noopener noreferrer}

I downloaded iso file and mount it, and I have a file named **AutoRun.lnk**. Read that file and I had a powershell command which redirect me to a github link that containing the malicious file: https://gist.githubusercontent.com/hackeverythingsgg/722e57dda6c68b644e20a4ee3af4db53/raw/a9b10eafbd516d662c69126dcd8499bdf50a5803/DSKy829rioas.ps1

Now let's analyze that file. As we can see in the source, there are 2 main functions: Compress and Exfil. 
- Compress function: it will compress all datas into gzip file 
- Exfil function: Use that IP to send ICMP packet and each byte in ICMP has been encrypted with XOR algorithm which use "0xfa" as the key to encrypt 
and in other parts, they will encode all datas in base64 format. Follow the workspace, it will encrypt with XOR first, then Base64 and decrypted data is the raw data of gzip file 

Having understood the workflow, I've extracted all ICMP data and I've used CyberChef to decrypt the data, extract all the datas in gzip file 
and decompress that file, I got new file 
//insert image hereb
