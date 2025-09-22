---
layout: post
title: TetCTF 2024 - Writeup
description: All challenges I solved
tags: [Writeup, Command and Control, Word, Macros, Forensic, Blue Team, CTFtime]
---
Hi everyone, just a few day more, we will deep in Tet holiday, and each year, TetCTF will celebrate a competition for all students and people who're interested in Cyber Security. This is the first time
I participated this CTF because I always thought it's very hard and it's not for me. But after joining and experiencing, I realised that I was wrong 😊. So let's start!

## Welcome:
Just do as they said and you will get the flag

## TET & 4N6:

This is a forensic challenge and I really like forensic, so I decided to solve this question first. This is what we have to do:<br>
![]({{ site.url }}/assets/images/tetctf2024/1.png)<br><br>
We have these evidences: a .ad1 file and a memory dump file. With the description, I understood that all problems occured come from a Word document. Not waiting, I opened ad1 file with **7-zip** and because I solved it in the morning, I have so much time to search each directory 😊. 
After a long time, finally I found the file looks so weird in **\Roaming\Microsoft\Templates**:<br><br>
![]({{ site.url }}/assets/images/tetctf2024/2.png)<br><br>
With Word documents, hacker can insert some [Macros](https://knowadays.com/blog/what-is-a-macro-in-microsoft-word/){:target="_blank"}{:rel="noopener noreferrer"} that stealing sensitive data from target machine. In Linux, we have **olevba** which can be used to find Macros inside the Word file. And what we got is a very long code (you must do by yourself). And you can see that in that code include a IP:port and a function named **revshell()** which is used to create connection to 172.20.25.15:4444. So we can decide that this connection is Command and Control server.<br>

If you observe carefully, you can a weird encoded string:<br> **Vmxjd2VFNUhSa2RqUkZwVFZrWndTMVZ0ZUhkU1JsWlhWRmhvVldGNlZrbFdSM2hQVkd4R1ZVMUVhejA9**. In my experience, maybe it's a base64 string, trying to decode and I'm right, but I need to decode many times and you will get the second flag:<br><br>
![]({{ site.url }}/assets/images/tetctf2024/3.png)<br><br>
How about the final flag? Well, we need to read description again: a person participate in TetCTF, they read Word document and then their machine have problems, while in final question they ask you to recover credentials, so it must be TetCTF credentials, not credentials to login to their machine. After thinking I decided to check in browser history. Follow this [page](https://www.inversecos.com/2022/10/recovering-cleared-browser-history.html){:target="_blank"}{:rel="noopener noreferrer"}, we can gather browser history through some files started with **Session** or **Tab** in **C:\Users\<name>\AppData\Local\Google\Chrome\User Data\Default\Sessions**. From here you have two choices, you can use volatility to extract file, or you can use .ad1 file to extract. Read Session... file, I found the final flag 😊 (I don't know if this solution is unintended or not)<br><br>
![]({{ site.url }}/assets/images/tetctf2024/4.png)<br><br>
BTW, thank TetCTF for many fun challenges, especially thank **Stirring** for nice forensic challenge!!!! See you in next year!!!! Thank you for reading my post, happy new year!!!!!!
