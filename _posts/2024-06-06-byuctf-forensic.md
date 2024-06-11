---
layout: post
title: BYUCTF 2024 - Forensic 
description: All solved forensic challenges
tags: [BYUCTF, Writeup, Forensic, DFIR, CTFtime]
---

Hi everyone, I just joined BYUCTF two days ago and till now I feel very happy because I solved 5/6 forensic challenges here. Below is my writeup, let's go: 

![image](https://github.com/odintheprotector/BYUCTF-2024/assets/75618225/e25d90b1-fd3c-4d94-a98d-880b297bae00)

### Who Am I

For this challenge, they gave me a docx file, and our mission is finding author of this file. Very easy, just navigate to File -> Info, you will see author information

**Flag: byuctf{Ryan Sketchy}**

### Advanced Steak 

We have a .001 file and a decryptor tool written by Python to decrypt .cow file, and we need to find the secret inside .001 file. First, I need to know how a .cow file works: 

I used **xxd** to see hex value inside the file and I realised its signature is 1337beef and the end is 4d6f6f6f (Mooo):

![image](https://github.com/odintheprotector/BYUCTF-2024/assets/75618225/93dbae76-eb7c-47a2-a6c5-8f81636b688d)

![image](https://github.com/odintheprotector/BYUCTF-2024/assets/75618225/c7fe169a-68a2-4495-944f-243e086ab203)

Moreover, I cannot import .001 file to FTK imager, from here I was stuck for a long time, and then an idea in my mind appeared: "I wonder if there's any .cow file inside it?", so I opened it in hexedit, and searched for 1337beef and 4d6f6f6f. Fortunately, it had: 

![image](https://github.com/odintheprotector/BYUCTF-2024/assets/75618225/dec5739a-c1a7-4ba0-8c94-b6800d1876e8)

![image](https://github.com/odintheprotector/BYUCTF-2024/assets/75618225/6a35c7fe-3063-4f22-b6b4-98e336476c03)

From here I extracted it using my friend (sorry for that 😂😂😂) and used cow decryptor tool to decrypt it, save it into a file, open it and enjoy your result: 

![image](https://github.com/odintheprotector/BYUCTF-2024/assets/75618225/ffb7a9a3-8bdd-4457-9227-6ac05f55aa62)

### Not again! I've been BitLockered out of my own computer!

The sample is a memory file and we need to find FVEK which is used to encrypt hard-drive in Bitlocker. Fortunately, I found a [plugin](https://github.com/Rmejia39/bitlocker) for solving it. Now everything is easy now, just follow the guideline and enjoy your result:

![image](https://github.com/odintheprotector/BYUCTF-2024/assets/75618225/7cfd5f04-1a53-4656-8e18-0b95b39129ac)

### Not sure I'll recover from this: 

We need to find answers for security questions, and if you learn about Windows OS, you will know that these questions are stored in SAM.
- First thing to do is open .vhdx file in **Autopsy** (or you can mount in Windows directly):

![image](https://github.com/odintheprotector/BYUCTF-2024/assets/75618225/8add2d24-3384-4cdc-809c-3da703166535)

- Second, navigate to C:\Windows\System32\config\

![image](https://github.com/odintheprotector/BYUCTF-2024/assets/75618225/d61a66bb-3901-4df9-8401-bbfe5a1957f4)

- Third, export SAM to our machine and import it to Registry Explorer:

![image](https://github.com/odintheprotector/BYUCTF-2024/assets/75618225/1955b927-5b58-4347-8d87-d8e61e019400)

Result: {"version":1,"questions":[{"question":"What was your first pet’s name?","answer":"jimothy"},{"question":"What’s the name of the city where your parents met?","answer":"Idaho Falls"},{"question":"What’s the first name of your oldest cousin?","answer":"Zephanias"}]}

**Flag: byuctf{jimothy_Idaho Falls_Zephanias}**

### Did nobody see: 

They gave us a Windows backup, and it contains prefetch files, windows event log file, some database files... At first I saw many log files, and I think I had to look at it to find the answer, but after about 2 hours, I didn't get anything. From here I was stuck, very stuck, and fortunately, my "bi quan" brother gave me a hint: 

![image](https://github.com/odintheprotector/BYUCTF-2024/assets/75618225/05af4a93-4208-45df-bad7-0ddb4ed7899f)

The answer was not in log file, so where I found now, and I remembered that one thing I didn't notice: SAM, SYSTEM and SECURITY. From here I use ChatGPT to learn about them and I really found the answer: 

![image](https://github.com/odintheprotector/BYUCTF-2024/assets/75618225/2cc89223-82c4-45f6-ae5e-e079effdffa0)

Not waiting, I imported SYSTEM file to Registry Explorer, followed the instruction and I found the answer: 

![image](https://github.com/odintheprotector/BYUCTF-2024/assets/75618225/c9f525bb-7a99-4f7d-810e-635fd39bffd7)

**Flag: byuctf{162.252.172.57}**

### The worst challenge ever: 

As the name, it's a f*cking guessy challenge, and I SPENT A NIGHT to solve it but I could not get anything. I was going to write 4 challenges solutions instead of 5 as u can see, but fortunately, my Malaysian bro gave me the solution for it 😂😂😂.
When I saw the solution, it's more guessy than my thinking 😂😂😂. Ok so it will work like this: 

- Open it by hexedit, you will see that there's a space that only contains 0s and 1s:

![image](https://github.com/odintheprotector/BYUCTF-2024/assets/75618225/b3418f61-0c78-430e-a972-d1b75f1dcf25)

- The idea is, delete two strings at the first and the end, consider all 01 as separators, and the problem is: split the string 010101,... which use 01 as comma, caculate the length of each string and chr() it:

  + Extract data:
 
  ![image](https://github.com/odintheprotector/BYUCTF-2024/assets/75618225/04252ace-a556-4569-95d3-e849a8f6f477)

  + Write a Python script to decrypt:

  ```
  with open("C:\\Users\\Admin\\Downloads\\download (2).dat", 'r') as file:
    arr = file.read().split(" 01 ")

  for i in arr:
      print(chr(len(i.split())), end='')
  ```

  ![image](https://github.com/odintheprotector/BYUCTF-2024/assets/75618225/3f8cf294-68b5-464a-82ee-736cd8126292)

Guessy, right? Btw, this is all challenges I solved in BYUCTF. In general, it's very fun and interesting, and I learnt many things from it. Thank you for reading, see you next time! 


  















