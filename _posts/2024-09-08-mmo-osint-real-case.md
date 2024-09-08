---
layout: post
title: MMO Scammer - OSINT Real Case
description: A real case related to a MMO scammer in Viet Nam in 2015
tags: [Real Case, OSINT, Blue Team, Forensic]
---

Hi everyone, after playing with my lover 😂😂😂, my brother told me that I can post a writeup that I've made before about OSINT because his company said it was disclosure! 
This is an interesting case and I want to share it to you. Let's start! 

![image](https://github.com/user-attachments/assets/f84bface-59c9-429a-8093-3f0bf94bcf94)

First, they gave us the website belongs to scammer: **https[://]mymin[.]net**:

![image](https://github.com/user-attachments/assets/1131771e-4540-49d8-992d-b3eba493596a)

With the first request: **find Google Analytic ID of this website**, we can find it easily by inspecting the website. For anyone doesn't know GA ID will help developer 
manage website activities and analyse user's behaviours, and it's clear that GA code will be inside source code so that website can do everything I've told you before. Not 
waiting, I pressed **Ctrl + U**, and GA ID will start with GA or UA, so you just press **Ctrl + F**, type GA or UA and you will find it: 

![image](https://github.com/user-attachments/assets/e2de51e7-4c30-47be-8de4-968b26831ead)

Next, we need to find the origin IP of this website. I guess many people will ask me like: "Hey Odin, I thought the real IP still there?", if you learn a bit about website, you should know 
how developers keep them safe on the Internet. Because that, they must use **proxy** - which is same with a wall, no one can see it through, right? And in that case will be same, no attacker want to be arrested 
😂😂😂 so they must use this to hide themselve on the Internet:

![image](https://github.com/user-attachments/assets/6fd2d29a-1390-41ff-9bf4-5a9752e3e2f9)

![image](https://github.com/user-attachments/assets/e0369d8e-0270-4281-b403-40d3edb773d1)

The problem here is how to find it? With my experience, sometimes attackers forgot to delete their old websites or some old DNS records, so they're still public on the Internet. Because 
I checked DNS records as image above and got nothing, I took a part of that website and searched it:

![image](https://github.com/user-attachments/assets/675bdd8a-bb92-4e62-82d3-a435c26c9fee)

I tried to take the keyword: "Cộng Đồng MYMIN" and searched it on Google: 

![image](https://github.com/user-attachments/assets/cdbfdf7a-02d2-4708-ad8c-f7df8dd9f352)

You can see that there's a website which has raw IP address, and to ensure that it's a static IP, I tried to use **dig** again also edit **/etc/hosts** and access website again, 
if it points to that website directly, that's the real IP. After trying, fortunately my thinking was correct so far: 

![image](https://github.com/user-attachments/assets/1422d8e6-e040-42a4-96db-9314a04c7526)

![image](https://github.com/user-attachments/assets/6e7b523a-12a4-4771-ab8f-a51aa5c6bfcb)

![image](https://github.com/user-attachments/assets/a6399a0a-5d88-4cb2-a840-aab2152e59d1)

Next, I dug this website deeper by using **whois** and I found admin informations: 

![image](https://github.com/user-attachments/assets/ff182d52-3314-4249-8e7e-64ce1afb26ea)

Admin Information: 
- Name: Hau Nguyen
- Home: 342A LE HONG PHONG, NHA TRANG
- Phone number: 1206020905
- Email: ilgbt.net@gmail.com

Moreover, I used [shodan.io](https://www.shodan.io/) to find whether there's any useful information or not, and I found that this website had another domain: **ussv.net**:

![image](https://github.com/user-attachments/assets/1881977a-ac22-4158-9b3f-cc44458e63f5)

From here I used [Wayback Machine](https://web.archive.org/) to find its behaviours in the past and I found that this website worked very active in 2015-2017: 

![image](https://github.com/user-attachments/assets/700e5d96-06ac-48be-b3eb-6eea16f8d277)

I took an event from this time and I got its interface: 

![image](https://github.com/user-attachments/assets/ff816b61-b1a6-4559-8c5c-c0a61b6657fb)

This is one of login methods that was used frequently by scammer, even now it's still happening. I tried going to register page and I found his Facebook:

![image](https://github.com/user-attachments/assets/c59ea9d4-953f-45a3-b053-a0c38eb4479f)

![image](https://github.com/user-attachments/assets/5ab9aef2-d47a-4539-8218-76d822023139)

Next, I continued to explore more and I found a big change in 2015: 

![image](https://github.com/user-attachments/assets/32a29360-8b64-4a4c-8439-2963f99ef352)

In 08 October 2015, its background was changed also login method, beside I found some files in **AddOn**:

![image](https://github.com/user-attachments/assets/f1c698dd-3600-4fa5-931e-1f2af5b16070)

I downloaded it and tried to analyse and this is my summary: 

![image](https://github.com/user-attachments/assets/384f85b0-09a5-4d03-9f76-261d4075250a)

![image](https://github.com/user-attachments/assets/60b1f430-5e74-4564-8a00-21c34916648d)

![image](https://github.com/user-attachments/assets/e108e721-61a8-44a6-b961-d238fae42717)

There's not much differences between two files, but in the first file it will disable Google protection method and in the second file it will load extension, and this is not 
good at all. Remember Facebook account we found before? I found a [forum](https://mmo4me.com/threads/event-card-dt-haivl-chap-canh-duoi-scammer.191472/page-4#post-3648364):

![image](https://github.com/user-attachments/assets/8d5a84b9-3762-49ed-a1b4-217b857e0ad3)

From here we can see another his username: **ukesemeseke** and to ensure this username and his Facebook don't mention another man, I kept finding and I found a 
[post](https://mmo4me.com/threads/share-200-lan-check-acc-facebook-chua-dung-stellar-free-5-nguoi.201689/#post-3842280) to prove that they are one:

![image](https://github.com/user-attachments/assets/a167f85a-f244-47d0-bb71-5bfb4af19562)

Moreover, in that post you can find his [Youtube channel](https://www.youtube.com/@AdminFriendlyUSS), videos mentioned about how to check Facebook accounts of people, and this is illegal:

![image](https://github.com/user-attachments/assets/dc827fb3-5a63-491e-b4d4-15ecc23dda65)

Also I found his face when I watched his video 😂😂😂:

![image](https://github.com/user-attachments/assets/69a271d5-16a6-48ee-81fa-81479d5abbe4)

With username **ukesemeseke** I used **sherlock**, a framework support you finding username in another platforms:

![image](https://github.com/user-attachments/assets/d9278340-5236-47b6-863b-911ccd02295d)

After filtered this was all his available social medias: 

-	https://mmo4me.com/threads/event-card-dt-haivl-chap-canh-duoiscammer.191472/page-4#post-3648364 
-	https://mmo4me.com/threads/share-200-lan-check-acc-facebook-chuadung-stellar-free-5-nguoi.201689/#post-3842280 
-	https://www.youtube.com/@AdminFriendlyUSS/videos 
-	https://www.instagram.com/ukesemeseke/ 
-	https://www.freelancer.com/u/ukesemeseke 
-	https://freesound.org/people/ukesemeseke/?downloaded_sounds=1 
-	https://github.com/ukesemeseke 
-	https://imgur.com/user/ukesemeseke/ 
-	https://bodyspace.bodybuilding.com/about-me/ukesemeseke 
-	https://www.fiverr.com/ukesemeseke 
-	https://www.smule.com/ukesemeseke 
-	https://www.youtube.com/@jessesharp44 

Above is my process when searching for information about this website. This is a very good case study for me because I can apply all the knowledge I have learned while playing CTF. Thank you my dear brother 
for giving me the opportunity to experience real problems, I really learned a lot from this case study. Thank you for reading my articles, if you have any questions, please contact me on Facebook.

See you in the next articles in the future. Bye!!! 🫀🫀🫀



















