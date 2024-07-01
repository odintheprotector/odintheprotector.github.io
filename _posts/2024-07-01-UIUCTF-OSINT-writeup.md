---
layout: post
title: UIUCTF 2024 - SoMeSINT writeup
description: SoMeSINT series writeups
tags: [UIUCTF, Writeup, OSINT, CTFtime]
---

Hi guys, this time I joined UIUCTF 2024 and we got 28th place, and happier that we really defeated Emu Exploit 😂😂😂. This is a huge victory for us, and now it's my writeup for SoMesint series, let's go!

![image](https://github.com/odintheprotector/odintheprotector.github.io/assets/75618225/e0aa0ed4-7760-459e-86ad-9db228be2ed2)

### Hip With the Youth 

![image](https://github.com/odintheprotector/odintheprotector.github.io/assets/75618225/22a79c46-c2a8-4c13-acb3-afcfbfdb759a)

Notice to detail, you can see that they wanted us to find information in LISA instagram. Not waiting, I accessed to Instagram, searched "LISA" keyword and I got this:

![image](https://github.com/odintheprotector/odintheprotector.github.io/assets/75618225/63124bd1-279b-4973-8887-a69ebe7f6934)

Navigated to their profile, I checked 2 newest posts but there're nothing, and I saw a [Threads link](https://www.threads.net/@longislandsubwayauthority?xmt=AQGzjeNCfiZJXho_Kr9yrhUmSRyEW46pHNwtP9ETNscl6wA) in their profile: 

![image](https://github.com/odintheprotector/odintheprotector.github.io/assets/75618225/5892a939-de93-41a0-8d22-fd3226630a00)

Followed it, reloaded the site, and I saw a suspicious post: "**I've been told if I include a flag with my post I'll get more engagement, well here goes nothing!**". Clicked for more details, and I found the flag:

![image](https://github.com/odintheprotector/odintheprotector.github.io/assets/75618225/c1d42017-c758-4a42-ad9f-76ed06a3b01e)

**Flag: uiuctf{7W1773r_K!113r_321879}**

### An Unlikely Partnership

Continued to dig deeper, in Threads profile, I found a [LinkedIn link](https://www.linkedin.com/in/long-island-subway-authority/):

![image](https://github.com/odintheprotector/odintheprotector.github.io/assets/75618225/9e018abc-5f33-4647-ad9a-6b2039151271)

Searched a bit and I found that in Skills category, there's 1 endorsement in Transportation, checked it and I found a profile: 

![image](https://github.com/odintheprotector/odintheprotector.github.io/assets/75618225/65b06dd1-9ffd-4144-9b9d-799560ab3a3d)

I went to his profile and I found the flag:

![image](https://github.com/odintheprotector/odintheprotector.github.io/assets/75618225/307f8c3e-7ff9-4e95-bbde-d5bc22855f9b)

**Flag: uiuctf{0M160D_U1UCCH4N_15_MY_F4V0r173_129301}**

### The Weakest Link

While I found the flag for **An Unlikely Partnership**, I also found an important information:

![image](https://github.com/odintheprotector/odintheprotector.github.io/assets/75618225/6e24382e-33c1-4355-8456-a12298588eb1)

I knew that he had a Spotify account and he attached it to his profile, and I found his Spotify account in **Contact info**: 

![image](https://github.com/odintheprotector/odintheprotector.github.io/assets/75618225/a0b88d45-17bf-4ade-92c9-3370c8ec80da)

![image](https://github.com/odintheprotector/odintheprotector.github.io/assets/75618225/7fb123b3-23e4-4599-869a-eb8e46365eb0)

I tried to search carefully each playlist, but it seems not easy as I thought. Until I read the detail in LinkedIn profile again, I noticed a string: **I love music! I quite literally play it at all times**. I thought maybe there's a playlist that he always played it, so I tried to look for his activity status, and I found a playlist that was running:

![image](https://github.com/odintheprotector/odintheprotector.github.io/assets/75618225/144b7853-d588-4293-94b7-c0e4e46069dc)

Navigated to it and I found the flag: 

![image](https://github.com/odintheprotector/odintheprotector.github.io/assets/75618225/4fae3271-8825-4b11-8253-80d9597450ee)

**Flag: uiuctf{7rU1Y_50N65_0F_7H3_5UMM3r_432013}**

Thank you for reading my writeup. If you have any question, you can ask me directly on Facebook or Discord. See you next time, bye!!! ❤️❤️❤️
