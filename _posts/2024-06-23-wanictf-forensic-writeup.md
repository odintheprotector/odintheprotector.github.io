---
layout: post
title: WaniCTF 2024 - Forensic 
description: All solved forensic challenges
tags: [WaniCTF, Writeup, Forensic, DFIR, CTFtime, Blue Team, Memory Forensic, Network Forensic]
---

Hi everyone, this time I joined WaniCTF 2024 and fortunately we got 2nd place, this is a big victory for us. Now it's my writeup for forensic category. Let's go! 

![image](https://github.com/odintheprotector/odintheprotector.github.io/assets/75618225/0d1e14fa-b060-4841-be23-c93a424de706)

### tiny_usb
In this challenge they gave us a ISO file, I was sure that flag would be inside this ISO. To analyse ISO file, there's a [script in github](https://github.com/evild3ad/isodump) will help us analyse it. 
First, I listed all files inside ISO file:

![image](https://github.com/odintheprotector/odintheprotector.github.io/assets/75618225/6e31ac29-2b01-479b-a839-39f9d5c0a0e5)

You can see that there's a PNG file name **FLAG.PNG**, and we just extract it to our machine: 

![image](https://github.com/odintheprotector/odintheprotector.github.io/assets/75618225/82d75fd3-9587-4f6f-a961-5adb26affb6d)

Open file and enjoy the result: 

![image](https://github.com/odintheprotector/odintheprotector.github.io/assets/75618225/bf12b4dd-0c8c-479e-b0aa-a68ed2d25599)

**Flag: FLAG{hey_i_just_bought_a_usb}**

### Surveillance_of_sus

In this challenge they gave us a cached file, and we need to analyse it. First, I checked file signature to know which type of cached file was:

![image](https://github.com/odintheprotector/odintheprotector.github.io/assets/75618225/cb2b7ec9-d830-41df-81b7-bbf3612a63be)

Very clear, it's RDP8bmp file and we can analyse it by [a tool on github](https://github.com/ANSSI-FR/bmc-tools)

![image](https://github.com/odintheprotector/odintheprotector.github.io/assets/75618225/6a21c462-14b4-444e-a125-4395d69ab63f)

By this way you can extract all cache datas inside this file:

![image](https://github.com/odintheprotector/odintheprotector.github.io/assets/75618225/65486fd3-8c55-4400-b226-410c9bdb6f34)

I will open it in File Manager to avoid wasting time. Search a bit and I found somes that when we combine them together, we will get the flag: 

![image](https://github.com/odintheprotector/odintheprotector.github.io/assets/75618225/e136a1be-4d99-4dc5-a7d6-aa5019b48d99)

**Flag: FLAG{RDP_is_useful_yipeee}**

### I_wanna_be_a_streamer
I have to say this must be the best challenge when I solved forensic. Go with me to see how interesting it is. In this challenge we had a pcap file, let's open it in Wireshark and analyse it:

![image](https://github.com/odintheprotector/odintheprotector.github.io/assets/75618225/77601bf2-0a90-4cf4-9f3e-5dff65cbb112)

There're so many RTP and RTSP packets, these packets are very common in transfering video and sound through Internet, normally you can see it in VoiP, streaming media, camera...

![image](https://github.com/odintheprotector/odintheprotector.github.io/assets/75618225/a89d04df-124f-4dd5-8c13-4d633c15d231)

RTSP and HTTP functions are the same, However, RTSP depends on a dedicated server for streaming and relies on RTP to transmit multimedia content. Therefore, this protocol does not support content encryption or retransmission of lost packets. That means we can extract all the datas that transfered through Internet.

Read challenge carefully, you can see they noted about H.264 video encoding, after searching I found [plugins](https://github.com/volvet/h264extractor) for extracting H.264 data inside RTP packets. And now it's how to extract data step-by-step:
- Copy plugins to /home/<user>/.local/lib/wireshark/plugins/
- Restart Wireshark to load plugins
- Go to Edit -> Preference -> Protocol -> H.264, set RTP payload type to 96 (if you look packets carefully you can see that it's RTP-Type-96)
- Go to Tools -> Extract h264 stream from RTP

After these steps you will get h264 data: 

![image](https://github.com/odintheprotector/odintheprotector.github.io/assets/75618225/601a6346-0910-4c31-9bd5-0e03173b1abb)

![image](https://github.com/odintheprotector/odintheprotector.github.io/assets/75618225/1f866532-2698-4385-9806-4d251d53f8ac)

To convert from h264 to mp4, you can use **ffmpeg** to process it: 

![image](https://github.com/odintheprotector/odintheprotector.github.io/assets/75618225/b411a085-b42c-4b3f-b795-e57d86295062)

Open video and enjoy your result: 

![image](https://github.com/odintheprotector/odintheprotector.github.io/assets/75618225/6f2a51a4-1d03-4a15-aa9c-0f0f894288fa)

**Flag: FLAG{Th4nk_y0u_f0r_W4tching}**

### mem_search
I don't know why organizers marked this challenge as **Hard**, I solved it about 2-3 minutes, nevermind, let's start. For this challenge we had a full dump memory file, and I used **volatility** to analyse it. Check processes list, I noticed that **notepad.exe** and **tabtip.exe** were running.

![image](https://github.com/odintheprotector/odintheprotector.github.io/assets/75618225/7091debb-d198-496d-b042-feb63c13c7b1)

Maybe they tried to type something, so I decided to use **filescan** plugin to extract all files inside the memory file: 

![image](https://github.com/odintheprotector/odintheprotector.github.io/assets/75618225/3f0b2d48-c2f4-43d1-a7c6-cbea2a011b20)

You can see that there're two files **read_this_as_admin** in Desktop and Downloads. Let's extract and read content inside them: 

![image](https://github.com/odintheprotector/odintheprotector.github.io/assets/75618225/e32af988-f39d-4bcf-98d2-6a074acc0238)

- In **read_this_as_admin.download** it will download .lnk file from **192.168.0.16:8282**:

![image](https://github.com/odintheprotector/odintheprotector.github.io/assets/75618225/7f31f01b-1fb7-4704-b9bb-c4610f835c90)

- In **read_this_as_admin.lnknload** it will decode a base64 string and execute it, let's decode it:

![image](https://github.com/odintheprotector/odintheprotector.github.io/assets/75618225/8e44703f-b8bb-4968-85f9-acb77508803d)

![image](https://github.com/odintheprotector/odintheprotector.github.io/assets/75618225/485e8e0f-8f82-4278-b36d-91b1cf3554aa)

You will see that when you combine it together, you will get a link that downloaded a file named **chall_mem_search.exe**, created **WaniTemp** directory inside **Temp** directory, saved chall_mem_search.exe to **msedge.exe** (that's why you got msedge.exe process at first). Look at the link carefully, you will see B64_dec..., you can know easily that they wanted us to decode that string, decode it and you will get the flag:

![image](https://github.com/odintheprotector/odintheprotector.github.io/assets/75618225/49a1a9d5-2eab-476d-8a98-22c821b01df3)

**Flag: FLAG{Dayum_this_is_secret_file}**

### tiny_10px

This challenge will help understand deeper about jpg structure, idea for solving this challenge is changing size of the image by following this [blog](https://cyberhacktics.com/hiding-information-by-changing-an-images-height/):

In that blog they noticed about image height and width information:

![image](https://github.com/odintheprotector/odintheprotector.github.io/assets/75618225/220d3ea5-6b11-4d03-a80b-3624741e58ba)

Apply it to our case, we can easily find it: 

![image](https://github.com/odintheprotector/odintheprotector.github.io/assets/75618225/315168a1-be99-47b5-a4dd-9d205c5aff99)

After a long time tried, I finally found correct dimension and got the flag (change **ff c0 00 11 08 00 0a 00 0a** to **ff c0 00 11 08 00 a0 00 a0**):

![image](https://github.com/odintheprotector/odintheprotector.github.io/assets/75618225/43cfb194-22fd-4ded-92b1-6d15256ea635)

Thank you for reading my writeup. See you next time, bye!!!! ❤️❤️❤️




