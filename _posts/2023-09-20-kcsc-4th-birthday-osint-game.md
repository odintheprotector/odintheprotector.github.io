---
layout: post
title: KCSC - 4th Birthday OSINT game
description: OSINT problem - 4th KCSC Birthday 
tags: ["KCSC", "Writeup", "OSINT"]
---

Hi everyone, just a few day ago, KCSC created a OSINT challenge because of its 4th birthday. Fortunately, I solved this challenge, and today
I will show you how to solve it. Let's go!

First, I have a Github username: shr1mpl0v3r, so the first thing to do is access github and find shr1mpl0v3r username:

![]({{site.url}}/assets/images/KCSCbirthday/image.png)

Go to Repositories, we could see the **Not-Important** repo, I could guess that it contains some suspicious things. Not waiting,
I go to it and there's a file named **history.csv**. Click to it, you can see there're so many things here, and if you don't know,
there're Google history. 

![]({{site.url}}/assets/images/KCSCbirthday/Screenshot_2023-08-07_07_06_06.png)

Scroll down, there has a drive, access it, we have file **ImportantData.zip**, and inside it, there's flag.txt:

![]({{site.url}}/assets/images/KCSCbirthday/Screenshot_2023-08-07_07_10_06.png)

Immediately, I downloaded that file and get the flag, but no, it's scammmmmmmmmmm........ F*ck!

![]({{site.url}}/assets/images/KCSCbirthday/image2.png)

For that, I continued searching by accessing commit history where editting history appears. After a short time, I found new thing: **KCSCGift.zip**

I was sure that there's the thing that I was finding. Download it and unzip, but there's an error: **unsupported compression method 99**. This
error appears because compression method 99 error indicates the AES (Adavance Encryption Standard) encryption and unfortunately, this encryption standard is currently not supported by unzip binary. However, we can use 7z to unzip the file. But when unzipping, it needs password. So where we find password now?

Look into the profile, there's a [X profile](https://twitter.com/anokflexer){:target="_blank"}{:rel="noopener noreferrer"}. I accessed it, after searching, there's nothing interest. I go to followers, there's a user named **ricon** and in the newest post, in this pic, there's a paper which has suspicious strings, take a closer look, I can see there're some strings: "echo", "pass", "KCSC08082019". And maybe "KCSC08082019" is the password of .zip file. Trying to enter and boom, I opened the file and get the real flag!!

![]({{site.url}}/assets/images/KCSCbirthday/image4.png)

Thanks KCSC for nice challenge, hope you have more challenges like this in the future!