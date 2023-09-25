---
layout: post
title: HackTheBox - Illumination
description: Github problem
tags: ["HackTheBox", "Writeup", "Git log"]
---

CHALLENGE DESCRIPTION
```
A Junior Developer just switched to a new source control platform. Can you find the secret token?
```

First, I've downloaded challenge attached file, first thing I look into is .git folder:

![]({{site.url}}/assets/images/illumination/1.png)

I've guessed it maybe related to Github problem, when developers're careless in managing project
Immediately, I use 'git log' to check edit history

![]({{site.url}}/assets/images/illumination/Screenshot_2023-08-02_07_07_24.png)

With my experience, I've checked the oldest commit because it's unedited by using 'git show commit'.
Navigating to the end, we'll see the token encoded by base64:

![]({{site.url}}/assets/images/illumination/Screenshot_2023-08-02_07_07_55.png)

Decode it and we get the flag!

![]({{site.url}}/assets/images/illumination/Screenshot_2023-08-02_07_08_10.png)

That's it! This is easy challnge so I don't want to explain too much about it. Hope you like it.
If you want to get many announce about new article, please follow me on Facebook (I attached the link into the main page)

And, my English is not good, so if something's wrong, you can contact and guild me. I'm improving it day by day

See you next time, byeeee!
