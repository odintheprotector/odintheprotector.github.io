---
layout: post
title: HackTheBox - Diagnostic
description: Command and Control server problem
tags: [HackTheBox, Writeup, Command and Control, Virustotal, Powershell, Blue Team]
---
CHALLENGE DESCRIPTION:

```
Our SOC has identified numerous phishing emails coming in claiming to have a document about an upcoming round of layoffs in the company. The emails all contain a link to diagnostic.htb/layoffs.doc. The DNS for that domain has since stopped resolving, but the server is still hosting the malicious document (your docker). Take a look and figure out what's going on.
```

As the description, there's the server that is still running while DNS for that server has since stopped resolving, so we can still interact normally with server.
We can download or do anything we want. That's the problem, it means I can download layoffs.doc from that server that I don't need its DNS resolving. Immediately,
I've checked and I've got file diagnostic.doc (try it out)

With the new file, I've uploaded to Virustotal, after seconds, I've got the [report](https://www.virustotal.com/gui/file/2ea9745d9561d44a3177334c95ceecff83f8362b4b1c234a1aa13ab506f68dca/details){:target="_blank"}{:rel="noopener noreferrer"}

You can see that the report show the file is malicious with Community Score 32/62. Moving to Behaviour tab, I've noticed Memory Pattern Urls field
which contains a URL same as previous description and it has a file named "223_index_style_fancy.html".

![]({{ site.url }}/assets/images/diagnostic/Screenshot_2023-08-04_08_04_39.png)

I've tried to download the file, it returned a empty page, inspect it, I got a powershell script:

![]({{site.url}}/assets/images/diagnostic/Screenshot_2023-08-04_08_05_44.png)

There're so many base64 string, I tried to the first one, decode it:

![]({{site.url}}/assets/images/diagnostic/Screenshot_2023-08-04_08_09_43.png)

Notice to file variable, we can realize that if we combine it together, we'll get the flag!
