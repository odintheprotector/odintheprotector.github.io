---
layout: post
title: HackTheBox - Reminiscent
description: Memory forensic problem
tags: ["HackTheBox", "Writeup", "Memory Forensic", "Email forensic", "Volatility"]
---

CHALLENGE DESCRIPTION
```
Suspicious traffic was detected from a recruiter's virtual PC. A memory dump of the offending VM was captured before it was removed from the network for imaging and analysis. Our recruiter mentioned he received an email from someone regarding their resume. A copy of the email was recovered and is provided for reference. Find and decode the source of the malware to find the flag.
```

Hi everyone, it's me again. In the previous post, we know how important Git log is and 
consequence if developers don't delele some important commit. Today, I'll show you how 
incident responders investigate memory through this challenge.

A memory file, a info of image, an email, that's all we have. First thing I did was checking
OS version of that memory file in imageinfo.txt

![]({{site.url}}/assets/images/reminiscent/Screenshot_2023-08-02_19_57_55.png)

Follow my experience, the longest is the most correct, I use it to check process:

```
python2 ../../volatility2/vol.py -f flounder-pc-memdump.elf --profile=Win2008R2SP1x64_23418 pslist
```

![]({{site.url}}/assets/images/reminiscent/Screenshot_2023-08-02_19_59_08.png)

Looking to the last 3 lines, we'll see process powershell.exe. I guess it's the process which malicious file use to execute command.
Navigating to email, we can see it's attached a .zip file named resume.zip. 

![]({{site.url}}/assets/images/reminiscent/Screenshot_2023-08-02_19_59_49.png)

Returning to memory file, I scan all file named resume.zip. There're two files named resume.zip.lnk, immediately, I dump both of them 

![]({{site.url}}/assets/images/reminiscent/Screenshot_2023-08-02_20_01_00.png)

Read to file with strings, there has a very long base64 string, decode it and we have a powershell command 

![]({{site.url}}/assets/images/reminiscent/Screenshot_2023-08-02_20_01_38.png)

There's a base64 string again, decode it and we get the flag!

![]({{site.url}}/assets/images/reminiscent/Screenshot_2023-08-02_20_02_04.png)

Thanks for watching, hope you enjoy that!!!! 