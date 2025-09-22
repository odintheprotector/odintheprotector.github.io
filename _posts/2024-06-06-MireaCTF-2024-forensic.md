---
layout: post
title: MireaCTF 2024 - Forensic
description: All solved forensic challenges
tags: [MireaCTF, Forensic, Writeup, DFIR, CTFtime]
---

Hi, it's me Odin. Yesterday me and my team World Wide Flag have a competition in MireaCTF and I'm very happy that we got 3rd place. Moreover, I solved all forensic challenges, and now it's writeup for them.

## Optography:
- For this challenge, they gave me a .vmem file, and we will use volatility3 for analysing it:

![image](https://github.com/odintheprotector/ctf-writeup/assets/75618225/f87c1ea1-596a-4d43-a390-d53db4709232)

I checked filescan and pslist but it looked normal, from here I was stuck for 2 HOURS because there's nothing special (F*CKKKKKKKKKKKK)

![image](https://github.com/odintheprotector/ctf-writeup/assets/75618225/9daf2c22-350f-4f27-b166-703233eafca3)

After that I checked cmdline and I thought I found a thing to investigate:

![image](https://github.com/odintheprotector/ctf-writeup/assets/75618225/9fdea15e-34e4-4b25-ad12-db9950b40b0a)

You can see that mspaint process was running and maybe they hid something inside Paint, I tried to look for .msp file (Paint file) in filescan but there's nothing ;-;

After searching on Google for a long time, finally I found an [interesting article](https://w00tsec.blogspot.com/2015/02/extracting-raw-pictures-from-memory.html).

From that I had the idea to solve the problem: 
- Dump mspaint.exe process:
  
```python3 vol.py -f chall.vmem windows.memmap --dump --pid 8168```

- Change from .dmp to .data:
  
```mv pid.8168.dmp 8168.data```

- Import it to GIMP. I know that 1920x1080 is a common size for PC/laptop background, so I checked it and you can see that there's PC/laptop background:

![image](https://github.com/odintheprotector/ctf-writeup/assets/75618225/c5ded59a-514f-46d6-b7e4-7303ddb642bc)

Edit a bit and I found the flag:

![image](https://github.com/odintheprotector/ctf-writeup/assets/75618225/305e7333-2f97-4bff-befd-61c0227ee033)

**Flag: mireactf{dump_scr33n_fr0m_m3m0ry_1s_base?}**

## SOC moment:

In this challenge they gave us a network capture file, and our mission is analysing it to get the flag:

Open it by Wireshark and in this captured file, I always check HTTP protocol:

![image](https://github.com/odintheprotector/ctf-writeup/assets/75618225/33500aad-a3b1-4b6a-8d20-95a731664c28)

You can see that there're many packets and it seems uploading files or transfering files. Go to **File -> Export Objects -> HTTP** and hostname **10.177.22.215:1337** is the most suspicious address:

![image](https://github.com/odintheprotector/ctf-writeup/assets/75618225/dc305ed8-2a52-444f-a8a3-5a369247ea87)

I extracted **some_secret_file_encoded** and continue to analyse: 

![image](https://github.com/odintheprotector/ctf-writeup/assets/75618225/33e1314e-72e9-429c-8e97-8bc501713e30)

The file content was encoded and we need to decode it, I used CyberChef and use **Magic** plugin and you can see that it's base58 string and after decoding, the result is the ELF file:

![image](https://github.com/odintheprotector/ctf-writeup/assets/75618225/dbe3ca43-fbac-4008-87e7-f348a5f3cdbd)

Save it to a file and let's analyse it by IDA:

![image](https://github.com/odintheprotector/ctf-writeup/assets/75618225/745a98a4-9e15-46b1-845a-b08248bc894d)

Main function: 
```
int __fastcall main(int argc, const char **argv, const char **envp)
{
  __int64 v3; // rax
  __int64 v4; // rax
  __int64 v5; // rax
  __int64 v6; // rax
  __int64 v7; // rax
  __int64 v8; // rax
  __int64 v9; // rax
  __int64 v10; // rax
  __int64 v11; // rax
  __int64 v12; // rax
  __int64 v13; // rax
  __int64 v14; // rax
  __int64 v15; // rax
  __int64 v16; // rax
  __int64 v17; // rax
  __int64 v18; // rax
  __int64 v19; // rax
  __int64 v20; // rax
  __int64 v21; // rax
  __int64 v22; // rax
  __int64 v23; // rax
  __int64 v24; // rax
  __int64 v25; // rax
  __int64 v26; // rax
  __int64 v27; // rax
  __int64 v28; // rax
  __int64 v29; // rax
  __int64 v30; // rax
  __int64 v31; // rax
  __int64 v32; // rax
  __int64 v33; // rax
  __int64 v34; // rax
  __int64 v35; // rax
  __int64 v36; // rax
  __int64 v37; // rax
  __int64 v38; // rax
  __int64 v39; // rax
  __int64 v40; // rax
  __int64 v41; // rax
  __int64 v42; // rax
  __int64 v43; // rax
  __int64 v44; // rax
  __int64 v45; // rax
  __int64 v46; // rax
  __int64 v47; // rax
  __int64 v48; // rax
  __int64 v49; // rax
  __int64 v50; // rax
  __int64 v51; // rax
  __int64 v52; // rax
  __int64 v53; // rax
  __int64 v54; // rax
  __int64 v55; // rax
  char v57[53]; // [rsp+Bh] [rbp-35h] BYREF

  qmemcpy(v57, "rl>ii}8P:>g8P8z?m;P<9a}8:P9a>g8<b?:P:>P<}<g8ti{lnj}fb", sizeof(v57));
  v3 = std::operator<<<std::char_traits<char>>(&std::cout, 98LL, envp);
  v4 = std::operator<<<std::char_traits<char>>(v3, (unsigned int)v57[51], v3);
  v5 = std::operator<<<std::char_traits<char>>(v4, (unsigned int)v57[50], v4);
  v6 = std::operator<<<std::char_traits<char>>(v5, (unsigned int)v57[49], v5);
  v7 = std::operator<<<std::char_traits<char>>(v6, (unsigned int)v57[48], v6);
  v8 = std::operator<<<std::char_traits<char>>(v7, (unsigned int)v57[47], v7);
  v9 = std::operator<<<std::char_traits<char>>(v8, (unsigned int)v57[46], v8);
  v10 = std::operator<<<std::char_traits<char>>(v9, (unsigned int)v57[45], v9);
  v11 = std::operator<<<std::char_traits<char>>(v10, (unsigned int)v57[44], v10);
  v12 = std::operator<<<std::char_traits<char>>(v11, (unsigned int)v57[43], v11);
  v13 = std::operator<<<std::char_traits<char>>(v12, (unsigned int)v57[42], v12);
  v14 = std::operator<<<std::char_traits<char>>(v13, (unsigned int)v57[41], v13);
  v15 = std::operator<<<std::char_traits<char>>(v14, (unsigned int)v57[40], v14);
  v16 = std::operator<<<std::char_traits<char>>(v15, (unsigned int)v57[39], v15);
  v17 = std::operator<<<std::char_traits<char>>(v16, (unsigned int)v57[38], v16);
  v18 = std::operator<<<std::char_traits<char>>(v17, (unsigned int)v57[37], v17);
  v19 = std::operator<<<std::char_traits<char>>(v18, (unsigned int)v57[36], v18);
  v20 = std::operator<<<std::char_traits<char>>(v19, (unsigned int)v57[35], v19);
  v21 = std::operator<<<std::char_traits<char>>(v20, (unsigned int)v57[34], v20);
  v22 = std::operator<<<std::char_traits<char>>(v21, (unsigned int)v57[33], v21);
  v23 = std::operator<<<std::char_traits<char>>(v22, (unsigned int)v57[32], v22);
  v24 = std::operator<<<std::char_traits<char>>(v23, (unsigned int)v57[31], v23);
  v25 = std::operator<<<std::char_traits<char>>(v24, (unsigned int)v57[30], v24);
  v26 = std::operator<<<std::char_traits<char>>(v25, (unsigned int)v57[29], v25);
  v27 = std::operator<<<std::char_traits<char>>(v26, (unsigned int)v57[28], v26);
  v28 = std::operator<<<std::char_traits<char>>(v27, (unsigned int)v57[27], v27);
  v29 = std::operator<<<std::char_traits<char>>(v28, (unsigned int)v57[26], v28);
  v30 = std::operator<<<std::char_traits<char>>(v29, (unsigned int)v57[25], v29);
  v31 = std::operator<<<std::char_traits<char>>(v30, (unsigned int)v57[24], v30);
  v32 = std::operator<<<std::char_traits<char>>(v31, (unsigned int)v57[23], v31);
  v33 = std::operator<<<std::char_traits<char>>(v32, (unsigned int)v57[22], v32);
  v34 = std::operator<<<std::char_traits<char>>(v33, (unsigned int)v57[21], v33);
  v35 = std::operator<<<std::char_traits<char>>(v34, (unsigned int)v57[20], v34);
  v36 = std::operator<<<std::char_traits<char>>(v35, (unsigned int)v57[19], v35);
  v37 = std::operator<<<std::char_traits<char>>(v36, (unsigned int)v57[18], v36);
  v38 = std::operator<<<std::char_traits<char>>(v37, (unsigned int)v57[17], v37);
  v39 = std::operator<<<std::char_traits<char>>(v38, (unsigned int)v57[16], v38);
  v40 = std::operator<<<std::char_traits<char>>(v39, (unsigned int)v57[15], v39);
  v41 = std::operator<<<std::char_traits<char>>(v40, (unsigned int)v57[14], v40);
  v42 = std::operator<<<std::char_traits<char>>(v41, (unsigned int)v57[13], v41);
  v43 = std::operator<<<std::char_traits<char>>(v42, (unsigned int)v57[12], v42);
  v44 = std::operator<<<std::char_traits<char>>(v43, (unsigned int)v57[11], v43);
  v45 = std::operator<<<std::char_traits<char>>(v44, (unsigned int)v57[10], v44);
  v46 = std::operator<<<std::char_traits<char>>(v45, (unsigned int)v57[9], v45);
  v47 = std::operator<<<std::char_traits<char>>(v46, (unsigned int)v57[8], v46);
  v48 = std::operator<<<std::char_traits<char>>(v47, (unsigned int)v57[7], v47);
  v49 = std::operator<<<std::char_traits<char>>(v48, (unsigned int)v57[6], v48);
  v50 = std::operator<<<std::char_traits<char>>(v49, (unsigned int)v57[5], v49);
  v51 = std::operator<<<std::char_traits<char>>(v50, (unsigned int)v57[4], v50);
  v52 = std::operator<<<std::char_traits<char>>(v51, (unsigned int)v57[3], v51);
  v53 = std::operator<<<std::char_traits<char>>(v52, (unsigned int)v57[2], v52);
  v54 = std::operator<<<std::char_traits<char>>(v53, (unsigned int)v57[1], v53);
  v55 = std::operator<<<std::char_traits<char>>(v54, (unsigned int)v57[0], v54);
  std::ostream::operator<<(v55, &std::endl<char,std::char_traits<char>>);
  return 0;
}
```
The code will take each characters from end to begin then print it: 

![image](https://github.com/odintheprotector/ctf-writeup/assets/75618225/85ae123d-f510-49fd-bcd5-8a4b4a801159)

From here I thought the string was encoded by XOR algorithm. Not waiting, I checked it right after and I found the flag:

![image](https://github.com/odintheprotector/ctf-writeup/assets/75618225/d938c7fa-584b-4e5d-b7d2-2a5f4e93840a)

**Flag: mireactf{7h3r3_15_50m37h1n6_57rn63_4b0u7_7h15_7rff1c}**


