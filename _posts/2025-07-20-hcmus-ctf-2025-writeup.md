---
layout: post
title: HCMUS CTF 2025 - Forensic
description: Writeups for Forensic category
tags: [HCMUS, Writeup, Command and Control, Blue Team, Network Forensic, Disk Forensic]
---

Hi guys, I just joined **HCMUS CTF 2025** with my team: **L3_u3th** and we got 30th rank, although it's not the good rank, but we tried our best, so we are chill guys. This is 
my writeup for some challenges in Forensic. Let's go! 

![image](https://github.com/user-attachments/assets/8797a6aa-bc40-4d4d-9067-befbed0bf88e)

### TLS Challenge

![image](https://github.com/user-attachments/assets/7f7843db-6bd9-42cc-8b66-43e5cf3b2e1d)

Basically we have 2 files: a network capture file and keylog file. Based on the title I could guess easily that this challenge will focus on decrypting TLS traffic. The 
configuration is very easy, you just import keylog file to Wireshark, reload the wireshark and you will see decrypted traffic: 

![image](https://github.com/user-attachments/assets/fecdba78-3ab1-491a-931b-6a079283a727)

By navigating to Edit -> Preference -> Protocol -> TLS, then importing keylog file, finally you will have the same result above. Follow TLS traffic, you will get the flag:

![image](https://github.com/user-attachments/assets/fc258512-5abf-479e-908c-a20777a7122f)

### Trashbin

![image](https://github.com/user-attachments/assets/0c85304b-53b7-4439-a9ea-2a63888bade0)

For this challenge we have another network capture file. I checked the file and found SMB traffic: 

![image](https://github.com/user-attachments/assets/ca76c2bf-c832-4f66-94e3-4329223e6762)

Basically we will extract all of them by going to File -> Export Objects -> SMB and we will save all of them to your own somewhere:

![image](https://github.com/user-attachments/assets/37fb6303-8d56-4611-a754-6a7c099598ba)

You can see that there are so many zip files, so I wrote a simple Python script for extracting automatically: 

```python
import os
import zipfile

zip_folder = './'
extract_folder = './extracted_files'
os.makedirs(extract_folder, exist_ok=True)
for filename in os.listdir(zip_folder):
    if filename.endswith('.zip'):
        file_path = os.path.join(zip_folder, filename)
        try:
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                # Extract to a subfolder named after the zip file (without .zip)
                subfolder_name = os.path.splitext(filename)[0]
                subfolder_path = os.path.join(extract_folder, subfolder_name)
                os.makedirs(subfolder_path, exist_ok=True)
                zip_ref.extractall(subfolder_path)
                print(f"Extracted: {filename} to {subfolder_path}")
        except zipfile.BadZipFile:
            print(f"Bad zip file: {filename}")
```

![image](https://github.com/user-attachments/assets/90563cea-6083-4734-b531-bd0a6781002d)

![image](https://github.com/user-attachments/assets/1ab72623-8877-4ef9-b809-8c8bf59e4543)

You can see there are so many directories, and when I checked I found inside each directory would have a txt file, so I just modified code a little bit to read all 
contents in one time: 

```python
with open(combined_txt, 'w', encoding='utf-8') as outfile:
    for root, dirs, files in os.walk(extract_folder):
        for file in files:
            if file.endswith('.txt'):
                txt_path = os.path.join(root, file)
                try:
                    with open(txt_path, 'r', encoding='utf-8') as infile:
                        content = infile.read()
                        outfile.write(f"===== {txt_path} =====\n")
                        outfile.write(content + "\n")
                        print(f"Added: {txt_path}")
                except Exception as e:
                    print(f"Failed to read {txt_path}: {e}")

print(f"All .txt files combined into: {combined_txt}")
```

![image](https://github.com/user-attachments/assets/67d9d2e1-4146-4a1b-9ec0-2e1d48f448c4)

Then I searched on file and found the flag: 

![image](https://github.com/user-attachments/assets/ab53d6fb-8019-4025-a0cf-c261a67b91f3)

### File Hidden

![image](https://github.com/user-attachments/assets/d786e577-bec4-464b-83d5-b659e15ff815)

For this challenge, it's steganography, not forensic but yeah if I don't solve it I will feel sad so yeah, enjoy it! We were given a wav file. At first, I tried to 
search for spectrogram on **Audacity** but I had no result:

![image](https://github.com/user-attachments/assets/bc8f7778-5178-468f-a487-8f05f39f0fd7)

Now it's the most terrible part in my life: trying all tools I knew until a guy brings me result. After used script from many articles, tried tools on Github, finally 
I found a tool that gave me the result: [HiddenWave](https://github.com/techchipnet/HiddenWave). I installed it, ran and I found zip file inside wav file: 

![image](https://github.com/user-attachments/assets/c2f4f0e5-b3da-4c3f-9d05-8d3938c4f08a)

You can see the header of zip file and flag.txt inside, in this part I saved the result to a file, went to CyberChef, deleted every part not essential:

![image](https://github.com/user-attachments/assets/9715ad96-04bd-4bb4-93db-e5fa1cf9b399)

![image](https://github.com/user-attachments/assets/7f399aa0-f604-46a5-a8b6-076f4a75a588)

### Disk Partition 

For this challenge we have img file and we will have 2 choices: FTK imager or Autopsy, but I love FTK imager more so I chose this guy (this is not advertisement). Simply 
open the file, I searched on MacOS partition and found the flag: 

![image](https://github.com/user-attachments/assets/93c7efc8-98fb-4a29-9a0d-ca888312c313)

That's all. I wonder whether they lacked forensic guys or not, btw I hope they will have Steganography category particularly! Thank you for reading my writeup, see you in 
the next post. Bye 💙💙💙






