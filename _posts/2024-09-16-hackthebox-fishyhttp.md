---
layout: post
title: HackTheBox - Fishy HTTP
description: I found a suspicious program on my computer making HTTP requests to a web server. Please review the provided traffic capture and executable file for analysis!
tags: [HackTheBox, Writeup, Blue Team, ILSpy, Malware, Command and Control]
---

Hi everyone, I have not been writing any solutions related to HackTheBox challenges and I returned it last night, choosed a challenge and solved it. It's just for fun so... let's go!

These are two files we will use to solve their challenge: 

![image](https://github.com/user-attachments/assets/ba8352c4-98b6-4914-89f6-a22f099c99c9)

First, I checked pcapng file by using Wireshark: 

![image](https://github.com/user-attachments/assets/a0d58224-10e7-48c9-b4f3-787912b98515)

There're just HTTP packets, so I will watch their stream to see whether anything is interesting or not and I found a weird string in stream 1:

![image](https://github.com/user-attachments/assets/6aea1dcf-9efc-4df5-b745-cbafb82996f6)

From here I could guess that all things were created by that executable file, let's reverse it to see inside. First, I checked by using **exiftool**:

![image](https://github.com/user-attachments/assets/5e6a4d5b-0023-4408-8158-606a304ec140)

The first name of this file is **MyProject.dll** and in its exiftool information there's nothing interesting. If you learnt about how an executable file is created, you 
must know that an exe file is created by many files; example, for Windows an exe file will be created by compiling source code, linking with other DLL files inside system and 
you will get an exe file and these informations you can find easily by **strings** the file 😂😂😂. I tried to use it and I found that it was created by using IL code: 

![image](https://github.com/user-attachments/assets/86122805-a8af-49f8-a98a-f4efd5f3e03c)

From here I used [ILSpy](https://github.com/icsharpcode/ILSpy) to decompile it: 

![image](https://github.com/user-attachments/assets/f6b9896a-e8e2-4cbb-a20c-60b8a9bbc5db)

First, they created a dictionary, I don't know how to describe so I wrote a Python script to describe its mechanism:

![image](https://github.com/user-attachments/assets/25873edf-e704-4a30-8f98-2e5cd579ba5a)

![image](https://github.com/user-attachments/assets/0a3080bd-2840-45a6-b684-509e653cf877)

And with this dictionary, they encoded each character in their payload in **EncodeData** function, you can understand like this: if your payload is "bruhbruhlmao", this code will take each 
character inside this payload, take a random string in dictionary that its first character is the taken character before:

![image](https://github.com/user-attachments/assets/d9ad6278-0314-47ef-a112-2688d345a33d)

After that the payload will be passed into a **KeyValuePair** variable named **feedback** and sent through IP and port as you can see in Wireshark:

![image](https://github.com/user-attachments/assets/87e87308-6318-4fb6-ad93-3a026ec81e78)

![image](https://github.com/user-attachments/assets/ea780793-49be-4213-a246-e519ccc793fd)

Now we know their type of encoding, let's decode it. We just do it reversingly and we will get the first part of flag:

```
import base64
def decode_base64(a):
    temp = ""
    for j in a.split(" "):
        temp += j[0]
    print(base64.b64decode(temp).decode())
with open("C:\\Users\\Admin\\Documents\\Code\\Python\\download.dat", "r") as file:
    payload = file.read().split("\n")

for i in range(len(payload)):
    decode_base64(payload[i])
```

![image](https://github.com/user-attachments/assets/9aa3ff6d-4ce2-418c-99f1-ebe48dff9fc5)

**The first part: h77P_s73417hy_revSHELL}**

And the final function is DecodeData which is used to decode data in HTML body tag:

![image](https://github.com/user-attachments/assets/d0e69b94-6252-426c-90ef-b7f4d1b37505)

Again, write a Python script to decode it and we will get the final part of the flag: 

```
import base64
import random
import re
import requests
import subprocess
from collections import defaultdict
from urllib.parse import urlencode

# Main function
# Decode data
tag_hex = {
    "cite": "0",
    "h1": "1",
    "p": "2",
    "a": "3",
    "img": "4",
    "ul": "5",
    "ol": "6",
    "button": "7",
    "div": "8",
    "span": "9",
    "label": "a",
    "textarea": "b",
    "nav": "c",
    "b": "d",
    "i": "e",
    "blockquote": "f"
}

def decode_data(data):
    body = re.search(r"<body>(.*?)</body>", data, re.S)
    if not body:
        return ""
    
    body_text = body.group(1)
    lines = body_text.splitlines()
    string_builder = []
    
    for match in re.finditer(r"<(\w+)[\s>]", lines[0], re.S):
        tag = match.group(1)
        if tag != "li":
            string_builder.append(tag_hex[tag])
    
    return hex_string_to_bytes("".join(string_builder))


# Hex string to bytes
def hex_string_to_bytes(hex_str):
    bytes_data = bytes.fromhex(hex_str)
    return bytes_data.decode('ascii')

#print(decode_data("<body><button>leaf tree glasses uniform guitar tiger umbrella book</button><button>panda universe quartz laptop</button><ol><li>rabbit jewel avocado sun plane</li></ol><div>house ball elephant trumpet fence mango fire hedgehog</div><ol><li>jar garden</li></ol><blockquote>mango yucca yurt bird lion</blockquote><ol><li>ball question apple necklace penguin zone xanthan quadrilateral</li></ol><h1>ice universe car tooth castle</h1><ol><li>notebook popcorn flag helicopter ant mailbox</li></ol><b>dinosaur door octopus</b><ol><li>mouse pencil grape quill pear utensil quiver</li></ol><span>utensil elephant grape cookie apple heart yucca knight anchor</span></body>"))
with open("C:\\Users\\Admin\\Documents\\Code\\Python\\download.dat", "r") as file:
    arr = file.read().split("\n")
payload = ''.join(arr)
print(decode_data(payload))
```

![image](https://github.com/user-attachments/assets/1ff6565c-838a-4da3-b429-81e370f5518b)

**Flag: HTB{Th4ts_d07n37_h77P_s73417hy_revSHELL}**

That's it, this is an easy challenge and it's very suitable for newbies (I think so). OK thank you very much for reading my article. See you in the next post, bye 🫀🫀🫀










