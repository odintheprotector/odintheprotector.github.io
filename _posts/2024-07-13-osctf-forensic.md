---
layout: post
title: OSCTF 2024 - Forensic
description: All solved forensic challenges
tags: [OSCTF, Writeup, Command and Control, Powershell, Blue Team]
---

Hi guys, this time I joined HITCON CTF with my team: World Wide Union, but because of no forensic challenges, I had to go here and try to solve some challenges. Now it's my writeup for them, let's go!

### The Lost Image Mystery

They gave us a corrupted image and we need to recover it. I used **xxd** to check hex values inside: 

![image](https://github.com/user-attachments/assets/47973ec9-b605-4461-b735-6120298a3f34)

You can guess easily it must be JPG or JPEG file because of **...IF**. From here you can use this [list](https://en.wikipedia.org/wiki/List_of_file_signatures) to check the signature for the file:

![image](https://github.com/user-attachments/assets/ebe36603-a769-4532-bf37-f6b9735c717b)

Use **hexedit** to edit hex value, open the file again and enjoy your result: 

![image](https://github.com/user-attachments/assets/60eb75f6-7a8f-499f-bf01-6977ee5852f3)

**Flag: OSCTF{W0ah_F1l3_h34D3r5}**

### The Hidden Soundwave

We got an audio file, and as the title, you need to find hidden information inside the audio file. Very basic, I always check **spectrogram** because it appeared in many CTFs 😂😂😂. From here I used **audacity** to open audio file, change to spectrogram view and I got the flag:

![image](https://github.com/user-attachments/assets/51967e98-e818-4a7b-af1c-140f88493948)

**Flag: OSCTF{M3s54g3_1nt3Rc3p7eD}**

### Mysterious Website Incident

Now we had a nginx log, and very simple, we just open in text editor and analyse it: 

![image](https://github.com/user-attachments/assets/52e22c77-2d97-453e-9a5c-fa682a4d3f19)

After searching, I found a GG drive link, open it and I got the flag:

![image](https://github.com/user-attachments/assets/d7a937f7-f3fc-45b3-9214-759634091db8)

![image](https://github.com/user-attachments/assets/e66189b3-c4b1-4971-9f37-279f3eb67aec)

**Flag: OSCTF{1_c4N_L0g!}**

### Phantom Script Intrusion

For this challenge, they gave us a PHP code, and it was obfucated:

![image](https://github.com/user-attachments/assets/48606e3c-d53f-47a3-a5fb-5d227cec4175)

To make it easier to follow, I deobfucated it and this is my final script:

```
${"GLOBALS"} = "hXXps://sh0rturl.at/s1fW2";
${"var1"} = str_rot13("${\"\\x47\\x4c\\x4f\\x42\\x41\\x4c\\x53\"}");
${"var2"} = base64_decode(${${"var1"}});
if (strlen(${"var2"}) > 0) {
    ${"var3"} = ${"var2"};
} else {
    ${"var3"} = "";
}
${"var4"} = "";
foreach (str_split(${"var3"}) as ${"var5"}) {
    ${"var4"} .= chr(ord(${"var5"}) - 1);
}
eval(${${"var4"}});
```

There's a [shorturl link](https://drive.google.com/file/d/1_Gc2BdQZyft9UTv-BmwMiXXcqH6kNLeE/view), access it and got the flag:

![image](https://github.com/user-attachments/assets/3a70768d-d0d7-4d4e-931d-9883c0c7cd94)

**Flag: OSCTF{M4lW4re_0bfU5CAt3d}**

### PDF Puzzle

Just check the metadata of the file => get the flag:

![image](https://github.com/user-attachments/assets/b32eed43-874f-46f5-8e74-a6839f600866)

**Flag: OSCTF{H3il_M3taD4tA}** 

### Seele Vellorei

In this challenge we had a docx file. At first I tried to find out VBA code inside, but there's nothing, so I think maybe flag was hidden somewhere inside the file. Because word structure is same with zip file, you can use **binwalk** to extract all files inside: 

![image](https://github.com/user-attachments/assets/8f384d0c-a1f1-4041-975f-e3aa302d2c42)

Navigate to **document.xml** where content of file was stored, use **grep** and I found the flag: 

![image](https://github.com/user-attachments/assets/2feeac78-d25a-442e-8dfe-3bbf51091076)

**Flag: OSCTF{V3l10n4_1s_Gr43t}** 

### FOR101

I love this challenge most, so I will explain it carefully. In this challenge we had a zip file contains datas inside an User directory. I opened it by **7z**:

![image](https://github.com/user-attachments/assets/0de1901e-4f8a-464d-a23b-0d8725d5eba9)

After searching, I found an .eml file at **\Users\Administrator\Downloads\Outlook Files** named **Notifications.eml**:

![image](https://github.com/user-attachments/assets/0ef40292-0336-4da1-a012-e826f34cd2c7)

I extracted it to my machine and use **ThunderBird** to open the file: 

![image](https://github.com/user-attachments/assets/4e5b1b59-8cdb-41d7-b478-a199cd2b8922)

You can see that there's a zip file and the password is **CreditsCardForFree**. Now let's open this file and see what inside:

![image](https://github.com/user-attachments/assets/d8f612fe-6c93-4f31-bbb5-fc6826393bcd)

There's a xlsm file, and as usual, I always check VBA code inside by using **olevba**:

![image](https://github.com/user-attachments/assets/96207dd2-518a-46f4-8686-3f47352d483f)

You can see that there's a VBA code and it's obfucated, and we don't any choice except deobfucate it by your hand or you can read code by **Ctrl+F+the_name_of_func**. After this I found that function will process a string looks like URL:

![image](https://github.com/user-attachments/assets/9393de57-7d6e-4f90-be80-005f8c8a3f62)

![image](https://github.com/user-attachments/assets/ea01c679-d2e7-451f-a665-0435bc78b875)

From here I can realise that our function are trying to decode that string. Based on their function, I rewrote a Python script for automatic decoding:

```
def decode_string(encoded_string, decode_table, encoded_substitution):
    decoded_string = ""
    for y in range(len(encoded_string)):
        char_index = decode_table.find(encoded_string[y])
        if char_index > -1:
            decoded_char = encoded_substitution[char_index]
            decoded_string += decoded_char
        else:
            decoded_string += encoded_string[y]
    return decoded_string
encoded_string = "Ü³³Bb://B_b³Ekài~B#/jàEÄ/²_Ä/À60äm_§À"
decode_table = " ?!@#$%^&*()_+|0123456789abcdefghijklmnopqrstuvwxyz.,-~ABCDEFGHIJKLMNOPQRSTUVWXYZ¿¡²³ÀÁÂĂÄÅÓÔƠÖÙÛÜàáâăäåØ¶§Ú¥"
encoded_substitution = "ăXL1lYU~Ùä,Ca²ZfĂ@dO-cq³áƠsÄJV9AQnvbj0Å7WI!RBg§Ho?K_F3.Óp¥ÖePâzk¶ÛNØ%G mÜ^M&+¡#4)uÀrt8(Sw|T*Â$EåyhiÚx65Dà¿2ÁÔ"
decoded_string = decode_string(encoded_string, decode_table, encoded_substitution)
print(decoded_string)
```

![image](https://github.com/user-attachments/assets/721d9a31-7f9a-41ff-82c3-e58963912504)

I got a link, now let's open it and see what inside:

![image](https://github.com/user-attachments/assets/93b35702-5f13-4b85-990b-a00897f64d08)

You can see that there's a Powershell script and it will execute a command that was encoded by base64. Now we continue to decode base64 string:

![image](https://github.com/user-attachments/assets/b65900e1-7e5d-4283-8419-66db8f0a0dd8)

There's a base64 string again. I decoded it and got one more script:

![image](https://github.com/user-attachments/assets/2684a7ef-fb65-4c14-8f6a-c15c9b19d49f)

In **$galf** variable, it will take each elements in **$qwedfaz** and decode it to ascii character. From here I wrote a Python script again: 

```
arr = [104,116,116,112,115,58,47,47,112,97,115,116,101,98,105,110,46,112,108,47,118,105,101,119,47,114,97,119,47,98,100,99,97,49,55,48,50]

for i in arr:
    print(chr(i), end='')
```

![image](https://github.com/user-attachments/assets/5b6a1a0a-6340-4670-aada-3cb12c45d4a2)

I got a link again, opened it and I got the flag:

![image](https://github.com/user-attachments/assets/00dd5ca6-04c9-47d1-ae74-3148db26a504)

**Flag: OSCTF{JU5t_n0rmal_eXE1_f113_w1th_C2_1n51De}**

Thank you for watching, hope you enjoy this. I solved other challenges but I still love forensic so I just wrote writeup for it 😂😂😂. See you in other CTFs, bye!!!





