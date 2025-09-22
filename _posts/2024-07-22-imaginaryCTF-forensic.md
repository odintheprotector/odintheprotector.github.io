---
layout: post
title: ImaginaryCTF 2024 - Forensic
description: Solutions of some forensic challenges
tags: [ImaginaryCTF, Writeup, Blue Team, Forensic, DFIR]
---

Hi everyone, Imaginary CTF 2024 was celebrated successfully and my team - World Wide Flags got 13th place, and this is my writeup for some challenges (this time I'm lazy 😂😂😂). Ok let's go!

![image](https://github.com/user-attachments/assets/3f99d1a4-38bd-41a9-be0b-9c973a4ede3a)

### bom 

In this challenge they gave us a file contains a Chinese string: 

![image](https://github.com/user-attachments/assets/52072e7d-2321-4515-9762-4762fba7a44c)

You just view hex value inside it and get the flag: 

![image](https://github.com/user-attachments/assets/591c300a-650e-4abb-ab35-5294c3f7588c)

The flag became Chinese string because of a pair of hex value: FE and FF, you know that just one hex value be changed, all content of a file will be changed, and same with this challenge, because FE and FF are in Unicode range, 
the content of file also be affected! 

**Flag: ictf{th4t_isn7_chin3se}**

### packed & routed

I will solve two challenges at a time because they used one sample. In this case they gave us a .pkz file, it's a Packet Tracer file. Very simple, you just download and install Packet Tracer and open file: 

![image](https://github.com/user-attachments/assets/0972b207-f291-4459-86bd-e9d58f9100b3)

At first, I checked all configurations of this file but I could not find anything. After that I thought: "How about checking command history?". Not waiting, I checked and I found many hints about flag (**go to Option -> View command log**):

![image](https://github.com/user-attachments/assets/4770f1ce-aa57-4904-aefa-6b4efb365b7a)

Searched a bit, I found they typed password, and they used mode 7 for typing password:

![image](https://github.com/user-attachments/assets/12d867d3-3cf4-4f99-8cc9-6b9c50b19a98)

Also I found an [article](https://www.cisco.com/c/en/us/support/docs/security-vpn/remote-authentication-dial-user-service-radius/107614-64.html) talks about it. They noted that: "**If that digit is a 7, the password has been encrypted with the weak algorithm.**".
Very clear, we can decrypt this hash, and fortunately I found a [tool](https://packetlife.net/toolbox/type7/) that help me decrypt it: 

![image](https://github.com/user-attachments/assets/8bac5db2-d609-4e02-999a-e8c10bcaf676)

Check the flag with MD5 in detail, it's same, so it's our flag for this challenge!

**Flag 1: ictf{hidden_not_hashed}**

For the second challenge, we need to dig deeper, and if you learn about .pkz file, you will know that .pkz files contain many files inside (you can read more [here](https://contenthub.netacad.com/legacy/I2PT/1.1/en/course/files/4.2.1.1%20Video%20-%20PT%20File%20Types.pdf)):

I used this [tool](https://www.ezyzip.com/open-extract-pkz-file.html) to extract all files inside:

![image](https://github.com/user-attachments/assets/887a16bb-be02-40a8-a772-e034f994163d)

There's a file named **secret.png**. Open it and you will get the flag: 

![image](https://github.com/user-attachments/assets/e62eb0d7-8d68-47db-878a-9c78d11be652)

**Flag 2: ictf{ab4697882634d4aeb6f21141ea2724d0}**

### elf in front of a sunset

For this challenge, they gave us a picture, and we need to analyse it. First, I analysed hex values inside the picture: 

![image](https://github.com/user-attachments/assets/4b606cde-c47b-4b91-9659-18854755c0d0)

If you notice, you will some familiar strings: GGGNNNUU -> GNU; llliiibbb666444 -> lib64;... from here I can be sure that there's an executable file inside. Searched a bit and I found that it must be ELF file: 

![image](https://github.com/user-attachments/assets/ed0e45ee-b1a9-4e59-9fbe-c70d33512030)

Ok so now this is how I extract ELF file. Because they just tripled the number of character, we just reduce it, and also we need to arrange so that all will combine correctly and make an ELF file. because ELF signature was placed in these last lines, I guessed maybe I just reversed it and then I could get ELF file. And now everything is clear, now we will extract it:

- Choose parts that have tripled characters:

![image](https://github.com/user-attachments/assets/41b892d0-6f91-4887-85f1-eba779ac0462)

![image](https://github.com/user-attachments/assets/f7144cf9-4bce-4799-bb9f-201871ac5c20)

- Check length of that part, and divide it into many smaller parts. I took the part that contain signature because it's in these last lines, I guessed authors splited ELF file to many smaller parts that have same length with it. From here you can write a Python script to check length of it:

```
with open("C:\\Users\\Admin\\Documents\\Code\\Python\\payload", "r") as file:
    print(len(file.read().strip().split(' ')))
```

(payload contains file signature part)

![image](https://github.com/user-attachments/assets/69e77f30-5c12-4f2c-afdb-cdab55d022fd)

- Take the length of tripled part divide it by the length we found to find the number of smaller parts that was divided by authors:

```
with open("C:\\Users\\Admin\\Documents\\Code\\Python\\encrypted.txt", 'r') as file:
    arr = file.read().strip().split(" ")
print(len(arr) / 3048)
```

![image](https://github.com/user-attachments/assets/f491ca1b-642a-469f-91da-5410fe1ce518)

- You can see that there're 17 parts, and now as my thinking before, reverse it, decode from hex and we will get the ELF file:

```
with open("C:\\Users\\Admin\\Documents\\Code\\Python\\encrypted.txt", 'r') as file:
    arr = file.read().strip().split(" ")

result = []

for i in range(0, len(arr), 3048):
    result.append(arr[i:i+3048])
payload = result[::-1]

elf = ""
for j in payload: 
    for k in range(0, len(j), 3):
        elf += j[k]
with open("C:\\Users\\Admin\\Documents\\Code\\Python\\result.txt", "w") as f:
    f.write(elf)
```

![image](https://github.com/user-attachments/assets/91a27fb3-e292-4ddc-83ea-25ee8676e806)

Now we got the correct ELF file, we will use IDA or Ghidra to analyse this file: 

![image](https://github.com/user-attachments/assets/551ec689-9371-414c-8e5a-5bed93e1b442)

```
int __fastcall main(int argc, const char **argv, const char **envp)
{
  unsigned __int64 v3; // rbx
  size_t v4; // rax
  char v6; // [rsp+7h] [rbp-49h]
  int i; // [rsp+8h] [rbp-48h]
  char s[40]; // [rsp+10h] [rbp-40h] BYREF
  unsigned __int64 v9; // [rsp+38h] [rbp-18h]

  v9 = __readfsqword(0x28u);  // Read the value of the FS segment base address, not important for the scrambling
  strcpy(s, "_{f2isfsatutflwa_nh2}__asitib1leefwcuk");  // Copy the original string into s
  srand(0x123123Du);  // Seed the random number generator with a specific seed

  for (i = 0; i < strlen(s); ++i)  // Loop over each character in the string
  {
    v6 = s[i];  // Store the current character in v6
    v3 = rand();  // Generate a random number
    v4 = strlen(s);  // Get the length of the string
    s[i] = s[(int)(v3 % v4)];  // Replace the current character with the character at the random position
    s[(int)(v3 % v4)] = v6;  // Replace the character at the random position with the current character
  }
  puts(s);  // Print the scrambled string
  return 0;
}
```

From here I wrote a C code to decrypt it: 

```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void shuffle(char* flag, int* swaps, int size) {
    for (int i = 0; i < size; i++) {
        int idx = rand() % size;
        swaps[i] = idx;
        char tmp = flag[i];
        flag[i] = flag[idx];
        flag[idx] = tmp;
    }
}

void reverse_shuffle(char* flag, int* swaps, int size) {
    for (int i = size - 1; i >= 0; i--) {
        int idx = swaps[i];
        char tmp = flag[i];
        flag[i] = flag[idx];
        flag[idx] = tmp;
    }
}

int main() {
    srand(0x123123D);
    char scrambled_flag[] = "_{f2isfsatutflwa_nh2}__asitib1leefwcuk";
    int size = strlen(scrambled_flag);
    int swaps[40];

    // Perform the shuffle to record the swaps
    char dummy_flag[40];
    strcpy(dummy_flag, scrambled_flag);
    shuffle(dummy_flag, swaps, size);

    // Reverse the shuffle to recover the original flag
    reverse_shuffle(scrambled_flag, swaps, size);
    puts(scrambled_flag);
    return 0;
}
```

![image](https://github.com/user-attachments/assets/d059a564-6fa9-4bf4-add1-50ef061d03e1)

**Flag: ictf{elf_waifus_best_waifus_2h12lntka}**

Thank you for watching, hope you enjoy it 🫀. See you in the next writeup, bye!!!!!






