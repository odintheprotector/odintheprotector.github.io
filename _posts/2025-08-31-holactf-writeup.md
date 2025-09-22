---
layout: post
title: HolaCTF 2025 - Writeup
description: Writeups for some challenges I solved
tags: [HolaCTF, Crypto, Writeup, Blue Team, Memory Forensic, OSINT]
---

Hi guys, I and my teammates from **L3_u3th** have joined HolaCTF 2025 and got 8th place overall. This was a good rank for us and now it is time for my writeups. 
Let's go!

### OSINT - HolaCTF
First, we had an image from organizers: 

![image](https://github.com/user-attachments/assets/8d8e1fe7-f497-40ea-967c-8d960a1d86a0)

Based on the image, we could know the existence of HolaCTF 2023, I searched on Google and I found posts of it:

![image](https://github.com/user-attachments/assets/58b29715-b540-44e6-a97d-ee85ce485b6c)

I went to the Facebook page of EHC, searched for **HolaCTF 2023** and I found their post: 

![image](https://github.com/user-attachments/assets/f07d0410-9921-4bfe-9c34-557531286ead)

Searched for the newest comment, I found **anhshidou** comment:

![image](https://github.com/user-attachments/assets/59718d46-342d-4d77-a4ab-28e12ee9522f)

We can see that there has a tag which looks like being encoded. In that part I guess a little bit and I found it using **Vigenere cipher** for encoding which key is 
**HolaCTF**:

![image](https://github.com/user-attachments/assets/42fc6e11-61e6-4519-96a8-bccd40fd28ae)

It's an Instagram profile which takes us to another guys: 

![image](https://github.com/user-attachments/assets/7f44e78b-75ea-46a1-9bac-5698d7efec49)

In my writeup that I submitted to organizers I don't notice about how many times I take myself to rabbit hole, now it's time for them 💀. First, with the username 
I found, I used **sherlock** which will use this username and search on another platform:

![image](https://github.com/user-attachments/assets/da7f0bb6-d873-49e1-9bbf-828f3b3a3913)

Beside Instagram, I tried to look at some sites in that list and I got nothing. Then I used this username and searched on Github and I found a commit:

![image](https://github.com/user-attachments/assets/ee414e7c-4ad3-48de-aa5d-dd7eca31de8f)

This commit led to another account: **liemaiball**. I searched on his Github but all I got were checking on Instagram again. Since I have not watched video carefully, 
I always tried to find information through this username. Then I repeated my process, used **sherlock** but no result. Moreover, I extracted his email by adding **.patch** 
to the commit:

![image](https://github.com/user-attachments/assets/dff61bfb-74eb-442b-8d10-099a87f3f042)

With this email I used **blackbird** to search how many platforms using this email and I found it on Twitter:

![image](https://github.com/user-attachments/assets/d644d381-1c44-400e-a727-5148b268bc14)

![image](https://github.com/user-attachments/assets/b4f5a271-602a-4401-8dfd-ab23490e6410)

I went to this account and... I got into rabbit hole again 💀:

![image](https://github.com/user-attachments/assets/88f50e9c-18f3-4a3b-8517-a942a3b6bdfd)

Then I tried to look up on comment section and I found **anhshidou** comments:

![image](https://github.com/user-attachments/assets/6adacf5a-78fd-429a-bf80-a107b699b56d)

Go to his profile, I found a Discord link which redirected me to a Discord server, I searched flag on that server and booyahh... rabbit hole again 💀. Ok, I felt 
depressed at that moment, then I tried to watch video again and I realised how I was careless, I found another link when watched video: 

![image](https://github.com/user-attachments/assets/c40f5ec5-36b9-45d0-8583-706bfbe0c490)

OK 💀. From here I accessed website:

![image](https://github.com/user-attachments/assets/827906e0-daa2-4396-99a6-756f1ade4810)

I inspected the website and I found a comment: 

![image](https://github.com/user-attachments/assets/ca48cef9-6291-4704-8d43-6e80e3fbd562)

First, I tried to search on Wayback Machine since it could have record before, but when I searched it had no result, then I tried to look at DNS record since the 
website could not access anymore and even the website was down, DNS records could still be in, so I used **dig** to search and I got good result:

![image](https://github.com/user-attachments/assets/25a049f5-8c25-4f4a-987a-29631dc4c051)

OK so it would have possibility to have another DNS record, I searched on TXT record and I found the flag 💀 (nice challenge btw):

![image](https://github.com/user-attachments/assets/92085c81-5711-4c67-adfc-b6667b4dc2f5)

### Forensic - First step into forensic

In this challenge we have 3 files: 1 zip file, 1 kdbx file and 1 dmp file, at first glance we can guess that we will find a way to open the kdbx file. This article is a true string grep 💀💀💀
At first I used r2 with the intention of extracting the exe file for analysis, but there was no feasible result and I also found this part absurd because if the key 
appeared in the process like this, it would be really bad, but I still followed the concept and searched for articles, and I found 
[an article](https://www.sysdig.com/blog/keepass-cve-2023-32784-detection) that I thought was quite ok for my idea: 

In the article, it mentioned extracting all possible masterkeys and at the same time bruteforce to detect the password, however, after using some related tools, I 
still couldn't detect anything, and here I used the last step which was also the step I didn't want to do: strings + grep 💀💀💀
I strings the entire file into another file and read from from beginning to end 💀💀💀 (sorry anhshidou 😄), and I found a rather suspicious string:

![image](https://github.com/user-attachments/assets/d5b4b43c-e330-4038-b4f8-5b95f119f6fa)

I used this string as password to open kdbx file and I opened it sucessfully 💀:

![image](https://github.com/user-attachments/assets/5c7d0169-afde-4fcb-98a9-aebfe02169bd)

Press Ctrl + H to reveal all passwords and I got zip password: 

![image](https://github.com/user-attachments/assets/532c0a9f-83f7-4466-a773-1b12020d84e0)

The password is **chaomungtoiholactf2025kekw** and I could unzip with this password: 

![image](https://github.com/user-attachments/assets/e06834a0-d1e2-4c96-8e5e-6b5f4fde1d08)

I stringed the file and got the flag: 

![image](https://github.com/user-attachments/assets/3777ebb8-9bf8-4db2-b5bd-d5f7e1e88cf1)

### Crypto - Cs2Trash and ImLosingYou

These 2 challenges I used ChatGPT for solving so I hope you will feel good for this and it might be chance to prove the power of AI 😂.

Script for Cs2Trash: 

```python
from Crypto.Util.number import long_to_bytes, inverse
from math import gcd
import random

# --- given ---
e = 65537
n1 = 106274132069853085771962684070654057294853035674691451636354054913790308627721
n2 = 73202720518342632558813895439681594395095017145510800999002057461861058762579
n3 = 58129476807669651703262865829974447479957080526429581698674448004236654958847

# >>> paste your ciphertexts here <<<
c1 = 40409669713698525444927116587938485167766997176959778633087672968720888190012
c2 = 50418608792183022472533104230595523000246213655735834753443442906871618770832
c3 = 7151799367443802424297049002310776844321501905398348074481144597918413565153

def is_probable_prime(n, k=12):
    if n < 2: return False
    small = [2,3,5,7,11,13,17,19,23,29,31,37]
    for p in small:
        if n % p == 0:
            return n == p
    # Miller–Rabin
    d = n - 1
    s = 0
    while d % 2 == 0:
        s += 1
        d //= 2
    for _ in range(k):
        a = random.randrange(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for __ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False
    return True

def decrypt_if_prime(n, c):
    if is_probable_prime(n):
        d = inverse(e, n - 1)
        m = pow(c, d, n)
        return m
    return None

def pollards_rho(n):
    if n % 2 == 0: return 2
    if is_probable_prime(n): return n
    while True:
        x = random.randrange(2, n-1)
        y = x
        c = random.randrange(1, n-1)
        d = 1
        f = lambda v: (v*v + c) % n
        while d == 1:
            x = f(x)
            y = f(f(y))
            d = gcd(abs(x - y), n)
        if d != n:
            return d

def factor_semiprime(n):
    # quick try: Pollard Rho once
    p = pollards_rho(n)
    if p in (1, n): return None
    q = n // p
    if p*q == n:
        return int(p), int(q)
    return None

def decrypt_if_composite(n, c):
    # You already checked gcds == 1, so try to factor n itself
    pq = factor_semiprime(n)
    if not pq:
        return None
    p, q = pq
    phi = (p-1)*(q-1)
    d = inverse(e, phi)
    return pow(c, d, n)

pairs = [(n1, c1), (n2, c2), (n3, c3)]
plain_candidates = []

for (n, c) in pairs:
    m = decrypt_if_prime(n, c)
    if m is None:
        m = decrypt_if_composite(n, c)
    if m is None:
        print(f"Could not decrypt with modulus n={n}")
    else:
        plain_candidates.append(m)

# sanity: all match?
if plain_candidates and all(x == plain_candidates[0] for x in plain_candidates):
    m = plain_candidates[0]
    print("m =", m)
    try:
        print("bytes =", long_to_bytes(m))
    except Exception:
        print("Could not convert to bytes cleanly.")
else:
    print("Recovered plaintexts do not all agree yet (or none recovered).")
```

And for the last challenge, we will solve by using **Coppersmith small-root**:

```python
# recover.py  -- run with: sage -python recover.py
from sage.all import Integer, PolynomialRing, ZZ

# === paste your values here ===
n = 5655306554322573090396099186606396534230961323765470852969315242956396512318053585607579359989407371627321079880719083136343885009234351073645372666488587
c = 249064480176144876250402041707185886135379496538171928784862949393878232927200977890895568473400681389529997203697206006850790029940405682934025
mod_m = 499063603337435213780295973826237775412685978121823376141602090122856806
# ==============================

# variable and polynomial ring over integers
R = PolynomialRing(ZZ, 'x')
x = R.gen()

# polynomial f(x) = (mod_m + x)^2 - c
f = (mod_m + x)**2 - c

# bound on root (80 bits)
X = 2**80

# use Sage's small_roots (Coppersmith)
roots = f.small_roots(X=X)   # returns a list of integer roots

if not roots:
    print("No small roots found (increase X or check values).")
else:
    for r in roots:
        m = mod_m + Integer(r)
        # sanity check: does m^2 % n == c ?
        if pow(int(m), 2, int(n)) == int(c):
            try:
                flag_bytes = Integer(m).to_bytes((m.bit_length()+7)//8, 'big')
                print("Recovered r =", r)
                print("Recovered m =", m)
                print("Flag bytes:", flag_bytes)
                print("Flag (utf-8):", flag_bytes.decode('utf-8', errors='replace'))
            except Exception as e:
                print("Recovered m but failed to convert to bytes:", e)
        else:
            print("Root found but verification failed for r =", r)
```

![image](https://github.com/user-attachments/assets/09e91ba4-24b2-47fa-8512-2bae153930c2)














