---
layout: post
title: Securinets CTF 2025 - Forensic
description: The solutions for all forensic challenges in this CTF
tags: [Securinets, Writeup, Command and Control, Virustotal, Blue Team, Reverse Engineering, Disk Forensic, Network Forensic, Memory Forensic, Golang]
---

Hi everyone, it's very happy that we gained the 16th rank in **Securinets CTF 2025**, and this is my writeup for all forensic challenges. Let's go

### Silent Visitor

These were the answers for this challenge, this challenge I will try to summarize how I have solved since I am too lazy to write details 😙:

```
What is the SHA256 hash of the disk image provided?
Input: 122b2b4bf1433341ba6e8fefd707379a98e6e9ca376340379ea42edb31a5dba2
Correct answer
Identify the OS build number of the victim’s system?
Input: 19045
Correct answer
What is the ip of the victim's machine?
Input: 192.168.206.131
Correct answer
What is the name of the email application used by the victim?
Input: thunderbird
Correct answer
What is the email of the victim?
Input: ammar55221133@gmail.com
Correct answer
What is the email of the attacker?
Input: masmoudim522@gmail.com
Correct answer
What is the URL that the attacker used to deliver the malware to the victim?
Input: https://tmpfiles.org/dl/23860773/sys.exe
Correct answer
What is the SHA256 hash of the malware file?
Input: be4f01b3d537b17c5ba7dc1bb7cd4078251364398565a0ca1e96982cff820b6d
Correct answer
What is the IP address of the C2 server that the malware communicates with?
Input: 40.113.161.85
Correct answer
What port does the malware use to communicate with its Command & Control (C2) server?
Input: 5000
Correct answer
What is the url if the first Request made by the malware to the c2 server?
Input:  http://40.113.161.85:5000/helppppiscofebabe23
Correct answer
The malware created a file to identify itself. What is the content of that file?
Input: 3649ba90-266f-48e1-960c-b908e1f28aef
Correct answer
Which registry key did the malware modify or add to maintain persistence?
Input: HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\MyApp
Correct answer
What is the content of this registry?
Input: C:\Users\ammar\Documents\sys.exe
Correct answer
The malware uses a secret token to communicate with the C2 server. What is the value of this key?
Input:
Input: e7bcc0ba5fb1dc9cc09460baaa2a6986
Correct answer
Sahaaaaaaaaaaa Securinets{de2eef165b401a2d89e7df0f5522ab4f}
by enigma522
```

Q2: Check on **SOFTWARE\Microsoft\Windows NT\CurrentVersion**

Q3: Check on **SYSTEM\ControlSet001\Services\Tcpip\Parameters\Interfaces**

Q4: The email application used was **thunderbird**

![image](https://github.com/user-attachments/assets/e0d6b222-5f2d-4ee1-b4ed-51f6348bf3e1)

Q5 + Q6: You could find the both emails in Thunderbird profile: 

![image](https://github.com/user-attachments/assets/cc68aa0e-fc96-47c4-ac01-d3df2d3e7be3)

Q7 + Q8 + Q9 + Q10: I used Virustotal mainly, for the first 3 questions you could find them easily and for Q10 in Virustotal, the malware dropped a file which was 
**id.txt** in **Public/Documents** and you could find it easily:

![image](https://github.com/user-attachments/assets/184f2dd0-d3a6-4d48-a7f6-711f2bca1ece)

Q10 + Q11: Virustotal contained information about Q10, and we could find the value of registry by parsing **NTUSER.dat**:

![image](https://github.com/user-attachments/assets/e99976b1-4a10-42bd-87b4-7aeb328035af)

For the last questions we must reverse the malware sample (actually not quite), open it on IDA and you can find that secret on main function:

![image](https://github.com/user-attachments/assets/462458e1-f896-4e8a-b083-d7a2008dd064)

### Lost File

We were given 2 samples: an AD1 file and a vmem file. First, I opened AD1 by FTK Imager: 

![image](https://github.com/user-attachments/assets/d03bf1ae-a50d-4040-88e2-dcc2a64ba4d4)

And as the image you could see there are an executable file and encrypted file and that's our answer. I simple exported the exe file and analyzed on IDA Pro:

![image](https://github.com/user-attachments/assets/c1129ded-a061-46cb-b710-6a3ea8cd5901)

This was the full disassembled code of main function: 

```asm
int __cdecl main(int argc, const char **argv, const char **envp)
{
  size_t v4; // ebx
  size_t v5; // eax
  char FileName[260]; // [esp+14h] [ebp-694h] BYREF
  size_t ElementCount; // [esp+118h] [ebp-590h] BYREF
  void *v8; // [esp+11Ch] [ebp-58Ch] BYREF
  size_t v9; // [esp+120h] [ebp-588h] BYREF
  void *Src; // [esp+124h] [ebp-584h] BYREF
  char v11[260]; // [esp+128h] [ebp-580h] BYREF
  BYTE v12[4]; // [esp+22Ch] [ebp-47Ch] BYREF
  int v13; // [esp+230h] [ebp-478h]
  int v14; // [esp+234h] [ebp-474h]
  int v15; // [esp+238h] [ebp-470h]
  BYTE v16[4]; // [esp+23Ch] [ebp-46Ch] BYREF
  int v17; // [esp+240h] [ebp-468h]
  int v18; // [esp+244h] [ebp-464h]
  int v19; // [esp+248h] [ebp-460h]
  int v20; // [esp+25Ch] [ebp-44Ch] BYREF
  void *Block; // [esp+260h] [ebp-448h] BYREF
  char Buffer[260]; // [esp+264h] [ebp-444h] BYREF
  CHAR Filename[260]; // [esp+368h] [ebp-340h] BYREF
  char Str[260]; // [esp+46Ch] [ebp-23Ch] BYREF
  char Destination[256]; // [esp+570h] [ebp-138h] BYREF
  FILE *Stream; // [esp+670h] [ebp-38h]
  BYTE *pbData; // [esp+674h] [ebp-34h]
  size_t Size; // [esp+678h] [ebp-30h]
  size_t v29; // [esp+67Ch] [ebp-2Ch]
  DWORD ModuleFileNameA; // [esp+680h] [ebp-28h]
  char *v31; // [esp+684h] [ebp-24h]
  size_t Count; // [esp+688h] [ebp-20h]
  CHAR *i; // [esp+68Ch] [ebp-1Ch]
  int *p_argc; // [esp+69Ch] [ebp-Ch]

  p_argc = &argc;
  __main();
  if ( argc <= 1 )
    return 1;
  v31 = (char *)argv[1];
  memset(Destination, 0, sizeof(Destination));
  if ( read_computername_from_registry((LPBYTE)Destination, 256) )
  {
    strncpy(Destination, "UNKNOWN_HOST", 0xFFu);
    Destination[255] = 0;
  }
  fflush(&__iob[1]);
  memset(Str, 0, sizeof(Str));
  memset(Filename, 0, sizeof(Filename));
  ModuleFileNameA = GetModuleFileNameA(0, Filename, 0x104u);
  if ( !ModuleFileNameA || ModuleFileNameA > 0x103 )
    goto LABEL_18;
  for ( i = &Filename[ModuleFileNameA - 1]; i >= Filename && *i != 92 && *i != 47; --i )
    ;
  if ( i >= Filename )
  {
    Count = i - Filename;
    if ( i == Filename )
    {
      strncpy(Str, Filename, 0x103u);
      Str[259] = 0;
    }
    else
    {
      if ( Count > 0x103 )
        Count = 259;
      strncpy(Str, Filename, Count);
      Str[Count] = 0;
    }
  }
  else
  {
LABEL_18:
    strcpy(Str, ".");
  }
  v29 = strlen(Str);
  if ( v29 && (Str[v29 - 1] == 92 || Str[v29 - 1] == 47) )
    snprintf(Buffer, 0x104u, "%ssecret_part.txt", Str);
  else
    snprintf(Buffer, 0x104u, "%s\\secret_part.txt", Str);
  Block = 0;
  v20 = 0;
  read_file_to_buffer(Buffer, (int)&Block, (int)&v20);
  DeleteFileA(Buffer);
  v4 = strlen(v31);
  Size = v4 + strlen(Destination) + v20 + 10;
  pbData = (BYTE *)malloc(Size);
  if ( v20 )
    snprintf((char *const)pbData, Size, "%s|%s|%s", v31, Destination, (const char *)Block);
  else
    snprintf((char *const)pbData, Size, "%s|%s|", v31, Destination);
  v5 = strlen((const char *)pbData);
  if ( sha256_buf(pbData, v5, v16) )
  {
    puts("SHA256 failed");
    return 1;
  }
  else
  {
    *(_DWORD *)v12 = *(_DWORD *)v16;
    v13 = v17;
    v14 = v18;
    v15 = v19;
    if ( Str[strlen(Str) - 1] == 92 || Str[strlen(Str) - 1] == 47 )
      snprintf(v11, 0x104u, "%sto_encrypt.txt", Str);
    else
      snprintf(v11, 0x104u, "%s\\to_encrypt.txt", Str);
    Src = 0;
    v9 = 0;
    if ( read_file_to_buffer(v11, (int)&Src, (int)&v9) )
    {
      printf("Target file not found: %s\n", v11);
      return 1;
    }
    else
    {
      v8 = 0;
      ElementCount = 0;
      if ( aes256_encrypt_simple((int)v16, v12, Src, v9, (int)&v8, (int)&ElementCount) )
      {
        puts("Encryption failed");
        return 1;
      }
      else
      {
        if ( Str[strlen(Str) - 1] == 92 || Str[strlen(Str) - 1] == 47 )
          snprintf(FileName, 0x104u, "%sto_encrypt.txt.enc", Str);
        else
          snprintf(FileName, 0x104u, "%s\\to_encrypt.txt.enc", Str);
        Stream = fopen(FileName, "wb");
        if ( Stream )
        {
          fwrite(v8, 1u, ElementCount, Stream);
          fclose(Stream);
          if ( Block )
            free(Block);
          if ( Src )
            free(Src);
          if ( v8 )
            free(v8);
          free(pbData);
          return 0;
        }
        else
        {
          return 1;
        }
      }
    }
  }
}
```

First, this program would take the input user, find the computer name and if file exists, then jump to **LABEL_18**:

![image](https://github.com/user-attachments/assets/d6377162-336b-422c-a550-8bea413a754d)

![image](https://github.com/user-attachments/assets/7f6c19c8-a42b-47fa-b54c-5f7c83c0709b)

You could find out that this label contained encryption method, and notice that they use **snprintf** which was used to write formatted string and in this case the 
string contained 3 parts: **v31**, **Destination** and **Block**. **v31** is user input and **Destination** is computer name and **Block** is something we don't know. After 
formatted string, the program would compute the SHA256 value and used as a key for AES256 encryption:

![image](https://github.com/user-attachments/assets/eb87f742-d85e-4fb4-a35d-b3769ea911d8)

Now we will dig into vmem file, for v31 and Destination we could find them easily by using volatility plugins: **envars** and **consoles**:

![image](https://github.com/user-attachments/assets/882e2aca-ac73-4f04-8dbb-97b2d6680e93)

![image](https://github.com/user-attachments/assets/e2cdf509-3e7b-45de-bebd-f21a441760b4)

And for the last part, I searched on FTK Imager and I found a deleted file which contained a string "sigmadroid" so I knew that's the thing I needed. From here we can 
recover the AES key and iv and decrypt easily: 

![image](https://github.com/user-attachments/assets/dc0789ac-2096-489f-b0d2-50e509c993b5)

![image](https://github.com/user-attachments/assets/1983b860-c54e-4972-87fb-dd99fb5294c0)

### Recovery

We had 2 files: a pcapng file and a backup. First, I looked through the backup: 

![image](https://github.com/user-attachments/assets/22cc82a0-1506-498a-b095-99eadf3f5a13)

When I opened files, I could not read since they were encrypted although their name looked normal:

![image](https://github.com/user-attachments/assets/26f4b96e-8468-4687-9541-df49a4a682d5)

From here I read content of powershell_history.txt for more information and I noticed a github repo:

![image](https://github.com/user-attachments/assets/0a7f13be-cece-4062-83d9-3ef02356b148)

It looked so suspicious so I accessed this repo. Read app.py and this was result: 

![image](https://github.com/user-attachments/assets/9032ff48-fd52-479f-b9d8-624d875c8259)

I checked commit to see file history and I found many things interesting, especially DNS exfiltration which used domain **meow**. To confirm this information I opened 
**Wireshark** and fortunately it's correct:

![image](https://github.com/user-attachments/assets/c560a652-8cf7-43a8-8ab7-afb5571b76bc)

When we solved, we found the dns6 commit contained the correct decryption method for this case, and I rewrote the script for decryption:

```python
import argparse
import base64
import os
from collections import defaultdict
from dnslib import DNSRecord
from scapy.all import PcapReader, UDP


def xor_bytes(data_bytes, key_byte):
    """XOR every byte with a single-byte key."""
    return bytes([b ^ key_byte for b in data_bytes])


def padded_base32(s: str) -> bytes:
    """Pad a base32 string to a multiple of 8 and decode."""
    # base32 expects padding with '=' to a multiple of 8
    pad_len = (8 - (len(s) % 8)) % 8
    s_padded = s + ("=" * pad_len)
    return base64.b32decode(s_padded, casefold=True)


def process_dns_qname(qname: str, special_domain: str = "meow"):
    """
    If query name matches the pattern chunk.index.meow... (i.e. labels[0]=chunk, labels[1]=index, labels[2]=meow),
    return (index:int, chunk_bytes:bytes). Otherwise return None.
    """
    labels = qname.rstrip(".").split(".")
    if len(labels) < 3:
        return None
    # We expect the third label to be the special domain according to user's format
    if labels[2].lower() != special_domain.lower():
        return None

    chunk_label = labels[0]
    index_label = labels[1]

    # special-case: end.<something>.meow  (original script used labels[0]=="end")
    if chunk_label.lower() == "end":
        try:
            # if index present use it, otherwise -1
            idx = int(index_label) if index_label.isdigit() else -1
        except Exception:
            idx = -1
        return ("__END__", idx)

    # otherwise try to decode
    try:
        decoded = padded_base32(chunk_label)
        if len(decoded) < 1:
            return None
        key_byte = decoded[0]
        encrypted_chunk = decoded[1:]
        original = xor_bytes(encrypted_chunk, key_byte)
        index = int(index_label)
        return (index, original)
    except Exception:
        return None

def extract_from_pcap(pcap_path: str, out_path: str, special_domain: str = "meow", verbose: bool = True):
    """
    Iterate through pcapng, parse DNS queries and collect chunks.
    When an 'end' marker is found, reconstruct file and write to out_path.
    """
    chunks = dict()
    seen_indices = set()
    end_seen = False

    if verbose:
        print(f"[+] Opening pcap file: {pcap_path}")

    total_packets = 0
    dns_packets = 0
    with PcapReader(pcap_path) as reader:
        for pkt in reader:
            total_packets += 1
            # Filter UDP DNS queries (port 53) - both src or dst 53 possible depending on capture direction
            if not pkt.haslayer(UDP):
                continue
            udp = pkt[UDP]
            sport = int(udp.sport) if hasattr(udp, "sport") else None
            dport = int(udp.dport) if hasattr(udp, "dport") else None
            if sport != 53 and dport != 53:
                continue

            # get raw UDP payload (may be DNS)
            try:
                raw = bytes(udp.payload)
                if not raw:
                    continue
                # parse DNS packet using dnslib for robustness
                try:
                    dns = DNSRecord.parse(raw)
                except Exception:
                    continue
                # only process queries (QR=0) and at least one question
                if dns.header.get_qr() != 0 or len(dns.questions) == 0:
                    continue

                qname = str(dns.q.qname)
                dns_packets += 1
                result = process_dns_qname(qname, special_domain=special_domain)
                if result is None:
                    continue
                if isinstance(result, tuple) and result[0] == "__END__":
                    end_seen = True
                    if verbose:
                        idx = result[1]
                        print(f"[+] Found END marker (index={idx}) at packet #{total_packets}, qname={qname}")
                    # do not break; keep scanning to collect all chunks (pcap might have chunks after end marker)
                    continue
                index, data = result
                if index in chunks:
                    # if duplicate, skip or optionally prefer first seen
                    if verbose:
                        print(f"[*] Duplicate chunk index {index} encountered; skipping duplicate.")
                else:
                    chunks[index] = data
                    seen_indices.add(index)
                    if verbose:
                        print(f"[+] Collected chunk index={index}, len={len(data)} qname={qname}")

            except Exception as e:
                if verbose:
                    print(f"[!] Failed to process packet #{total_packets}: {e}")
                continue

    if verbose:
        print(f"[+] Finished scanning pcap: total pkts={total_packets}, DNS-like pkts={dns_packets}")
        print(f"[+] Collected {len(chunks)} chunks, end_seen={end_seen}")

    if not chunks:
        raise RuntimeError("No valid meow chunks found in pcap.")

    # Reconstruct ordered by index (lowest to highest)
    ordered_indices = sorted(chunks.keys())
    # Check for missing indices (optional)
    min_idx = ordered_indices[0]
    max_idx = ordered_indices[-1]
    missing = [i for i in range(min_idx, max_idx + 1) if i not in chunks]
    if missing and verbose:
        print(f"[!] Warning: missing chunk indices between {min_idx} and {max_idx}: {missing}")

    reconstructed = b"".join(chunks[i] for i in ordered_indices if i in chunks)

    # Write to disk
    out_dir = os.path.dirname(out_path)
    if out_dir and not os.path.exists(out_dir):
        os.makedirs(out_dir, exist_ok=True)

    with open(out_path, "wb") as f:
        f.write(reconstructed)

    if verbose:
        print(f"[+] Reconstructed file written to: {out_path} (size={len(reconstructed)} bytes)")
        print("[!] Note: this script does NOT execute the file. If you need to run it, do so manually in a safe, isolated environment (VM).")

    return out_path, len(reconstructed), missing


def main():
    ap = argparse.ArgumentParser(description="Extract meow DNS exfil chunks from pcapng and reconstruct file.")
    ap.add_argument("pcap", help="Path to pcapng / pcap file")
    ap.add_argument("-o", "--out", help="Output file path", required=True)
    ap.add_argument("--domain", help="Special domain label (default: meow)", default="meow")
    ap.add_argument("--noisy", help="Verbose output", action="store_true")
    args = ap.parse_args()

    try:
        out_path, size, missing = extract_from_pcap(args.pcap, args.out, special_domain=args.domain, verbose=args.noisy)
        print(f"Done. Wrote {size} bytes to {out_path}. Missing indices: {missing}")
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
```

I ran the code and got a packed executable file: 

![image](https://github.com/user-attachments/assets/54ac1819-fc5c-48a6-841e-89cc6272ee6c)

![image](https://github.com/user-attachments/assets/4d81efd5-6e0e-40da-81e9-4de0769a08e9)

Simply I unpacked it and used IDA Pro again: 

![image](https://github.com/user-attachments/assets/3e825ee6-89c9-4703-9531-409249555e99)

![image](https://github.com/user-attachments/assets/c304d35a-bcc3-4a02-a1e9-44ff672713c2)

I searched and found the function for encrypting files:

![image](https://github.com/user-attachments/assets/476eab13-0688-4621-8f03-bb1278e3a095)

You could see that they used a simple XOR operation for encryption. But we need to know exactly how they implemented their encryption method. Next we will dig into 
**sub_401460** which processed the **Filename** for something:

```asm
int __cdecl sub_401460(const char *a1, int a2, int a3)
{
  int v3; // edx
  int v4; // ebx
  unsigned int v5; // kr04_4
  char v6; // cl
  int v7; // esi
  int i; // eax
  int v9; // ebx
  char v10; // cl
  int result; // eax

  v3 = 0;
  v4 = 0;
  v5 = strlen(a1) + 1;
  while ( v4 != v5 - 1 )
  {
    v6 = 8 * (v4 & 3);
    v7 = a1[v4++];
    v3 ^= v7 << v6;
  }
  for ( i = 0; i != 37; ++i )
  {
    v9 = byte_40B200[i];
    v10 = i;
    v3 ^= v9 << (8 * (v10 & 3));
  }
  for ( result = a2; result != a2 + a3; *(_BYTE *)(result - 1) = v3 )
  {
    ++result;
    v3 = 1664525 * v3 + 1013904223;
  }
  return result;
}
```

**sub_401460** takes a string a1, a buffer address a2, and a length a3, and uses the string to produce a deterministic stream of pseudorandom bytes written into the 
buffer. It begins by building a 32-bit seed v3 from the input string: each character is XORed into v3 at byte-aligned positions (cycling through shifts of 0, 8, 16, 24 bits), 
then the seed is further mixed by XORing in 37 bytes from **byte_40B200**. That mixed value becomes the initial state for a standard linear congruential 
generator (v3 = 1664525 * v3 + 1013904223), and the routine iterates the LCG to produce a3 bytes, storing the low byte of the LCG state sequentially into the buffer 
at a2. 

To know what 37 bytes string was, we just simple click on the variable and we can see the content:

![image](https://github.com/user-attachments/assets/f2fde8dd-139d-4192-85fb-bb0b1396f464)

Because filename was an important part of seeding process, giving correct filepath is very essential and just a small modification will change the seed. And fortunately 
this function below gave me how the filepath looked like:

```asm
void *__cdecl sub_4015FD(char *a1)
{
  void *result; // eax
  void *v2; // edi
  int v3; // eax
  const char *Str1; // ebx
  _stat32 Stat; // [esp+2Ch] [ebp-43Ch] BYREF
  char FileName[1048]; // [esp+50h] [ebp-418h] BYREF

  result = (void *)sub_403A60(a1);
  if ( result )
  {
    v2 = result;
    while ( 1 )
    {
      v3 = sub_403C20(v2);
      if ( !v3 )
        break;
      Str1 = (const char *)(v3 + 12);
      if ( strcmp((const char *)(v3 + 12), ".") )
      {
        if ( strcmp(Str1, "..") )
        {
          if ( strcmp(Str1, "AppData") )
          {
            sub_4023B0(FileName, 1024, "%s\\%s", a1, Str1);
            if ( stat(FileName, &Stat) != -1 )
            {
              if ( (Stat.st_mode & 0xF000) == 0x4000 )
              {
                sub_4015FD(FileName);
              }
              else if ( (Stat.st_mode & 0xF000) == 0x8000 )
              {
                sub_4014D1(FileName);
              }
            }
          }
        }
      }
    }
    return (void *)sub_403C70(v2);
  }
  return result;
}
```

In short, the filepath will use double backslash, filepath will be put into the seeding. So this is my Python script for decryption:

```python
import sys
import os

SECRET = b"evilsecretcodeforevilsecretencryption"
A = 1664525
C = 1013904223
MASK32 = 0xFFFFFFFF
BLOCK_SIZE = 64 * 1024  # 64 KiB

def build_seed_from_filename(filename: str) -> int:
    """
    Recreate seed from the original malware logic:
      full = "C:\\Users\\gumba\\Desktop\\" + filename
      seed = 0
      for each byte in full: seed ^= (byte << ((i % 4) * 8))
      for each byte in SECRET: seed ^= (byte << ((i % 4) * 8))
    """
    full = "C:\\Users\\gumba\\Desktop\\" + filename
    fb = full.encode("utf-8", errors="replace")
    seed = 0
    for i, b in enumerate(fb):
        seed ^= (b & 0xFF) << ((i & 3) * 8)
        seed &= MASK32
    for i, b in enumerate(SECRET):
        seed ^= (b & 0xFF) << ((i & 3) * 8)
        seed &= MASK32
    return seed & MASK32

def keystream_generator_for_filename(filename: str):
    """
    Generate keystream bytes for the given filename. Update LCG state first, then output (state & 0xFF).
    """
    state = build_seed_from_filename(filename)
    while True:
        state = (state * A + C) & MASK32
        yield state & 0xFF

def decrypt_file(filename: str):
    if not os.path.isfile(filename):
        print(f"[!] File not found: {filename}")
        return 1
    size = os.path.getsize(filename)
    if size == 0:
        print(f"[!] Empty file, skipping: {filename}")
        return 1
    
    keystream = keystream_generator_for_filename(filename)
    outname = f"decrypted_{filename}"
    key_preview = bytearray()

    with open(filename, "rb") as inf, open(outname, "wb") as outf:
        while True:
            block = inf.read(BLOCK_SIZE)
            if not block:
                break
            out_block = bytearray(len(block))
            for i, b in enumerate(block):
                k = next(keystream)
                out_block[i] = b ^ k
                if len(key_preview) < 64:
                    key_preview.append(k)
            outf.write(out_block)

    print(f"[+] Decrypted {filename} -> {outname} (size={size} bytes)")
    print(f"[+] Keystream preview (first {len(key_preview)} bytes): {key_preview.hex()}")
    return 0

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <filename>")
        sys.exit(1)
    filename = sys.argv[1]
    decrypt_file(filename)

if __name__ == "__main__":
    main()
```

Run with the filename and you got the flag:

![image](https://github.com/user-attachments/assets/72c7aa50-ceb4-40f8-b0cf-27e88323f0b5)

That's my writeup for all forensic challenges. Thank you for reading my blog, see you in the next post. Byeeee!!!

