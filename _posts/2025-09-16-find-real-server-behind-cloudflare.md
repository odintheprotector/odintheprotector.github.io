---
layout: post
title: Find Origin IP address behind CloudFlare server
description: List of approachings to find origin IP behind CloudFlare server
tags: [Threat Intelligence, Blue Team, CloudFlare, OSINT, CDN]
---

Hi everyone, as usual I always try to learn something new when I don't know what to do after school time, and this post will be about finding origin IP behine CloudFlare 
server since CloudFlare is good at hiding **website identity** (you already knew what it is). After learnt from many articles, those are several ways to find out, I wrote 
this article not only for my note during investigation but also I wanted to share it to you all, at least basic ways to explore. Let's go!

![image](https://github.com/user-attachments/assets/538e7e45-543c-469e-be55-94df8b4d2385)

### What is Origin IP. How CDN works?

Origin IP is just simply the actual IP of the server that hosting a website, an application... Hiding this information is extremely important since:
  - From defense view, cybersecurity experts could protect their website from DDoS, direct exploitation and reconnaissance...
  - From threat actors view, they could hide their identities to avoid being investigated and being taken down...

To conduct that there are many CDNs to support us nowadays such as **CloudFlare**, **Akamai**, **Amazon CloudFront**... In general, a CDN will work simply like this (I love 
writing since it's a good way to learn something new):

![image](https://github.com/user-attachments/assets/4bcd28fb-f98c-45ad-a36e-8a98852cfac4)

Normally we access a website, that website should be hid by CloudFlare, assume that an attacker tries to attack that website, for the first stage: reconaissance 
it will fail since CDN will provide dynamic DNS records, dynamic IP address, each time they access the IP address will be changed. 

### List of ways to find out origin IP 
#### Check DNS records

This is the simplest way to find out, even a bad actor's website be taken down, it still has possibility to leave old DNS records and those will contain the real IP address 
**(I told about this from HolaCTF 2025, you could check it)**. Different types of DNS could help you explore valuable information:

- **A Records**: Link a domain name to an IPv4 address. Looking at past A records can reveal older IPs the domain used before moving behind a CDN.
- **AAAA Records**: The IPv6 counterpart of A records. Reviewing their history can show prior IPv6 addresses tied to the domain.
- **MX Records**: Define which mail servers handle email for the domain. These servers often bypass the CDN, sometimes exposing the origin server’s real IP.
- **TXT Records**: Hold miscellaneous text-based data, such as email verification info or service metadata. In some cases, they may unintentionally leak internal IPs or sensitive details.
- **CNAME Records**: Map one domain as an alias of another. Tracing the CNAME chain can lead to the original domain that reveals the actual server IP.

#### Search Google ¯\_(ツ)_/¯

It sounds weird but in some cases it really works by just typing the name of the website and a second website has same content and raw IP address appears 😄

#### Search for title

By using tools like **Censys Search** or **URLscan**, we can find all possible websites having the same titles. Those are commands we could use for this two platforms: 
- Censys Search: **services.http.response.html_title:"<your_title_here>"**
- URLscan: page.title="<your_title_here>"

![image](https://github.com/user-attachments/assets/be520653-1047-47c7-9eea-ace76a084683)

#### TLS/SSL certificate

After learnt from many resources, I must say it is one of the most valuable resource for investigating. TLS certificate is unique for each website and this information 
could help you define various things including its public key and this can be used to find out the real IP address even if a website is hid by CDN. Moreover, TLS cert can 
be used again and again by different websites so we can trace other websites or a big campaign easily.

#### Content Security Policy Header 

A Content-Security-Policy (CSP) header can accidentally reveal an origin server’s IP address when it contains raw IPs or points directly to backend endpoints: 
for example, a **report-uri** or **report-to** directive configured with an IP (e.g., **report-uri http://1.1.1.1/...**) or **script-src**, **img-src** or other source 
lists that include IP addresses will expose infrastructure details; similarly, CSP entries that reference internal subdomains may resolve via DNS to the real 
backend IP rather than the CDN or proxy. this is a technical indicator of misconfiguration that falls under exposed infrastructure intelligence, and it can escalate 
into a high-value finding if the IP belongs to a production backend otherwise hidden. Monitoring for these leaks is essential for defenders, as adversaries commonly 
automate CSP header collection during reconnaissance to enrich their infrastructure mapping and identify weak points for further intrusion. Fortunately, Censys Search help 
us verify by this query: **services.http.response.header.content_security_policy: <your_website_here>**

#### Subdomain of a website

This could be possible, you can check it through CSP header or use recon tool like DNSrecon,....

#### CloudFlair

This is an interesting tool I just found, by using Censys API you can analyse different certificates related to a specific target:

![image](https://github.com/user-attachments/assets/1e0c7b47-0430-4aaa-a2f8-b0997c218842)

### Conclusion

Bad actors always try to change strategies to face with us, and these ways are not enough definitely, but you know our ancestor used old weapons to fight against invaders, 
so those are not useless, understanding these basic things will help you foresee the bad actors ways and the others will base on your creative. This is the end for my post, 
thank you so much for reading till this line. As usual if you have any question, just DM me through Facebook. See you in other articles, bye 💙💙💙

### References
- https://maddevs.io/writeups/finding-servers-origin-ip/
- https://github.com/christophetd/CloudFlair
- https://www.verylazytech.com/pentesting-web/identify-a-servers-origin-ip
- https://maddevs.io/writeups/finding-servers-origin-ip/
- https://ostechnix.com/cloudflair-find-origin-servers-websites-protected-cloudflare/
- https://www.embeeresearch.io/infrastructure-tracking-locating-vultur-domains-with-passive-dns/
- https://0xdefh.github.io/posts/OSINT-TTP-How-to-find-server-behind-Cloudflare/#refs

