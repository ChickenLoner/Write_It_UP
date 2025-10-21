# [LetsDefend - PrintNightmare](https://app.letsdefend.io/challenge/PrintNightmare)
Created: 11/06/2024 11:54
Last Updated: 07/01/2025 21:08
* * *
<div align=center>

**PrintNightmare**
![82b9d0cf9aaec7faed15471154c385b0.png](/_resources/82b9d0cf9aaec7faed15471154c385b0.png)
</div>
Our system exploited by PrintNightmare vulnerability. You should investigate the case.

~~Log Files (pass: infected): [Download](https://files-ld.s3.us-east-2.amazonaws.com/PrintNightmare.zip)~~
Log Files (pass: infected): C:\Users\LetsDefend\Desktop\Files\PrintNightmare.zip

Note: You can use "[Redline](https://www.fireeye.com/services/freeware/redline.html)" for investigation

This challenge prepared by [@Bohan Zhang](https://www.linkedin.com/in/bohan-zhang-078751137/)

* * *
## Start Investigation
> Looking through the alerts in Brim, what is the vulnerability name and its corresponding CVE?

![d5d926b599a51ce7a9bd5cc128b549f5.png](/_resources/d5d926b599a51ce7a9bd5cc128b549f5.png)

To answer this question as it intended, There is a brim setup guide for us to follow inside extracted folder

![da1486b4aa26b145282ed5a317a7f38f.png](/_resources/da1486b4aa26b145282ed5a317a7f38f.png)

Since built-in VM for this challenge couldn't download brim suricata then we need to use another way to solve this challenge

And I was lucky enough to download challenges file when it was available on challenge description (go back to challenge description to download it) so I'll analyze them locally

![9d1bc31817d088d2bbf40a7efec78b6f.png](/_resources/9d1bc31817d088d2bbf40a7efec78b6f.png)

Open Zui Desktop (Brim) then go to "File" -> "Settings..."

![85ffb1c2c006e2d095d172e8b959fcdb.png](/_resources/85ffb1c2c006e2d095d172e8b959fcdb.png)

Go to "Packet Captures" -> "LOCAL SURICATA RULES FOLDER" and select a folder that stores `suricata.rules`

![5f97766e26e0667f9ef82d67cd618a0e.png](/_resources/5f97766e26e0667f9ef82d67cd618a0e.png)

If you tried to do this on built-in vm (Zui 1.7.0), you will find that there is no suricata rule importing inside Settings menu... so get files to investigate locally or make VM be able to connect to the internet for updating

![8082e86a20e7494ea252c47e6977d2d9.png](/_resources/8082e86a20e7494ea252c47e6977d2d9.png)

Load Data then enjoy Brim security with custom Suricata alerts which you can see that it worked well when inspect this alert event telling us that there were an exploitation of [CVE-2021-34527](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527) priviledged RCE vulnerability that let threat actor execute any commands as SYSTEM

```
PrintNightmare, CVE-2021-34527
```

> What is Attacker's IP?

![50374013fdab50e39a842218d4f55878.png](/_resources/50374013fdab50e39a842218d4f55878.png)

We already know how this vulnerability works and when you inspected process in memory dump file captured with Mandiant Redline then you can see that `SYSTEM` process has a connection to threat actor IP address 

```
10.10.10.2
```

> What is Attacker's share path?

![a1265f1038083b6fbb292ad31e9157f0.png](/_resources/a1265f1038083b6fbb292ad31e9157f0.png)

In Zui, search for share or smb then you will see the path of the share 

```
\\10.10.10.2\share
```

> What is the name of the malicious DLL file hosted by the attacker?

![25d248634fff9841b1b4ec3ac3452713.png](/_resources/25d248634fff9841b1b4ec3ac3452713.png)

Searching for files and we can see that there is only 1 dll file detected from this pcap

```
notsostealthy.dll
```

> What is the MD5 hash of the DLL file?
```
8ac469b77518820bbf0603a9ad56691d
```

> What is the email address used for the self-signed SSL Certificate in the traffic?

![85a3fb59a94683e29d830facfad9e171.png](/_resources/85a3fb59a94683e29d830facfad9e171.png)
```
override@shields.mertz.net
```

> What is the domain user used by the attacker to exploit the vulnerability?

![4450b246d82b02928f360ed41f01cc01.png](/_resources/4450b246d82b02928f360ed41f01cc01.png)

Go to "System Information" then we can see which hostname that vulnerable and exploited by threat actor including domain

![a233249fccb65c6d1c26f547006185c9.png](/_resources/a233249fccb65c6d1c26f547006185c9.png)

We got domain from Redline now we can search it on Zui to find username that was used to exploit 

```
BELLYBEAR\Jesse.Harmon
```

> What is the exploit server's hostname?
```
WIN-FLO4EU2VMSM
```

> What is the username created by the attacker for persistence?

![62e65fd8de7c4ad5b1539c1be86fa894.png](/_resources/62e65fd8de7c4ad5b1539c1be86fa894.png)

Go to "Users", which you will find `hacker` user that has the weird Last Login time

```
hacker
```

> What is the event ID for user creation in Windows, and when was the user being created?

![5be90399dd663b3e51e69f81d513f62c.png](/_resources/5be90399dd663b3e51e69f81d513f62c.png)

user creation in AD can be searched on event log with event ID 4720

![e72ef428294accc7f15011835422de52.png](/_resources/e72ef428294accc7f15011835422de52.png)

Filter for both keywords then we will have the time this log was generated and timestamp when this user was created in details

```
4720, 2021-08-16 19:31:46Z
```

> What process name is used to establish the shell connection between the attacker's machine and the Windows server? and what is the listening port on the attacker's machine?

![4a518d807f331a0370fbe570fe07ab67.png](/_resources/4a518d807f331a0370fbe570fe07ab67.png)

We know that the payload is dll file which mean `rundll32.exe` will be responsible for executing dll file and made a connection to threat actor C2, we can see that a port that being used for this connection is 443 (HTTPS) which make me think that a payload could be generated from msfvenom or metasploit

```
rundll32.exe, 443
```

> The attacker used a famous post-exploitation framework to create the DLL file and establish the shell connection to the Windows server, what is the payload the attacker used?

![211e7895fd4dde821b85c5b5d7735551.png](/_resources/211e7895fd4dde821b85c5b5d7735551.png)

So based on my skeptical, I searched on Google which payload could established a connection on port 443

![b9980f963803f86b9763f32e56a2e47a.png](/_resources/b9980f963803f86b9763f32e56a2e47a.png)

Which we can see that [payload](https://www.rapid7.com/blog/post/2010/04/13/persistent-meterpreter-over-reverse-https/) for this actually existed in metasploit framework but its not the right answer yet

![acbdbf4a0239c2a58c8c46e2c1d276d0.png](/_resources/acbdbf4a0239c2a58c8c46e2c1d276d0.png)

When I started learning penetration testing, one thing I remembered about Windows payload is there are 2 types of the same payload which are x86 and x64 architecture and after confirming architecture of this system then we can also determine which payload threat actor used for reverse shell connection

```
windows/x64/meterpreter/reverse_https
```

> The attacker left a text file for the user Administrator, can you find what the filename is?

![1b0afc934e46d6235b2eddbb1fdcd27a.png](/_resources/1b0afc934e46d6235b2eddbb1fdcd27a.png)

I found this weird text file inside `C:\Users\Administrator\Document\` which is the one we're looking for 

```
This-is-really-a-nightmare.txt
```

* * *
## Summary

On this challenge, we learned how to import suricata rule into Brim/Zui for network analysis and with the memory dump image we can also determined which file, process, user and payload that the threat actor used to exploit PrintNightmare vulnerability and eventually created a new domain user for persistence and more 
<div align=center>

![d7a22205b75cda85a799908f99412d07.png](/_resources/d7a22205b75cda85a799908f99412d07.png)
https://app.letsdefend.io/my-rewards/detail/2dae49f34a014290a5ecee66de6e7048
</div>

* * *
