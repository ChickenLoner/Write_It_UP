# [CyberDefenders - EscapeRoom](https://cyberdefenders.org/blueteam-ctf-challenges/escaperoom/)
Created: 29/05/2024 18:55
Last Updated: 30/05/2024 19:48
* * *
>Category: Network Forensics
>Tags: PCAP, Wireshark, Linux, Network, T1066, T1014, T1071, T1110, T1548, T1547.001, T1059
* * *
**Scenario**:
You as a soc analyst belong to a company specializing in hosting web applications through KVM-based Virtual Machines. Over the weekend, one VM went down, and the site administrators fear this might be the result of malicious activity. They extracted a few logs from the environment in hopes that you might be able to determine what happened.
This challenge is a combination of several entry to intermediate-level tasks of increasing difficulty focusing on authentication, information hiding, and cryptography. Participants will benefit from entry-level knowledge in these fields, as well as knowledge of general Linux operations, kernel modules, a scripting language, and reverse engineering. Not everything may be as it seems. Innocuous files may turn out to be malicious so take precautions when dealing with any files from this challenge.

**Helpful Tools**:
- [Wireshark](https://www.wireshark.org/)
- [NetworkMiner](https://www.netresec.com/?page=networkminer)
- [BrimSecurity](https://www.brimdata.io/download/)
- [UPX](https://upx.github.io/)
- [IDA](https://www.hex-rays.com/ida-pro/ida-disassembler/)
* * *
## Questions
> Q1: What service did the attacker use to gain access to the system?

We got 1 pcap file and 3 log files on this challenge
![d46cc76d0a573916225185ad255c5db2.png](../../_resources/d46cc76d0a573916225185ad255c5db2.png)
So I'll start with pcap file first since other logs wouldn't have the answer of this question
![c64bde22c14eaf0b0f1b0641bb73939a.png](../../_resources/c64bde22c14eaf0b0f1b0641bb73939a.png)
After opened pcap file with Wireshark, First thing that caught by eyes immediately after opened evidence pcap file is SSH protocol 

So I checked out the Protocol statistics
![1c0edb48d4d02fe645669ec25c257a6b.png](../../_resources/1c0edb48d4d02fe645669ec25c257a6b.png)
This page showed that there are SSH and HTTP protocols that I could investigate on this PCAP file 
So now I can assume that the attacker is 23.20.23.147 judging from the destination port of SSH is 22
![c0457b3bc97150ebf8c6e5a8217be0f7.png](../../_resources/c0457b3bc97150ebf8c6e5a8217be0f7.png)

```
ssh
```

> Q2: What attack type was used to gain access to the system?(one word)

Still on the Wireshark, I shifted my focus on the right and saw there is a pattern of communications happened constantly
![8f8728b5d7e3fd0d04780c4b3160ec8c.png](../../_resources/8f8728b5d7e3fd0d04780c4b3160ec8c.png)
So I came back to the Info of SSH packages
![9f0f99c7bcef5d69613ab874c6f1b110.png](../../_resources/9f0f99c7bcef5d69613ab874c6f1b110.png)
I found that after client offer new keys to the server, something happened and then the connection cut off (looking at FIN, ACK flag) and then after that user tried to make a connection to the server again
![ee3b35ade55cbfa6a09eab5af441b909.png](../../_resources/ee3b35ade55cbfa6a09eab5af441b909.png)
It happened for a while before they finally got a real conversation.

So I think this is bruteforce attack on SSH to gain unauthorized access on the server

But I didn't think Wireshark is enough so I used Zui Desktop Application from Brim to visualize and made everything look simple
![5739e6b17701da50725d5d8553f4d6ab.png](../../_resources/5739e6b17701da50725d5d8553f4d6ab.png)
The first filter I made is ssh as you can see that there are a lot of SSH auth attempt so It is indeed bruteforce attack

```
bruteforce
```

> Q3: What was the tool the attacker possibly used to perform this attack?

I didn't know how to obtain this answer from the evidence file but I knew that hydra and medusa could do SSH bruteforce and when I tried to answer, Hydra is the right answer
```
hydra
```

> Q4: How many failed attempts were there?

![0d30474c7c0d90ae2000db3ac950c43a.png](../../_resources/0d30474c7c0d90ae2000db3ac950c43a.png)
From this query, There are 54 attempts on SSH bruteforce attack, 2 of them got succcess and the rest which got null value are failed attempts

So to confirmed the answer, I putted more filter on auth_success==null
![7e667d24e5d628a2f948212b1249a346.png](../../_resources/7e667d24e5d628a2f948212b1249a346.png)
And the result showed 52 is the total number of failed attempts as expected
```
52
```

> Q5: What credentials (username:password) were used to gain access? Refer to shadow.log and sudoers.log.

![74e77f10aa0501f37281efc9c7a631b3.png](../../_resources/74e77f10aa0501f37281efc9c7a631b3.png)
Lets use john to bruteforce all possible passwords in shadow file here (`john --wordlist=/usr/share/wordlists/rockyou.txt shadow.log`), after a while we have this 3 users and the one that match the answer format it manager user
```
manager:forgot
```

> Q6: What other credentials (username:password) could have been used to gain access also have SUDO privileges? Refer to shadow.log and sudoers.log.

![c150044ae0165a7b2542121f027fc3c1.png](../../_resources/c150044ae0165a7b2542121f027fc3c1.png)
From sudoers file, we can see that manager and sean are in admin group that may gain root privilege so the other user is sean
```
sean:spectre
```

> Q7: What is the tool used to download malicious files on the system?

![6ae7107f48134e05f3d1027b8ecc427f.png](../../_resources/6ae7107f48134e05f3d1027b8ecc427f.png)
Filtered by HTTP, we can see that all of HTTP requests have Wget as user-agent 
![4932923d5d23c7214899ef468cd6b820.png](../../_resources/4932923d5d23c7214899ef468cd6b820.png)
Its wget without a doubt here since its only 1 user-agent that so obvious
```
wget
```

> Q8: How many files the attacker download to perform malware installation?

![7f656cf2add48fdb8c837d97c59d5ffb.png](../../_resources/7f656cf2add48fdb8c837d97c59d5ffb.png)
Lets take a look at rest_mime_types so we can see which types of file that were requests sorting by time, first one is an executable file, second is an object and third is shellscript while the rest are bmp images
![dd0d5d2553a53e66d556aeb806047366.png](../../_resources/dd0d5d2553a53e66d556aeb806047366.png)
first 3 files were requested almost at the same time and it took a while before the rest were being requested
```
3
```

> Q9: What is the main malware MD5 hash?

![f363148667b24459da450c7b2256552e.png](../../_resources/f363148667b24459da450c7b2256552e.png)
Lets examine first 3 files first, I used Network Miner since its automatically detected files for us 
![f8cb4b38a57f2e9274475ad5d3d8c877.png](../../_resources/f8cb4b38a57f2e9274475ad5d3d8c877.png)
Check file details to obtain hash
![9fb7e014a22faf063cac7b8ca9c7418f.png](../../_resources/9fb7e014a22faf063cac7b8ca9c7418f.png)
First file is confirmed to be a malware while second file identified as a rootkit on VirusTotal, then the first should be main file and rootkit purpose is still unknown (probably for persistence and evade detection? since we already know that malware could abused sudo privilege as manager user in admin group)
```
772b620736b760c1d736b1e6ba2f885b
```

> Q10: What file has the script modified so the malware will start upon reboot?

![bb05293f18e95b7ee521fb7e388fbad2.png](../../_resources/bb05293f18e95b7ee521fb7e388fbad2.png)
After examined a shell script, we can see that this script aims to maintain persistent of the first file which was renamed to `mail` from `1` then grant execution privilege to `/var/mail/mail` and writes a script to `rc.local` that will be executed every system boot 
```
/etc/rc.local
```

> Q11: Where did the malware keep local files?
```
/var/mail/
```

> Q12: What is missing from ps.log?

![9b72a99dcc30fd103de632260290a380.png](../../_resources/9b72a99dcc30fd103de632260290a380.png)
From here we can see that `mail` was supposed to be executed in the background and rootkit (second file) was moved and renamed to `sysmon.ko`, generates modules dependency information for the current kernel, add rootkit to `/etc/modules` to be loaded automatically when boot then you can also see it sleeps for a sec before hide process id of `mail` before removing this shell script
![f5cb6766581ef8dba0a2a7d220380de1.png](../../_resources/f5cb6766581ef8dba0a2a7d220380de1.png)
We didn't see malicious process that was supposed to be running from a shell script we just examined 
```
/var/mail/mail
```

> Q13: What is the main file that used to remove this information from ps.log?

Its rootkit file that was renamed
```
sysmod.ko
```

> Q14: Inside the Main function, what is the function that causes requests to those servers?

![6255de5a6695ba25381a1af8b659f6f7.png](../../_resources/6255de5a6695ba25381a1af8b659f6f7.png)
I used Detect It Easy to see if this malware can be decompiled and look like we need to unpack it first
![999e5366df8a6b17849fa8459598c7e8.png](../../_resources/999e5366df8a6b17849fa8459598c7e8.png)
Using upx to unpack then put it in Detect It Easy again, we can see that its an ELF linux executable file as expected
![0093ce7366edf9c5a25b7ca672846eff.png](../../_resources/0093ce7366edf9c5a25b7ca672846eff.png)
Open it in decompiler like Ghidra / IDA Pro or Cutter and navigate to main function, we can see that there is a function named "requestFile" which likely to be the one responsible for other file requests
![590d6c29d7965b12a3804fd7b073179e.png](../../_resources/590d6c29d7965b12a3804fd7b073179e.png)
Which it is
```
requestFile
```

> Q15: One of the IP's the malware contacted starts with 17. Provide the full IP.

![fabd7c9a67797bdd8fa5c296eddcca9b.png](../../_resources/fabd7c9a67797bdd8fa5c296eddcca9b.png)
```
174.129.57.253
```

> Q16: How many files the malware requested from external servers?

![21b331e1ed94dbc632d4fbc45fceb13f.png](../../_resources/21b331e1ed94dbc632d4fbc45fceb13f.png)
We know that first 3 files were used for malware installation
```
9
```

> Q17: What are the commands that the malware was receiving from attacker servers? Format: comma-separated in alphabetical order

![7eeb16d25a9fd191488a4807acb474b7.png](../../_resources/7eeb16d25a9fd191488a4807acb474b7.png)
when receive something from a server, it often check the value first and the first one I found is in "decryptMessage" function
![d5429def0e6601877ee4c926dcdaffe9.png](../../_resources/d5429def0e6601877ee4c926dcdaffe9.png)
Which translate to NOP (No operation)
![4e6e097b6a19ca427b8ad0b9bb940a50.png](../../_resources/4e6e097b6a19ca427b8ad0b9bb940a50.png)
Look like we will eventually found both on "processMessage" function
![3d544d4fc363ed1a510d110a6bb258e1.png](../../_resources/3d544d4fc363ed1a510d110a6bb258e1.png)
Translate to RUN
```
NOP,RUN
```

![18563b258460ebca1974df53836a9d91.png](../../_resources/18563b258460ebca1974df53836a9d91.png)
* * *
