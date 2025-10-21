# [LetsDefend - LockBit](https://app.letsdefend.io/challenge/lockbit)
Created: 19/06/2024 17:25
Last Updated: 23/09/2024 08:21
* * *
<div align=center>

**LockBit**
![9f40f2d3907b48db6f4ae47532a9533a.png](../../_resources/9f40f2d3907b48db6f4ae47532a9533a.png)
</div>

You are a Digital Forensics and Incident Response (DFIR) analyst tasked with investigating a ransomware attack that has affected a company's system. The attack has resulted in file encryption, and the attackers are demanding payment for the decryption of the affected files. You have been given a memory dump of the affected system to analyze and provide answers to specific questions related to the attack.


Memory dump (password: infected): /root/Desktop/ChallengeFile/Lockbit.zip

This challenge prepared by [@MMOX](https://www.linkedin.com/in/0xMM0X)
* * *
## Start Investigation
>Can you determine the date and time that the device was infected with the malware? (UTC, format: YYYY-MM-DD hh:mm:ss)

![8d0ef1d56653171bfd9ac57bd5cebdbb.png](../../_resources/8d0ef1d56653171bfd9ac57bd5cebdbb.png)

After determine which profile to use with `vol.py -f Lockbit.vmem imageinfo` then we can use pstree plugin or other similar plugin related to process to list all processes to find which process is the most suspicious one

![fa709f5f82c6a981e75399df949f5acb.png](../../_resources/fa709f5f82c6a981e75399df949f5acb.png)

After using `vol.py -f Lockbit.vmem --profile=Win7SP1x64 pstree`, we can see that malware process doesn't hide itself at all

```
2023-04-13 10:06:45
```

>What is the name of the ransomware family responsible for the attack?

![0a13a65d64de8b8f881db08acefd4368.png](../../_resources/0a13a65d64de8b8f881db08acefd4368.png)

I used `vol.py -f Lockbit.vmem --profile=Win7SP1x64 cmdline` to find full path of this malware

![77328ef1324f8fe74ab5c587a229c1a6.png](../../_resources/77328ef1324f8fe74ab5c587a229c1a6.png)

Then I used `vol.py -f Lockbit.vmem --profile=Win7SP1x64 filescan > filescan.txt` and  `grep "mal.exe" filescan.txt` to find an offset of this file then dump it with `vol.py -f Lockbit.vmem --profile=Win7SP1x64 dumpfiles -Q 0x000000007cde5320 -D .`

![2646fd91dabcc8e50830ca53e7c1ed24.png](../../_resources/2646fd91dabcc8e50830ca53e7c1ed24.png)

Then search filehash on VirusTotal, we can see that its lockbit ransomware just like the name of this challenge

```
lockbit
```

>What file extension is appended to the encrypted files by the ransomware?

![d5e88727bc2293fccb4cc51409edb4b4.png](../../_resources/d5e88727bc2293fccb4cc51409edb4b4.png)

Go to dropped files under Relations and Behavior tab then we can see that all encrypted files have `.lockbit` extension 

```
.lockbit
```

>What is the TLSH (Trend Micro Locality Sensitive Hash) of the ransomware?

![d1f5a26569052b537995f034df2a8132.png](../../_resources/d1f5a26569052b537995f034df2a8132.png)

Go to Details tab for this question

```
T119E3163DB459E165C8CF04B57E2516BAD671F83C037989F3EBD38C299420EE86626B07
```

>Which MITRE ATT&CK technique ID was used by the ransomware to perform privilege escalation?

![58a3946e053576edd1cde8c90f60aa11.png](../../_resources/58a3946e053576edd1cde8c90f60aa11.png)

This malware has many activities falls under Privilege Escalation tactic but an answer of this question is Windows Service

```
T1543
```

>What is the SHA256 hash of the ransom note dropped by the malware?

![233ac13eb2601613387e3ce0c5223736.png](../../_resources/233ac13eb2601613387e3ce0c5223736.png)

Go to Behavior tab, and find a file dropped that look like ransomnote and append details for SHA256 

```
67c6784a5296658ac4d633f4e8c0914ecc783b1cf2f6431818c4e2f3cdcce91f
```

>What is the name of the registry key edited by the ransomware during the attack to apply persistence on the infected system?

![752da4f6584455f9e2ef593371f440c6.png](../../_resources/752da4f6584455f9e2ef593371f440c6.png)

Under Registry Edited section, we can see that this weird value was added to Run registry key

```
XO1XADpO01
```

* * *
## Summary

Its an easy challenge that can be solved using Volatility and VirusTotal or other malware analysis platform to solve and the ransomware that infected this system is LockBit ransomware.

<div align=center>

![36fe983b8d10f812efbc3226018aa359.png](../../_resources/36fe983b8d10f812efbc3226018aa359.png)
</div>

* * *
