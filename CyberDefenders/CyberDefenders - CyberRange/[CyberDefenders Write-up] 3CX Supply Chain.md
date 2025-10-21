# [CyberDefenders - 3CX Supply Chain](https://cyberdefenders.org/blueteam-ctf-challenges/3cx-supply-chain/)
Created: 18/05/2024 14:06
Last Updated: 04/06/2024 08:30
* * *
>**Category**: **Threat Intel**
>**Tags**: Malware Analysis, APT, threat intel, 3CX Supply Chain
* * *
**Scenario:**
A large multinational corporation heavily relies on the 3CX software for phone communication, making it a critical component of their business operations. After a recent update to the 3CX Desktop App, antivirus alerts flag sporadic instances of the software being wiped from some workstations while others remain unaffected. Dismissing this as a false positive, the IT team overlooks the alerts, only to notice degraded performance and strange network traffic to unknown servers. Employees report issues with the 3CX app, and the IT security team identifies unusual communication patterns linked to recent software updates.

As the threat intelligence analyst, it's your responsibility to examine this possible supply chain attack. Your objectives are to uncover how the attackers compromised the 3CX app, identify the potential threat actor involved, and assess the overall extent of the incident. 

**Tools**:
- VirusTotal

* * *
## Questions
>Q1: Understanding the scope of the attack and identifying which versions exhibit malicious behavior is crucial for making informed decisions if these compromised versions are present in the organization. How many versions of 3CX running on Windows have been flagged as malware?

![4165c170490bc3315deb83177da34dd4.png](https://github.com/ChickenLoner/Write_It_UP/blob/main/_resources/4165c170490bc3315deb83177da34dd4-2.png)
I did some research on this Supply Chain compromised and there are a lot of news, blogs, articles were made about this so pick one of them and you should be able to answer this question correctly (this image was taken from an article on [The Hacker News](https://thehackernews.com/2023/03/3cx-supply-chain-attack-heres-what-we.html))
```
2
```

>Q2: A supply chain attack targets a third-party vendor to gain unauthorized access to an organization's systems. The attacker compromises the vendor’s software or hardware supply chain, injecting malware or other malicious code that undermines the security of organizations using the vendor’s products. What's the UTC creation time of the .msi malware?

![a62faf1035b5e80416919184517e3aae.png](https://github.com/ChickenLoner/Write_It_UP/blob/main/_resources/a62faf1035b5e80416919184517e3aae-2.png)
calculate file hash and search it on [VirusTotal](https://www.virustotal.com/gui/file/59e1edf4d82fae4978e97512b0331b7eb21dd4b838b850ba46794d9c7a2c0983/details) or you can upload it directly (since it will calculate a hash and searching through their record of this file anyway)
Then go to Details tab to grab Creation Time from this section
```
2023-03-13 06:33:26 UTC
```

* This question was supposed to ask for how many dropped files but since its impossible to find an actual answer as time files, more re-scan will be made and file dropped number will be changed so prop to CyberDefenders Team for adjusting this problem!
![e34e1b128d06362423533df9c155bab5.png](https://github.com/ChickenLoner/Write_It_UP/blob/main/_resources/e34e1b128d06362423533df9c155bab5-2.png)

>Q3: Executable files (.exe) are frequently used as primary or secondary malware payloads, while dynamic link libraries (.dll) often load malicious code or enhance malware functionality. Analyzing files deposited by the Microsoft Software Installer (.msi) is crucial for identifying malicious files and investigating their full potential. Which malicious DLLs were dropped by the .msi file?

![b6a58994a9f21e40e17b19c4999c6271.png](https://github.com/ChickenLoner/Write_It_UP/blob/main/_resources/b6a58994a9f21e40e17b19c4999c6271-2.png)
Every articles and blogs talking about them so you can just copy one of them to answer this question (This image was taken from a blog from [Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2023/04/03/3cxdesktopapp-backdoored-in-a-suspected-lazarus-campaign))
```
ffmpeg.dll d3dcompiler_47.dll
```

>Q4: Recognizing the persistence techniques used in this incident is essential for current mitigation strategies and future defense improvements. What is the MITRE sub-technique ID employed by the .msi files to load the malicious DLL?

![f288c1d61ec6eb15b9d663f912ec00d3.png](https://github.com/ChickenLoner/Write_It_UP/blob/main/_resources/f288c1d61ec6eb15b9d663f912ec00d3-2.png)
Luckily a blog made by [Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2023/04/03/3cxdesktopapp-backdoored-in-a-suspected-lazarus-campaign) have MITRE TID Mapping section, we know its dll side loading so it has to be this one
```
T1574.002
```

>Q5: Recognizing the malware type (threat category) is essential to your investigation, as it can offer valuable insight into the possible malicious actions you'll be examining. What is the malware family of the two malicious DLLs?

![2a5bbdeb626722c53fd0d51a1af59139.png](https://github.com/ChickenLoner/Write_It_UP/blob/main/_resources/2a5bbdeb626722c53fd0d51a1af59139-2.png)
Now we are back to VirusTotal and we will take a look at both files here
![141aa8948880a03d8123f2b84917c30c.png](https://github.com/ChickenLoner/Write_It_UP/blob/main/_resources/141aa8948880a03d8123f2b84917c30c-2.png)
[ffmpeg.dll](https://www.virustotal.com/gui/file/7986bbaee8940da11ce089383521ab420c443ab7b15ed42aed91fd31ce833896) is a trojan
![a08cdf19063286ef736d3e18c96b69db.png](https://github.com/ChickenLoner/Write_It_UP/blob/main/_resources/a08cdf19063286ef736d3e18c96b69db-2.png)
[d3dcompiler_47.dll](https://www.virustotal.com/gui/file/11be1803e2e307b647a8a7e02d128335c448ff741bf06bf52b332e0bbf423b03/detection) is also a trojan
```
trojan
```

>Q6: As a threat intelligence analyst conducting dynamic analysis, it's vital to understand how malware can evade detection in virtualized environments or analysis systems. This knowledge will help you effectively mitigate or address these evasive tactics. What is the MITRE ID for the virtualization/sandbox evasion techniques used by the two malicious DLLs?

![9b14c29c637752cefd3de9f7b1562ebb.png](https://github.com/ChickenLoner/Write_It_UP/blob/main/_resources/9b14c29c637752cefd3de9f7b1562ebb-2.png)
On Behavior tab of msi file and under of MITRE ATT&CK Tactics and Techniques, you will obtain MITRE there
![ad431375f21376dee9ad4e604bbed99e.png](https://github.com/ChickenLoner/Write_It_UP/blob/main/_resources/ad431375f21376dee9ad4e604bbed99e-2.png)
Or just from this blog made by [Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2023/04/03/3cxdesktopapp-backdoored-in-a-suspected-lazarus-campaign) (just cut sub-technique ID out to match answer-format)
```
T1497
```

>Q7: When conducting malware analysis and reverse engineering, understanding anti-analysis techniques is vital to avoid wasting time. Which hypervisor is targeted by the anti-analysis techniques in the ffmpeg.dll file?

![57ecd4da612be9313e69bf91f532deb9.png](https://github.com/ChickenLoner/Write_It_UP/blob/main/_resources/57ecd4da612be9313e69bf91f532deb9-2.png)
Go to [ffmpeg.dll](https://www.virustotal.com/gui/file/7986bbaee8940da11ce089383521ab420c443ab7b15ed42aed91fd31ce833896) behavior tab, under of MITRE ATT&CK Tactics and Techniques then you will see which hybervisor that was targeted by this dll file
```
VMWare
```

>Q8: Identifying the cryptographic method used in malware is crucial for understanding the techniques employed to bypass defense mechanisms and execute its functions fully. What cryptographic protocol is used for encryption by the ffmpeg.dll file?

![ad8bccdd361c394f2addbc9df64d1180.png](https://github.com/ChickenLoner/Write_It_UP/blob/main/_resources/ad8bccdd361c394f2addbc9df64d1180-2.png)
It was RC4
```
RC4
```

>Q9: As an analyst, you've recognized some TTPs involved in the incident, but identifying the APT group responsible will help you search for their usual TTPs and uncover other potential malicious activities. Which group is responsible for this attack?

![6e0d759ccc5cc20904f91b59e3163a45.png](https://github.com/ChickenLoner/Write_It_UP/blob/main/_resources/6e0d759ccc5cc20904f91b59e3163a45-2.png)
Wired posted an [article](https://www.wired.com/story/3cx-supply-chain-attack-times-two/) about this which believe that North Korea nation-stated hacker group response for this attack
![eeaabe9366c505053856faead60413ff.png](https://github.com/ChickenLoner/Write_It_UP/blob/main/_resources/eeaabe9366c505053856faead60413ff-2.png)
This group also known as Lazarus group
```
Lazarus
```

![83dd121257751d96f77c4cdde1527d98.png](https://github.com/ChickenLoner/Write_It_UP/blob/main/_resources/83dd121257751d96f77c4cdde1527d98-1.png)
* * *
