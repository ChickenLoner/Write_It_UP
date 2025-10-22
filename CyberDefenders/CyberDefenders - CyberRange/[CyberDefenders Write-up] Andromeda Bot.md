# [CyberDefenders - Andromeda Bot](https://cyberdefenders.org/blueteam-ctf-challenges/andromeda-bot/)
## Table of Contents

- [Scenario](#scenario)
- [Questions](#questions)

* * *
## Scenario
As a member of the DFIR team at SecuTech, you're tasked with investigating a security breach affecting multiple endpoints across the organization. Alerts from different systems suggest the breach may have spread via removable devices. You’ve been provided with a memory image from one of the compromised machines. Your objective is to analyze the memory for signs of malware propagation, trace the infection’s source, and identify suspicious activity to assess the full extent of the breach and inform the response strategy.

**Category**: Endpoint Forensics

**Tools**:
MemProcFS
VirusTotal
Evtxcmd
Timeline Explorer
* * *
## Questions
>Q1: Tracking the serial number of the USB device is essential for identifying potentially unauthorized devices used in the incident, helping to trace their origin and narrow down your investigation. What is the serial number of the inserted USB device?

![d28c97ede0e0b6a4a241e51d5c8871a4.png](/resources/d28c97ede0e0b6a4a241e51d5c8871a4.png)

After launching a lab, we have `memory.dmp` as an initial evidence for this lab which we might have to use MemProcFS and Volatility to analyze it and extract files out of it.

![f7b55a37f910cb76de45fb11dc9cd205.png](/resources/f7b55a37f910cb76de45fb11dc9cd205.png)

I started with MemProcFS to let it auto-analyze and extracting files for me and it will take a while to complete forensic mode depend on the size of memory dump and then MemProcFS will mount the analysis result to M drive.

Command : `memprocfs.exe -f "C:\Users\Administrator\Desktop\Start Here\Artifacts\memory.dmp" -forensic 3`

![240f8298f927ef051ba7a4e7f52cc90f.png](/resources/240f8298f927ef051ba7a4e7f52cc90f.png)

Now we have so many ways to find the answer of this question. Why? because of when the USB is plugged in, the USBSTOR registry key will record its existence which included Serial Number and Model of the device so we can either use Registry Forensic tool such as Registry Explorer so browser for this key directly or we can use the `timeline_registry.txt` file which is one of the output of forensic mode of MemProcFS right here.

![eecbeae745900c16c8467c6ddae15ab0.png](/resources/eecbeae745900c16c8467c6ddae15ab0.png)

Then we can just simply search for USBSTOR which we can see that at 2024-10-04 13:48:18 UTC, the USB with serial number "7095411056659025437&0" was plugged in/connected from the user with RID 1001 (tommy user) indicate by Mountpoint registry that was edit/created at the same time this USB was connected.

```
7095411056659025437&0
```

>Q2: Tracking USB device activity is essential for building an incident timeline, providing a starting point for your analysis. When was the last recorded time the USB was inserted into the system?
```
2024-10-04 13:48
```

>Q3: Identifying the full path of the executable provides crucial evidence for tracing the attack's origin and understanding how the malware was deployed. What is the full path of the executable that was run after the PowerShell commands disabled Windows Defender protections?

![bf89953864fd3647e348eb470d4d90e4.png](/resources/bf89953864fd3647e348eb470d4d90e4.png)

I tried to look into the process tree by using Volatility 3 with plugin "windows.pstree" but there is not much interesting thing from the process tree but then I noticed `Sysmon.exe` process and that's mean the compromised machine have Sysmon install and we can leverage sysmon log to find out about the malware that was executed from USB drive.

Command : `python vol.py -f "C:\Users\Administrator\Desktop\Start Here\Artifacts\memory.dmp" windows.pstree > pstree.txt`

![d32d8594550d7c7e15e0d4140d1132fd.png](/resources/d32d8594550d7c7e15e0d4140d1132fd.png)

I parsed the whole logs folder into a single CSV file (Which I do not usually do it because parsing each log separately help me manage each filter for each file efficiently ) and then filter for Sysmon Event ID 1 from Tommy user and then we can see that the `Trusted Installer.exe` executable was executed from USB drive that was mounted to E drive after the PowerShell command to disable Real-time scanning of Windows Defender. and we can also see that an another executable was executed from Temp folder of Tommy user and parse the `Trusted Installer.exe` executable as an argument. this is odd but we will have to study about this malware to understand why it is the case here.

Command : `EvtxECmd.exe -d "M:\forensic\files\ROOT\Windows\System32\winevt\Logs" --csv output`

```
E:\hidden\Trusted Installer.exe
```

>Q4: Identifying the bot malware’s C&C infrastructure is key for detecting IOCs. According to threat intelligence reports, what URL does the bot use to download its C&C file?

![80a4167b34d8d4c4eaf1ae5ecdd05632.png](/resources/80a4167b34d8d4c4eaf1ae5ecdd05632.png)

Sysmon record MD5, SHA256 and Imphash of all executable that was being executed so we can search for MD5 or SHA256 hash of `Trusted Installer.exe` executable on [VirusTotal](https://www.virustotal.com/gui/file/9535a9bb1ae8f620d7cbd7d9f5c20336b0fd2c78d1a7d892d76e4652dd8b2be7/detection).

![9283d52d31df37813282634d883dd5fa.png](/resources/9283d52d31df37813282634d883dd5fa.png)

Then we can go to Relations tab which reveal the answer of this question right here.

![52b0a203205f3d5a40774efa57ffaf7f.png](/resources/52b0a203205f3d5a40774efa57ffaf7f.png)

We can use SHA256 hash to search for malware analysis report of this malware and some of search result will make us come across - "[Andromeda Malware Analysis](https://www.nec.com/en/global/solutions/cybersecurity/blog/240823/index.html)" by NEC Corporation and this blog post had analyzed Andromeda malware with the sample used on this lab and we can see that there are so many domains that were contacted with this sample but most have `/in.php` endpoint as we discovered from VirusTotal.

```
http://anam0rph.su/in.php
```

>Q5: Understanding the IOCs for files dropped by malware is essential for gaining insights into the various stages of the malware and its execution flow. What is the MD5 hash of the dropped .exe file?

![9d1bfe987ec8a3d09e77131ea9c81743.png](/resources/9d1bfe987ec8a3d09e77131ea9c81743.png)

By looking at the process tree from the blog, we can see that we also have `Sahofivizu.exe` that was executed from the Temp folder of user who executed the malware and the same parent process (`Trusted Installer.exe` in our case) will get executed many times across the process tree but we did not see that much from Sysmon.

![16d311acd32c9ae38b90a1778068607c.png](/resources/16d311acd32c9ae38b90a1778068607c.png)

Then from the behavior overview part of this blog, we can see that the sample (`Trusted Installer.exe` in our case) will drop 5 files but only one is the .exe file as we already discovered and the reason that the sample was executed so many times in chain is to conduct different job so the first execution will drop files then the `Sahofivizu.exe` will execute the sample again to delete indicators and start another example which drop new file and eventually injected the code into the memory to `msiexec.exe` and `svchost.exe` and the code that was injected to `svchost.exe` is responsible for the communication with C2 servers.

![72ffeb8011b9a16c93c0415ca3fb889f.png](/resources/72ffeb8011b9a16c93c0415ca3fb889f.png)

Now lets get the answer of this question from Sysmon right here.

```
7FE00CC4EA8429629AC0AC610DB51993
```

>Q6: Having the full file paths allows for a more complete cleanup, ensuring that all malicious components are identified and removed from the impacted locations. What is the full path of the first DLL dropped by the malware sample?

![720ef32ccf0826da656ea7ba5a5f207d.png](/resources/720ef32ccf0826da656ea7ba5a5f207d.png)

We can use Sysmon Event ID 11 with the `Trusted Installer.exe` as the image file which will reveal 4 dlls and 1 exe that was dropped by this sample and `Gozekeneka.dll` is the first of them.

```
C:\Users\Tomy\AppData\Local\Temp\Gozekeneka.dll
```

>Q7: Connecting malware to APT groups is crucial for uncovering an attack's broader strategy, motivations, and long-term goals. Based on IOCs and threat intelligence reports, which APT group reactivated this malware for use in its campaigns?

![8ec0792931f5da834b9b4490693fe587.png](/resources/8ec0792931f5da834b9b4490693fe587.png)
![b53d25b8f66221472c3318ec2d759740.png](/resources/b53d25b8f66221472c3318ec2d759740.png)

The blog post also talked about the background of this malware which was deployed by Turla team or UNC4210, reported by researchers from [Mandiant](https://cloud.google.com/blog/topics/threat-intelligence/turla-galaxy-opportunity/).

```
Turla
```

https://cyberdefenders.org/blueteam-ctf-challenges/achievements/Chicken_0248/andromeda-bot/ 
* * *
