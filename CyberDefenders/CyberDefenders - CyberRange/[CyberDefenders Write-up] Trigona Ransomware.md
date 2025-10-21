# [CyberDefenders - Trigona Ransomware](https://cyberdefenders.org/blueteam-ctf-challenges/trigona-ransomware/)
[toc]
* * *
## Scenario
As a forensic investigator at IResponseDash, you are tasked with examining a ransomware attack that has compromised multiple endpoints. Your primary objective is to determine the delivery method of the ransomware and to trace all activities of the attacker to understand the progression of the attack.

To accomplish this, you will analyze logs, review system and network activities, and gather evidence of the attacker's actions. This investigation will allow you to provide recommendations for addressing the current incident and enhancing defenses to prevent future attacks.

**Category**: Endpoint Forensics

**Tools**:
EZ Tools
Event Log Explorer
KAPE
Event Viewer
NTFS Log Tracker
CyberChef

* * *
## Questions
>Q1: Knowing the IP address of the machine that initiated the attack helps trace the attack's origin. What is the IP address of the attacker's machine?

![03f199deb61c335d9c334c916f2b2167.png](/_resources/03f199deb61c335d9c334c916f2b2167.png)

On this lab, We have KAPE collected artifacts of 2 machines which is the File Server and IT machine.

![d578f696754f4f6dc29e4698a98de885.png](/_resources/d578f696754f4f6dc29e4698a98de885.png)
![ed8eac865a954c98707f01645c0254e2.png](/_resources/ed8eac865a954c98707f01645c0254e2.png)

IT machine only has C drive but on the other hand, We got evidence from C and F drive from the File Server, from the folder name it could indicate that F drive on this File Server was used to for SMB shares internally.

![35a2e5532da8d00f2b3b8051b078d5bf.png](/_resources/35a2e5532da8d00f2b3b8051b078d5bf.png)

I made an hypothesis that the ransomware must have been detonated from the IT machine and the malware will effected the mount shares so I parsed logs folder of the IT Machine with EvtxECmd.

**Command** : `EvtxECmd.exe -d "C:\Users\Administrator\Desktop\Start Here\Artifacts\IT-Machine\Evidence-IT\C\Windows\System32\winevt\logs" --csv "C:\Users\Administrator\Desktop\Start Here\Artifacts" --csvf it-machine-all-logs.csv`

![620ca6007e0b28395edb93d3d72ac786.png](/_resources/620ca6007e0b28395edb93d3d72ac786.png)

After filtered with Event ID 4624 from Security log, I noticed that there is RDP logon on this machine from 192.168.19.100 as "Hanii-IT" user at 2024-06-30 11:26:57 UTC

![10564db92901d9199a56e958a76c5bf9.png](/_resources/10564db92901d9199a56e958a76c5bf9.png)

The LocalSession Manager log also record the same IP address connected to the IT Machine via RDP.

![7c3e6f9e92c6432b2b86d1ad36e93b00.png](/_resources/7c3e6f9e92c6432b2b86d1ad36e93b00.png)

To establish some baseline of this user, I searched for this specific user name which reveals that this user usually logged on with 192.168.19.144 so the IP address 192.168.19.100 is not normal at all and we can conclude that this IP address is belong to the threat actor's machine.

```
192.168.19.100
```

>Q2: Knowing the account used by the attacker helps track activities and identify compromised accounts. What is the SID of the account the attacker used to gain initial access on the victim machine?

![5dffd540e54fba2ba78471697532acbb.png](/_resources/5dffd540e54fba2ba78471697532acbb.png)

We know that the threat actor successfully logged on as "Hanii-IT" user via RDP so we can display SID of this user from its successful authentication right here.

```
S-1-5-21-1393444541-2628512620-2908104607-1112
```

>Q3: Identifying PowerShell commands reveals attackers' activities such as avoiding detection. What was the first PowerShell command the attacker used for defense evasion?

![4d8cd7dfabd3ba6fb6bb17b1b09993f7.png](/_resources/4d8cd7dfabd3ba6fb6bb17b1b09993f7.png)

This time, I filtered for Event ID 4104 for PowerShell Remote Execution from "Hanii-IT" user (filtered with SID) which reveals that at 2024-06-30 11:31:44 UTC, there is a command to disable Windows Defender Real Time Monitoring from  "Hanii-IT" user as we can see in the image above.

```
Set-MpPreference -DisableRealtimeMonitoring $true
```

>Q4: We need to find the enumeration output file revealing the network information gathered by the attacker. What is the TXT filename output of one of the network enumeration activities performed by the attacker?

![390dc08b573b715e47050e0c119ba4b0.png](/_resources/390dc08b573b715e47050e0c119ba4b0.png)

Now we have to conduct User Entity & Behavior Analysis (UEBA) of this user since the threat actor connected to IT Machine via RDP.

![ff57eba1c36850e13b0bc66afe920ebb.png](/_resources/ff57eba1c36850e13b0bc66afe920ebb.png)

There are 2 main ways to discover recent files access from this user which are "RecentDocs" registry key from `NTUSER.DAT` hive and the other one is JumpList as we can see from the image above here that there is 1 text file with the name `ipall.txt` was opened at 11:34 and the folder name `Tools` was opened at 11:31, additionally `System32` folder shoutcut file was also modified at 11:34 and it could indicate that this folder opened this folder at the same time as the text file or the text file was located inside this folder.

![fab1e4dd932d106693155b504f3a326b.png](/_resources/fab1e4dd932d106693155b504f3a326b.png)

We can use JumpList Explorer to parse these files from `AutomaticDestinations` and reveal the access timestamp and full path of these files.

![c5a9f3117a9f5364d324690610a8acb5.png](/_resources/c5a9f3117a9f5364d324690610a8acb5.png)

And now we can see that `ipall.txt` was located on `C:\Windows\System32` which is totally not common at all and as the name of the file indicates that this file might contains the result of pingsweep or IP discovery process of the attacker.

```
ipall.txt
```

>Q5: Identifying the tools used reveals the methods and scope of network enumeration. After gathering basic information about the network, what third-party tool did the attacker use to identify the file share and perform network enumeration?

![44993964c0aefb8dceee59b17cb246c3.png](/_resources/44993964c0aefb8dceee59b17cb246c3.png)

Knowing the existence of `Tools` folder, I parsed prefetch folder of IT Machine with PECmd from Eric Zimmerman Tools suite.

**Command** : `PECmd.exe -d "C:\Users\Administrator\Desktop\Start Here\Artifacts\IT-Machine\Evidence-IT\C\windows\prefetch" --csv "C:\Users\Administrator\Desktop\Start Here\Artifacts"`

![3507397caf27c0efb81ae1e3121eb43e.png](/_resources/3507397caf27c0efb81ae1e3121eb43e.png)

Then I used Timeline Explorer to open the prefetch timeline cve file and filter with "Tools" keyword which reveals 3 executables that was executed from the `Tools` folder and it located on the Desktop of "Hanii-IT" user.

It also reveals that the threat actor utilized `netscan.exe` for network enumeration then use `rclone.exe` to exfiltrate files and lastly the `FINAL.exe` could be a Trigona ransomware as stated in the name of the lab.

```
netscan
```

>Q6: Knowing the tool used for data exfiltration helps in identifying the methods and channels used by the attacker to exfiltrate sensitive data. What command-line tool did the attacker use to attempt data exfiltration?
```
rclone
```

>Q7: Identifying the IP addresses of the machines involved in lateral movement helps map the attacker's path and understand the attack's scope. Can you provide the IP address of the machine to which the attacker moved laterally and the IP address of the initial access machine?

![c42b26f31a008786d0c37f491e8161a5.png](/_resources/c42b26f31a008786d0c37f491e8161a5.png)

We know that the threat actor gained access to IT Machine first and then we have File Server artifact which indicates that the threat actor then RDP'ed to the file server next after gained access to IT Machine and to find out the IP of both machines, we have to look at Network Interface registry key within the `SYSTEM` hive of both machines. 

![c58b214377086664ef32e7361fef985a.png](/_resources/c58b214377086664ef32e7361fef985a.png)

Registry Explorer already bookmarked this registry for us so we can see that IT Machine have 2 active network interfaces and lets mark this IP address first. 

![fcaaf4c758c387f050ea5bf129165f24.png](/_resources/fcaaf4c758c387f050ea5bf129165f24.png)

And then we can open `NTUSER.dat` of "Hanii-IT" user since the attacker gained access to IT Machine as this user and RDP'ed to File Server so we can see that this user was used to connect to 192.168.19.130 during the incident, indicates by the last write timestamp of this key.

![9251f3f00f890c3d9567812cc5f79f69.png](/_resources/9251f3f00f890c3d9567812cc5f79f69.png)

And after we open `SYSTEM` hive of the File Server then we can see that the IP address of this machine was actually 192.168.19.130 so if we parsed local session manager event log of this machine then we gonna see it was connected from 192.168.31.129.

```
192.168.31.130, 192.168.31.129
```

>Q8: Knowing the path of the file share targeted by the attacker helps in identifying compromised data and understanding the attack's impact. What is the full path of the file share on the file server that was targeted by the attacker?

![83d1af43840e9ea4a8bd34871b77448b.png](/_resources/83d1af43840e9ea4a8bd34871b77448b.png)

Since we already opened the `SYSTEM` hive of the File server then we can take a look at "Shares" registry key which record the file share of that particular machine and we can see that there is only 1 share from this File Server.

```
F:\Shares\BusinessMaterial
```

>Q9: Identifying the SHA1 file hash of the malware helps in verifying the exact malicious file and correlating it with known malware signatures. What is the SHA1 file hash of the ransomware run on the file server and IT-machine?

![6a1bc09a0b90718400977f857e0bb1b5.png](/_resources/6a1bc09a0b90718400977f857e0bb1b5.png)

The only artifacts that record the SHA1 of executed executable files on Windows is Amcache (but not all will be recorded) so we can use AmcacheParser to parse `Amacache.hve` hive and open Unassociated File output csv in Timeline Explorer.  

**Command** : `AmcacheParser.exe -f "C:\Users\Administrator\Desktop\Start Here\Artifacts\IT-Machine\Evidence-IT\C\Windows\AppCompat\Programs\Amcache.hve" --csv "C:\Users\Administrator\Desktop\Start Here\Artifacts"`

![d191829ef998bcb6bd65ffb073322ba2.png](/_resources/d191829ef998bcb6bd65ffb073322ba2.png)

Since we already suspected the `final.exe` is the ransomware so we can grab it SHA1 right here and search it on VirusTotal.

![1d67a464dfa9a04a1ffe290b2e3ec9ba.png](/_resources/1d67a464dfa9a04a1ffe290b2e3ec9ba.png)

The [VirusTotal](https://www.virustotal.com/gui/file/dd34bb9b403e1daaf35ad243d4e6bd73b30c6b82d6026e8e69ccf66f521882df/detection) result confirmed that this file is really a Trigona Ransomware.

```
cfaa59dd3288387f62efbf54477d531f4d3964f3
```

>Q10: Knowing the extension of encrypted files can potentially help us with identifying the ransomware variant. What is the file extension of the encrypted files?

![97d718ef7b146111ec2e40cf3e0a31c8.png](/_resources/97d718ef7b146111ec2e40cf3e0a31c8.png)

There are several ways to discover this such as MFT, UsnJournal and LogFile but in this write up, I went with MFT.

**Command** : `MFTECmd.exe -f "C:\Users\Administrator\Desktop\Start Here\Artifacts\IT-Machine\Evidence-IT\C\$MFT" --csv "C:\Users\Administrator\Desktop\Start Here\Artifacts"`

![02e25e5127ee37ce52dec1e6ce3a65dd.png](/_resources/02e25e5127ee37ce52dec1e6ce3a65dd.png)

The ransomware must have renamed the file on the `Users` folder who detonated the ransomware first so we can just simply use "Hanii" to search which reveals the extension that was used to indicate the encrypted file as `._vNrFy5`

```
_vNrFy5
```

>Q11: Determining the registry modifications by the malware is crucial for identifying its malicious activities. What registry value did the malware add to display its ransom message?

![391340f55a967bbd7c73f2cb2060c791.png](/_resources/391340f55a967bbd7c73f2cb2060c791.png)

While I browsed the registry of "Hanii-IT" user, I discovered odd run persistence key and turned out its a key that will display the content of hta file every startup of this user.

```
c:\users\hanii_it\appdata\local\temp\how_to_decrypt.hta
```

https://cyberdefenders.org/blueteam-ctf-challenges/achievements/Chicken_0248/trigona-ransomware/ 

## Lab Inspiration
![f2873cbe978d98c4ef98ca78e75294fd.png](/_resources/f2873cbe978d98c4ef98ca78e75294fd.png)

After finishing the lab, I discovered that this lab took an inspiration from the "[Buzzing on Christmas Eve: Trigona Ransomware in 3 Hours](https://thedfirreport.com/2024/01/29/buzzing-on-christmas-eve-trigona-ransomware-in-3-hours/)" of The DFIR report which started from initial access via RDP, turn off Windows Defender, using `netscan.exe` to conduct network enumeration, lateral movement to File Server via RDP, exfiltrate files via `rclone.exe` and detonate Trigona ransomware at the end.

So if you have a time, I really recommend to read this report as you goes while doing lab or just read it to understand what happened!

* * *
