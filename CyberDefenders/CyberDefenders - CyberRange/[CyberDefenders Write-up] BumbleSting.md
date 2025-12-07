# [CyberDefenders - BumbleSting](https://cyberdefenders.org/blueteam-ctf-challenges/bumblesting/)
## Table of Contents

- [Scenario](#scenario)
  - [Network Diagram](#network-diagram)
- [Questions](#questions)
  - [Initial Access](#initial-access)
  - [Execution](#execution)
  - [Defense Evasion](#defense-evasion)
  - [Discovery](#discovery)
  - [Credential Access](#credential-access)
  - [Privilege Escalation](#privilege-escalation)
  - [Lateral Movement](#lateral-movement)
  - [Persistence](#persistence)
  - [Collection](#collection)
  - [Command and Control](#command-and-control)
  - [Impact](#impact)
- [Extra Resources](#extra-resources)

* * *
## Scenario
CompliantSecure Company has fallen victim to a significant security breach initiated by a phishing email. An unsuspecting employee interacted with the malicious email, allowing the attacker to infiltrate the company's network. Leveraging this initial access, the attacker escalated privileges, gaining control over critical systems, including the Domain Controller.

This breach has resulted in substantial operational disruption, raising concerns about potential exposure or compromise of sensitive data. Your team has been assigned the critical task of investigating the incident to unravel the attack’s progression and assess the full scope of the compromise.

### Network Diagram
- Below is a network infrastructure diagram, showing key systems and segments.

![8e72833748c68478e54ddf74ca9e526a.png](/resources/8e72833748c68478e54ddf74ca9e526a.png)

**Category**: Threat Hunting

**Tools**:
Splunk
ELK
SIEM

* * *
## Questions
![f7d8b8d8749300b1a4ad0323ad9dff65.png](/resources/f7d8b8d8749300b1a4ad0323ad9dff65.png)

This lab allows us to deploy either Splunk or Elastic SIEM to investigate an incident which I'm more comfortable with Splunk so I deployed it and after check up the "Data Summary", it reveals 6 different hosts and thousand of sources and sourcestype so our main way to query in the limited scope for optimization is to use `host` to focus on each host.

And as we can see that the `host` for Mail server seperate into 2 hosts, first is `MAIL01` and latter is `ip-10-10-3-108` which has only 16,xxx events so my starting point would be this host first to determine if i could find something related to this incident.

### Initial Access
>Q1: The Mail Server logs indicate a connection was made to a suspicious domain known for malicious email activities. What was the IP address of the domain involved in this connection?

![a142373536864d523a82ef633188ea3b.png](/resources/a142373536864d523a82ef633188ea3b.png)

As I sampled the query from `ip-10-10-3-108` host, the log that was ingested into splunk is `syslog` which make it easier to query since I can query for `postfix/smtpd` event only which reveals the suspicious email coming from `emkei.cz` at 2024-12-01 20:38

Query: `host="ip-10-10-3-108" smtpd | sort _time`

![a956ca5c21ec6b94ef5e5aa505303a7e.png](/resources/a956ca5c21ec6b94ef5e5aa505303a7e.png)

This domain is known for malicious mail sender and could be used to send many spoofed emails all at once.

```
114.29.236.247
```

>Q2: During the initial phase of the attack, a suspicious file was downloaded via a webmail client. The file's hash can help confirm its identity and origin. Identify the SHA256 hash of the downloaded file and provide it.

![04572f68a545a3c272ecf39c812346b3.png](/resources/04572f68a545a3c272ecf39c812346b3.png)

Since we know that the email was sent at 2024-12-01 20:38 then we can reduce our query scope to not show any event before this.

![a531884b61f2c0db82f68e4fc2149a57.png](/resources/a531884b61f2c0db82f68e4fc2149a57.png)

Now I will focus on the File Creation event and image that known for email client (such as browser and outlook) which I found that there is suspicious `NovaSecure_Audit_Findings.iso` file downloaded via Chrome at 2024-12-01 21:02

Query: `source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11 Image="*chrome.exe" | sort UtcTime | table UtcTime,Image,file_path,user,host`

![a208745420b794098c96d42eb95f87a6.png](/resources/a208745420b794098c96d42eb95f87a6.png)

To obtain the hash of this file, along with confirm that it really come from an email. I query with Sysmon Event ID 15 which reveals both SHA256 hash of this file and also reveal the content of Zone.Identifier and it indicates that this file was indeed, downloaded from webmail from the victim organization.

Query: `source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=15 NovaSecure_Audit_Findings.iso | sort UtcTime | table UtcTime,Image,file_path,user,host,SHA256,Contents`

```
F445F806066028D621D8E6A6B949E59342C309DFEB1D517BD847F70069B1B8DD
```

* * *
### Execution
>Q3: During the investigation, it was identified that a file executed by the user initiated a series of events that led to the execution of malicious code. What is the name of the file executed by the user?

![7b55b9524a024cd674c3649b497d2fd1.png](/resources/7b55b9524a024cd674c3649b497d2fd1.png)

Since the file that was downloaded is an ISO image file which needed to be mounted or extracted, then the victim will eventually executed whatever inside that lead to infection. then I query for Process Creation event which reveals that victim used 7Zip to extract the content of ISO image file and then suspicious `23.dll` was executed which leads to multiple situation awareness command execution later from `ImagingDevices.exe`. we will need to look at file creation event when 7zip extraction to see what really extracted from this ISO file.

Query: `source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 host=IT01 user=Administrator 
|  sort UtcTime | table UtcTime,CommandLine,ParentCommandLine,SHA256`

![08ddeca957e133d9898386eb168529b7.png](/resources/08ddeca957e133d9898386eb168529b7.png)

The file creation events reveal 3 different files extracted from this ISO file including suspicious dll file and shortcut file, the pdf file is likely the lure file to make it look more legitimate.

So if we could guess what happened then the victim executed lnk file which will then executed `23.dll` file with `rundll32.exe`, if I have `NTUser.dat` hive then I would inspect the UserAssist key to find if the lnk was really indeed executed but thats the limit of this lab and as well as actual investigation.

Query: `source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11 Image="*7zG.exe" | sort UtcTime | table UtcTime,Image,file_path,user,host`

```
Compliance_Reports.lnk
```

>Q4: Following the execution of the previous file, a file was loaded and executed by a legitimate Windows utility as part of the attack chain. What is the name of this file?
```
23.dll
```

>Q5: The beacon spawned an instance of a specific executable. What is the name of the created process?

![0fe74e4e0ed7fabb5e1d3124b7d99b16.png](/resources/0fe74e4e0ed7fabb5e1d3124b7d99b16.png)

As we already discovered that most of suspicious commands that were executed from `ImagingDevices.exe` so it must be this process but how it went from `rundll32.exe` to this image?

![6493484a49fea2092c2faa8581f1a43e.png](/resources/6493484a49fea2092c2faa8581f1a43e.png)

I query for another process creation event (Event ID 4688) to see the child-parent relationship that sysmon might have missed which reveals that the `ImagingDevices.exe` is the new process spawned from `rundll32.exe`

Query: `EventCode=4688 host=IT01 user=Administrator parent_process_path=*rundll32.exe* | sort SystemTime | table SystemTime,new_process,new_process_id,parent_process_path,parent_process_id`

![c65136e60251edc58d72ea617f36a181.png](/resources/c65136e60251edc58d72ea617f36a181.png)

My curiosity does not end here. I also query for Event ID 8 for potentially process injection activity and it reveals the possibility of process injection as expected.

Query: `EventCode=8  *ImagingDevices.exe* | sort UtcTime | table UtcTime, TargetImage,TargetProcessId,SourceImage,SourceProcessId`

![66d4803a4206b8cb8185c5ec6671761c.png](/resources/66d4803a4206b8cb8185c5ec6671761c.png)

We can even correlated this with Event ID 10 as well

Query: `source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10  *ImagingDevices.exe* | sort UtcTime | table UtcTime, TargetImage,TargetProcessId,SourceImage,SourceProcessId`

```
ImagingDevices.exe
```

>Q6: On DC01, the attacker dropped a compressed archive, likely staging for malicious activities. They then executed a command to extract its contents. What was the exact command used for this operation?

![37acf84f2c36b8b6992280e6f39a89a0.png](/resources/37acf84f2c36b8b6992280e6f39a89a0.png)

First, I query for file creation event on the domain controller first to look for suspicious image that created suspicious file which reveals that `SYSTEM` process dropped `0453497.exe` file at 2024-12-01 22:03 which likely to be the psexec-like lateral movement from other compromised endpoint and then `rundll32.exe` was likely to be the child process that spawned from `0453497.exe` which is common for C2 framework like Cobalt Strike.

After that, there are 2 files created from `rundll32.exe` including `1.7z` and then `7zr.exe` was used to extract content from this archive file.

The file created from `7zr.exe` reveals `AdFind.exe`, a domain enumeration tool and also `AnyDesk.exe`, a popular RMM that was spotted abused by threat actor group that used to BumbleBee to deliver Cobalt Strike beacon.

Query: `source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11 host="DC01" | sort UtcTime | table UtcTime,Image,file_path,user,host`

![aafaaaaac558b2599a8698a1c34bc54e.png](/resources/aafaaaaac558b2599a8698a1c34bc54e.png)

Looking at the process creation event belong to SYSTEM user on the domain controller, it reveals the story like we expected which including the extracting of `1.7z` but there is no `AdFind.exe` or `AnyDesk.exe` installation from SYSTEM user which mean both file was likely to be the staged for new backdoor admin user "sql_admin" that was created after extracing archive file.

Query: `source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 host=DC01 user=SYSTEM Image!="*wmiprvse.exe" | sort UtcTime | table UtcTime,CommandLine,process_id,ParentCommandLine,user,SHA256`

```
7zr.exe x 1.7z
```

* * *
### Defense Evasion
>Q7: A process injection occurred on IT01, where a new thread was created in the target process to execute malicious code. What was the start address of the injected code within the target process?

![264986fc67b471d805156a3cc13230eb.png](/resources/264986fc67b471d805156a3cc13230eb.png)

As we already discovered that the `ImagingDevices.exe` was injected from `rundll32.exe` (likely cobalt strike beacon), we can add more field to our table (StartAddress) to see the StartAddress of the injected code within this process.

Query: `EventCode=8  *ImagingDevices.exe* | sort UtcTime | table UtcTime, TargetImage,TargetProcessId,SourceImage,SourceProcessId,StartAddress`

```
0x000001C75CB60000
```

* * *
### Discovery
>Q8: The attacker’s sequence of commands shows a focus on domain-specific reconnaissance on IT01. Which command was executed to explore domain trust relationships within the environment?

![a2ef095b28a174292301e421335f5237.png](/resources/a2ef095b28a174292301e421335f5237.png)

Going back to the process creation event on the IT01 (patience zero / breachhead), we can see that after injected into `ImagingDevices.exe`, the threat actor executed multiple situation command including
- `ipconfig  /all`
- `arp -a`
- `nbtstat  -n`
- `ping  -n 1 ad.compliantsecure.store`
- `nltest /dclist:`
- `nltest /domain_trusts`

Before dumping lsass with sysinternal's process dump and compressed it to `doc1.7z` before deleting it (probably downloaded before deletion event but downloading event from C2 could not be logged with Sysmon)

```
nltest  /domain_trusts
```

>Q9: Network scanning activity was observed across the environment on DC01, focusing on key systems with straightforward network reachability tests. Further investigation revealed that the attacker utilized a script to automate these actions. What was the name of the script used in this operation?

![a33ac56631949862631de6bacc3dff15.png](/resources/a33ac56631949862631de6bacc3dff15.png)

As we already discovered the new backdoor admin user created on the domain controller, we can focus the process creation event from this user which reveals the execution of `1.bat` which ping all computers in the environment then later opened sensitive file from the file hash, compress files from the share and executed `patch.exe`

Query: `source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 host=DC01 user=sql_admin Image!="*wmiprvse.exe" | sort UtcTime | table UtcTime,CommandLine,process_id,ParentCommandLine,user,SHA256`

![ff2fa3cf40e921bda227ad53ac16844e.png](/resources/ff2fa3cf40e921bda227ad53ac16844e.png)

The same script was observed from this case as well - report published by The DFIR Report - [BumbleBee: Round Two](https://thedfirreport.com/2022/09/26/bumblebee-round-two/)

```
1.bat
```

* * *
### Credential Access
>Q10: On IT01, The attacker dropped a tool for credential dumping during the attack. What is the full path where this tool was created on the system?

![09c7a4ef4ea86ce3a5913df3b924492a.png](/resources/09c7a4ef4ea86ce3a5913df3b924492a.png)

As we already discovered that the threat actor used sysinternal's process dump to dump lsass then we can use the full image path as the answer of this question.

Query: `source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 host=IT01 *procdump* | sort UtcTime | table UtcTime,CommandLine,process_id,ParentCommandLine,SHA256`

![3fedfcf6f0cb723dab984ba69fb3a1af.png](/resources/3fedfcf6f0cb723dab984ba69fb3a1af.png)

To find out about how many files were dropped from injected process, I query for the file creation event again which reveals 5 different files dropped from this process including debug file, process dump, `7zr.exe` (used to compress lsass dump) and lastly, `patch.exe` that also seen executed on the domain controller. 

Query: `source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11 host=IT01 Image="*ImagingDevices.exe*"
| sort UtcTime | table UtcTime,Image,file_path,user,host`

```
C:\ProgramData\procdump64.exe
```

>Q11: Timing is critical for understanding the attacker’s actions and reconstructing the sequence of events. What was the timestamp when the attacker executed the credential dumping operation?
```
2024-12-01 21:15
```

>Q12: the attacker dropped a compression tool on IT01. What is the full path where this tool was created on the system?
```
C:\ProgramData\7zr.exe
```

* * *
### Privilege Escalation
>Q13: Due to a weak password, the attacker quickly cracked the credentials of a domain administrator account and used them to explicitly authenticate on IT01, gaining domain admin privileges. What is the username of the account whose credentials were stolen?

![1721d7a4ba19db93791b5aacb818b6d2.png](/resources/1721d7a4ba19db93791b5aacb818b6d2.png)

By querying the successful logon attempt from IT01 host, we can see that `markw` was the target user that has the most successful logon event during the incident timeframe if not including the machine account. 

Query: `EventCode=4624 src="10.10.11.110" | stats count by Target_User_Name`

![993d3383cce7d0d653e5f8f975ee5a13.png](/resources/993d3383cce7d0d653e5f8f975ee5a13.png)

I focus on the process creation from this user next, Which I can see that this user was used to install AnyDesk on the domain controller so it is confirmed that this user was indeed stolen.

Query: `source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 user=markw | sort UtcTime | table UtcTime,CommandLine,process_id,ParentCommandLine,host`

```
markw
```

* * *
### Lateral Movement
>Q14: A specific port was used during the lateral movement from IT01 to DC01. What was the port number?

![a7f4dfa4fa59cbd87710d69c26631da5.png](/resources/a7f4dfa4fa59cbd87710d69c26631da5.png)

Knowing the threat actor compromised markw account, we can use that with Event ID 4648 (log when the credential was given and not current user) which reveals that the threat actor used SMB authentication to access other resources from file shares.

Query: `EventCode=4648 dest="DC01.ad.compliantsecure.store" TargetUserName=markw | sort SystemTime |  table SystemTime,src_ip,src_port,src_user`

![4bb05f65260e02342aede43252a8e21b.png](/resources/4bb05f65260e02342aede43252a8e21b.png)

As we seen in the process creation event from FILESERVER, the threat actor archive file in the share folder before executing `patch.exe`

Query: `source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 user=markw host="fileserver01" | sort UtcTime | table UtcTime,CommandLine,process_id,ParentCommandLine,host`

```
445
```

>Q15: The malicious executable was stored in a shared location before execution. What was the full path where the executable was first created on DC01?

![37acf84f2c36b8b6992280e6f39a89a0.png](/resources/37acf84f2c36b8b6992280e6f39a89a0.png)

As we already discovered that `0453497.exe` was likely to be ps-exec like executable created on the domain controller to run beacon as SYSTEM after already compromised administrator-level user. 

```
C:\Windows\0453497.exe
```

>Q16: The attacker initiated an RDP connection to DC01 using a compromised account. What is the name of the attacker's workstation?

![a82fcf4a978a09ef7a75314837e52487.png](/resources/a82fcf4a978a09ef7a75314837e52487.png)

I query for successful logon as markw user again and focus on the workstation name which reveals that there are suspicious authentication as this user from Amazon EC2 instance which is not in the network diagram. indicating network pivoting capablities of the C2 framework used by the threat actor.

Query: `EventCode=4624 TargetUserName=markw  WorkstationName!="-" | sort SystemTime    | table  SystemTime,Computer,WorkstationName,LogonType`

```
EC2AMAZ-NVLPEI1
```

>Q17: The attacker utilized the remote access tool to establish a connection to the system and performed the first interactive login using the created account for persistence. At what time did this logon occur?

![4ee8afc3037eb794204da09ebe12cc4c.png](/resources/4ee8afc3037eb794204da09ebe12cc4c.png)

As we already discovered that the sql-admin is the backdoor user created for persistence and AnyDesk was installed from markw user, we can query successful logon from this backdoor which reveals the first logon event at 2024-12-01 22:25 to the domain controller and we can also see that this user was also used to access file server as well.

Query: `EventCode=4624 TargetUserName=sql_admin  WorkstationName!="-" | sort SystemTime    | table  SystemTime,Computer,WorkstationName,LogonType`

```
2024-12-01 22:25
```

* * *
### Persistence
>Q18: Performed lateral movement to DC01. To establish persistence, they installed a malicious service on DC01. What was the name of the service created on DC01?

![a54f6271b1fc597d125367ae71e48079.png](/resources/a54f6271b1fc597d125367ae71e48079.png)

As we already know that the threat actor used psexec-like capability to gain SYSTEM privilege shell on the domain controller, which mean the service creation will also logged this event as well and we can see both service installation for both psexec-like activity and anydesk here.

Query: `EventCode=7045 | sort SystemTime | table SystemTime,ServiceName,ImagePath,StartType`

```
0453497
```

>Q19: To establish persistence on DC01, the attacker created a new local user account and elevated its privileges. What were the username and password set for this account?

![d79efaca2997adec9b5e7e658c9b7a19.png](/resources/d79efaca2997adec9b5e7e658c9b7a19.png)

```
sql_admin:P@ssw0rd!
```

>Q20: The attacker installed a remote access tool on DC01 to enable persistent remote access and ensure continued control over the system. At what exact time was this service installed?

![a54f6271b1fc597d125367ae71e48079.png](/resources/a54f6271b1fc597d125367ae71e48079.png)

```
2024-12-01 22:17
```

* * *
### Collection
>Q21: After executing the reconnaissance script, the attacker directed their efforts toward a network folder share. Navigating through the shared directories, they stumbled upon a file that potentially contained critical information. This file was subsequently opened. What was the name of the file accessed by the attacker in this operation?

![cc261120fb6cf708278ce5abe8ee2af2.png](/resources/cc261120fb6cf708278ce5abe8ee2af2.png)

As we already seen on the process creation event as sql-admin on the domain controller which reveals that the threat actor opened `Admin_Passwords_v3_HASHED.csv` file from the file share using notepad then use 7zip to create an archive of file share into `Shares.7z` file before executed `patch.exe`

```
Admin_Passwords_v3_HASHED.csv
```

>Q22: The attacker leveraged an RDP connection from DC01 to FileServer01 to access and collect sensitive documents. After gathering the files, the attacker used a compression utility to archive them into a single file, preparing the data for exfiltration. What was the name of the compressed file created by the attacker during this operation?
```
Shares.7z
```

>Q23: The attacker initiated an RDP connection from their workstation to Support01 and accessed the mail server through a web browser. Using compromised credentials—reused by the domain admin for both Active Directory and the mail server—they successfully logged in. Then, the attacker downloaded a file containing potentially sensitive information from the compromised email account.
What was the name of the file downloaded by the attacker?

![2f02d78c73be900eb85efe39cd6a14dc.png](/resources/2f02d78c73be900eb85efe39cd6a14dc.png)

As we already discovered the the threat actor also utilized markw account to access SUPPORT01 as well.

![8949d6f728acc84a0143d1db1bbddbf4.png](/resources/8949d6f728acc84a0143d1db1bbddbf4.png)

I start by query process creation event on this host which reveal the usage of chrome browser and the existence of the `Accounts_Updates_1524.csv` file that was opened from the download folder of markw user that likely indicate that this csv file was downloaded via chrome browser

Query: `source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 host=SUPPORT01 user=markw Image!="*wmiprvse.exe" | sort UtcTime | table UtcTime,CommandLine,process_id,ParentCommandLine,user,SHA256`

![dbedc3394bfaa189978124fceb09c15c.png](/resources/dbedc3394bfaa189978124fceb09c15c.png)

File creation event also reveals the creation of zone.identifier of this csv file which confirm that this csv file was indeed downloaded via chrome browser by the threat actor.

Query: `source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11 host=SUPPORT01 Image="*chrome.exe" user=markw | sort UtcTime | table UtcTime,Image,file_path,user,host`

```
Accounts_Updates_1524.csv
```

* * *
### Command and Control
>Q24: Following the execution of the initial access malicious file, a network connection was established with a Command and Control (C2) server. What is the destination IP address and port to which the connection was made?

![d0e10747f77db884c970ea640b5e070e.png](/resources/d0e10747f77db884c970ea640b5e070e.png)

We can query for the network connection event (TCP) originate from `rundll32.exe` because `23.dll` is the C2 beacon which reveals the connection to 3.68.97.124 on port 443.

Query: `source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3 host=IT01 | sort UtcTime | stats count by user,dest_ip,dest_port,process_path`

```
3.68.97.124:443
```

>Q25: The spawned process by the beacon established a network connection to another external Command-and-Control (C2) server. What is the IP address and port of the C2 server that was contacted?

![0193a3f607d6faf5073724012e01f61b.png](/resources/0193a3f607d6faf5073724012e01f61b.png)

By querying Event ID 5156 (The Windows Filtering Platform has allowed a connection) from Windows Filtering Platform (WFP), we can see the different C2 address that was used by this injected process but use the same port as the first beacon.

Query: `EventCode=5156 host=IT01| sort SystemTime | stats count by DestAddress,DestPort,Application`

```
18.193.157.255:443
```

>Q26: After obtaining domain admin privileges on DC01, the attacker established a network connection to an external Command-and-Control (C2) server. What was the destination IP address and port of this connection?

![ad6a3811230e222585132deccb6ebaee.png](/resources/ad6a3811230e222585132deccb6ebaee.png)

We can make the same query used in Q24 but change the hostname which reveal another IP address used for psexec-like c2 beacon that connect to different C2 server at 3.68.27.19 and additionally we can also see 3 more IP addresses that might belong to the threat actor from AnyDesk as well (or probably anydesk server itself.)

Query: `source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3 host=DC01 | sort UtcTime | stats count by user,dest_ip,dest_port,process_path`

```
3.68.27.19:443
```

* * *
### Impact
>Q27: The attacker placed a malicious file in a shared folder accessible across the network and executed it remotely on multiple machines. What was the path from which the malicious file was executed?

![f262abe735cb620721f19ed999673814.png](/resources/f262abe735cb620721f19ed999673814.png)

As seen in many host that `patch.exe` was executed at the end of each host that likely to be the ransomware, I query for file creation event first to confirm that this file might be the ransomware which reveal a lot of `R3ADM3.txt` file across 3 hosts which mean this file is indeed the ransomware.

Query: `EventCode=11 Image="*patch.exe*" | sort UtcTime | table UtcTime,Image,file_path,user,host`

![ad71b1b01ce7fcab22e7a0a27e9372f4.png](/resources/ad71b1b01ce7fcab22e7a0a27e9372f4.png)

Then we can also see that this file was first executed from the file server and by dropping this file on the share folder, the threat actor could execute this file across many different hosts that can access this file share as seen that this file also executed on the domain controller (via sql_admin user) and SUPPORT01 host (via markw) user.

Query: `source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*patch.exe" | sort UtcTime | table UtcTime,CommandLine,process_id,ParentCommandLine,user,SHA256,host`

```
\10.10.11.18\Shares\patch.exe
```

>Q28: The malware executed across multiple machines on the network was identified as part of a well-known ransomware family. What is the name of the ransomware family associated with the malware?

![36fac796a48cd09cf3ddd1639cb32f32.png](/resources/36fac796a48cd09cf3ddd1639cb32f32.png)

We can search the file hash of this ransomware on [VirusTotal](https://www.virustotal.com/gui/file/d9243af49f96c8b66715287d0dc26dbd82eab8570d5f20629ddf9e5fe06c051c) which reveals the ransomware familty and look like this ransomware is from the Conti ransomware family.

```
Conti
```

>Q29: A message files were dropped on the infected systems, which likely contained ransom instructions. What was the name of the message file dropped by the malware?
```
R3ADM3.txt
```


https://cyberdefenders.org/blueteam-ctf-challenges/achievements/Chicken_0248/bumblesting/

* * *
## Extra Resources
- https://thedfirreport.com/2022/08/08/bumblebee-roasts-its-way-to-domain-admin/
- https://thedfirreport.com/2022/09/26/bumblebee-round-two/
- https://thedfirreport.com/2022/11/14/bumblebee-zeros-in-on-meterpreter/

* * *
