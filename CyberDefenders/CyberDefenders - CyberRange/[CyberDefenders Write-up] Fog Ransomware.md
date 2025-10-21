# [CyberDefenders - Fog Ransomware](https://cyberdefenders.org/blueteam-ctf-challenges/fog-ransomware/)
[toc]
* * *
## Scenario
On April 30, 2025, a Finance department user received a phishing email with a RAR file. Trusting the sender, the user extracted and opened it. GOAT Capital’s SOC detected suspicious PowerShell activity from the user’s workstation. Soon after, mass file deletions and changes occurred, followed by ransom notes demanding Monero. Your task: investigate the true attack vector, identify attacker techniques, and assess the scope of the compromise.

**Category**: Endpoint Forensics

**Tools**:
Event Log Explorer
DB Browser for SQLite
Registry Explorer
NTFS Log Tracker
Timeline Explorer
EvtxECmd
Eric Zimmerman Tools

* * *
## Questions
### Initial Access
>Q1: To trace the origin of the attack, it's essential to identify where the malicious file was obtained. What is the complete URL from which the user downloaded the malicious RAR file?

![9a63e7cb3ed2c3f6caa19adb3227cd7e.png](/_resources/9a63e7cb3ed2c3f6caa19adb3227cd7e.png)

After deploying the lab machine, we can see that KAPE-collected artifacts are available. From the name of this lab, it’s strongly implied that we’ll be investigating a system infected by Fog Ransomware.

![05740843a77a68b20bad5315d7053611.png](/_resources/05740843a77a68b20bad5315d7053611.png)

Knowing what kind of malware we’re dealing with definitely helps, since we can refer to public reports that have already analyzed this ransomware’s capabilities. For this lab, I’ll be using the [FOG Ransomware Spread by Cybercriminals Claiming Ties to DOGE](https://www.trendmicro.com/en_us/research/25/d/fog-ransomware-concealed-within-binary-loaders-linking-themselve.html) article published by Trend Micro. In that report, the initial access vector for Fog Ransomware—downloading a malicious ZIP file—is very similar to our case. As we continue investigating, the findings will increasingly resemble what’s described in the article.

![cfc9d0c535763b8a1d9495a8148fb60f.png](/_resources/cfc9d0c535763b8a1d9495a8148fb60f.png)
![1cf41a4ad0a1e2a59322164c5521b910.png](/_resources/1cf41a4ad0a1e2a59322164c5521b910.png)
Now it’s time to look at the users on this machine. Besides the Administrator and Default accounts, there’s one more user—the author of this lab. Normally, I would start with that user before checking the Administrator account. However, after reviewing the browser history for both accounts, I found that the Administrator’s Edge browser history contains the information we need. So, we’ll be digging into that.

![723bcc77a3bcf4320569bd5891c89bca.png](/_resources/723bcc77a3bcf4320569bd5891c89bca.png)

We can use DB Browser for SQLite to open the History file from Microsoft Edge, but another option is to use Hindsight, which extracts all the juicy browser information for us. After running it, we just need to access the web interface through a browser.

![2ab8e9b26ccb346fa387d93aee911181.png](/_resources/2ab8e9b26ccb346fa387d93aee911181.png)

Now we need to specify the profile path of Edge browser (`C:\Users\Administrator\Desktop\Start Here\Artifacts\C\Users\Administrator\AppData\Local\Microsoft\Edge\User Data`) then make sure that Timezone is UTC[+0:00] before clicking Run.

![5d201b5cd0462b5ea311c8728ab00d70.png](/_resources/5d201b5cd0462b5ea311c8728ab00d70.png)

After hindsight finished processing browser artifacts, we can save file to open with our Timeline Explorer or browse the result via web browser with "View SQLite DB in browser".

![3b4a9b3da8a0c684907ee215acb05ab3.png](/_resources/3b4a9b3da8a0c684907ee215acb05ab3.png)

I like Timeline Explorer more so I went with this option and after we filtered with the word "download", we can see that it comes down to only one result which is the `pay rate.pdf.rar` that was downloaded at 2025-04-30 20:28:45 via limewire but this is not the answer of this question yet.

![da27ad5ad5b31f144102549eb4d1fe93.png](/_resources/da27ad5ad5b31f144102549eb4d1fe93.png)

Now we can filter for "limewire" to find record from "url" table which we can finally obtain the answer of this question here.

![f309d489374d0c71b704264a51d02de6.png](/_resources/f309d489374d0c71b704264a51d02de6.png)

We can use an MFT parser tool like MFTExplorer or MFTECmd to find the record of the RAR file downloaded by the Administrator account. This record should also include an alternate data stream (Zone.Identifier) indicating the download URL of the file. Unfortunately, in this case, only the Limewire domain was recorded.

Another thing we can notice is the `.flocked` file extension along with the presence of a `readme.txt`, which indicates that Fog Ransomware has already executed on this system and encrypted most of the files.

```
https://limewire.com/d/lihUt#NrUgowrb29
```

>Q2: Establishing an exact timeline helps reconstruct the attack sequence accurately. What is the exact timestamp when the user downloaded the RAR file to the system?
```
2025-04-30 20:28
```

>Q3: Understanding how the payload was executed reveals the user action that led to compromise. Which file extracted from the archive was launched by the user, triggering the attack?

![cf58ab78322294027d8763f7df91d907.png](/_resources/cf58ab78322294027d8763f7df91d907.png)

According to the article, Fog Ransomware was distributed through a shortcut file (.lnk) compressed into a ZIP archive and sent to the victim. We can also confirm the existence of this file in the Administrator’s Recycle Bin.

![9b4ca53312b9797b45d51c7b27f13d66.png](/_resources/9b4ca53312b9797b45d51c7b27f13d66.png)

By using `RBCmd.exe` to parse the $I file, we can see the full path of the file before it was deleted. It confirms that this was indeed a shortcut file extracted from the ZIP archive we found earlier, along with details such as its file size and deletion time.

Command : `RBCmd.exe -f "C:\Users\Administrator\Desktop\Start Here\Artifacts\C\$Recycle.Bin\S-1-5-21-1505444485-2617992307-1870881995-500\$I50Y0C5.lnk"`

![bfd5d95148606fb7823a5233fff15dea.png](/_resources/bfd5d95148606fb7823a5233fff15dea.png)

Since we also have the $R file—the actual file moved to the Recycle Bin (but not yet deleted)—we can use `LECmd.exe` to parse this shortcut. From it, we can extract valuable information such as the file’s creation time, the hostname that created it, and the relative path configured to execute a PowerShell command that fetched and executed `troubleshooting.ps1` from 192.168.1.54 on port 4561.

Command : `LECmd.exe -f "C:\Users\Administrator\Desktop\Start Here\Artifacts\C\$Recycle.Bin\S-1-5-21-1505444485-2617992307-1870881995-500\$R50Y0C5.lnk"`

```
pay rate.pdf.lnk
```

### Execution
>Q1: Identifying the initial script clarifies the method used to deliver and execute malicious payloads. What is the name of the PowerShell script that executed the payloads?

![ec44bba78da2af4243868e95ab3d4366.png](/_resources/ec44bba78da2af4243868e95ab3d4366.png)

Since we’ve confirmed that the shortcut file retrieved another payload via PowerShell—matching the behavior described in the Trend Micro article—we should expect the next stage of this execution to involve the drop of the ransomware loader (`cwiper.exe`), `ktool.exe`, and additional PowerShell scripts.

```
troubleshooting.ps1
```

>Q2: Pinpointing when ransomware activity began is crucial for defining the start of encryption. When did the ransomware first execute on the victim machine?

![6e5cd7d4c8f5f71108ea020b9240172d.png](/_resources/6e5cd7d4c8f5f71108ea020b9240172d.png)

After I found that the shortcut file will execute PowerShell script upon execution, I went to check Windows Event log which we can see that we have Sysmon log here as well so lets parse this log first until we need PowerShell log.

![d51c3219f250c7f8862a1f0d0f9a28c3.png](/_resources/d51c3219f250c7f8862a1f0d0f9a28c3.png)
We could parse this with EvtxECmd and we can see that there are total of 3,171 records from this event log and my focus is Event ID 1 that has 204 events. 

Command : `EvtxECmd.exe -f "C:\Users\Administrator\Desktop\Start Here\Artifacts\C\Windows\system32\winevt\logs\Microsoft-Windows-Sysmon%4Operational.evtx" --csv output --csvf sysmon.csv`

![3035693d9284951003f2b7736fdbb73a.png](/_resources/3035693d9284951003f2b7736fdbb73a.png)

After opening the output file in Timeline Explorer and filtering for Sysmon Event ID 1 under the Administrator user, we can see that the shortcut file was executed at 2025-04-30 20:32:06. This action initiated the infection chain by running `troubleshooting.ps1`, opening a YouTube video, creating a hidden folder in the global startup directory (and marking it hidden), dropping `Adobe Acrobat.exe` (ransomware loader) into it, displaying the ransom note, and more.

![9df407685a9e2557cbc4e57d3f1f610c.png](/_resources/9df407685a9e2557cbc4e57d3f1f610c.png)

This align with the `stage1.ps1` script from Trend Micro here.

```
2025-04-30 20:32
```

>Q3: Hash values allow correlation of the malware across systems and threat intelligence sources. What is the SHA256 hash of the ransomware executable used in this attack?

![745d490d5109412c22db6d26f31a268a.png](/_resources/745d490d5109412c22db6d26f31a268a.png)
![331027991aad692635926ec3f6e4bcde.png](/_resources/331027991aad692635926ec3f6e4bcde.png)

We can also retrieve the SHA256 hash of the ransomware loader here, since it was executed to encrypt the files on this system and we can confirm it by searching this file hash on VirusTotal.

![8cbf50444a1ae8087e4ece756f5799b6.png](/_resources/8cbf50444a1ae8087e4ece756f5799b6.png)

[VirusTotal](https://www.virustotal.com/gui/file/113a06c8ba6069d345f3c3db89051553d8aff7d27408945b50aa94256277dcb3/detection) result did not shown much about the name of this ransomware but we will confirm it as Fog ransomware as we dig into Comments tab.

![c6450c5c2cade614eb34f4c3dea13cbf.png](/_resources/c6450c5c2cade614eb34f4c3dea13cbf.png)

Inside the comment tab, we can see that Thor scanner detected this as Fog ransomware as it matches rules from different articles, one from Trend Micro article that we alreadt discovered and the other one is [Cyble](https://cyble.com/blog/doge-big-balls-ransomware-edward-coristine/) article which will also tell the similar story.

```
113A06C8BA6069D345F3C3DB89051553D8AFF7D27408945B50AA94256277DCB3
```

### Persistence & Privilege Escalation
>Q1: Knowing how persistence was maintained helps ensure thorough malware removal. What MITRE ATT&CK sub-technique ID did the attacker use to gain persistence post-reboot?

!![cd408b1e72af483e54759166fc082206.png](/_resources/cd408b1e72af483e54759166fc082206.png)

Since this ransomware made itself persistence by placing it on global startup folder, this is obviously [T1547.001](https://attack.mitre.org/techniques/T1547/001/)

```
T1547.001
```

>Q2: Exploited drivers often reveal the attacker’s method for gaining elevated privileges. What is the name of the vulnerable driver the attacker used for privilege escalation?

![121e0f1fc350ede469f097a9bc5c2e73.png](/_resources/121e0f1fc350ede469f097a9bc5c2e73.png)
![d93cc31706f7c75e7bc1feab5eccefab.png](/_resources/d93cc31706f7c75e7bc1feab5eccefab.png)


The PowerShell script also dropped `Ktool.exe`, which was used for privilege escalation by exploiting the vulnerable Intel Network Adapter Diagnostic Driver (CVE-2015-2291). We can see that it takes two arguments: a process ID and a hardcoded key to activate the exploit.


![3f985aee5a52a4bed8c29607acaaa10e.png](/_resources/3f985aee5a52a4bed8c29607acaaa10e.png)
We can also confirm that the driver was dropped during the ransomware’s execution, meaning it leveraged a BYOVD (Bring Your Own Vulnerable Driver) technique to escalate privileges.

```
iqvw64e.sys
```

>Q3: Mapping kernel-level techniques helps identify sophisticated system access methods. What technique did the attacker use to gain kernel-level access?
```
Bring your own vulnerable driver
```

### Collection
>Q1: Tracking files written by malware provides insight into its actions and scope. What is the name of the log file created by the ransomware to record its operations?

![c6a53e7d3d9f609856339a00f2c9112a.png](/_resources/c6a53e7d3d9f609856339a00f2c9112a.png)
![144dd156e1477b9fa304ffd3272be730.png](/_resources/144dd156e1477b9fa304ffd3272be730.png)

As noted in the Trend Micro article, the ransomware loader also dropped a log file, DbgLog.sys, which records encryption-related events. By reviewing Sysmon Event ID 11, we can confirm that this log file was also dropped on this system, as shown in the image above.

```
DbgLog.sys
```

### Command and Control & Impact
>Q1: Command-and-control contact details help trace external infrastructure used in the attack. What IP address and port number did the downloader connect to in order to retrieve the payload?

![7d67b1b24cca2b7e44062008a3a6ed3d.png](/_resources/7d67b1b24cca2b7e44062008a3a6ed3d.png)

Since we already discovered that the shortcut file connects to 192.168.1.54 on port 4561 to retrieve and execute the PowerShell script troubleshooting.ps1, we can confirm this activity with Sysmon Event ID 3, as shown in the image above.

```
192.168.1.54:4561
```

>Q2: Understanding encryption behavior is vital for response and recovery planning. What file extension did the ransomware append to encrypted files?
```
.flocked
```

>Q3: Ransom communication links are key for attribution and negotiation strategy. What is the .onion link provided by the attacker for ransom payment or communication?

![e38eee6e6ea5dff135e7e4704d205537.png](/_resources/e38eee6e6ea5dff135e7e4704d205537.png)
![9b52df5289f3a0d49287dc0c2fa77ee5.png](/_resources/9b52df5289f3a0d49287dc0c2fa77ee5.png)

We can go back to VirusTotal to get the onion link in the Behavior tab, under Decoded text or we can use [Recorded Future Tria.ge](https://tria.ge/250505-eyv9wa1ns3) to get the malware configuration, both will lead us to the same answer which is xql562evsy7njcsngacphc2erzjfecwotdkobn3m4uxu2gtqh26newid[.]onion and now we are done with this lab!

```
xql562evsy7njcsngacphc2erzjfecwotdkobn3m4uxu2gtqh26newid.onion
```

https://cyberdefenders.org/blueteam-ctf-challenges/achievements/Chicken_0248/fog-ransomware/ 
* * *
