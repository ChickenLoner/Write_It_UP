# [Blue Team Labs Online - Monitor](https://blueteamlabs.online/home/investigation/monitor-84a39e5da1)

![6baf1039a99b95cd75e14f8469427ff1.png](/resources/6baf1039a99b95cd75e14f8469427ff1.png)

Investigating a large ProcMon output to answer questions about a ransomware incident.

>**Reverse Engineering**

>**Tags**: ProcMon
* * *
**Scenario**
Investigating a large ProcMon output to answer questions about a ransomware incident.

When launching ProcMon you may get a UAC prompt. Click "More choices" at the bottom then select the BTLO user.
* * *
## Investigation
>Q1) Identify the domain from which the malware was downloaded. What is the source process in this download event? (Format: domain.tld:port, processname.exe)

![f1315370e2086dde58dadc39db5ea41c.png](/resources/f1315370e2086dde58dadc39db5ea41c.png)
This challenge only provides us with ProcMon and CyberChef so lets just dive into this!

![c937090db1530fd441aa9e2d87d3e15f.png](/resources/c937090db1530fd441aa9e2d87d3e15f.png)

First, we can start by display process tree by clicking "Tools" > "Process Tree" which we should be able to see this suspicious process with a lot of child processes that are not common to use by normal user and we could confirm that this has to be the ransomware we are looking for.

![165a69ba1dd2dc6281cba312d542c37a.png](/resources/165a69ba1dd2dc6281cba312d542c37a.png)
Next, I opened network summary by clicking "Tools" > "Network Summary"  which we could see this domain that use the same word as the ransomware so lets find out which process was used to contact this domain by clicking "Go to process".

![644f4016ec2dcae8fe065ca060249e35.png](/resources/644f4016ec2dcae8fe065ca060249e35.png)

Display only network connection then we could see `chrome.exe` was connected to this domain before ransomware was executed so user downloaded ransomware using Chrome 

and there is one more thing we might take note which is this domain was also connected from PowerShell possibly another payload download or data exfiltration.

<details>
  <summary>Answer</summary>
<pre><code>completesurveyforyou.com:1337, chrome.exe</code></pre>
</details>

>Q2) What is the PS1 file downloaded and executed in a fileless way? (Format: filename.ps1) 

![2c3ba156ca0414593803e5435c3b2278.png](/resources/2c3ba156ca0414593803e5435c3b2278.png)

Now go back to process tree, which we should be able to see these PowerShell commands that executed base64 encoded commands and disable firewall and Windows Defender so lets change our Procmon to display process and thread activity and click "Go to process" of the first command with base64 we found.

![2c34481f67668f1796946531d6989b65.png](/resources/2c34481f67668f1796946531d6989b65.png)

another thing that we should do is to filter for parent process ID of the ransomware process to filter for only all child processes of the ransomware. 

![5300e652c9dd5539a7d177a447d76a8d.png](/resources/5300e652c9dd5539a7d177a447d76a8d.png)

Then go to process ID 10140 which is the first base64 we found from easily, click "Propeties" from Process Start operation/event then copy base64 encoded command and put it in CyberChef.

![8283211dcee8d72f99758975a462410f.png](/resources/8283211dcee8d72f99758975a462410f.png)
We could see that this is a command to download and execute PowerView, a post exploitation powershell framework in fileless way and also doing some basic AD enumuration, Shares, GPO on infected machine. 

<details>
  <summary>Answer</summary>
<pre><code>PowerView.ps1</code></pre>
</details>

>Q3) Hunt for T1489 and identify how many services are impacted (Format: number)

![46e44baa028def9de7bd317105f11b98.png](/resources/46e44baa028def9de7bd317105f11b98.png)
[T1489](https://attack.mitre.org/techniques/T1489/) is Service Stop technique and the first thing I could think of is to find `net stop` commands so lets find out if we could find one from process tree.

![296429f1ec32b463fb8895861f2b78bb.png](/resources/296429f1ec32b463fb8895861f2b78bb.png)

Sure enough, there are a bunch of net stop commands so lets go back to filter and filter for "net1 stop" for detail and `net.exe` for password.

![9242608f747663abedd4853f2ab4a011.png](/resources/9242608f747663abedd4853f2ab4a011.png)

Then we will have total of 14 events at the end which is the correct answer of this question.

<details>
  <summary>Answer</summary>
<pre><code>14</code></pre>
</details>

>Q4) What is the name of the file that was downloaded from the same domain the initial malware was downloaded from, and identify the tool name using its command line argument (Format: filename.exe, ToolName)

![dc621cc0eb54a443e2d7f98b130040a3.png](/resources/dc621cc0eb54a443e2d7f98b130040a3.png)
The other powershell command with base64 also have mimikatz as a child process that dumped credentials so even if we didn't decode it, we could assume that it will download mimikatz as `cats.exe` and execute it with `privilege debug` and `sekurlsa::logonpasswords`.	

![8cf1a63a3fdcf73a7437dce9fce4579e.png](/resources/8cf1a63a3fdcf73a7437dce9fce4579e.png)

But just to make sure, lets go to that process and decode it.

![0e79c1e313fc0f9092028023bee60bdd.png](/resources/0e79c1e313fc0f9092028023bee60bdd.png)

After decoding, we could also see that it will also delete mimikatz executable after dumping credentials.

<details>
  <summary>Answer</summary>
<pre><code>cats.exe, mimikatz</code></pre>
</details>

>Q5) What is the PID for the event which does T1518.001 (Format: PID)

![a89879246de63fdb8b5ca95ad532b40e.png](/resources/a89879246de63fdb8b5ca95ad532b40e.png)
[T1518.001](https://attack.mitre.org/techniques/T1518/001/) is Security Software Discovery so lets take a look at process tree again to find any commands that can discovery security software.

![89dc51adaeffe420c6fda4073bcf7c3d.png](/resources/89dc51adaeffe420c6fda4073bcf7c3d.png)

Then we will eventually find that this ransomware used wmic to list all anti-virus product on infected system.

<details>
  <summary>Answer</summary>
<pre><code>2320</code></pre>
</details>

>Q6) What are the 2 parameters modified in Windows Defender using a PowerShell command? (Format: Parameter1, Parameter2)

![717a0d4fbadd56ef221060f6f8eb8e8b.png](/resources/717a0d4fbadd56ef221060f6f8eb8e8b.png)
We already seen both of them on process tree, first is to disable real-time monitoring and controlled access folder.
<details>
  <summary>Answer</summary>
<pre>DisableRealtimeMonitoring,EnableControlledFolderAccess<code></code></pre>
</details>

>Q7) The malware targeted only one folder for encryption. What is the folder path and extension of the encrypted file? (Format: C:\...\..., .extension)

![bfec573b7a4d5e3c188c07a87018d54b.png](/resources/bfec573b7a4d5e3c188c07a87018d54b.png)
Changing our filter to Process ID of the ransomware then display only file activity then we should be able to see that file with `.encrypted` file inside IEUser's Document folder which is the only folder that got encrypted by this ransomware.
<details>
  <summary>Answer</summary>
<pre><code>C:\Users:\IEUser\Documents, .encrypted</code></pre>
</details>

>Q8) What is the PID used for displaying the ransom note? (Format: PID)

![0e388a6121bbec70f9edf6e387a56214.png](/resources/0e388a6121bbec70f9edf6e387a56214.png)
Most ransom notes are in text file and the built-in Windows text editor software is notepad so I went back to process tree and find out if there is one notepad process that opened `ransomnote.txt` at the bottom of process tree of ransomware process.
<details>
  <summary>Answer</summary>
<pre><code>4956</code></pre>
</details>

![f1fa1535d7401f8be31c751d6a99e6df.png](/resources/f1fa1535d7401f8be31c751d6a99e6df.png)
https://blueteamlabs.online/achievement/share/52929/160
* * *
## Summary
A malware was downloaded by user which was executed which it did 
- Executed PowerView filelessly for AD enumuration, Shares, GPO on infected machine
- Downloaded mimikatz to dump credential and deleted the file as soon as it finished dumping credential
- Disabled Security features such as Windows Defender, Firewall
- Added registry keys for more capabilities such as full administrative access for local accounts remotely, shared network drive access across session types. and enable long path support.
- Disable services
- Encrypted files in `C:\Users:\IEUser\Documents`
- Display ransomnote and remove itself at the end.

### Timeline
- 2023-08-23 06:10:15 : completesurveyforyou[.]com was contacted via chrome browser
- 2023-08-23 06:11:04 : Malware was executed.
- 2023-08-23 06:11:51 : Malware started host enumuration.
- 2023-08-23 06:12:18 : Powershell command to download and execute `PowerView.ps1` was executed.
- 2023-08-23 06:12:41 : Mimikatz was executed to dump logon passwords.
- 2023-08-23 06:13:19 : Malware disabled Windows Defender.
- 2023-08-23 06:13:39 : Malware disabled Windows Firewall.
- 2023-08-23 06:14:22 : Malware stopped the first service.
- 2023-08-23 06:14:26 : Malware stopped the last service.
- 2023-08-23 06:16:12 : Malware displayed a ransomnote via notepad.
- 2023-08-23 06:16:37 : Malware deleted itself (executable).

### IOCs
- `completesurveyforyou[.]com`
- `hxxp://192.168.0.101:1337`
- `CompleteThisSurvey.exe`
- `cats.exe`
- `ransomnote.txt`
- `*.encrypted`

* * *