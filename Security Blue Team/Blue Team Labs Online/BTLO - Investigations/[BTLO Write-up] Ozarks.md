# [Blue Team Labs Online - Ozarks](https://blueteamlabs.online/home/investigation/ozarks-66864262c0)
<div align=center>

![40eb42e811bd0cf1e6a68d4efa28d2fc.png](..//resources/40eb42e811bd0cf1e6a68d4efa28d2fc.png)
</div>
The threat actors are exploiting the digital infrastructure, attempting to disrupt the festival and steal sensitive information. Can Ozark's SOC Analysts stop it?

> Security Operations

>**Tags**: Hayabusa, TimeLine Explorer, Network Miner, Wireshark, T1566.001, T1055
* * *
**Scenario**
Ozark Inc., known for its security expertise, has been hired to protect the Haunted Festival's digital infrastructure. The festival has become an interconnected experience where attendees use mobile apps for ticketing, access virtual haunted house simulations, and interact with digital attractions. As the festival approaches, Ozark's SOC analysts begin noticing unusual activity, suggesting that the event has been compromised by a group of sophisticated attackers. The threat actors are exploiting the digital infrastructure, attempting to disrupt the festival and steal sensitive information. We know that Ruth, who is part of the Domain Admin group, was targeted. The success of the festival now depends on their ability to identify the attackers' tactics, techniques, and procedures (TTPs) and neutralize the threat before the festival is ruined.

* * *
## Investigation Submission

![828a8c2b7df9cd0563aec99e161a6242.png](..//resources/828a8c2b7df9cd0563aec99e161a6242.png)

After deployed an investigation machine, we have 2 folders on the desktop prepared for us, "Case Artifacts" folder contains artifacts need for this investigation from 2 workstations (DC and WK) which are
- Windows Defender Logs
- Window Event Logs
- Windows Temp directories(?)
- PCAP files

![8d44079cd903143543bb649e9e20187b.png](..//resources/8d44079cd903143543bb649e9e20187b.png)

And we got 5 tools that can be used.

![8fd64dd082f5dd50f03e2b846b8c5979.png](..//resources/8fd64dd082f5dd50f03e2b846b8c5979.png)

After navigate to Windows event log to check for sysmon log, look like We got SYSMON log too.

>Q1) A user received a phishing email containing a zip file, which included a malicious attachment. Upon interaction with the file, the infection chain was initiated. Identify the name of the compromised user. (Format: xxxxx)

![04616dba36d2c1fbac087ab54bd9e69c.png](..//resources/04616dba36d2c1fbac087ab54bd9e69c.png)

Since we have sysmon then it would be easier to use LogParser to convert them into csv file with `LogParser.exe "SELECT * INTO C:\Users\BTLOTest\Desktop\Tools\output.csv FROM 'C:\Users\BTLOTest\Desktop\Case Artifacts\Artifacts\WK\Artifacts\C\Windows\System32\winevt\logs\sysmon.evtx'" -i:EVT -o:CSV` (Yes lets start with WK first)

![3a38e28e0b58b0fc0f27fc3532921c6a.png](..//resources/3a38e28e0b58b0fc0f27fc3532921c6a.png)

While waiting for the convert, Lets use hayabusa to create HTML report from this sysmon this with this `hayabusa-2.17.0-win-x64.exe -csv-timeline -f "C:\Users\BTLOTest\Desktop\ Case Artifacts\WK\Artifacts\C\Windows\System32\winevt\logs\sysmon.evtx" --HTML -report sysmon.html --output sysmon.html`

![e4cc9ef72c8b4bc8d3b77fd1079cb1ff.png](..//resources/e4cc9ef72c8b4bc8d3b77fd1079cb1ff.png)

Nice! hayabusa found Sliver C2 implant, Process Injection and MMC spawning Windows process.

![a9e65135f821cb813cae664d63344dc2.png](..//resources/a9e65135f821cb813cae664d63344dc2.png)

Then we can access HTML report to found more about these events.

![bb65a45e4351a0b1588d6326e97e3152.png](..//resources/bb65a45e4351a0b1588d6326e97e3152.png)

Our main focus is the Sliver C2 implant so we will have to filter happened during this day.

![6c3c92be8c8c68b255c09556e3bd8350.png](..//resources/6c3c92be8c8c68b255c09556e3bd8350.png)

We can filter log file like this to focus the date of C2 implant activities(I would recommended doing this on Timeline Explorer with output.csv that we just created using LogPaser)

![002fe6487082a20addf72304654ad406.png](..//resources/002fe6487082a20addf72304654ad406.png)

Which I found this command was executed by user "wendy" that downloaded executable file from C2, executed it then create a task to make sure it will execute every time any user has logged on which will execute this file as SYSTEM hence... privilege escalation with persistence.

<details>
  <summary>Answer</summary>
<pre><code>wendy</code></pre>
</details>

>Q2) The file type has been abused by the threat group Kimsuky (aka APT43, Velvet Chollima) since April 2024. Provide the name of the malicious file. (Format: file.ext)

From hayabusa, we found that `mmc.exe` was used to create Windows process which should not be possible since it can be used for monitor and configure system.

![f4c8ec67dbdd5faa4645885cd5be4d83.png](..//resources/f4c8ec67dbdd5faa4645885cd5be4d83.png)

Then we will see that this activity was really suspicious and from this case, MMC was used to bypass UAC according to [LOLBAS](https://lolbas-project.github.io/lolbas/Binaries/Mmc/) 

![f321142e68d7419b8d1b3f4a7ca0abd4.png](..//resources/f321142e68d7419b8d1b3f4a7ca0abd4.png)

Then after searching about this kind of exploit, I found [Operation ControlPlug: APT Attack Campaign abusing MSC file](https://jp.security.ntt/tech_blog/controlplug-en) detailing about this operation and how MSC file can be abused to execute arbitrary commands, so we got the right file to submit. 

<details>
  <summary>Answer</summary>
<pre><code>Financial_Report_2024.MSC</code></pre>
</details>

>Q3) When the user clicked the link in the malicious file, a PowerShell command was triggered to download a payload from a command-and-control (C2) server. Provide the IP address of the C2 server. (Format: XXX.XXX.XX.XXX)

![40fddd75b2f4ffe1edd7fe11f55b5a51.png](..//resources/40fddd75b2f4ffe1edd7fe11f55b5a51.png)

We know which url and payload that will be downloaded so after open WK pcap file then we should be able to see an IP address of C2 right here.

<details>
  <summary>Answer</summary>
<pre><code>192.168.42.131</code></pre>
</details>

![707b153c5e69937666624adba5ee14ce.png](..//resources/707b153c5e69937666624adba5ee14ce.png)

Now its time to export it, Go to File -> Export Objects -> HTTP...

![38fbd3fc88862bdaf49c029c863f7f27.png](..//resources/38fbd3fc88862bdaf49c029c863f7f27.png)

Select malware payload then save.

![abe77982d82e4c33bbb738a80864ae45.png](..//resources/abe77982d82e4c33bbb738a80864ae45.png)

And look like defender is working well on this machine since it instantly quarantined this file.

![06ab1a57b6ccfe343e6f4ddb5b764762.png](..//resources/06ab1a57b6ccfe343e6f4ddb5b764762.png)

Then I went back to pcap again to see what happened after the file was downloaded since we already know that it was executed right away once the download was completed which we can see that there is a connection back to C2 on port 8888 which mean this is reverse shell payload.

>Q4) The payload was initially blocked by Windows Defender antivirus. Name the signature of the threat. (Format: Signature Name)

![9c22e2ee76eda8b791bb70aefbfdceda.png](..//resources/9c22e2ee76eda8b791bb70aefbfdceda.png)

Well... I already got the answer of this question by exporting it out which was unintended but guess that worked... but to find out about this legitimately, we have to find it on Windows Defender log of WK machine like this.
<details>
  <summary>Answer</summary>
<pre><code>Trojan:Win32/SuspGolang.AG</code></pre>
</details>

>Q5) The file establishes persistence by creating a scheduled task. Provide the name of this scheduled task. (Format: Task Name)

![002fe6487082a20addf72304654ad406.png](..//resources/002fe6487082a20addf72304654ad406.png)

We already found this one on the first task.
<details>
  <summary>Answer</summary>
<pre><code>OneDrive Security Task</code></pre>
</details>

>Q6) Identify the name of the command-and-control (C2) tool used by the threat actors to manage their malicious operations. (Format: Xxxxxx)

![a9e65135f821cb813cae664d63344dc2.png](..//resources/a9e65135f821cb813cae664d63344dc2.png)
Hayabusa detected Sliver C2 implant.
<details>
  <summary>Answer</summary>
<pre><code>Sliver</code></pre>
</details>

>Q7) A few minutes after the initial infection, the threat actor engaged in hands-on keyboard activity for domain reconnaissance. Specify the timestamp (in UTC) for the first executed command. (Format: YYYY-MM-DD HH:MM:SS)

![0d168b813fd19220bcbe42ea1510e991.png](..//resources/0d168b813fd19220bcbe42ea1510e991.png)

After initial infection, the threat actor created PowerShell interactive shell with this command first.

![9d1f6dda7747d697f28d4c7662c9f1e9.png](..//resources/9d1f6dda7747d697f28d4c7662c9f1e9.png)

Then use PowerShell process ID as a guide, we can see that around this time, the threat actor executed `ipconfig /all` as the first command to gather information about this host.

<details>
  <summary>Answer</summary>
<pre><code>2024-10-04 15:34:03</code></pre>
</details>

>Q8) This was followed by the dumping of the LSASS process using the initial C2 implant. Provide the process ID of the source process. (Format: XXXXX) 

![1a665267e997cdcd81b7e004405058f0.png](..//resources/1a665267e997cdcd81b7e004405058f0.png)
Lets get process ID of reverse shell payload since this process was the source of all sort of commands used by the threat actor.
<details>
  <summary>Answer</summary>
<pre><code>10840</code></pre>
</details>

>Q9) During their discovery activities within the network using Windows utilities like nltest.exe and net.exe, the threat actor found a privileged user's login session (informed in the scenario). To escalate their privileges and bypass defenses, the attacker injected a command-and-control (C2) implant into a legitimate process. Identify the process ID. (Format: XXXX)

![2ac73dbc67dc52639bd53b34da9619c2.png](..//resources/2ac73dbc67dc52639bd53b34da9619c2.png)

Then we can see that the threat actor started by retrieving domain admins information.

![4df8007ea937f8f9bc8425867bd8d5a1.png](..//resources/4df8007ea937f8f9bc8425867bd8d5a1.png)

Another 3 commands related to domain controllers were executed around this time.

![5a4f7f95af28a122610dd77ec56bd838.png](..//resources/5a4f7f95af28a122610dd77ec56bd838.png)

registry query were made to retrieve user logon credential.

![15fc964d5c83660750c7305c0d1e9f2b.png](..//resources/15fc964d5c83660750c7305c0d1e9f2b.png)

Then we could see that lsass was accessed around this time which sysmon matched it to Credential Dumping rules

![840ef1a9d24b1a48a55a902259cb443f.png](..//resources/840ef1a9d24b1a48a55a902259cb443f.png)

Then finally if we just filtered for sysmon event ID 8 (created thread) which we will see `spooler.exe` was injected which made the threat actor gained SYSTEM privilege which made me think that the threat actor exploited PrintNightmare vulnerability for privilege escalation. 

![b265e83f3e778706ff7a014e7bdd959a.png](..//resources/b265e83f3e778706ff7a014e7bdd959a.png)

Then we could see msedge process was created by SYSTEM user and the process ID of this one is the one we are looking for.

<details>
  <summary>Answer</summary>
<pre><code>9056</code></pre>
</details>

>Q10) The threat actor attempted to move laterally to the domain controller. During the initial attempt, the service was detected by Windows Defender AV. Provide the name of the service. (Format: Xxxxxx)

![66ec9ba286a8deff3f922d3a38961177.png](..//resources/66ec9ba286a8deff3f922d3a38961177.png)

Now lets get this one from DC's Windows Defender log which we can see a service name "intune" was detected as malware.
<details>
  <summary>Answer</summary>
<pre><code>intune</code></pre>
</details>

>Q11) The threat actor ultimately succeeded in pivoting to the domain controller. Identify the name of the account used by the attacker for this action. (Format: Xxxxxxxxxxxxx)

![53b7fafa2089664c562d60d4b553a9a7.png](..//resources/53b7fafa2089664c562d60d4b553a9a7.png)

Since we already know the IP address of the threat actor so I filtered for sysmon event ID 3 from DC event log which we can see a connection was established with `sls.exe` file.

![82b865d0d65cceb2fba68d2fef6e63f0.png](..//resources/82b865d0d65cceb2fba68d2fef6e63f0.png)

And the user who executed this file is Administrator.

<details>
  <summary>Answer</summary>
<pre><code>Administrator</code></pre>
</details>

>Q12) The attacker returned to the beachhead and attempted to execute commands using a popular IDE platform. This technique was recently used by a Chinese Advanced persistent threat (APT) group to carry out cyber espionage attacks. Provide the executed command. (Format: Command)

![5051220b147b3b7d77641abc2d492f03.png](..//resources/5051220b147b3b7d77641abc2d492f03.png)
After searching on the internet about Chinese APT abused IDE then I found this [article](https://unit42.paloaltonetworks.com/stately-taurus-abuses-vscode-southeast-asian-espionage/) published by Unit42 which reduce my scope to find only VSCode.

![d30b4d5536381b2c2f8ee95502c07037.png](..//resources/d30b4d5536381b2c2f8ee95502c07037.png)

And there it is, VSCode was downloaded and installed on WK machine by wendy user.

![f27a7a1a060bafb74341bfa0bf293617.png](..//resources/f27a7a1a060bafb74341bfa0bf293617.png)

Then we can see `code-tunnel.exe` was executed with PowerShell by wendy but this is not the one we are looking for. 

![a2053065f854596212e5828c59594756.png](..//resources/a2053065f854596212e5828c59594756.png)

After a while we will finally see a command resemble command we found on Unit42 article which was the answer of this question... (well I should have submit what I found on that article right after I read it...)

<details>
  <summary>Answer</summary>
<pre><code>Code.exe tunnel</code></pre>
</details>

While I searched for last Q, I also found this medium blog which is also helpful resources teaching about how to [block, create Sentinel Detection, and add Environment Prevention](https://medium.com/@truvis.thornton/visual-studio-code-embedded-reverse-shell-and-how-to-block-create-sentinel-detection-and-add-e864ebafaf6d) of this activity, I suggest you to read it too!

![4c1046d31803e93c7994af21684eda5c.png](..//resources/4c1046d31803e93c7994af21684eda5c.png)
https://blueteamlabs.online/achievement/share/52929/239
* * *