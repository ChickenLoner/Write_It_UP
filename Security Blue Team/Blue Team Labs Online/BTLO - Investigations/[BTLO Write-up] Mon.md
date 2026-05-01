# [Blue Team Labs Online - Mon](https://blueteamlabs.online/home/investigation/mon-07cae5a947)

![7c0e466036a22c0aa1687caa3bfc77f2.png](/resources/7c0e466036a22c0aa1687caa3bfc77f2.png)

As a SOC Analyst you need to deal with a lot of logs. Your Senior assigned you the task of creating a new detection rule for a malware he created.

>**Incident Response**

>**Tags**: Sysmon Notepad++ T1071.001 T1053.005
* * *
**Scenario**
As a SOC Analyst you need to deal with a lot of logs. Your Senior assigned you the task of creating a new detection rule for a malware he created.

He provided you with the malware sample and a config file to setup, experiment, and extract the relevant logs to create a detection rule.

Good Luck!
* * *
## Environment Awareness
### Evidence & Tool Discovery
![2cc2518178e7740a469656538e5c94da.png](/resources/2cc2518178e7740a469656538e5c94da.png)

We have a PE32 executable sample of a malware within `sample` folder located on the desktop and we have sysmon and CyberChef available on this machine which mean we will have to install sysmon and detonate malware to find out what happened after.

***
### Tool Preparation
![7795fb339bb53314da8b8fc521f39563.png](/resources/7795fb339bb53314da8b8fc521f39563.png)

To install sysmon, we can use `Sysmon.exe -accepteula -i config.xml` that will install a sysmon including its driver with configuration from `config.xml` and the reason why I used `-accepteula` because all tools from SysInternals could not be used if we did not accept EULA, we can install this without this flag which a new pop up will prompt you to accept EULA anyway.

Now Sysmon is installed, no need to restart and we can open Event Viewer then go to "Applications and Services" -> "Microsoft" -> "Windows" -> "Sysmon"

***
## Investigation
>Q1) After initial execution, what is the Parent Process Name observed for the provided sample? (Format: ParentProcessName.ext)

![85ea80d85c3166249cc700b9e1eb917a.png](/resources/85ea80d85c3166249cc700b9e1eb917a.png)

After renaming a file extension to exe then executed it, we can see that this process was created as a child process of `explorer.exe` which is normal for user execution so if we find any suspicious process as a child process of `explorer.exe`, then it could mean the user executed that file or `explorer.exe` was injected by malicious process.

<details>
  <summary>Answer</summary>
<pre><code>Explorer.EXE</code></pre>
</details>

>Q2) What is the domain used for command-and-control by the malware sample? (Format: domain.tld)

![48e2c4f1445cf9687a8516fe5087c065.png](/resources/48e2c4f1445cf9687a8516fe5087c065.png)

After malware was executed, we can see that there is a new file created in `C:\Windows\System32\chickid`

![6c8f0a382cdae1299ad79b49b142eba7.png](/resources/6c8f0a382cdae1299ad79b49b142eba7.png)

Then a schedule task was created to maintain persistence which will start the executable file that was just created every logon event by any user (Q5-6)

![ae04f1b01504193b55482b12bc75b6c2.png](/resources/ae04f1b01504193b55482b12bc75b6c2.png)

Then that executable was executed.

![a096c41c4909df4fb3d861d8bce047aa.png](/resources/a096c41c4909df4fb3d861d8bce047aa.png)

a suspicious bat file was also created on user's temp folder and executed via `cmd.exe` 

![63384e6f568d18f03f0dd57540f35973.png](/resources/63384e6f568d18f03f0dd57540f35973.png)

Then we will see what we are looking for on EventID 22 - DNSEvent (Q3) which was contacted by the executable file that dropped on `C:\Windows\System32\chickid`

<details>
  <summary>Answer</summary>
<pre><code>chichtopluhyk.com</code></pre>
</details>

>Q3) What is the number of the Sysmon Event ID that helped to find the C2 domain? (Format: SysmonEventID)
<details>
  <summary>Answer</summary>
<pre><code>22</code></pre>
</details>

>Q4) What is the location where a .bat files is created? (Format: C:\Path\To\Folder\)

![a096c41c4909df4fb3d861d8bce047aa.png](/resources/a096c41c4909df4fb3d861d8bce047aa.png)
<details>
  <summary>Answer</summary>
<pre><code>C:\Users\BTLOTest\AppData\Local\Temp\</code></pre>
</details>

>Q5) What is the name of the scheduled task created by the malware? (Format: ScheduledTaskName)

![6c8f0a382cdae1299ad79b49b142eba7.png](/resources/6c8f0a382cdae1299ad79b49b142eba7.png)
<details>
  <summary>Answer</summary>
<pre><code>CTFMonitor_SecureStartUp</code></pre>
</details>

>Q6) What is the location chosen by the sample to maintain persistence? (Format: C:\Path\To\Persistence.ext)

![c3760bdec3d8845de1eba3ce49710734.png](/resources/c3760bdec3d8845de1eba3ce49710734.png)
<details>
  <summary>Answer</summary>
<pre><code>C:\Windows\system32\chickid\ctfkabab.exe</code></pre>
</details>

>Q7) Find and submit the File Version and File Description of the malware (Format: FileVersion, Description)

![8a4cf722c1cc49e4374e6a3fbf5c8f10.png](/resources/8a4cf722c1cc49e4374e6a3fbf5c8f10.png)

To find out about this, we can take a look at EventID 1 of `ctfkabab.exe` which we can see both file version and file description including original filename and company (Q8) of this executable from this event as well

<details>
  <summary>Answer</summary>
<pre><code>1.2.3.4,  Monitor for CTF Events</code></pre>
</details>

>Q8) Find and submit theOriginalFileName and Company properties of the sample (Format: OriginalFileName, Company) 

![67a04f3981449146559681678aaa7dbf.png](/resources/67a04f3981449146559681678aaa7dbf.png)
<details>
  <summary>Answer</summary>
<pre><code>CTFMon1.0, CTFer</code></pre>
</details>

>Q9) Find and submit the Copyright property set by the malware author for the provided sample (Format: Copyright Text) 

![110b5cf8092e91db8bd190ccd6c16765.png](/resources/110b5cf8092e91db8bd190ccd6c16765.png)

To find this, I opened an executable file on CyberChef to find any string close to the string "Copyright" which we can see that this method worked out well since PE executable might also stores this information while its being compiled.

<details>
  <summary>Answer</summary>
<pre><code>CTF Gangs</code></pre>
</details>

>Q10) When running the created bat file, what string is echoed to the console? (Format: string)

![0388feffe355c547e140e95a0e959683.png](/resources/0388feffe355c547e140e95a0e959683.png)

Go to User temp folder to find bat script then we can see that it will echo "DONT CLOSE THIS WINDOWS!" before execute `ctfkabab.exe` and delete itself from this system.

<details>
  <summary>Answer</summary>
<pre><code>DONT CLOSE THIS WINDOW!</code></pre>
</details>

![cf1d1089cae987bcb108f4ba2c40b0ec.png](/resources/cf1d1089cae987bcb108f4ba2c40b0ec.png)
https://blueteamlabs.online/achievement/share/52929/91
* * *