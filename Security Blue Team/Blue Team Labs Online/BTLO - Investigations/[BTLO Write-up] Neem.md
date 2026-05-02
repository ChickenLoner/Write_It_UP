# [Blue Team Labs Online - Neem](https://blueteamlabs.online/home/investigation/neem-cf357e6d39)
<div align=center>

![f7430cc5b2a0395667b085bb993b7f86.png](/resources/f7430cc5b2a0395667b085bb993b7f86.png)
</div>
A user reported to the security team that his machine had been behaving abnormally since he tried to download a cracked software version.

>**Reverse Engineering**

>**Tags**: HashCalc PowerShell PeStudio Detect It Easy API Monitor
* * *
**Scenario**
A user reported to the security team that his machine had been behaving abnormally since he tried to download a cracked software version. He mentioned “he downloaded a file which requests to double click so that it will create a free version of software on Desktop which inturn deleted itself when tried to execute”

Malware samples were collected for further analysis.

Tip: Malicious executable will be deleted after execution. Please keep a copy before execution if required
* * *
## Environment Awareness
### Evidence Discovery
![fdb037d8f125e3ebad9badb6cc2a07f4.png](/resources/fdb037d8f125e3ebad9badb6cc2a07f4.png)

We have 2 files inside `Sample` folder located on the Desktop, first is LNK file and second is PE32 executable file.
***
### Tool Discovery and Preparation
![d885ff4193ff1d0a6dd0235618d1ad0f.png](/resources/d885ff4193ff1d0a6dd0235618d1ad0f.png)

Beside CyberChef that always present on every investigation machine, we have 4 more tools that will assist in our investigation which are
- Detect It Easy (DIE) can be used to conduct static analysis of any file.
- pestudio can be used to conduct static analysis PE32 executable file on Windows
- HashCalc can be used to calculate several kind of hash of a file
- API Monitor can be used to monitor API called by processes

***
## Investigation
>Q1) Submit md5 hashes of “lnk file” and the malicious free software executable. (Hint: Verify via Powershell too) (Format: MD5, MD5)

![180fd48f7b97a69d69396fe95be80e10.png](/resources/180fd48f7b97a69d69396fe95be80e10.png)

We can use HashCalc for this but Lets just do it with PowerShell so we will familiarize ourselves with command that can be used to calculate various of hash on PowerShell. 

<details>
  <summary>Answer</summary>
<pre><code>99FDD2A7222BD31031758725D0D8BC23, EE679366389D2ECD5D9A56720B36C95A</code></pre>
</details>

>Q2) Name of the system utility used to download the malicious executable (Format: filename.exe)

![627e6ad58e2765212dbfb0cfa59b580f.png](/resources/627e6ad58e2765212dbfb0cfa59b580f.png)

Now lets take a closer look at LNK file, we could extract command that will be executed by right-click -> "Properties" then copy whatever is in "Target" box to somewhere that easier to read.

![c7cad91447fc17c04c0572a21ea5540e.png](/resources/c7cad91447fc17c04c0572a21ea5540e.png)
Then we can see that when this file is opened then certutil will be utilized to download malicious exe file to user desktop.

<details>
  <summary>Answer</summary>
<pre><code>certutil.exe</code></pre>
</details>

>Q3) Submit the full URL of the payload server. Use CyberChef Defang URL recipe (Format: hxxp[://]domain[.]tld/file)

![1141c886fcd0ae8291ce7a1616d06b47.png](/resources/1141c886fcd0ae8291ce7a1616d06b47.png)
Lets defang this URL using "Defang URL" in CyberChef
<details>
  <summary>Answer</summary>
<pre><code>hxxp[://]eastzonentp[.]com/Photoshop-Free-Cracked-Version[.]exe</code></pre>
</details>

>Q4) What is the Compiler and Language used for the malicious binary creation? (Format: Compiler, Language)

![8dcb0a19938fab8421ed81dea0a59ba9.png](/resources/8dcb0a19938fab8421ed81dea0a59ba9.png)
Use Detect It Easy to scan this malicious exe file then we could see that this file was written and compile by [Nim](https://www.youtube.com/watch?v=WHyOHQ_GkNo) which is general purpose scripting language that could deliver high performance with simplicity, cross-compilation capabilities and ease of access to the Windows API so it also becomes popular in ethical hacking community (of course non-ethical hacking community too) 
<details>
  <summary>Answer</summary>
<pre><code>Nim, Nim</code></pre>
</details>

>Q5) Submit the import function responsible for Mitre technique Sandbox Evasion (Format: function)

![e863d5d8f48e1a3ef869a820f40bb846.png](/resources/e863d5d8f48e1a3ef869a820f40bb846.png)
PEStudio has a feature to map MITRE technique to function/string that likely to use for that technique so if we open malicious exe file into PEStudio and sort by "technique" then we should be able to see the only function that was mapped as Sandbox Evasion by PEStudio.
<details>
  <summary>Answer</summary>
<pre><code>sleep</code></pre>
</details>

>Q6) Submit the User-Agent used for network communications (Format: User-Agent String)

![0a471990cbd9847dee0ee63864fc5d5e.png](/resources/0a471990cbd9847dee0ee63864fc5d5e.png)
Since there is no decompiler and there are so much strings extracted in PEStudio then its time for Dynamic Analysis with API Monitor which we can see that after we monitoring this process, it will contact C2 on HTTP default port (Q7) with WinHTTPConnect API and the request will have this weird user-agent probably to identify itself to C2 server.
<details>
  <summary>Answer</summary>
<pre><code>Best C2 Client</code></pre>
</details>

>Q7) Submit the C2’s IP and Port (Format: X.X.X.X:port)

![574d9eabc68c330a333f74c844605760.png](/resources/574d9eabc68c330a333f74c844605760.png)
Default HTTP port is 80 so its not that hard to guess
<details>
  <summary>Answer</summary>
<pre><code>5.188.118.181:80</code></pre>
</details>

![ac6479767387ef870f796f1a80ae5eea.png](/resources/ac6479767387ef870f796f1a80ae5eea.png)
https://blueteamlabs.online/achievement/share/52929/201
* * *
## Summary
Upon opening a shortcut file, certutil will be utilized to download malicious PE32 executable file from C2 server then executed to connect to another C2 server using HTTP protocol but it won't run in any environment since it imports some function that could check for a sandbox and prevent itself from the execution.

### IOCs
- `99FDD2A7222BD31031758725D0D8BC23`
- `EE679366389D2ECD5D9A56720B36C95A`
- `hxxp[://]eastzonentp[.]com/Photoshop-Free-Cracked-Version[.]exe`
- `5[.]188[.]118[.]181`
- `Best C2 Client` (User-agent)

* * *