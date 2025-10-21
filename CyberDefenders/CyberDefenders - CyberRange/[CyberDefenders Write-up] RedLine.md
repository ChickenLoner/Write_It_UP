# [CyberDefenders - RedLine](https://cyberdefenders.org/blueteam-ctf-challenges/redline/) 
Created: 05/03/2024 14:43
Last Updated: 05/03/2024 16:13
* * *
>Category: Endpoint Forensics
>Tags: Redline, Volatility, NIDS, Network Intrusion Detection System, T1055
* * *
**Scenario**:
As a member of the Security Blue team, your assignment is to analyze a memory dump using Redline and Volatility tools. Your goal is to trace the steps taken by the attacker on the compromised machine and determine how they managed to bypass the Network Intrusion Detection System "NIDS". Your investigation will involve identifying the specific malware family employed in the attack, along with its characteristics. Additionally, your task is to identify and mitigate any traces or footprints left by the attacker.

**Tools**:
- [Volatility](https://www.volatilityfoundation.org/26)
* * *
## Questions
> Q1: What is the name of the suspicious process?

I started using volalitity3 with `windows.pslist` plugin but I was overwhelmed with too many processes, So I used `windows.malfind` plugin to narrow things down for me
![69007183e2941be29539e336a024b810.png](../../_resources/69007183e2941be29539e336a024b810.png)
Which lead me to these 2 suspicious processes but there is only 1 process that is the answer of this question so I came back to `windows.pslist` plugin and then save the output to text file to find relationship between processes of these 2 processes (if you're working on Linux, use `grep`)

I started with `smartscreen.exe`
![470160378fe763e48a5f1c2a94aac01d.png](../../_resources/470160378fe763e48a5f1c2a94aac01d.png)
This process shared parent process with multiple processes
![5f23472ce0164d1a680ad16896e8aa06.png](../../_resources/5f23472ce0164d1a680ad16896e8aa06.png)
And its parent process is `svchost.exe`

Then I did some research about this research and found that this process is legitimate Windows software called [Windows SmartScreen](https://www.file.net/process/smartscreen.exe.html) a cloud based antimalware and anti-phishing software
So Its understandable that malfind found this suspicious and now we got `oneetx.exe` that is one and only suspicious process here.

```
oneetx.exe
```

> Q2: What is the child process name of the suspicious process?

Since 5896 is the process ID of `oneetx.exe` then I searched this process ID on my text file and found that `rundll32.exe` is a child process of this suspicious process
![b1cad70090e6f6e5e378b2a74ffe5cdd.png](../../_resources/b1cad70090e6f6e5e378b2a74ffe5cdd.png)
It also means that this suspicious process has dynamic link library (dll) file that came with it so it spawn `rundll32.exe` to execute that dll file.

![22342311d882ded73afac83ae6aea2ef.png](../../_resources/22342311d882ded73afac83ae6aea2ef.png)
And if you used `windows.pstree` plugin, We can also see that the suspicious process was executed from Temp folder
```
rundll32.exe
```

> Q3: What is the memory protection applied to the suspicious process memory region?

Back to `windows.malfind` plugin
![06593d476ee41aa56d1a1eb7fffaf603.png](../../_resources/06593d476ee41aa56d1a1eb7fffaf603.png)
We can see that this process has everything it needed, memory region should be both readable and writable, allowing it to be used for storing executable code and data.
```
PAGE_EXECUTE_READWRITE
```

> Q4: What is the name of the process responsible for the VPN connection?

I used `windows.netscan` plugin to find that which process made a connection to the internet (external)
![ab482f1201817762771af58b9120ca32.png](../../_resources/ab482f1201817762771af58b9120ca32.png)
These processes showed up, Then `tun2socks.exe` look like the VPN process the most so I did some research on this and I was right! [tun2socks](https://www.file.net/process/tun2socks.exe.html) is the one, I was looking for
![68e1bc335fc4de89f6977b7a4d9aea30.png](../../_resources/68e1bc335fc4de89f6977b7a4d9aea30.png) but when I submitted, Its not this process 

So I went back to `pstree` to find the parent process
![58e2572fab66f7ff77d0a3d28109e933.png](../../_resources/58e2572fab66f7ff77d0a3d28109e933.png)
Which is `Outline.exe`, and this process has `explorer.exe` as a parent process so It might got executed by user from Windows Explorer

```
Outline.exe
```

> Q5: What is the attacker's IP address?

From `windows.netscan` plugin I used eariler, and I knew which process is suspicious so I searched by using process name and found it
![4809ff9a1381d569a476e0ac488ff64b.png](../../_resources/4809ff9a1381d569a476e0ac488ff64b.png)
```
77.91.124.20
```

> Q6: Based on the previous artifacts. What is the name of the malware family?

I used `windows.dumpfiles.DumpFiles` plugin to extract process into an executable file first
![c1021815e8e2fb765d78e79fc17bf00f.png](../../_resources/c1021815e8e2fb765d78e79fc17bf00f.png)
Then I renamed it, and generated file hash to search on VirusTotal
![90b7bf0dc99c0ede946fb20619d38213.png](../../_resources/90b7bf0dc99c0ede946fb20619d38213.png)
![f56f1bc121345d149da559197da4a88b.png](../../_resources/f56f1bc121345d149da559197da4a88b.png)
[VirusTotal](https://www.virustotal.com/gui/file/8d5d5bbdccb82a10ac28e2779ba0821f12da3e1f08f03ec467ce213a6fccf38c) told me its a Mars Stealer but I also got IP address to search then
![fce3f49eed3ecbc600e68201a7438fdc.png](../../_resources/fce3f49eed3ecbc600e68201a7438fdc.png)
This IP address was used by RedLine so Its RedLine Stealer
```
RedLine Stealer
```

> Q7: What is the full URL of the PHP file that the attacker visited?

I didn't know which plugin to use but since I already got the IP address so I used strings and filter out all the rest and looking for the attacker IP address
![27993fd733a0f8952e4f901c66b56426.png](../../_resources/27993fd733a0f8952e4f901c66b56426.png)
And found it
```
http://77.91.124.20/store/games/index.php
```

> Q8: What is the full path of the malicious executable?

I already got the answer from `pstree` plugin
![145425270b125a7d2eb87fd8a8c3a5d8.png](../../_resources/145425270b125a7d2eb87fd8a8c3a5d8.png)
```
C:\Users\Tammam\AppData\Local\Temp\c3912af058\oneetx.exe
```

![9a7fe2d9b4ba2d2085563e8efb665ff2.png](../../_resources/9a7fe2d9b4ba2d2085563e8efb665ff2.png)
* * *