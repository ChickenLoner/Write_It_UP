# [LetsDefend - DLL Stealer](https://app.letsdefend.io/challenge/dll-stealer)
Created: 30/04/2024 15:55
Last Updated: 30/04/2024 18:07
* * *
<div align=center>

**DLL Stealer**
![8d4697cf1e3489329768556cb577c163.png](../../_resources/8d4697cf1e3489329768556cb577c163.png)
</div>
You work as a cybersecurity analyst for a major corporation. Recently, your company's security team detected some suspicious activity on the network. It appears that a new DLL Stealer malware has infiltrated your system, and it's causing concern due to its ability to exfiltrate critical DLL files from your system.

**File Location**: C:\Users\LetsDefend\Desktop\ChallengeFile\sample.zip

**File Password**: infected

* * *
## Start Investigation
> What is the DLL that has the stealer code?

![64f3f4d891beff7410884558ebb102f2.png](../../_resources/64f3f4d891beff7410884558ebb102f2.png)
We got a file without an extension to work with so I used Detect It Easy to find out more about this file and results show that this file is Portable Executable for x64 system which was complied by Microsoft Visual Studio
![dd2853d7e2ddb996b709b3cf10b17afd.png](../../_resources/dd2853d7e2ddb996b709b3cf10b17afd.png)
An executabile file which compiled by Visual Studio couldn't be decompile using Ghidra or IDA Free but we still have dotPeek which is a perfect tool for this file, you can see that there are 2 dll files were bundled with this PE.
![c9642dbf38daedee87e3f81f57a26887.png](../../_resources/c9642dbf38daedee87e3f81f57a26887.png)
`Test-Anitnazim.dll` holds `main` function which call Colorful that held in `Colorful.dll`
![a03ff16a17f4d254f80364fa7c6071c3.png](../../_resources/a03ff16a17f4d254f80364fa7c6071c3.png)
You can see that this dll is very suspicious due to `IsVirusTotal` function inside of it
![a6141d32d9ab504e159310899fae3ca9.png](../../_resources/a6141d32d9ab504e159310899fae3ca9.png)
It does check for VirusTotal by comparing infected hostname to `usernameList` which is a list that stores VirusTotal's hostnames.
![8c748742febad106a3b2238789f235ad.png](../../_resources/8c748742febad106a3b2238789f235ad.png)
Then this PE will check and mass create directories. 
![13ded9f9f2d228fc31b8230c0e8a877c.png](../../_resources/13ded9f9f2d228fc31b8230c0e8a877c.png)
Which will be used to store data that will be copied to, which mean this PE is an infostealer malware.
```
Colorful.dll
```

> What is the anti-analysis method used by the malware?

![a6141d32d9ab504e159310899fae3ca9.png](../../_resources/a6141d32d9ab504e159310899fae3ca9.png)
```
IsVirusTotal
```

> What is the full command used to gather information from the system into the “productkey.txt” file?

![16a91533a29a4d12dd7514351f7fa044.png](../../_resources/16a91533a29a4d12dd7514351f7fa044.png)
You can find for specific string which is productkey then I found this snippet, this malware used wmic to query for product key then save to a text file
```
wmic path softwareLicensingService get OA3xOriginalProductKey >> productkey.txt
```

> What is the full command used to gather information through the "ips.txt" file?

![064eda1de2ce6efab0f73d4fab3610a1.png](../../_resources/064eda1de2ce6efab0f73d4fab3610a1.png)
Malware used `ipconfig/all` to display all IP configuration of infected system then save to text file
```
ipconfig/all >> ips.txt
```

> What is the webhook used by the malware?

![a2209fc6980eace293d946fe646f7641.png](../../_resources/a2209fc6980eace293d946fe646f7641.png)
An infostealer malware need to send information that was gathered to C2 server which can commonly be found on bottom part of the code by using compression to make it more transferable so I scrolled at the bottom then I saw `curl` then which confirmed that this malware compressed all information to zip file then using curl to send it somewhere
![dd0a205fae400b159f4cfd5270368080.png](../../_resources/dd0a205fae400b159f4cfd5270368080.png)
and that is a discord webhook
```
https://discord.com/api/webhooks/1165744386949271723/kFr6Cc0DSTK1jB8aV3820mBxji06gF2KorUuO2Rd2ckLkhUEHxdi6kv6UHwgJ_W82fgZ
```

* * *
## Summary

On this challenge we got a PE64 file complied by Visual Studio to investigate which could only be decompiled using JetBrains dotPeek or .NET decomplier and after analyzed decompiled code, It is confirmed that this PE64 file is an infostealer malware that using VirusTotal's hostnames to evade debugging.

What we're learned
- How to analyze a file compiled by Visual Studio
- Anti-Debugger method specific for VirusTotal
- How an infostealer malware collect sensitive information on infected host
- A way to send sensitive information back to a webhook or C2

<div align=center>

![87072fa7b9a85dfe70c84ed8c4398993.png](../../_resources/87072fa7b9a85dfe70c84ed8c4398993.png)
</div>

* * *
