# [CyberDefenders - BlackEnergy](https://cyberdefenders.org/blueteam-ctf-challenges/blackenergy/)
Created: 24/05/2024 17:48
Last Updated: 12/06/2024 07:40
* * *
>Category: Endpoint Forensics
>Tags: Memory Forensic, Volatility, T1093.004, T1055.001
* * *
**Scenario**:
A multinational corporation has been hit by a cyber attack that has led to the theft of sensitive data. The attack was carried out using a variant of the BlackEnergy v2 malware that has never been seen before. The company's security team has acquired a memory dump of the infected machine, and they want you, as a soc analyst, to analyze the dump to understand the attack scope and impact.
* * *
## Questions
> Q1: Which volatility profile would be best for this machine?

By using volatility 2 imageinfo plugin `vol.py -f CYBERDEF-567078-20230213-171333.raw imageinfo`, it will suggest that 2 profiles but the one we will use will be "WinXPSP2x86"
```
WinXPSP2x86
```

> Q2: How many processes were running when the image was acquired?

![80318a1e2063833eae819a32d87aa2c1.png](../../_resources/80318a1e2063833eae819a32d87aa2c1.png)
by running `vol3 -f CYBERDEF-567078-20230213-171333.raw psscan`, we can see that there are 25 processes and 6 processes were already exited which leave us with 19 processes that still running
```
19
```

> Q3: What is the process ID of cmd.exe?

![9a0bbdeda7bdb5ab86ae247230859a7b.png](../../_resources/9a0bbdeda7bdb5ab86ae247230859a7b.png)
```
1960
```

> Q4: What is the name of the most suspicious process?

![2005827e9e3a75067fe6bdddaefb0e23.png](../../_resources/2005827e9e3a75067fe6bdddaefb0e23.png)
Well.. Its self-explanatory here
```
rootkit.exe
```

> Q5: Which process shows the highest likelihood of code injection?

![f104bc256c49797733b92a7176b328c7.png](../../_resources/f104bc256c49797733b92a7176b328c7.png)
malfind plugin will help us find that process so I used `vol3 -f CYBERDEF-567078-20230213-171333.raw windows.malfind` then after scanning is completed, there are a lot of winlogon.exe found and this svchost.exe that caught my eyes has "MZ.." in it so I'll look into this process first

![e77badc225f9d5e5c97e1f0d6235dd3b.png](../../_resources/e77badc225f9d5e5c97e1f0d6235dd3b.png)
Lets dump it using with `vol3 -f CYBERDEF-567078-20230213-171333.raw -o /tmp/outfile windows.malfind --pid=880 --dump` then use md5sum to calculate file hash then search it on VirusTotal
![c2fe170e054e5c80c9145167b404f0e7.png](../../_resources/c2fe170e054e5c80c9145167b404f0e7.png)
As expected this process is indeed malicious

![47151de00c311555450936dbd18558d9.png](../../_resources/47151de00c311555450936dbd18558d9.png)
And if its really BlackEnergy malware then it made sense why it has to be this process
```
svchost.exe
```

> Q6: There is an odd file referenced in the recent process. Provide the full path of that file.

![406b646ca8374749e44fdd173b69e3ee.png](../../_resources/406b646ca8374749e44fdd173b69e3ee.png)
I used `strings /tmp/outfile/pid.880.vad.0x980000-0x988fff.dmp` to find any path hidden in this files and there is one
![7a146ab98b291ed3be598cdecde856cf.png](../../_resources/7a146ab98b291ed3be598cdecde856cf.png)
Probably for persistence
```
C:\WINDOWS\system32\drivers\str.sys
```

> Q7: What is the name of the injected dll file loaded from the recent process?

For a plugin that detected dll injection, I would recommend you to read this [blog](https://imphash.medium.com/windows-process-internals-a-few-concepts-to-know-before-jumping-on-memory-forensics-part-2-4f45022fb1f8) which is very helpful and informative for this question

![31cf201fd9ebd404ac4a1d62f99474b1.png](../../_resources/31cf201fd9ebd404ac4a1d62f99474b1.png)
So lets do this `vol3 -f CYBERDEF-567078-20230213-171333.raw windows.ldrmodules --pid=880` then we will find the only one dll that does not mapped for all 3 
```
msxml3r.dll
```

> Q8: What is the base address of the injected dll?

![c2783f5d1bd669f7e97f007f563c49ac.png](../../_resources/c2783f5d1bd669f7e97f007f563c49ac.png)
We can get this by using malfind and the base address could be found here
```
0x980000
```


You can read more about this malware [here](https://attack.mitre.org/software/S0089/)

![5132c0d47bd7dee4a9328c3fe2202e90.png](../../_resources/5132c0d47bd7dee4a9328c3fe2202e90.png)
* * *
