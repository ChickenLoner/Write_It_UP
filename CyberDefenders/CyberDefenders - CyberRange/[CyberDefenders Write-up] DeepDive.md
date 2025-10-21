# [CyberDefenders - DeepDive](https://cyberdefenders.org/blueteam-ctf-challenges/deepdive/)
Created: 11/06/2024 22:07
Last Updated: 12/06/2024 22:15
* * *
>Category: Endpoint Forensics
>Tags: Memory Forensic, Process Injection, Volatility, T1059, T1204, T1564.001, T1055
* * *
**Scenario**
You have given a memory image for a compromised machine. As a security blue team analyst Analyze the image and figure out attack details.

**Tools**
- [Volatility 2](https://github.com/volatilityfoundation/volatility)

**Resources**
- https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ob/inc/header/infomask.htm
 
* * *
## Questions
> Q1: What profile should you use for this memory sample?

First I'll use `vol.py -f banking-malware.vmem kdbgscan`  to identifying kernel structures which make imageinfo plugin a lot easier to determine which profile to use 

Because when running imageinfo plugin, it will also used result from kdbgscan to determine the most suitable profile for us

![07f9f7b7d8e03402e0b4e98aa6fd0317.png](../../_resources/07f9f7b7d8e03402e0b4e98aa6fd0317.png)

And the result shows sevaral profiles, normally first profile should be the one that I will be used but not on this lab so apparently we need to figure it out which one of this is the most suitable one

![3978f45b3add4872be5e5dfe671116c3.png](../../_resources/3978f45b3add4872be5e5dfe671116c3.png)

I used volatility 3 to help me scan for Windows information, you can see that it found build of this OS that is 24214 but we didn't have this exact profile from previous scan so the most suitable one should be 24000 build profile which is the closest build to 24214

```
Win7SP1x64_24000
```

> Q2: What is the KDBG virtual address of the memory sample?

![d8950594953fa5d9c981829e797d20c3.png](../../_resources/d8950594953fa5d9c981829e797d20c3.png)

We can find this from result of imageinfo plugin

```
0xf80002bef120
```

> Q3: There is a malicious process running, but it's hidden. What's its name?

![2dcc967723c86f401708325a1e44a523.png](../../_resources/2dcc967723c86f401708325a1e44a523.png)

To find hidden process, it mean it was hidden from pslist and psscan so we need to use `vol.py -f banking-malware.vmem --profile=Win7SP1x64_24000 psxview` to find it which you can see that only 1 process that couldn't be find with both plugins

```
vds_ps.exe
```

> Q4: What is the physical offset of the malicious process?
```
0x000000007d336950
```

> Q5: What is the full path (including executable name) of the hidden executable?

![361b3d9089d33261e50162d2b484af81.png](../../_resources/361b3d9089d33261e50162d2b484af81.png)

We can use filescan or `vol.py -f banking-malware.vmem --profile=Win7SP1x64_24000 cmdline --offset=0x000000007d336950` for this question

```
C:\Users\john\AppData\Local\api-ms-win-service-management-l2-1-0\vds_ps.exe
```

> Q6: Which malware is this?

![8925a64a821735f20a324a3c7fd1f825.png](../../_resources/8925a64a821735f20a324a3c7fd1f825.png)

Seem like using filescan (`vol.py -f banking-malware.vmem --profile=Win7SP1x64_24000 filescan | grep "vds_ps.exe"`) on previous question would be the best choice so we can use offset to dump this file rightaway

![728fade3920bff63b245b3fef48d7fc8.png](../../_resources/728fade3920bff63b245b3fef48d7fc8.png)

After got an offset of this file, use `vol.py -f banking-malware.vmem --profile=Win7SP1x64_24000 dumpfiles -Q 0x000000007d0035d0 -D /tmp/deepdive/` to dump it then we can see that we got 2 files from dumpfiles plugin but the one that will be flagged as malicious by VirusTotal is the `.img` file
 
![e62758e1ff67bf0cb2ba8546fa07090f.png](../../_resources/e62758e1ff67bf0cb2ba8546fa07090f.png)

it is EMOTET

```
Emotet
```

> Q7: The malicious process had two PEs injected into its memory. What's the size in bytes of the Vad that contains the largest injected PE? Answer in hex, like: 0xABC

![0b84bf0659870b91ae60c9adf67c6d29.png](../../_resources/0b84bf0659870b91ae60c9adf67c6d29.png)

First we need to use `vol.py -f banking-malware.vmem --profile=Win7SP1x64_24000 malfind --offset=0x000000007d336950` to find all PE that were injected by this process, results return with 3 different memory address but only 2 have the sign of injection that is 4d5a (MZ) - the magic number of an executable file (exe)

![7a8da67a38ca7c1ff30c99e55cb69dc7.png](../../_resources/7a8da67a38ca7c1ff30c99e55cb69dc7.png)

Copy both address that use vadinfo given offset of emotet process and address of injected PE to get the end of each injected PE in memory

- `vol.py -f banking-malware.vmem --profile=Win7SP1x64_24000 vadinfo --offset=0x000000007d336950 -a 0x2a10000`

- `vol.py -f banking-malware.vmem --profile=Win7SP1x64_24000 vadinfo --offset=0x000000007d336950 -a 0x2a80000`

![3ac4606981027b11dcc1749d5719b98e.png](../../_resources/3ac4606981027b11dcc1749d5719b98e.png)
![74f7a06403f4f5dd7b39335e75f39613.png](../../_resources/74f7a06403f4f5dd7b39335e75f39613.png)

After got start and end address of both then we can use calculator to calculate which one is the largest 

```
0x36fff
```

> Q8: This process was unlinked from the ActiveProcessLinks list. Follow its forward link. Which process does it lead to? Answer with its name and extension

**Understanding ActiveProcessLinks**
`ActiveProcessLinks` is a doubly linked list used by the Windows operating system to keep track of all active processes. Each process has a structure known as the `EPROCESS` (Executive Process), which contains various fields, including `ActiveProcessLinks`. This field is used to link each process to the next and previous process in the list, forming a circular list of all active processes. 

To put it simply, we just need to find process ID next to emotet process ID

![091a1dbaf046168e8bbb3d09b907dd04.png](../../_resources/091a1dbaf046168e8bbb3d09b907dd04.png)

This process has the next closest process ID to emotet process ID which should be this one 

```
SearchIndexer.exe
```

> Q9: What is the pooltag of the malicious process in ascii? (HINT: use volshell)

a pool tag is a four-character identifier that is associated with a memory allocation in the system's kernel memory pools. Each kernel-mode memory allocation (from the paged or non-paged pool) is tagged with a pool tag

Which we need to use `vol.py -f banking-malware.vmem --profile=Win7SP1x64_24000 volshell` to interactively interact with this memory dump like WinDbg

![be4bdee4efe19788bb38f67701f689d9.png](../../_resources/be4bdee4efe19788bb38f67701f689d9.png)

Next I used `dt( "_POOL_HEADER" ,0x000000007d336950, space=addrspace().base)` to display `POOL_HEADER` of this emotet process based on its offset but as you can see that PoolTag of this offset is 0 which mean we didn't give the right offset 

To be honest, This question is way too ahead of my leauge so I had some write-up to fully understand this but thats the point of all challenges right? its all about learning new things!

![072e32e60999157f826b86fbb65a0cfb.png](../../_resources/072e32e60999157f826b86fbb65a0cfb.png)

Here is the paged pool allocation diagram I found on this [write-up](https://medium.com/@sky__/memory-udom-x-m455-ctf-2023-writeup-a97e573f583d), what we want is PoolTag inside `_POOL_HEADER` and physical offset we got from psxview is `EPROCESS` object inside `Object Body` on this diagram

So we need to subtract by 0x30 to reach `_OBJECT_HEADER` Then lets use `dt("_OBJECT_HEADER", 0x000000007d336950-0x30, space=addrspace().base)` to identify where we're right now

![679bdc1cc3c991e4ad0c64eef0f0a618.png](../../_resources/679bdc1cc3c991e4ad0c64eef0f0a618.png)

we know for sure that it should be optional headers after `_OBJECT_HEADER`,  but doesn't mean all 5 optional headers should be presented at the same time  but rather one that used for the purpose of this allocation so to find an answer we should take a look at InfoMask which is represented used optional header

![6cdac73145fc25978f571822a504bd43.png](../../_resources/6cdac73145fc25978f571822a504bd43.png)

According from the table, its `_OBJECT_HEADER_QUOTA_INFO` which has a size of 32 bytes translated to 0x20

![5e647ccfa68f095abd8b74d04d061b64.png](../../_resources/5e647ccfa68f095abd8b74d04d061b64.png)

But its not there yet to find an actual PoolTag, we need to subtract with 0x10 to account for alignment or other kernel-level metadata that ensures the structures are correctly aligned in memory to be able to pinpoint at `POOL_HEADER` correctly

![8bee29bcf0ea07840f92b28405e9eb6d.png](../../_resources/8bee29bcf0ea07840f92b28405e9eb6d.png)

At the end we will have `dt("_POOL_HEADER", 0x000000007d336950-0x60, space=addrspace().base)` to print out pooltag in demical for us

![183d95b3d71a5e8e5088272ea0875d2b.png](../../_resources/183d95b3d71a5e8e5088272ea0875d2b.png)

Convert to HEX

![6c0783fb4c082785c9d30435aa084f87.png](../../_resources/6c0783fb4c082785c9d30435aa084f87.png)

Then convert HEX to ASCII but its not the final form yet, we still need to reverse it because of the endian

```
R0oT
```

> Q10: What is the physical address of the hidden executable's pooltag? (HINT: use volshell)

![b1f8ef6abc5c797672bcd30c9b4ee8a9.png](../../_resources/b1f8ef6abc5c797672bcd30c9b4ee8a9.png)

We need to add 4 bytes to this address because The PoolTag is an unsigned long (4 bytes) starting at offset 0x4 within the `_POOL_HEADER` structure. To access the PoolTag directly, we calculate its address by adding the offset where PoolTag is stored (0x4) to the base address of the` _POOL_HEADER`

```
0x7D3368F4
```

![1adb9f6550b7a035ee8d8a730e2f4e7b.png](../../_resources/1adb9f6550b7a035ee8d8a730e2f4e7b.png)
* * *
