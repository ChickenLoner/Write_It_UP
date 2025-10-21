# [CyberDefenders - NintendoHunt](https://cyberdefenders.org/blueteam-ctf-challenges/nintendohunt/)
Created: 15/06/2024 13:48
Last Updated: 15/06/2024 20:49
* * *
>Category: Endpoint Forensics
>Tags: Memory Forensics, Volatility, T1055.012, T1027
* * *
**Scenario**:
You have been hired as a soc analyst to investigate a potential security breach at a company. The company has recently noticed unusual network activity and suspects that there may be a malicious process running on one of their computers. Your task is identifying the malicious process and gathering information about its activity.

**Tools**:
- [Volatility 2](https://www.volatilityfoundation.org/)
* * *
## Questions
> Q1: What is the process ID of the currently running malicious process?

![35874c69cc9b84bddd8f3d73a9cf6ee9.png](../../_resources/35874c69cc9b84bddd8f3d73a9cf6ee9.png)

If you want to use volatility 2 for this memory dump then First, we need to determine which profile to use with kdbgscan and imageinfo plugin

But... problem is it took a long time to find suitable profile for us so knowing that this memory dump was captured from Windows system is enough for us to investigate this using volatility 3

![fa2d1cf318eb6b13d6de7723346c4832.png](../../_resources/fa2d1cf318eb6b13d6de7723346c4832.png)

So we will use `vol3 -f memdump.mem pstree` to display process tree from this memory dump, which you can see that it should be impossible for svchost processes to be child process of `explorer.exe` which made them totally suspicious 

To get the currently running one, we need to look for svchost process that does not have Exit Time

```
8560
```

> Q2: What is the md5 hash hidden in the malicious process memory?

![1d9fc2078012902018e321c9490eec0d.png](../../_resources/1d9fc2078012902018e321c9490eec0d.png)

To properly perform process dump properly, I need to go back to volatility 2 so I used  `vol3 -f memdump.mem windows.info` to help me determine which profile to use from unfinished kdbgscan of mine 

![1939d034ac1019d62fe0d1dc5a343b06.png](../../_resources/1939d034ac1019d62fe0d1dc5a343b06.png)

And look like "Win10x64_17134" is the most suitable profile 

![ce86446e4c45e0a6e7ac6eadc2f1369f.png](../../_resources/ce86446e4c45e0a6e7ac6eadc2f1369f.png)

Then after we got the suitable profile, lets use `vol.py -f memdump.mem --profile=Win10x64_17134 memdump -p 8560 -D /tmp/nthunt/` to dump memory dump this process

![6a81d7329383e11190e198c13b54c8dd.png](../../_resources/6a81d7329383e11190e198c13b54c8dd.png)

I tried using strings with several regex to find possible md5 inside but turns out it was encoded with base64 so I couldn't find using md5 regex

![d2bcb287c3c93ec4b4d5f8f36fc15602.png](../../_resources/d2bcb287c3c93ec4b4d5f8f36fc15602.png)

Now we can get an answer using `echo "M2ExOTY5N2YyOTA5NWJjMjg5YTk2ZTQ1MDQ2Nzk2ODA=" | base64 -d"` command 

```
3a19697f29095bc289a96e4504679680
```

> Q3: What is the process name of the malicious process parent?
```
explorer.exe
```

> Q4: What is the MAC address of this machine's default gateway?

We might want to look at keys under `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged` that serves a specific purpose related to network configuration and profile management in Windows.

![1eb87810d56a9122de2331e48712bdda.png](../../_resources/1eb87810d56a9122de2331e48712bdda.png)

First we need to get any subkey on this key by using `vol.py -f memdump.mem --profile=Win10x64_17134 printkey -K "Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged"` and now we can dig deeper into this subkey

![5b14c5dbbddee178ab4c066991b1351e.png](../../_resources/5b14c5dbbddee178ab4c066991b1351e.png)

Lets proceed with `vol.py -f memdump.mem --profile=Win10x64_17134 printkey -K "Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged\010103000F0000F0080000000F0000F0E3E937A4D0CD0A314266D2986CB7DED5D8B43B828FEEDCEFFD6DE7141DC1D15D"` which will print out MAC address of the default gateway here

```
00:50:56:fe:d8:07
```

> Q5: What is the name of the file that is hidden in the alternative data stream?

Alternate Data Streams (ADS) are a feature of the NTFS (New Technology File System) used by Windows. They allow files to contain more than one stream of data, essentially providing a way to store additional information associated with a file in a hidden manner which make it a turning point for bad actors to hide the presence of a secret or malicious file inside the file record of an innocent file.

You can read more about this on [Alternate Data Streams Overview Blog published by SANS](https://www.sans.org/blog/alternate-data-streams-overview/)

![77e8cf28e5d79999e70e5a8ad273b8f3.png](../../_resources/77e8cf28e5d79999e70e5a8ad273b8f3.png)

First, we will use `vol.py -f memdump.mem --profile=Win10x64_17134 mftparser > mft.txt` to pipe all output from mftparser to a file so we didn't have to rescan everything to find what we want.

![b323950faa7b26bf35a5a89d631e4585.png](../../_resources/b323950faa7b26bf35a5a89d631e4585.png)

We can use `grep -i "ads name" mft.txt` to get all ADS name from mftparser output and you can see that there is a suspicious text file there

```
yes.txt
```

> Q6: What is the full path of the browser cache created when the user visited "www.13cubed.com" ?

![6bd9753377344abf59393e130ee20a9d.png](../../_resources/6bd9753377344abf59393e130ee20a9d.png)

We will use `grep -i "13cubed" mft.txt` to find all files that have "13cubed" matches and there are 2 files return from this command

First one is htm file which is the file we want 

```
C:\Users\CTF\AppData\Local\Packages\MICROS~1.MIC\AC\#!001\MICROS~1\Cache\AHF2COV9\13cubed[1].htm
```

![f30781e3a20645fc129501cd897110cf.png](../../_resources/f30781e3a20645fc129501cd897110cf.png)
* * *
