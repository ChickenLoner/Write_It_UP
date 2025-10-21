# [LetsDefend - Windows Memory Dump](https://app.letsdefend.io/challenge/windows-memory-dump)
Created: 19/06/2024 07:59
Last Updated: 19/06/2024 10:30
* * *
<div align=center>

**Windows Memory Dump**
![10f64f96cc061cd522cea88dbea1beb5.png](../../_resources/10f64f96cc061cd522cea88dbea1beb5-1.png)
</div>

Our friend fell victim to a suspicious crack tool. But it seems it didn't go in the right path so investigate it to find any evidence.

**File Location**: /root/Desktop/ChallengeFile/vLP.vmem
* * *
## Start Investigation
>How many users are on the machine?

![66154dae1f0fbda4b843205cc7b438e7.png](../../_resources/66154dae1f0fbda4b843205cc7b438e7-1.png)

There are several ways to answer this question mine is to use `python3 vol.py -f vLP.vmem windows.sessions` then pipe output to ` ../ChallengeFile/sessions.txt`

![086490dd2c1a9ba8811119b46ef708d6.png](../../_resources/086490dd2c1a9ba8811119b46ef708d6-1.png)

Then use `cat ../ChallengeFile/sessions.txt | grep '/' | awk '{print $5}' | sort | uniq` to display all unique user process username from sessions then we will have 4 users have sessions on this system

```
4
```

>Which user is the infected one?

![7e7887be8c0d64b00abb70c23b30edbc.png](../../_resources/7e7887be8c0d64b00abb70c23b30edbc-1.png)

Scenario gave us a hint that victim fell to a suspicious crack tool which might be found on one of these 4 users Downloads folder so I used `python3 vol.py -f vLP.vmem windows.filescan > ../ChallengeFile/filescan.txt` to keep output from filescan plugin to a text file first

![780cd9c142ebc4e379e0b981423e0f88.png](../../_resources/780cd9c142ebc4e379e0b981423e0f88-1.png)

Then use `cat ../ChallengeFile/filescan.txt | grep "Downloads"` to find all files inside Downloads folder then we can see there is `Windows10Crack.exe` inside flapjack's Downloads folder

```
flapjack
```

>Which file dropped the ransomware?
```
Windows10Crack.exe
```

>How did that file drop the ransomware [URL]?

![a41912e0ebe0f3723b637a183ab11430.png](../../_resources/a41912e0ebe0f3723b637a183ab11430-1.png)

Lets dump `Windows10Crack.exe` from memory dump with `python3 vol.py -f vLP.vmem windows.dumpfiles --virtaddr 0xe4870d72ebf0`

![94237f194cb4c41f841f87c89e7040f7.png](../../_resources/94237f194cb4c41f841f87c89e7040f7-1.png)

Then use IDA Free to decompile this file which you will see that this file will drop ransomware to temp folder

```
http://48.147.154.231/XGUbdem0hd.exe
```

>What is the virtual offset of that ransomware?

![9084f40d4b7cafe8f317ea317a4cd350.png](../../_resources/9084f40d4b7cafe8f317ea317a4cd350.png)

Using `cat ../ChallengeFile/filescan.txt | grep "XGUbdem0hd.exe"` then we will have virtual offset of this ransomware

```
0xe4870d737570
```

>The ransomware edited one of the primary hash manager registry key. Find the key that got modified.

![499a8781773896366d7d33edb3658654.png](../../_resources/499a8781773896366d7d33edb3658654.png)

Lets dump it with `python3 vol.py -f vLP.vmem windows.dumpfiles --virtaddr 0xe4870d737570` then use `md5sum` to calculate file hash for us and we will search this hash on VirusTotal

![b6c986fc90852ba44a72898cd758ab21.png](../../_resources/b6c986fc90852ba44a72898cd758ab21.png)

Then we will see that this ransomware is called Blackcat ransomware

![eca1bc18d46ae6a39b8f44f1168dcb83.png](../../_resources/eca1bc18d46ae6a39b8f44f1168dcb83.png)

Go to behavior tab, under Registry actions and you will see that registry at the bottom of this list 

![42684d755630fac7c84745bdff1a6f66.png](../../_resources/42684d755630fac7c84745bdff1a6f66.png)

Here is the explaination about this key

```
HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters
```

>What is the credential of the AdminRecovery?

![05791a33529765c904d7f649b406ba12.png](../../_resources/05791a33529765c904d7f649b406ba12.png)

Go to the last section under behavior tab, we will see Decoded Text that has AdminRecovery's credential

```
K3ller!$Supp1y
```

* * *
## Summary

On this challenge, We've done several things as follows
- We used volatility 3 to dump malicious crack file and ransomware file
- We used IDA Free to analyze malicious crack file
- We used VirusTotal to determine edited registry key and credential of AdminRecovery

<div align=center>

![873aa3df426bb49bfcd3787f3fea8736.png](../../_resources/873aa3df426bb49bfcd3787f3fea8736.png)
</div>

* * *
