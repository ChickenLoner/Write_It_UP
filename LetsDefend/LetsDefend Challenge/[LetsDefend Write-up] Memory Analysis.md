# [LetsDefend - Memory Analysis](https://app.letsdefend.io/challenge/memory-analysis)
Created: 24/05/2024 16:41
Last Updated: 07/06/2024 08:29
* * *
<div align=center>

**Memory Analysis**
![383a9e53a21158e37d0de59545c37945.png](/_resources/383a9e53a21158e37d0de59545c37945.png)
</div>
A Windows Endpoint was recently compromised. Thanks to our cutting-edge EDR/IDS solution we immediately noticed it. The alert was escalated to Tier 2 (Incident Responders) for further investigation. As our Forensics guy, you were given the memory dump of the compromised host. You should continue to investigate.

~~**File link:**~~ [~~Download~~](https://drive.google.com/file/d/12vkQFSqZQkTu89g7NIlZsqW80SCP8O9_/view?usp=sharing) 
**File location**: /root/Desktop/ChallengeFile/MemoryDump.zip
**File Password:** infected

NOTE: You can use the <u>[Volatility](https://www.volatilityfoundation.org/releases)</u> for analysis.

This challenge prepared by [0xCyberJunkie.sh](https://www.linkedin.com/in/abdullah-bin-yasin-4b418119a)

* * *
## Start Investigation
> What was the date and time when Memory from the compromised endpoint was acquired?

![608a223b2e61352f9b66673eae191a7f.png](/_resources/608a223b2e61352f9b66673eae191a7f.png)
Volatility 2 didn't work well with this memory image (i tried) so I ended up with `vol3 -f dump.mem windows.info` to get SystemTime 
```
2022-07-26 18:16:32
```

> What was the suspicious process running on the system? (Format : name.extension)

![66a6442a9745d68d6741d794c3b83736.png](/_resources/66a6442a9745d68d6741d794c3b83736.png)
I used `vol3 -f dump.mem windows.pstree` and this lsass process is suddenly caught my eyes because it couldn't be the chlid process of explorer.exe
```
lsass.exe
```


> Analyze and find the malicious tool running on the system by the attacker (Format name.extension)

![7f09404b80e33e0c91c6c3083ec0c273.png](/_resources/7f09404b80e33e0c91c6c3083ec0c273.png)
Lets drump it with `vol3 -f dump.mem -o /tmp/outfile/  windows.pslist --pid 7592 --dump` then use `md5sum /tmp/outfile/pid.7592.0x2238edc0000.dmp` to calculate MD5 so we can use this hash to search on VirusTotal
![76bb3e4b2a6ad7ff2a2f04837bd368b9.png](/_resources/76bb3e4b2a6ad7ff2a2f04837bd368b9.png)
It's [winPEAS](https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS), so the attacker tried to gain system/admin privilege or enumerate system using this tool
```
winPEAS.exe
```

> Which User Account was compromised? Format (DomainName/USERNAME)

![6e46717375b7fd5ff9ed5a97f6fdfd1d.png](/_resources/6e46717375b7fd5ff9ed5a97f6fdfd1d.png)
We will use `vol3 -f dump.mem windows.sessions` to determine if that suspicious process has a session under any username, which there is
```
MSEDGEWIN10/CyberJunkie
```

> What is the compromised user password?

![718f4f633da3f58129c6342e0d319807.png](/_resources/718f4f633da3f58129c6342e0d319807.png)
I used hashdump plugin then filter for specific user and pipe it to a file with this `vol3 -f dump.mem hashdump | grep "Cyber" > CyberJunkie.hash`
![abef713f6b30c8e7eeef289e873175e4.png](/_resources/abef713f6b30c8e7eeef289e873175e4.png)
Then I made a little adjustment before using john to crack it
![c8a6b981c23fed540fe24e1d8d685bfd.png](/_resources/c8a6b981c23fed540fe24e1d8d685bfd.png)
Using `john --wordlist=/usr/share/wordlists/rockyou.txt CyberJunkie.hash --format=NT` then we have his password
```
password123
```

<div align=center>

![56d3f812e342819b58eea983d65f5ca7.png](/_resources/56d3f812e342819b58eea983d65f5ca7.png)
https://app.letsdefend.io/my-rewards/detail/302fcea4ab974645946afeed200dee30
</div>
* * *
