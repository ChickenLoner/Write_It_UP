# [LetsDefend - Windows Registry](https://app.letsdefend.io/challenge/windows-registry)
Created: 24/03/2025 20:21
Last Updated: 22/04/2025 20:15
* * *
As a cybersecurity analyst, you've been given an image containing all the registry hives from one of our employee’s machines. Your task is to thoroughly examine the provided artifacts and respond to a series of questions based on your analysis.

* * *
## Start Investigation
![b6de09721eae0100f683b670559a19fa.png](/_resources/b6de09721eae0100f683b670559a19fa.png)

After extracted the evidence 7zip file then we have 2 folders inside C folder and from the name of this challenge, we know that we will have to deal with registry.

![8c05ce2900902a4fe3376e13d99ca1bb.png](/_resources/8c05ce2900902a4fe3376e13d99ca1bb.png)

On Users folder, we have NTUSER.dat registry (HKCU) worth to check out for

![38877f410113f65da5ad717c2e7651b1.png](/_resources/38877f410113f65da5ad717c2e7651b1.png)

On the Windows folder, we have several registry hive to look for including Amcache as well so lets start our investigation right away and when I have registry hives, Registry explorer are always my go to which will bookmark common valueable registry keys for us investigator.

>How many users were added?

![16ab9e3a894e0b83ce54fd7a6fffc4b0.png](/_resources/16ab9e3a894e0b83ce54fd7a6fffc4b0.png)

When investigating about users or obtaining user information, SAM registry hive is the one that we have to utilize which its already bookmarked Users key for us (`HKLM\SAM\Domains\Account\Users`.

![8f6ad563f8682196918ecb788a1db448.png](/_resources/8f6ad563f8682196918ecb788a1db448.png)

Now we have to look at the bottom of this key to find out user that has RID over 1000 which if we reserved 1001 for the user who owns the system then we will have these 2 users that add at the same minutes on this system.

```
2
```

>What is the build number of the user's operating system?

![0e6c67d1bff473951178e6b7b7c99f09.png](/_resources/0e6c67d1bff473951178e6b7b7c99f09.png)

To find out the build number of the operating system via registry key then we will have to look at `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion` key which is already bookmarked for us as well.

```
19045
```

>What was the IP address of the machine you are investigating right now?

![b7527d1d321f09f1a15bc456a692b713.png](/_resources/b7527d1d321f09f1a15bc456a692b713.png)

This time we need to load SYSTEM hive and inspect `HKLM\SYSTEM\ControlSet001\Services\Tcpip\Parameters\Interfaces` which also conveniencely bookmarked for us right here and the reason we need to find this key is because this key stores DHCP related information for specific network interface which is also stores the IP address assigned to this system by the DHCP server as well.

```
192.168.110.130
```

>We suspect that the user may have some video games on their work PC. What is the name of the game?

![dae55d49858810f17215f44557fa407c.png](/_resources/dae55d49858810f17215f44557fa407c.png)

When user plays game, he/she then have to open the launcher so I loaded NTUser.dat and inspect `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs` which we can see that user on this machine plays or played Rainbow Six Siege.

```
Rainbow Six Siege
```

>There was a file that got executed from the Downloads directory. What is the modification time of the said file?
**Answer Format**: YYYY-MM-DD HH:MM:SS

![54fec0b5d5a6e01130201a79049293fc.png](/_resources/54fec0b5d5a6e01130201a79049293fc.png)

We have 4 different evidence of execution artifacts on the registry (BAM, Amcache, UserAssist and Shimcache) and since we already in HKCU then we can look at the `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist` first before proceeding with another artifacts that stores Modification time, then we can see that we have 3 different binary executed by this user from Downloads folder and `DeathNote.exe` is very standout from the rest here but that is not the one we are looking for on this question.

![f23e566949c392e7e34bd9ea5a4a2d3e.png](/_resources/f23e566949c392e7e34bd9ea5a4a2d3e.png)

Now we can look into the Shimcache which stores modification time of executed binary
at `HKLM\SYSTEM\ControlSet001\Control\Session Manager\AppCompatCache` (you can use AppCompatCache to parse this information out from SYSTEM hive as well) then we will have to modification time of `Docker Desktop Installer.exe` is the correct answer of this question and its the only one that from Downloads folder that presented on Shimcache here. 

```
2024-03-11 13:44:35
```

>We believe that the user may have installed some malicious files on their work PC. What is the SHA1 hash of the malicious file?

![8887f087cda25685f8083e4ed45376de.png](/_resources/8887f087cda25685f8083e4ed45376de.png)

We still have death note binary left to check out so we can look into Amcache to find SHA1 of this binary (Amcache stores SHA1 hash of executed binaries but not all of them)

![745a12d4585e371cd0564f2ef512cf82.png](/_resources/745a12d4585e371cd0564f2ef512cf82.png)

Then search this hash on [VirusTotal](https://www.virustotal.com/gui/file/1486c747b69c5bef4db22df9e508bdecffa85a2f79e97f88445494311f33555c) which reveals that this file is malicious and we can also see the family label of this file as well (the answer of next question) so this is the one we are looking for 

```
f7910c5a92168453106e4343032d1c5ca239ce16
```

>What is the malware family name of the previous file?
```
jaik
```

>The user opened a file on 2024-05-06 06:39:09 on their work PC. What is the name of that file?

![5c8c5b234f78de72f2b2c6fca919569a.png](/_resources/5c8c5b234f78de72f2b2c6fca919569a.png)

Now we go back to HKCU and inspect `RecentDocs` registry key again which we can see that `Note.txt` was opened at 2024-05-06 06:39:09 on this system.

```
Note.txt
```

>The user opened MSPaint on their work PC. Can you determine the exact time it happened?
**Answer Format**: YYYY-MM-DD HH:MM:SS

![24d6638a649fe9d99a179601fb56d840.png](/_resources/24d6638a649fe9d99a179601fb56d840.png)

Go to `UserAssist` key again then look for `mspaint.exe` binary which we can see that user opened MSPaint at 2024-05-06 06:43:38 with the focus time of 1 minute 3 seconds.

```
2024-05-06 06:43:38
```

>Can you find out how long the user had MSPaint open?
(**Answer Format**: MM:SS)
```
01:03
```

* * *
## Summary
On this challenge, we dived into 5 registry hives from SAM, SOFTWARE, SYSTEM with Shimcache, NTUSER.dat of Administrator user and Amcache to find out various kind of valuable information including user accounts, Windows build number, User behaviour and evidence of execution which highlight how Registry could be a gold source of evidence when its come to digital forensics!

<div align=center>

![89ce0a41fe715aa058a728e42b7abeab.png](/_resources/89ce0a41fe715aa058a728e42b7abeab.png)
https://app.letsdefend.io/my-rewards/detail/b154b8efb3e44992b403bea25628f1b9
</div>

* * *
