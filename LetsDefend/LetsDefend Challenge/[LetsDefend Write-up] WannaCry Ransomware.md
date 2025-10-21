# [LetsDefend - WannaCry Ransomware](https://app.letsdefend.io/challenge/wannacry-ransomware)
Created: 22/03/2024 14:06
Last Updated: 22/06/2024 13:36
* * *
<div align=center>

**WannaCry Ransomware**
![f58af1e882b7fbcd780298f479518ba1.png](../../_resources/f58af1e882b7fbcd780298f479518ba1.png)
</div>
MMOX Company GOT infected with ransomware, as one of our new employees was not aware enough of the phishing campaigns. Can you track what happened to answer the following questions?


File Link: [Download](https://letsdefend-images.s3.us-east-2.amazonaws.com/Challenge/WannaCry-Challenge/WannaStory.7z)

Or you can directly connect to the machine.

**File location(Windows)**: C:\Users\LetsDefend\Desktop\WannaStory
**File location(WSL-Ubuntu)**: C:\Users\LetsDefend\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\home\letsdefend\WannaStory

**WSL-Ubuntu username**: letsdefend
**WSL-Ubuntu password**: letsdefend

**Note**: If you want to transfer a file to WSL-Ubuntu firstly you should transfer the file and then you should restart Windows "LxssManager" service and re-open the WSL-Ubuntu shell. Then give permission to transfer file on WSL-Ubuntu.

**Note**: Use python2 to run the oledump tool. If necessary, you can download and install analysis tools.
* * *
## Start Investigation
>What is the md5 of the desk and memory images? Answer format: Desk hash_ Memory hash

We got HashMyFiles on Windows so throw both files into HashMyFile to calculate MD5 hash 
![9797ab5c9bf0eaa090328f83a38ff6a5.png](../../_resources/9797ab5c9bf0eaa090328f83a38ff6a5.png)
```
54839173ec35223144d9a5ad393eb437_0891e428785566cb5772bdb45993d92b
```

>What is the suitable profile for the memory dump?

Volatility was nowhere to be found on Windows system but on Ubuntu WSL, We got both volatility 2 (vol2) and volatility 3 (vol3) along with oledump from EZ tools
![a54ca8756e8e04a44bfb2f8ac7150971.png](../../_resources/a54ca8756e8e04a44bfb2f8ac7150971.png)
vol3 doesn't have profile anymore so vol2 is an only tool here, just use it with `imageinfo` to let vol2 determine suitable profile for this memory
![763d2b0a76d1112fef3e95e4762126ed.png](../../_resources/763d2b0a76d1112fef3e95e4762126ed.png)
```
Win10x64_19041
```

>When was the memory image captured?

The answer of this question could also be found on vol2 `imageinfo` result
![d580d75620036e2f99a4337f5779903a.png](../../_resources/d580d75620036e2f99a4337f5779903a.png)
```
2023-02-15 16:23:06
```

>What are the attacker's email address and the infected user's email address? Answer format: attacker email_infected user email

Back to Windows with FTK Imager provided, I opened an image file then determine which user got infected
![b4e8b7480601ef6468b1ef6c281d6f9b.png](../../_resources/b4e8b7480601ef6468b1ef6c281d6f9b.png)
The result shows that user atamer was infected by this ransomware
![b53f1872f6ff61638055351490e6a77d.png](../../_resources/b53f1872f6ff61638055351490e6a77d.png)
I also read ransomnote but look like contact info can also be found on decryptor

I also noticed that there is a tool provided by this challenge to view OST file so I went to `AppData\Microsoft\Outlook` to find an OST file of this user
![918b5f71a0ede30a32c11d26680ae02f.png](../../_resources/918b5f71a0ede30a32c11d26680ae02f.png)
As expected, this user used Microsoft Outlook to open an email so now we can use SysTools OST Viewer to open this file
![d14c70ca2cb98f3f373870ea574ea1af.png](../../_resources/d14c70ca2cb98f3f373870ea574ea1af.png)
Last email is obviously a phishing email by switching domain name from o to 0 and it also have an attachment with the same name as we found eariler
```
hr@mm0x.lab_atamer@mmox.lab
```

>What is the SHA-256 of the initial access file?

FTK Imager has Export File Hash List function but the limitation is it can only calculate for MD5 and SHA1 so the only way is to export it then using HashMyFile
![0037ff87565b286863342918ab48be1d.png](../../_resources/0037ff87565b286863342918ab48be1d.png)
```
12913f9984b8b5a940ef114579b831c0f361feb5f5618ccea11f5cb166a08c47
```

>What are the IP and the port that the attacker used to deliver the ransomware? Answer format: IP:Port

We got a malicious document file from an image so export it and then sent to Ubuntu WSL using python basic http server and wget 
![ba5d83bbd1a40e7233f7c0ea113936eb.png](../../_resources/ba5d83bbd1a40e7233f7c0ea113936eb.png)
![a88a03ea4220ee34b5632af0a08aabb6.png](../../_resources/a88a03ea4220ee34b5632af0a08aabb6.png)
After downloaded maldoc, we can use oledump to dump malicious macro from this maldoc file
![e0000535c25040ff09976c3b9e4c0f2b.png](../../_resources/e0000535c25040ff09976c3b9e4c0f2b.png)
Result shows that stream 8 and 9 are where the Macro was embbeded then we can use `-s 8` or `-s 9` to select a stream to dump
![0ab2ed5889a265769e04921c310fcc5f.png](../../_resources/0ab2ed5889a265769e04921c310fcc5f.png)
There is an IOC there so This ransomware was downloaded from `192.168.30.50` on port `8585` and was renamed it to `Thunder.exe` so this is an actual ransomware.
```
192.168.30.50:8585
```

>What is the PID of the 3 malicious processes that are related to the ransomware (Numerical order) Answer format: PID_PID_PID

Use vol2 or vol3 with pstree plugin to list process tree

Vol2: `python2 vol.py -f ~/WannaStory/Wanna-MEM.vmem --profile=Win10x64_19041 pstree`
Vol3: `python3 vol.py -f ~/WannaStory/Wanna-MEM.vmem windows.pstree.Pstree`

then find the explorer.exe or Thunder.exe
![c5a4df602aa21402d15c549e57ed0683.png](../../_resources/c5a4df602aa21402d15c549e57ed0683.png)
As expected, word was spawned from explorer when user opened maldoc then `Thunder.exe` (an actual ransomware) was downloaded and executed, which also spawn 2 more processes that have the same name
```
3780_4240_4296
```

>What is the Bitcoin address that will be used to pay the ransom?

There is a ransomnote on infected user's Desktop which will provide user a bitcoin address for their payment.
![5577f2df4cfdcccbf0937a70e06e707e.png](../../_resources/5577f2df4cfdcccbf0937a70e06e707e.png)
```
13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94
```

>There is a suspicious file that the main malicious process dumps what is the file's name and its offset Format: offset_name

Use handles plugin to understanding how processes interact with system resources, detecting suspicious activity, and uncovering hidden artifacts during memory analysis of Windows systems
![3faa4f6b8e920e2860b1ef10e0161d24.png](../../_resources/3faa4f6b8e920e2860b1ef10e0161d24.png)
Then we also know that a ransomware is named `Thunder` so add more filter to output of the vol3 
`python3 vol.py -f ~/WannaStory/Wanna-MEM.vmem windows.handles.Handles | grep "Thunder"`
![5095dfa2b00488b308baa66e46080500.png](../../_resources/5095dfa2b00488b308baa66e46080500.png)
There is a file created on Temp directory 
![c0f06c3c005f5b8192b291f07947ae29.png](../../_resources/c0f06c3c005f5b8192b291f07947ae29.png)
Confirmed on disk, its a huge file!
```
0xa20fea3487d0_hibsys.WNCRYT
```

>There is a mutex that the malware checks for to stop if it exists what is its name?

To find mutex, we need to add filter for `Mutent` from the previous command 
`python3 vol.py -f ~/WannaStory/Wanna-MEM.vmem windows.handles.Handles | grep "Thunder" | grep "Mutant"`
![89317f6640cd3ff7b05475d50af2b540.png](../../_resources/89317f6640cd3ff7b05475d50af2b540.png)
There were 2 mutexes
```
MsWinZonesCacheCounterMutexA0_MsWinZonesCacheCounterMutexA
```

* * *
## Summary

Phishing email was sent to a new employee named `atamer` which he downloaded a malicious document from an email then opened it and when malicious document was opened, It downloaded a wannacry ransomware from C2 server and named it `Thunder.exe` which executed once downloading was completed
<div align=center>

![6453347c60ce8d706f329050c36b9ba6.png](../../_resources/6453347c60ce8d706f329050c36b9ba6.png)
</div>

* * *
