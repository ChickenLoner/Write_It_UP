# [Blue Team Labs Online - Masquerade](https://blueteamlabs.online/home/investigation/masquerade-d41fa429f3)
<div align=center>

![25dd1c8d2ec779d65c6945e3aa0dbcac.png](../../../_resources/25dd1c8d2ec779d65c6945e3aa0dbcac.png)
</div>
Omar's USB drive might be the cause of the breach; Your task is to analyze these artifacts and determine exactly what happened.

>Digital Forensics

>**Tags**: Volatility 3, Registry Explorer, ShellBags Explorer, MFTECmd, Timeline Explorer, CyberChef, Notepad++, IDA, Strings, T1071, T1486, T1059.001, PR010.001,
* * *
**Scenario**
Allam, a senior infrastructure engineer at EZ-CERT, is known for hosting his annual "Haunted Festival" every Halloween. This year, during the event, a man named Omar approached Allam, asking if he could project something from his USB drive to enhance the party's spooky atmosphere. A day or two after the festival, Allam discovered that all his files had been encrypted, leaving him unable to access his data. Suspecting Omar's USB drive might be the cause; Allam has provided several digital artifacts for investigation. Your task is to analyze these artifacts and determine exactly what happened.
* * *
## Investigation Submission
>Q1) As you start piecing together the events from the festival, you notice that a USB device was connected to Allam's machine. What is the serial number of this USB device? (Format: XXXXXXXX)

![ea819049a6972d175b1d43cda809d848.png](../../../_resources/ea819049a6972d175b1d43cda809d848.png)

We were provided with artifacts from C drive and memory dump of infected machine and we have several tools to use but as the note on the desktop telling us that not all tools will be used, just pick your favorite/handy one. 

![a689e5a416577c801d3bb8b43c21ac15.png](../../../_resources/a689e5a416577c801d3bb8b43c21ac15.png)

To find out serial number of USB device, we have to read a specific key (USBSTOR) from SYSTEM registry hive and if we use registry explorer then it already bookmarked this registry for us which we can get serial number of the only USB storage device connected to this system right here.
<details>
  <summary>Answer</summary>
<pre><code>UM2I126E</code></pre>
</details>

>Q2) To narrow down the timeline. When Omar’s USB drive was first plugged into Allam’s computer. What exact time does it show? (Format: YYYY-MM-DD HH:MM:SS UTC)

![ca61c68801f067ecdfa1ea5d58cdc983.png](../../../_resources/ca61c68801f067ecdfa1ea5d58cdc983.png)

Get Installed or Last Connected time to answer this question.
<details>
  <summary>Answer</summary>
<pre><code>2024-08-21 08:50:12 UTC</code></pre>
</details>

>Q3) Digging deeper into the details of the connected USB, you’ll need to identify its manufacturer. What is the vendor ID of this device? (Format: XXXX)

![e10ec59117640f030419e18267d416b7.png](../../../_resources/e10ec59117640f030419e18267d416b7.png)

At first, I used this [website](https://the-sz.com/products/usbid/index.php?v=&p=&n=JetFlash) to search for vendor ID

![e34137df9a10018e399a3db849ef585d.png](../../../_resources/e34137df9a10018e399a3db849ef585d.png)

Then I also find out that we can also find this value from USB registry key right here.
<details>
  <summary>Answer</summary>
<pre><code>8564</code></pre>
</details>

>Q4) Knowing which drive letter was assigned to the USB can help trace its activity on the system. Which drive letter did the operating system assign to Omar’s USB? (Format: X:\)

![a4abf691073449c091e6d08b2dd5b0cc.png](../../../_resources/a4abf691073449c091e6d08b2dd5b0cc.png)
We can check value inside "MountedDevices" key which also stores the drive letter of each mounted storage on Windows.
<details>
  <summary>Answer</summary>
<pre><code>E:\</code></pre>
</details>

>Q5) Upon examining the contents of the USB drive, you find several files and directories. Name two folders that were present on Omar's USB. (Format: Folder1, Folder2)

![db00b9e1707837da881c9726c17a154f.png](../../../_resources/db00b9e1707837da881c9726c17a154f.png)

Time for ShellBag which used to store information about user preferences and interactions with folders in the file system so if user opened any folders inside that USB devices then it will be stores in ShellBag and that ShellBag is stored in UsrClass registry hive for each user right here. 

![3ed5451c86f4c0768a31a786fdb2d2b9.png](../../../_resources/3ed5451c86f4c0768a31a786fdb2d2b9.png)

Then we can see 2 folders that were present of this USB.

<details>
  <summary>Answer</summary>
<pre><code>Backup,Images</code></pre>
</details>

>Q6) It seems Allam opened a file from Omar’s USB, mistaking it for a harmless video. What is the name of the file he opened? (Format: File Name)

![c459cb9e21c3553242d0533ab4175cab.png](../../../_resources/c459cb9e21c3553242d0533ab4175cab.png)

Next artifacts that could be utilized is Jump Lists located here.

![fcba8d3aad81c9d94da0a50de2c12ecb.png](../../../_resources/fcba8d3aad81c9d94da0a50de2c12ecb.png)

Use `JLECmd.exe` to parse "AutomaticDestinations" folder

![b40a52172c9d82acd5982f2a1fd6d410.png](../../../_resources/b40a52172c9d82acd5982f2a1fd6d410.png)

Then we could see a PowerShell script mimic as MP4 video was opened by this user.

<details>
  <summary>Answer</summary>
<pre><code>Scary_Videos.mp4.ps1</code></pre>
</details>

>Q7) To see when Allam interacted with the USB. When did he open the suspicious file, believing it to be just a video? (Format: YYYY-MM-DD HH:MM:SS)

![a0ff163a837e7081fbb57b08a72409b8.png](../../../_resources/a0ff163a837e7081fbb57b08a72409b8.png)

Go to Target Accessed field to get the answer of this question

![a80b97774aa371f40c1b0c15a4be61eb.png](../../../_resources/a80b97774aa371f40c1b0c15a4be61eb.png)

If you prefered GUI, you can use JumpList Explorer to find out the answer like this.

<details>
  <summary>Answer</summary>
<pre><code>2024-08-21 09:33:04</code></pre>
</details>

>Q8) Analyzing the method used to disguise the malicious file, refer to the MITRE ATT&CK framework. What is the ID for the technique the attacker utilized? (Format: TXXXX.XXX)

![ab33cc7f32f1d3906fb2beb3a5eeee10.png](../../../_resources/ab33cc7f32f1d3906fb2beb3a5eeee10.png)
This is a [technique](https://attack.mitre.org/techniques/T1036/005/) utilized by this malicious file 
<details>
  <summary>Answer</summary>
<pre><code>T1036.005</code></pre>
</details>

>Q9) After opening the deceptive file, Allam’s machine initiated a download. Trace the network activity to find the full URL of the downloaded file. What is the full URL of the downloaded file? (Format: Full URL)

![aa866b98bf816c7c7784519dc9f1422f.png](../../../_resources/aa866b98bf816c7c7784519dc9f1422f.png)

This is a little bit tricky, I started from parsing prefetch with PECmd then open it with Timeline Explorer.

![15d526beaf7c9e78f872d193c97d356a.png](../../../_resources/15d526beaf7c9e78f872d193c97d356a.png)

Which I found certutil was executed after PowerShell and conhost so the malware might use certutil to download file from C2. 

![ed36cae113e5608a6aac971e130b24a6.png](../../../_resources/ed36cae113e5608a6aac971e130b24a6.png)

Cerutil stores both content and metadata inside CryptnetUrlCache folder under `%AppData&\LocalLow\Microsoft\` so lets navigate to this folder.

![4c9094c818811e7577d0d87173ca92b1.png](../../../_resources/4c9094c818811e7577d0d87173ca92b1.png)

There, we will found 2 files with has 43 KB and 71 KB size so lets confirm which one appear more suspicious.

![6d59245b3779e3474b1ece6fccd573b0.png](../../../_resources/6d59245b3779e3474b1ece6fccd573b0.png)

I started with 43 KB file which we can see that it has MZ header which mean this file is PE32 executable file.

![7e0aa8dd36a303cc51a742ff1cd3ac9d.png](../../../_resources/7e0aa8dd36a303cc51a742ff1cd3ac9d.png)

Go take a look at metadata of this file but we have to used strings or put it in CyberChef to make it appear more friendly to us.

![f14b93684b3419014726406e56bc1e81.png](../../../_resources/f14b93684b3419014726406e56bc1e81.png)

And there we got URL that resemble C2 address which is the correct answer of this question.

<details>
  <summary>Answer</summary>
<pre><code>http://3.121.78.204/ntshrul.dll</code></pre>
</details>

>Q10) Now that you have the URL, where did this file end up on the system? provide the full path. (Format: Full Path)

![0aa1c35e550d86ddb9e474b0c74e0e8a.png](../../../_resources/0aa1c35e550d86ddb9e474b0c74e0e8a.png)

Next artifact I utilized is $MFT. 

![7a9ff360742c13c1999d2fac26c77292.png](../../../_resources/7a9ff360742c13c1999d2fac26c77292.png)

Then we can see that this file was renamed and place it inside XPS Card Printer folder probably for DLL hijacking.

<details>
  <summary>Answer</summary>
<pre><code>C:\ProgramData\Datacard\XPS Card Printer\Service\DEVOBJ.dll</code></pre>
</details>

![06ba8589ea2a42d4bfc6521480dffed6.png](../../../_resources/06ba8589ea2a42d4bfc6521480dffed6.png)

Upon opening result from MFTCmd, we could see a lot of this weird note which might be a ransom note. 

>Q11) To ensure the integrity of your findings, calculate the SHA1 hash of the downloaded file on Allam’s system. What is the hash value? (Note: if you got the hash from anywhere else than the triage image, it won’t work.) (Format: SHA1 Hash)

![5403f57294d904b8d8e30cc4e7e4ed3f.png](../../../_resources/5403f57294d904b8d8e30cc4e7e4ed3f.png)

Lets calculate this hash using lolbas like certutil.
<details>
  <summary>Answer</summary>
<pre><code>309550407116c6d0f68dfd62d014e4a33001dac5</code></pre>
</details>

![53504cb63d0982d6233ff2d1adcee3db.png](../../../_resources/53504cb63d0982d6233ff2d1adcee3db.png)

Then if we searched this on VirusTotal, we could see its metasploit payload so this might actually be DLL hijacking attack.

>Q12) The attacker here exploited a vulnerable service on the machine to escalate his privilege on the machine. What is the CVE that he used? (Format: CVE-XXXX-XXXXX)

![970552990418e2b14c35063ca4665f72.png](../../../_resources/970552990418e2b14c35063ca4665f72.png)

Upon searching for this service [CVE](https://github.com/pamoutaf/CVE-2024-34329/blob/main/README.md), its quite new but it is indeed confirm that its DLL  that lead to local privilege escalation to SYSTEM.

<details>
  <summary>Answer</summary>
<pre><code>CVE-2024-34329</code></pre>
</details>

>Q13) Reviewing the privilege escalation technique used by the attacker, What is the MITRE ATT&CK technique ID that describes this method? (Format: TXXXX.XXX)

![52a22c6ec7bedbafb869bb777213e972.png](../../../_resources/52a22c6ec7bedbafb869bb777213e972.png)
This technique is known as "[DLL Search Order Hijacking](https://attack.mitre.org/techniques/T1574/001/)" by MITRE ATT&CK

<details>
  <summary>Answer</summary>
<pre><code>T1574.001</code></pre>
</details>

>Q14) To analyze the memory dump effectively, identify the profile image that matches the system’s configuration. What profile image does the memory dump correspond to? (Format: WinXXxXX_MinorVersion)

![3454302f32a8750cf18097e0034e3755.png](../../../_resources/3454302f32a8750cf18097e0034e3755.png)

Its time to analyze memory dump and to make our profile searching easier, we can use `windows.info` plugin from volatility 3 to determine architecture, major and minor version of Windows.

![e48690ec2f271af4114304670b1c5e80.png](../../../_resources/e48690ec2f271af4114304670b1c5e80.png)
Which we will have this profile perfectly matched the result found from volatility 3
<details>
  <summary>Answer</summary>
<pre><code>Win10x64_19041</code></pre>
</details>

>Q15) During your investigation, you find that the malicious file was injected into a legitimate process. What is the Process ID (PID) of this process? (Format: XXXX)

![606daf56ae483bd0714408d85e67ddf1.png](../../../_resources/606daf56ae483bd0714408d85e67ddf1.png)

Upon running any command with volatility 2, you will find this errors so just to make sure you don't use any of these plugins and if you have to then you will need to find the plugin equivalent to them in volatility 3.  

And well.. `malfind` did not work on this one so I had to use another plugin.

![556e5ab06b5d51c894d783ffcfe569b4.png](../../../_resources/556e5ab06b5d51c894d783ffcfe569b4.png)
Then the plugin that saved me on this one is `netscan` which we can see suspicious connection to C2 on port 1234 and the process responsible for this action is PID 2620 
<details>
  <summary>Answer</summary>
<pre><code>2620</code></pre>
</details>

>Q16) Trace the timeline further to pinpoint, When the malicious file was loaded into the legitimate process? (Format: YYYY-MM-DD HH:MM:SS)

![8edd1ad21c53639d9341fd5d21612b8b.png](../../../_resources/8edd1ad21c53639d9341fd5d21612b8b.png)

Since we already knew which DLL that was loaded and the process that connected C2 that we can use `dllist` plugin and specific PID 2620 to find loaded time of this dll right here.
<details>
  <summary>Answer</summary>
<pre><code>2024-08-21 14:17:24</code></pre>
</details>

>Q17) What is the memory address representing the starting point of the malicious file loaded into the legitimate process? (Format: 0xXXXXXXXXXXXX)

![c28e56c53dd49c0d0e65e4631bc4c9b2.png](../../../_resources/c28e56c53dd49c0d0e65e4631bc4c9b2.png)

We have to use `vadinfo` plugin for this one which we can see both starting point and ending point of this malicious file right here.

<details>
  <summary>Answer</summary>
<pre><code>0x7ff8500a0000</code></pre>
</details>

>Q18) What is the IP address and port number of the Command and Control (C2) server the malware connects to? (Format: IP Address:Port)
<details>
  <summary>Answer</summary>
<pre><code>3.17.35.28:1234</code></pre>
</details>

>Q19) What is the name of the function within the malicious file that initiated the connection to the C2 server? (Format: Function Name)

![0d0b2032e6e25db2a9844f70349709bc.png](../../../_resources/0d0b2032e6e25db2a9844f70349709bc.png)

Since we already have the payload from certutil then we could use IDA to find out the function that was used to initiate connection to C2 and to reduce our scope of finding, WSAConnect is the API used to establish a connection between a client socket and a remote server

![96e7db222c5bcb8ac7670b90c66e0d4c.png](../../../_resources/96e7db222c5bcb8ac7670b90c66e0d4c.png)

Then after find out this API, right click then click "Xrefs graph to.." to find cross reference to this API

![f75e553b10b477fe0a6ddec6036e4747.png](../../../_resources/f75e553b10b477fe0a6ddec6036e4747.png)

Then we could see a function that calls this API which is `extern_c`

![062a06764a6996e4574cb6b7cbeadb9f.png](../../../_resources/062a06764a6996e4574cb6b7cbeadb9f.png)

There we will find weird string along with C2 IP address in this function.
<details>
  <summary>Answer</summary>
<pre><code>extern_c</code></pre>
</details>

>Q20) What was the first command the attacker executed after gaining SYSTEM access on Allam's machine? (Format: Command Name)

![ce005aa169778962f6c35e60e425896e.png](../../../_resources/ce005aa169778962f6c35e60e425896e.png)

Used the output of prefetch parser to find the any executable that was executed after malicious dll was loaded which is `systeminfo.exe` 
<details>
  <summary>Answer</summary>
<pre><code>systeminfo</code></pre>
</details>

>Q21) Lucky for us, the machine that Allam was using for projecting at the festival wasn’t connected to the EZ-CERT Network. Unable to find valuable data, the attacker downloaded another file which resulted in the encryption of the entire system. What is the full URL of this file? (Format: Full URL)

![1d709cfa7fb2e610fa78572cbe21b538.png](../../../_resources/1d709cfa7fb2e610fa78572cbe21b538.png)

This one is a little bit tricky but when we use `pstree` plugin, we could see `conhost.exe` and `cmd.exe` under injected process so we have to dump `conhost.exe` (not process dump but memory dump) since conhost stores all command executed by `cmd.exe` in its memory.

![8df0ffe8c6c997499fb4b1b1efc7a827.png](../../../_resources/8df0ffe8c6c997499fb4b1b1efc7a827.png)
![b84f3a905ba3d9a40a3dd2c360fc7a78.png](../../../_resources/b84f3a905ba3d9a40a3dd2c360fc7a78.png)
After using `strings` on dumped file, then we will find this PowerShell executed base64 command which is why we couldn't use strings with regex to get url from memory dump directly. 

![16d6871f781c3329b3b6ceb65425a857.png](../../../_resources/16d6871f781c3329b3b6ceb65425a857.png)
Decode it then we will have URL that hosted ransomware.
<details>
  <summary>Answer</summary>
<pre><code>http://3.71.5.114/LBB.exe</code></pre>
</details>

>Q22) Identify the exact moment the ransomware was executed on Allam’s system. When did this happen? (Format: YYYY-MM-DD HH:MM:SS)

![7c085c723dd550a49765234e15a72165.png](../../../_resources/7c085c723dd550a49765234e15a72165.png)
Looking at this process tree again then you will find this weird process with `.tmp` extension was executed after the threat actor obtained SYSTEM privilege so it has to be this process.
<details>
  <summary>Answer</summary>
<pre><code>2024-08-21 14:24:09</code></pre>
</details>

>Q23) Tracking the ransomware process in Allam’s machine. What is the PID of the ransomware process? (Format: XXXX)
<details>
  <summary>Answer</summary>
<pre><code>2148</code></pre>
</details>

>Q24) Dump the ransomware process to the disk, What is the SHA256 hash of the .img file that is associated with the ransomware process that was active on the machine? (Format: SHA256 Hash)

![f26e49e88c72cdc340e294ff0e62d95c.png](../../../_resources/f26e49e88c72cdc340e294ff0e62d95c.png)

We could not use `filescan` right away due to Unicode encoder error so we will have to check this Beta box for UTF-8 encoding then restart the machine (not terminate but restart)

![c747109df88ec1964d04d284dc79ea05.png](../../../_resources/c747109df88ec1964d04d284dc79ea05.png)

Then we could be able to use `filescan` plugin to find the path of this file 

![af4efdf0e72051ba743b4dd6edd9241c.png](../../../_resources/af4efdf0e72051ba743b4dd6edd9241c.png)

along with physical offset of this file right here.

![fa954cd4bcd508a565db31e23ca452c4.png](../../../_resources/fa954cd4bcd508a565db31e23ca452c4.png)

Generate filehash of this file to submit.

<details>
  <summary>Answer</summary>
<pre><code>328786bf6dba5b29008e0469e0b972ce6062a08e37e02c5739c297466214db11</code></pre>
</details>

>Q25) Determine the type of ransomware that was used in this attack. What is the family name of the ransomware? (Format: Family Name)

![228d0b935ab03e48f1447e038230dcca.png](../../../_resources/228d0b935ab03e48f1447e038230dcca.png)
Search this filehash on VirusTotal then we can see that it is an infamous lockbit ransomware!
<details>
  <summary>Answer</summary>
<pre><code>lockbit</code></pre>
</details>

![9d51a703331aa566f6047031c05c2a28.png](../../../_resources/9d51a703331aa566f6047031c05c2a28.png)
https://blueteamlabs.online/achievement/share/52929/238

![f1d92c8333684e20974bba573e443f36.png](../../../_resources/f1d92c8333684e20974bba573e443f36.png)
And that's concluded my BTLO Halloween right here! Thanks for reading !
* * *