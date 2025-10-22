# [TryHackMe - Secret Recipe](https://tryhackme.com/room/registry4n6)
![6ffd218e1b80f4ca036d54222f66e09d.png](/resources/6ffd218e1b80f4ca036d54222f66e09d.png)
***
[toc]
***
## Introduction
**Jasmine owns a famous New York coffee shop Coffely which is famous city-wide for its unique taste. Only Jasmine keeps the original copy of the recipe, and she only keeps it on her work laptop. Last week, James from the IT department was consulted to fix Jasmine's laptop. But it is suspected he may have copied the secret recipes from Jasmine's machine and is keeping them on his machine.**

**His machine has been confiscated and examined, but no traces could be found. The security department has pulled some important registry artifacts from his device and has tasked you to examine these artifacts and determine the presence of secret files on his machine.**

>How many Files are available in the Artifacts folder on the Desktop?

![09d02e823dfae13c8f04231e0619ebdd.png](/resources/09d02e823dfae13c8f04231e0619ebdd.png)

We were given 6 registry hives as evidence and we have most of Eric Zimmerman's Tools (EZ Tools) to investigate this which the tool that can be used on registry hive has to be RegistryExplorer and RegRipper.

<details>
  <summary>Answer</summary>
<pre><code>6</code></pre>
</details>

***
## Windows Registry Forensics
![b341f32c7cf11869cb788412cb58eac5.png](/resources/b341f32c7cf11869cb788412cb58eac5.png)

I like Graphical Interface that RegistryExplorer provides so I loaded all registry at once and now lets start by going though each question until we complete the room.

>What is the Computer Name of the Machine found in the registry?

![91c6d76623c6d0d4437eeca6bba4901e.png](/resources/91c6d76623c6d0d4437eeca6bba4901e.png)

One feature I really like about Registry Explorer is the **bookmark** functionality, which automatically bookmarks interesting registry keys for us. For example, it bookmarks the `ControlSet001\Control\ComputerName\ComputerName` key from the **SYSTEM** registry hive, which stores the computer's name as you can see from the image above and its the answer of this question as well.

<details>
  <summary>Answer</summary>
<pre><code>JAMES</code></pre>
</details>

>When was the Administrator account created on this machine? (Format: yyyy-mm-dd hh:mm:ss)

![b5a591118d5a58bc70f2fe2ee4ef475d.png](/resources/b5a591118d5a58bc70f2fe2ee4ef475d.png)

To find any information related to Users accounts, we need to look into SAM registry which Registry Explorer already bookmarked `SAM\Domains\Account\Users` key for us which and then we can get the creation timestamp of user with RID 500 which is the default RID for Administrator on every WIndows system. 

<details>
  <summary>Answer</summary>
<pre><code>2021-03-17 14:58:48</code></pre>
</details>

>What is the RID associated with the Administrator account?
<details>
  <summary>Answer</summary>
<pre><code>500</code></pre>
</details>

>How many User accounts were observed on this machine?

![7019096341e37401451bb8abfdac6f22.png](/resources/7019096341e37401451bb8abfdac6f22.png)

Then we observed that there are total of 7 records from this registry key which indicates total of 7 users from 4 default users (Administrator, Guest and etc.) 

![a9600450f87a38c137add7d7c5250175.png](/resources/a9600450f87a38c137add7d7c5250175.png)

And other 3 normal user accounts but seem like there is a backdoor user as well with the name of "bdoor"

<details>
  <summary>Answer</summary>
<pre><code>7</code></pre>
</details>

>There seems to be a suspicious account created as a backdoor with RID 1013. What is the Account Name?
<details>
  <summary>Answer</summary>
<pre><code>bdoor</code></pre>
</details>

>What is the VPN connection this host connected to?

![7440516f4a9acf6fb1eb0adae75391e7.png](/resources/7440516f4a9acf6fb1eb0adae75391e7.png) 

There are several ways to get an answer on this question but the intended way is to inspect `Microsoft\Windows NT\CurrentVersion\NetworkList` registry key from **SOFTWARE** hive which is a key that hold information about networks the system connects to including wired, wireless, and VPN connections. and we can see that there is only one VPN listed on this key which is ProtonVPN and we also observed the first/last connected to the local time from this registry key as well.

<details>
  <summary>Answer</summary>
<pre><code>ProtonVPN</code></pre>
</details>

>When was the first VPN connection observed? (Format: YYYY-MM-DD HH:MM:SS)
<details>
  <summary>Answer</summary>
<pre><code>2022-10-12 19:52:36</code></pre>
</details>

>There were three shared folders observed on his machine. What is the path of the third share?

![32c1f1211f4a9f383f38ee2e933ddf1c.png](/resources/32c1f1211f4a9f383f38ee2e933ddf1c.png)

To get the name of each file shares, we have to inspect `ControlSet001\Services\LanmanServer\Shares` key from SYSTEM hive and Registry Explorer already got us covered! the third share was located on C drive and look like this shares store sensitive files just looking at its name.

<details>
  <summary>Answer</summary>
<pre><code>C:\RESTRICTED FILES</code></pre>
</details>

>What is the Last DHCP IP assigned to this host?

![f0e4e8f84d8b7fa47880352502b2dc0c.png](/resources/f0e4e8f84d8b7fa47880352502b2dc0c.png)

To get DHCP IP assigned to the host, We will have to look up the 
`ControlSet001\Services\Tcpip\Parameters\Interfaces` key from SYSTEM hive which we can see that the latest one of this list is 172.31.2.197 that was assigned by 172.31.0.1 DHCP Server.

<details>
  <summary>Answer</summary>
<pre><code>172.31.2.197</code></pre>
</details>

>The suspect seems to have accessed a file containing the secret coffee recipe. What is the name of the file?

![d9b259932c38ca46d732de762bc32baf.png](/resources/d9b259932c38ca46d732de762bc32baf.png)

When user opened any file, the `Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs` key of each user in NTUser.dat hive keep track of them which we can see that suspect seem to have accessed secret recipe file just after accessing the file share which mean this file was located on the file share.

<details>
  <summary>Answer</summary>
<pre><code>secret-recipe.pdf</code></pre>
</details>

>The suspect ran multiple commands in the run windows. What command was run to enumerate the network interfaces?

![01fc81f9018e68ae69be38c3075c4ac6.png](/resources/01fc81f9018e68ae69be38c3075c4ac6.png)

When user executed command via Run windows, `Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` key of each user (NTUser.dat hive) will keep track of them which we can see that the suspect used [pnputil](https://lolbas-project.github.io/lolbas/Binaries/Pnputil/) which is the binary used to install driver to enumerate network interface and devices and we also see other commands that could be used to enumerate resource such as `resmon`, system configuration (`msconfig`) and so on.

<details>
  <summary>Answer</summary>
<pre><code>pnputil /enum-interfaces</code></pre>
</details>

>In the file explorer, the user searched for a network utility to transfer files. What is the name of that tool?

![a96a2e4266cac579e9c5094f6f66ed7b.png](/resources/a96a2e4266cac579e9c5094f6f66ed7b.png)

When user searched for something using Windows Search, the
`Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery` key (in NTUser.dat) keep track of them which we can see that beside searching for secret files and recipe, the suspect also searched for netcat which is well known network utility tool that can be used for create remote connection and transfer file. 

<details>
  <summary>Answer</summary>
<pre><code>netcat</code></pre>
</details>

>What is the recent text file opened by the suspect?

![4b24cbeab6432d3e7b3a9a7807c5f7d2.png](/resources/4b24cbeab6432d3e7b3a9a7807c5f7d2.png)

Back to RecentDocs, we found the suspect opened another text file beside secret recipe as well and this file might contains secret code indicates by its file name. 

<details>
  <summary>Answer</summary>
<pre><code>secret-code.txt</code></pre>
</details>

>How many times was Powershell executed on this host?

![fb65f9fce5d4b8a96f3ef9634c7a46d1.png](/resources/fb65f9fce5d4b8a96f3ef9634c7a46d1.png)

When talking about program execution, there are several artifacts that could be used to find out when and what binary was executed but if we want to know which binary was executed by a user then we have to inspect `Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist` registry key for each NTUser.dat hive and the GUID that we gonna dig into is `{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}`, This GUID tracks the execution of programs and shortcuts launched by the user via the Start Menu or Desktop. and as you can see from the image above that PowerShell was executed 3 times in total.

<details>
  <summary>Answer</summary>
<pre><code>3</code></pre>
</details>

>The suspect also executed a network monitoring tool. What is the name of the tool?

![427d0ffabf6a3cb4e64a9994b03e635c.png](/resources/427d0ffabf6a3cb4e64a9994b03e635c.png)

Continue our search in UserAssist, we can see that WireShark was executed once and it can be used to monitor traffic so this is the answer of this question.

<details>
  <summary>Answer</summary>
<pre><code>wireshark</code></pre>
</details>

>Registry Hives also notes the amount of time a process is in focus. Examine the Hives. For how many seconds was ProtonVPN executed?

![f14985abe8945b188a0516624898238a.png](/resources/f14985abe8945b188a0516624898238a.png)

We can filter for ProtonVPN then we can see that there are 2 records of this program, but the first one is the installer so we got to get the focus time of the second one and convert it to seconds then we will have the answer of this question.

<details>
  <summary>Answer</summary>
<pre><code>343</code></pre>
</details>

>Everything.exe is a utility used to search for files in a Windows machine. What is the full path from which everything.exe was executed?

![ab576373f3af960133928e0b20e123e6.png](/resources/ab576373f3af960133928e0b20e123e6.png)

Lastly, we can search for this program then we will have the full path of this file right here.

<details>
  <summary>Answer</summary>
<pre><code>C:\Users\Administrator\Downloads\tools\Everything\Everything.exe</code></pre>
</details>

![edbd34fde93f36544da84622a163ab21.png](/resources/edbd34fde93f36544da84622a163ab21.png)
***