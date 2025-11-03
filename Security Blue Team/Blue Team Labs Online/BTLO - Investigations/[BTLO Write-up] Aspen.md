# [Blue Team Labs Online - Aspen](https://blueteamlabs.online/home/investigation/aspen-fa1048174e)
<div align=center>

![50ff2a5bb6449eb0026b6d6aa3e95555.png](/resources/50ff2a5bb6449eb0026b6d6aa3e95555.png)

</div>
FrostGuard sent some thieves to Dr. Lovelace's residence. What exactly is it after?

>**Digital Forensics**

>**Tags**: Arsenal Image Mounter MFTECmd Timeline Explorer Registry Explorer IF015.001
* * *
**Scenario**
Ava Lovelace—the world’s first programmer and head of the Council of Frost—had her home broken into. The thief seemed to have accessed her work computer, nothing else was tampered with. Can you find the motive for this breach?
* * *
## Environment Awareness
### Evidence Discovery
![430ea3205bb2c3fd1d139d15bb307f5d.png](/resources/430ea3205bb2c3fd1d139d15bb307f5d.png)

We are provide with vhdx disk image as a sole evidence on this investigation machine which we will have to mount it to discover more evidences.
***
### Tool Discovery and Preparation
There are 4 tools inside `Tools` folder on the Desktop which are
- **Arsenal Image Mounter** that could be used to mount disk image files
- **MFTECmd** from Eric Zimmerman's Tools that can be used to parse `$MFT` file (Master File Table)

we will have to mount this disk image with **Arsenal Image Mounter** first.

![577235465618baee78928d31ba66b392.png](/resources/577235465618baee78928d31ba66b392.png)

After open Arsenal Image Mounter program, click "Mount disk image"

![f437ff0663dc7dc1457c29e9d4be37c2.png](/resources/f437ff0663dc7dc1457c29e9d4be37c2.png)

You will have "Disk device, write temporary" option since we do need this write permission to make it online, then we can proceed with "OK"

![98c1851a40d8cecd04a024d2ada90877.png](/resources/98c1851a40d8cecd04a024d2ada90877.png)

Then 2 pop-up will appear, just click "YES" twice to make this disk image online.

![98fb85805e25bf9763efdf8a284a148b.png](/resources/98fb85805e25bf9763efdf8a284a148b.png)

Now we should be able to browse this disk image on our D drive!
* * *
## Investigation
>Q1) There is evidence of an anti-forensic tool during the break-in. What is the name of the software, what ITM ID corresponds with it, and when was it installed? (Format: Tool, AXXXX, YYYY-MM-DD HH:MM:SS UTC)

![8b0b07cb1ba365f25787bba34a88fca4.png](/resources/8b0b07cb1ba365f25787bba34a88fca4.png)

This disk image stores artifacts collected by **KAPE** then we can use Registry Explorer to browser **SOFTWARE** registry hive then locate to "**Uninstall**" registry key that holds path of each program that has uninstall executable and also have installation timestamp on each software.

![fa921dde3df58af022fa41a9abdb8283.png](/resources/fa921dde3df58af022fa41a9abdb8283.png)

Which we can see [Wise Force Deleter](https://www.wisecleaner.com/wise-force-deleter.html) program was installed which can be used to easily and securely delete files.

![c5c128e71df6112fe3c0a77f893cdbd4.png](/resources/c5c128e71df6112fe3c0a77f893cdbd4.png)
This action match [AF015: File Deletion](https://insiderthreatmatrix.org/articles/AR5/sections/AF015) from Insider Threat Matrix

<details>
  <summary>Answer</summary>
<pre><code>Wise Force Deleter, AF015, 2024-09-26 16:38:22 UTC</code></pre>
</details>

>Q2) It seems like multiple documents were accessed on Lovelace’s machine. What three projects, related to AI/Tech, have been accessed? Place in order of access time. (Format: Project Name, Project Name, Project Name)

![15ee1e7328faf11bb671183d0f9717d2.png](/resources/15ee1e7328faf11bb671183d0f9717d2.png)

The next key I utilized for this question is "**RecentDocs**" key of lovelace user's **NTUSER.dat** hive which we can see that there are 3 pdf files that has "Project" in their name so to get order of access, we have to take a look at "Value Name" field which lower number mean access before higher number. 

<details>
  <summary>Answer</summary>
<pre><code>Project Oracle, Project Phoenix, Project Thaw</code></pre>
</details>

>Q3) These documents were not local to Lovelace’s machine? From where did the hacker retrieve these confidential files? (Format: Location)

![2584a30f1ea80655c5431134b7490dec.png](/resources/2584a30f1ea80655c5431134b7490dec.png)

Next artifacts I was thinking of when asking about Origin of the file is **Zone.Identifier** so I used `MFTECmd.exe` to parse `$MFT` then use **Timeline Explorer** to open its result.

![8621ccd3b2ca4f5dbd75a54911f2da14.png](/resources/8621ccd3b2ca4f5dbd75a54911f2da14.png)

Then I filtered for "Zone.Identifier" of a filename that contains "Project" which we can see Zone ID Content of first record of this filter indicating it was downloaded from **OneDrive**

<details>
  <summary>Answer</summary>
<pre><code>Onedrive</code></pre>
</details>

>Q4) The hacker did not brute force Lovelace’s computer, given the ‘Invalid Login Count.’ In respective order, can you provide the User ID, Total Login Count, and Last Password Change? (Format: XXXX, XX, YYYY-MM-DD HH:MM:SS UTC)

![4a0aea0282f546e126efb738704680de.png](/resources/4a0aea0282f546e126efb738704680de.png)

This time, we will have to use Registry Explorer to open **SAM** registry hive then navigate to **Users** key to get all answers needed for this question. 
<details>
  <summary>Answer</summary>
<pre><code>1010, 13, 2024-09-26 15:34:24 UTC</code></pre>
</details>

>Q5) Review the searches typed by the Ava Lovelace account. It looks like the hacker was looking for documents, but what was the first term executed? (Format: String)

![fe697c216af523b5f7c52c4a45b8aef0.png](/resources/fe697c216af523b5f7c52c4a45b8aef0.png)

We can find search type history of each user from **WordWheelQuery** key reside their **NTUSER.dat** registry hive which we can see that the first search is the one with has the lowest Mru Position.
<details>
  <summary>Answer</summary>
<pre><code>AvaLovelace@Icesend.onmicrosoft.com</code></pre>
</details>

>Q6) Given the string in the previous question, it looks like the hacker utilized another piece of information to access the resources online (Q3). What is the name of the file that has login credentials? (Format: File.txt)

![5bc65419f9b41061857caf37e1974ca0.png](/resources/5bc65419f9b41061857caf37e1974ca0.png)

We can come back to **RecentDocs** registry key which we can see this text file was opened by lovelace user and it is the correct answer of this question.

![09a8fe5d84715b96bc424de5327f77d5.png](/resources/09a8fe5d84715b96bc424de5327f77d5.png)

Alternatively, you can also find this on **Recent** folder of lovelace user right here.

<details>
  <summary>Answer</summary>
<pre><code>MSFT_Password.txt</code></pre>
</details>

>Q7) The hacker changed the password for Lovelace’s account—the account in Q5. In what directory is the attacker storing this information and other stolen information, supposedly? (Format: Directory Name)

![aae628620e184ca601da413ef37fdac4.png](/resources/aae628620e184ca601da413ef37fdac4.png)

We're still at the **RecentDocs** registry key then we can see this weird folder with "Exfil" in its name which is a directory created to store information gathered on this machine.

![94ee5b90946e3c1ae021ba2e186bbc00.png](/resources/94ee5b90946e3c1ae021ba2e186bbc00.png)

Alternatively, you can also find this on **Recent** folder of lovelace user right here.

<details>
  <summary>Answer</summary>
<pre><code>Exfil-FOI</code></pre>
</details>

>Q8) Looks like the hacker tried to start an RDP session outbound to another system before settling for that Cloud Storage platform. What is the Execution Time of the program and the ITM ID that correlates with this event? (Format: YYYY-MM-DD HH:MM:SS UTC, MXXXX.XXX)

![15c3cfb4ebc913cd3c211a46af6d6a97.png](/resources/15c3cfb4ebc913cd3c211a46af6d6a97.png)

This time, I utilized **UserAssist** key from **SOFTWARE** registry hive to find the execution timestamp of RemoteDesktop program right here.

![034fccdf985dc51d3f73d0054bf98a82.png](/resources/034fccdf985dc51d3f73d0054bf98a82.png)

This match [ME003.010: RDP](https://insiderthreatmatrix.org/articles/AR2/sections/ME003/subsections/ME003.010) Clients of Insider Threat Matrix

<details>
  <summary>Answer</summary>
<pre><code>2024-09-26 16:21:02 UTC, ME003.010</code></pre>
</details>

>Q9) The hacker also shut down the system—after wiping the drive of the stolen files—to prevent RAM capture. What time did this occur? (Format: YYYY-MM-DD-SS HH:MM:SS UTC)

![7fdb8c3368dc26481bf435930e1140a6.png](/resources/7fdb8c3368dc26481bf435930e1140a6.png)

This question was a little bit mislead me into finding ShutDownTime registry key on this computer (which return incorrect answer of this question) so I went back to UserAssist key again and submit the timestamp of Wise Force Deleter Uninstallation executable file which got accepted as the correct answer. 🤔
<details>
  <summary>Answer</summary>
<pre><code>2024-09-26 16:54:58 UTC</code></pre>
</details>

>Q10) The hacker utilized the built-in image capture tool: Snipping. How many times was it run, and what is the total focus time of the tool? This further proves the screenshots being placed in the directory (Q7). (Format: XX, XXm, XXs, MXXXX)

![e3f77d7f76efbfc3d69a0192de4186d4.png](/resources/e3f77d7f76efbfc3d69a0192de4186d4.png)

We know that **UserAssist** Key also stores run counter and focus time so we will just have to find `SnippingTool.exe` and retrieve both values right here

![7257ddc76b01251aec6d6673e09a4a54.png](/resources/7257ddc76b01251aec6d6673e09a4a54.png)
This action match [ME013: Media Capture](https://insiderthreatmatrix.org/articles/AR2/sections/ME013) of Insider Threat Matrix

<details>
  <summary>Answer</summary>
<pre><code>15, 08m, 50s, ME013</code></pre>
</details>

![cbb2fe3af9fe615dddf796bb61ce81f0.png](/resources/cbb2fe3af9fe615dddf796bb61ce81f0.png)
https://blueteamlabs.online/achievement/share/52929/247
* * *