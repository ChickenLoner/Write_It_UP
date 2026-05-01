# [Blue Team Labs Online - Dissect](https://blueteamlabs.online/home/investigation/dissect-5c52a5da04)

![08de137e360670057d602321009f5680.png](/resources/08de137e360670057d602321009f5680.png)

XYZ Company is expanding its in-house security team capabilities and doing rapid experimentation on different open-source frameworks to perform DFIR.

>Digital Forensics

>**Tags**: dissect T1059
* * *
**Scenario**
XYZ Company is expanding its in-house security team capabilities and doing rapid experimentation on different open-source frameworks to perform DFIR. You were assigned a framework called “dissect” to test and validate the capabilities.

Boss quickly performed some actions(confidential data theft and a reverse shell case) on a machine and provided you with a disk image and asked you to prepare a proof of concept with “dissect” framework. Disk Image is placed on the desktop.

Research the framework. All the Best!
* * *
## Investigation Submission
>Q1) Submit the hostname and ip address of the target disk image (Format: hostname, x.x.x.x)

![f222fa8cd746131d99b375f81ee5c082.png](/resources/f222fa8cd746131d99b375f81ee5c082.png)

We got a disk image file on investigation desktop and the only tool we can use on this investigation is [dissect](https://docs.dissect.tools/en/stable/usage/introduction.html) so we can read the documentation to find out how we can use this tool and what options/plugins are available for us.

![8ec2b53f3a957f656bc517b3be240b28.png](/resources/8ec2b53f3a957f656bc517b3be240b28.png)

Which we will find that we can use `target-query` with `-f` tag with `hostname` and `ips` to retrieve answers of this question from disk image.

![12f34199ed441705db3dae221414fade.png](/resources/12f34199ed441705db3dae221414fade.png)

There you go.

<details>
  <summary>Answer</summary>
<pre><code>DESKTOP-42S4JRT ,10.0.2.30</code></pre>
</details>

>Q2) Submit the usernames of the 3 accounts present on the system (Format: username1, username2, username3)

![ba87f02f89877f7c07b967b90e56b8e8.png](/resources/ba87f02f89877f7c07b967b90e56b8e8.png)

There are 2 ways you can do this, first is to use `target-shell` to access files on this disk image directly

![a62246804316090e872ebd8beed4b9f0.png](/resources/a62246804316090e872ebd8beed4b9f0.png)

Which you can see that there are 3 users under 

![652eed0281d16346ad91b1ca029fa8bb.png](/resources/652eed0281d16346ad91b1ca029fa8bb.png)

The other way is to use `target-query` with `users` like this.

<details>
  <summary>Answer</summary>
<pre><code>jack, rose, steve</code></pre>
</details>

>Q3) Submit the full urls of the two confidential files that user downloaded (Format: http://something/something.ext, http://...)

![761b5c164bcbba102ad306b73efe015d.png](/resources/761b5c164bcbba102ad306b73efe015d.png)

If you didn't know which plugin to use next, run `target-query -l` which will display all available plugins.

For this one, we have to use `target-query dissectpoc.E01 -f iexplore.history -q | rdump -j > history.json` which will query Internet Explorer history then pipe output to `rdump` and make it json so we can search an output from dissect directly (since we can't use grep with the output from `target-query`)

![a031689de4f40dea78c53197bcfab65b.png](/resources/a031689de4f40dea78c53197bcfab65b.png)

Then we will have 2 files accessed from the same url right here.

<details>
  <summary>Answer</summary>
<pre><code>http://192.168.1.7/confidential_project_files/ProjectHunt_EarluEstimates_Confidential.pdf, http://192.168.1.7/confidential_project_files/Q4_Finances_Confidential.pdf</code></pre>
</details>

>Q4) Steve copied the confidential files to a USB drive. Submit the Friendly name of the USB (Format: USBFriendlyName)

![740730d8062b158e3c973bd434ee42d7.png](/resources/740730d8062b158e3c973bd434ee42d7.png)
Use `usb` plugin to retrieve information about any USB plug-in to this system.

<details>
  <summary>Answer</summary>
<pre><code>SanDisk Ultra USB Device</code></pre>
</details>

>Q5) Boss added a folder path as exclusion in Windows defender. Submit the exclusion path (Format: C:\directory\...)

![6431332a6d18d2e9bcc1e0f392c8e334.png](/resources/6431332a6d18d2e9bcc1e0f392c8e334.png)

I tried `defender.evtx` but did not work so I used `target-query dissectpoc.E01 -f evtx -q | rdump -j > evtx.json` then we can see that there is a folder on steve's desktop was added to exclusion.
<details>
  <summary>Answer</summary>
<pre><code>C:\Users\steve\Desktop\superfileInside</code></pre>
</details>

>Q6) Submit the full url from which reverse.exe was downloaded (Format: http://something...)

![650dc9c8ee0a322f9566d085b5ac70a2.png](/resources/650dc9c8ee0a322f9566d085b5ac70a2.png)

There are several plugins that can retrieve browser's download history and `chrome.downloads` is the one that we have to use to retrieve an answer of this question which you can see that user steve downloaded this file from Google Chrome on another internal IP address that hosted this file. 

<details>
  <summary>Answer</summary>
<pre><code>http://10.0.2.15:8000/reverse.exe</code></pre>
</details>

>Q7) Submit the SHA1 hash of reverse.exe (Format: SHA1Hash)

![28fe4e5d886f4b8af16f9c9211fc276c.png](/resources/28fe4e5d886f4b8af16f9c9211fc276c.png)

The only artifact that contains SHA1 of executable files on Windows is Amcache so we can use `amcache` plugin with `grep` and `rdump` to get SHA1 of this file like as shown above.
<details>
  <summary>Answer</summary>
<pre><code>5949c949292be4f0be28bb1323d73b1911d9432d</code></pre>
</details>

>Q8) Submit the registry key added by the boss for reverse.exe to maintain persistence (Format: KeyName)

![aa3921ac66e82a58201549b838a1b514.png](/resources/aa3921ac66e82a58201549b838a1b514.png)
The popular key used to maintain persistence is run key so we can use `runkeys` plugin to retrieve all run keys from disk image like this then we could see that `reverse.exe` path was added to "KeyAddedByBOSS" key under run key. 
<details>
  <summary>Answer</summary>
<pre><code>KeyAddedByBOSS</code></pre>
</details>

>Q9) Name of the file stored in recyclebin (Format: filename.ext)

![7cd9fec2b53810734859c5c93f7d62b5.png](/resources/7cd9fec2b53810734859c5c93f7d62b5.png)

We can use `recyclebin` plugin for this which you can see the only text file inside `$Recyble.bin`, the alternative way to find this answer is to dig into disk image with `target-shell` directly.

<details>
  <summary>Answer</summary>
<pre><code>MeetingMom.txt</code></pre>
</details>

>Q10) Boss kept a flag for you to find out (Hint: I capture the screens) (Format: flag{something})

![597e2c9721870f6931e58ab64f6e925b.png](/resources/597e2c9721870f6931e58ab64f6e925b.png)

The hint is pointing us to Screenshots folder inside steve's picture folder so we can use `target-shell` with `save` option to download this screenshot and open it.

![c275134077f5d3e142ec2742dae5dfac.png](/resources/c275134077f5d3e142ec2742dae5dfac.png)

Then we will have a flag of this question right here.

<details>
  <summary>Answer</summary>
<pre><code>flag{yougotthisdude}</code></pre>
</details>

![5864a2ac35ab3056a18222c777e6209d.png](/resources/5864a2ac35ab3056a18222c777e6209d.png)
https://blueteamlabs.online/achievement/share/52929/141
* * *