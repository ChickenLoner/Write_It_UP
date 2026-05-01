# [Blue Team Labs Online - First Day](https://blueteamlabs.online/home/investigation/first-day-b533e3d1a3)

![2df7d1743c259fb9c313f65753448c2d.png](/resources/2df7d1743c259fb9c313f65753448c2d.png)

Today marks your first day on the job as a Malware Analyst. Your boss sends an unknown malicious sample over Slack to you; to put your skills to the test. He wants to see if you have the ability to research, report and fully analyse this sample without any mistakes.

>Reverse Engineering

>**Tags**: VirusTotal PEstudio OSINT Procmon IDA T1041 T1055.001
* * *
**Scenario**
Today marks your first day on the job as a Malware Analyst. Your boss sends an unknown malicious sample over Slack to you; to put your skills to the test. He wants to see if you have the ability to research, report and fully analyse this sample without any mistakes. He concludes with a “Have fun! Don’t forget to take notes along the way”. Time to show him what you’ve learned over the past few months.

The sandbox machine you're using doesn't have an internet connection. To access VirusTotal and other online resources for research purposes, you should use your host machine and not the lab.
* * *
## Investigation Submission
>Q1) Can you identify the malware family of the provided sample? Research is key! (Format: Family Name)

![3d85a96a2ccb0cff617b703598ac1258.png](/resources/3d85a96a2ccb0cff617b703598ac1258.png)

We have pestudio, IDE Freeware and SysinternalsSuite to analyze malware sample so lets start with calculate filehash using pestudio and search it online.

![3e1f7dad94d86700dd13e8ed88585f27.png](/resources/3e1f7dad94d86700dd13e8ed88585f27.png)

Then we can see beside of this hash, there are a lot of indicators telling us this file is not a simple file but a malware.

![b46f74dc4839c9461a3168fe69802c10.png](/resources/b46f74dc4839c9461a3168fe69802c10.png)

Search its hash on VirusTotal then we can see that it matched Stealc and Oski YARA rule so we have 2 choices here.

![88af35a8a2b3473433609f6c164c6cb9.png](/resources/88af35a8a2b3473433609f6c164c6cb9.png)

We can confirm it via Community tab that contained this file in Oski Stealer collection so this is Oski malware.

<details>
  <summary>Answer</summary>
<pre><code>oski</code></pre>
</details>

>Q2) This malware family is known to reach out to its C2 for files. Locate the C2 and find which country it is based in (Format: IP, country) 

![e852797b09d981c7410010e1833c89ec.png](/resources/e852797b09d981c7410010e1833c89ec.png)

Go to Relation tab then we can see that this file will download 7 files from this IP address.

![9eeed80d6532880338aa61270724b576.png](/resources/9eeed80d6532880338aa61270724b576.png)

Then after followed this IP address on VirusTotal, we can see that its associated to Lithuania.

<details>
  <summary>Answer</summary>
<pre><code>62.77.159.212, Lithuania</code></pre>
</details>

>Q3) Commonly, this type of malware is known to download 7 additional files to aid in data exfiltration. List the files it downloads in alphabetical order (A-Z). (Hint: OSINT! Maybe someone else has researched this malware family before...) (Format: FileA.ext, FileB.ext, FileC.ext, ...)

![5177f46aeb84b2ebab32089bdce22b51.png](/resources/5177f46aeb84b2ebab32089bdce22b51.png)

We can dig into each file on VirusTotal but OSINT is the most effective way to get an answer of this question, [CyberAsk](https://www.cyberark.com/resources/threat-research-blog/meet-oski-stealer-an-in-depth-analysis-of-the-popular-credential-stealer) already published a blog about this malware and its capabilities which we can see that those 7 files we saw from VirusTotal are actually these 7 dll files

![97808c5ccd8499b779dc748b8ae9976b.png](/resources/97808c5ccd8499b779dc748b8ae9976b.png)

Copy them and let CyberChef or ChatGPT sort it to submit the correct answer.

<details>
  <summary>Answer</summary>
<pre><code>freebl3.dll,mozglue.dll,msvcp140.dll,nss3.dll,softokn3.dll,sqlite3.dll,vcruntime140.dll</code></pre>
</details>

>Q4) Can you find the entry point of the malware? (Format: 0xXXXXXXXX)

![5cbdd428415c6516375b54ab51bc3e77.png](/resources/5cbdd428415c6516375b54ab51bc3e77.png)

Back to pestudio then go to optional header which we can see entry-point address of the malware right here.
<details>
  <summary>Answer</summary>
<pre><code>0x0000717B</code></pre>
</details>

>Q5) Exfiltration happens quick and you can miss it if you blink. Where is the folder located for data exfiltration? (Format: X:\...\) 

![3063826c4c7a6f5450b79eb96c9ba40b.png](/resources/3063826c4c7a6f5450b79eb96c9ba40b.png)

Its time for procmon! lets open procmon and execute the malware.

![a6f384e571abe5a76b0de8c1d161ddb6.png](/resources/a6f384e571abe5a76b0de8c1d161ddb6.png)

To make our life easier, go to "Tools" -> "Process Tree" to open process tree windows then we can add this malware process to our included list.

![3d894cf7ab2ca046ad960ef0818a0220.png](/resources/3d894cf7ab2ca046ad960ef0818a0220.png)

Then we can see that there is a folder under ProgramData that store files collected by a malware.

<details>
  <summary>Answer</summary>
<pre><code>C:\ProgramData</code></pre>
</details>

>Q6) Perform some research to identify the type of cipher used to obfuscate the strings and then locate its cipher key (Format: Cipher-type, numeric_key)

![9b5c0142d0344ae5076ebfeccdd097b5.png](/resources/9b5c0142d0344ae5076ebfeccdd097b5.png)

From CyberAsk blog, we know that this malware use RC4 to obfuscate the string so lets load this malware on IDA and find a key and try to find a function that resemble `stringsSetup` function. 

![02c41a32abf1032aef7c1c255ec5ee05.png](/resources/02c41a32abf1032aef7c1c255ec5ee05.png)

First I went to `.rdata` section of this malware that hold read-only data which I found this weird numerical number resemble a key format.

![2410dc6d7de9cd0b677f78b82d71ef30.png](/resources/2410dc6d7de9cd0b677f78b82d71ef30.png)

I followed it and sure enough, this is the key use for decryption!

<details>
  <summary>Answer</summary>
<pre><code>RC4, 056139954853430408</code></pre>
</details>

>Q7) A configuration file is used to decide what needs to be exfiltrated. Find the name of this config and it’s filetype (Format: filename.ext)

![ed29932b08a090592f78ea033ca25f22.png](/resources/ed29932b08a090592f78ea033ca25f22.png)

We can get the answer of this question by reading CyberArk blog right here.

<details>
  <summary>Answer</summary>
<pre><code>main.php</code></pre>
</details>

![7d7f20ba7e8bcfa2221b27fef87b505c.png](/resources/7d7f20ba7e8bcfa2221b27fef87b505c.png)
https://blueteamlabs.online/achievement/share/52929/101
* * *