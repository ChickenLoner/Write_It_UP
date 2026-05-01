# [Blue Team Labs Online - Killer](https://blueteamlabs.online/home/investigation/killer-0fb56990a3)

![3b436a12e55fdbf14847901a11175a24.png](/resources/3b436a12e55fdbf14847901a11175a24.png)

After going through rigorous security awareness training also, the newly joined intern has fallen prey to a phishing email that claims that it provides Virus killing and burying services.

>**Reverse Engineering**

>**Tags**: Volatility PEStudio ResourceHacker HashCalc ProcessMonitor ProcessExplorer Autoruns T1547.001 T1566
* * *
**Scenario**
There is no patch for Human Stupidity.

After going through rigorous security awareness training also, the newly joined intern has fallen prey to a phishing email that claims that it provides Virus killing and burying services.

The IR team collected the memory dump of the intern’s machine before disconnecting the machine from the internet. Now as a junior malware analyst, your senior assigned the task to you to extract the viruskiller executable from memory, perform analysis and submit the IoCs.
* * *
## Environment Awareness
### Evidence & Tool Discovery
![580f62b6b7a72ae632fa57124cb4c829.png](/resources/580f62b6b7a72ae632fa57124cb4c829.png)

We have a memory dump in `MemoryDump` folder located on the desktop and we also have several tools within `Tools` folder too

Lets see what we can do with each tools
- pestudio : We can use this tool to conduct static analysis of Windows PE32 malware.
- resource hacker : We can also use this tool to conduct static analysis of a malware especially the resources it uses such as icon
- Autoruns : We can use this to find out persistence of malwares on Windows so we might have to conduct both static and dynamic analysis of a malware
- Hashcalc : We can use this to generate file hash
- Process Explorer : Task Manager on steroid
- Process Monitor : We can use this to conduct dynamic analysis of malware.
- volatility 2.6 : We can use this to conduct memory analysis of a memory dump we have.
- CyberChef : We can use this to decode, encode, decrypt and encrypt data

Now lets start the investigation.
***
## Investigation
>Q1) PID and PPID of Viruskiller executable

![c6fe93880d0d16a204de50457efb4539.png](/resources/c6fe93880d0d16a204de50457efb4539.png)

Lets start by determine which profile to use for the memory dump we have since we only have volatility 2 which required suitable profile for in-depth analysis, then we can see that there are 3 suitable profiles that we can use on this memory dump.

![a4895ac3a1380728d2e91b8cba27fbd1.png](/resources/a4895ac3a1380728d2e91b8cba27fbd1.png)

Then we can proceed with plugin that can be used to list processes such as `psscan`, `pslist`, `pstree` and `pstree` which we can see the `viruskiller.exe` process's PID and PPID right here.

<details>
  <summary>Answer</summary>
<pre><code>2736, 2880</code></pre>
</details>

>Q2) C2 Address: Port 

![027701d0f54decdc65c07de9497e0f62.png](/resources/027701d0f54decdc65c07de9497e0f62.png)

We can find any connection from processes with `netscan` plugin but even if we filtered for `viruskiller.exe`, the connection we want to look for might be at the bottom.

![680ac38596b998cc051cd13fc3a2d6b5.png](/resources/680ac38596b998cc051cd13fc3a2d6b5.png)

To filter those connection that not established then we can filter with string like "ESTABLISHED" then we will have C2 address and port that was contacted by this process right here.

<details>
  <summary>Answer</summary>
<pre><code>172.16.0.18:4872</code></pre>
</details>

>Q3) Volatility command used to dump a process executable

![de7e52c9ad5b191caaf87063e26185b7.png](/resources/de7e52c9ad5b191caaf87063e26185b7.png)

To dump an executable of a process, we have to use `procdump` plugin which we will have to use it on the next question.

<details>
  <summary>Answer</summary>
<pre><code>procdump</code></pre>
</details>

>Q4) SHA256 of viruskiller executable

![10dcbb7f4e2f817b9019ed9bc1d277b0.png](/resources/10dcbb7f4e2f817b9019ed9bc1d277b0.png)

After we dumped an executable process with `procdump` plugin, we can proceed with Hashcalc or pestudio to calculate SHA256 hash of this file but if you don't want to leave the terminal yet then we can use lolbin like `certutil` to generate the hash for us like this.

<details>
  <summary>Answer</summary>
<pre><code>8fb8adef07f4b351fc19a8e488542854d8eb83b5030563cd459eba0786e03eb4</code></pre>
</details>

>Q5) Compiler Timestamp of viruskiller

![1105ca4b54fe0b362304ace78df8d3c1.png](/resources/1105ca4b54fe0b362304ace78df8d3c1.png)

Lets open this viruskiller with pestudio, after wait for a while for the analysis then we will see the compiler timestamp of this malware right here.

<details>
  <summary>Answer</summary>
<pre><code>05/06/2020</code></pre>
</details>

>Q6) Which PE section has executable permissions

![40c23ff9babdaed1c1b85211233b3a5d.png](/resources/40c23ff9babdaed1c1b85211233b3a5d.png)

We can take a look at "sections" which we can see that there is only one section has executable permission which is **.text** section which should not be surprised since **.text** section contains all the executable codes the will be executed.

<details>
  <summary>Answer</summary>
<pre><code>.text</code></pre>
</details>

>Q7) Submit Company Name, File Description of viruskiller executable

![b80b124e3b8b4a1515c061f59b8a5ebe.png](/resources/b80b124e3b8b4a1515c061f59b8a5ebe.png)

pestudio also detect version of this executable which we can see them in "Version" and as you can see that its also contain Company Name and File Description of this file.

<details>
  <summary>Answer</summary>
<pre><code>Virus Killing Services, Kill and Buri The Virus</code></pre>
</details>

>Q8) What is the startup name of viruskiller

Its time to run this malware, when conducted dynamic malware analysis then we will have do launch 2-3 tools we found like procmon, procexp and Autoruns to detect and understand its behavior

![7b3a9a223dd2f2ad2d230cd0d031fa4a.png](/resources/7b3a9a223dd2f2ad2d230cd0d031fa4a.png)

 Autoruns detected new registry key has been added for persistence with the name of "killer_starts" which will execute a malware that copied itself to the new location (Q9)

<details>
  <summary>Answer</summary>
<pre><code>killer_starts</code></pre>
</details>

>Q9) After executing the viruskiller, to which location it is copied to maintain persistence

![0587b497344624a41ab72ed51d6213c9.png](/resources/0587b497344624a41ab72ed51d6213c9.png)

We can also see that after first Viruskiller successfully executed and terminiated itself, the new `viruskiller.exe` was executed from location we found on Q8

<details>
  <summary>Answer</summary>
<pre><code>C:\Users\BTLOTest\AppData\Roaming\virusburialground\viruskiller.exe</code></pre>
</details>

>Q10) Registry Path utilised by viruskiller to maintain persistence

![7b3a9a223dd2f2ad2d230cd0d031fa4a.png](/resources/7b3a9a223dd2f2ad2d230cd0d031fa4a.png)

Its run registry of this machine which mean any user if login, VirusKiller will be executed.

<details>
  <summary>Answer</summary>
<pre><code>HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run</code></pre>
</details>

![a25389220c5412a2ebd0d903d1ff1332.png](/resources/a25389220c5412a2ebd0d903d1ff1332.png)
https://blueteamlabs.online/achievement/share/52929/77
* * *