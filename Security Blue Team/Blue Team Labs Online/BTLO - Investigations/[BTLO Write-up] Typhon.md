# [Blue Team Labs Online - Typhon](https://blueteamlabs.online/home/investigation/typhon-339cc99cba)
<div align=center>

![fbaef5242263e9ddc5c063928582673d.png](../../../_resources/fbaef5242263e9ddc5c063928582673d.png)
</div>
A few nights ago, I downloaded a program called NG-IA.exe from a sketchy forum. If anyone knows how to stop the pop-ups, please help me. I’m running out of options.

>Indicent Response

>**Tags**: Procmon, Timeline Explorer, Wireshark, Process Explorer, TA0003, T1569.002, T1567, T1564.001
* * *
**Scenario**
I made a terrible mistake. A few nights ago, I downloaded a program called NG-IA.exe from a sketchy forum. It was advertised as a ‘Next-Gen AI tool’ that could automate my tasks. But ever since I ran it, things have changed in ways I can't explain. One time, when I ran it, nothing seemed to happen—luckily, I managed to capture the network traffic during that attempt. Now, it reappears every time I think I’ve removed it like it knows exactly what I’m trying to do. If anyone knows how to stop this, please help me. I’m running out of options.
* * *
## Investigation Submission
![933572be1e5c43d0ca20dae2d27eb8cf.png](../../../_resources/933572be1e5c43d0ca20dae2d27eb8cf.png)

This challenge provides with pcap file and malware inside "Investigation" folder and we have sysinternals to use which mean its dynamic malware analysis time. 

![54efecf1d19f8fc327d887e75a1383a9.png](../../../_resources/54efecf1d19f8fc327d887e75a1383a9.png)

Upon executed provided malware, There are a lot of ghost pop-up appeared and the only way to kill it is to kill `svchost.exe` process that is not the legitimate one.

But is that all? I don't think so, Shall we start our investigation for real?

>Q1) What is the domain and the IP address that the program attempts to connect to? (Format: Domain,IP)

![78d2a927fb4933f27045f312b8262101.png](../../../_resources/78d2a927fb4933f27045f312b8262101.png)

Then lets get the domain and IP address this program attempts to connect to from pcap file first.
<details>
  <summary>Answer</summary>
<pre><code>www.b4s1lisk.xyz, 159.65.12.25</code></pre>
</details>

>Q2) What is the HTTP request path and the encoded string returned in the response when the program communicates with the server? (Format: Path,String)

![3deded4fb1eb5f943bb5f75115b2408d.png](../../../_resources/3deded4fb1eb5f943bb5f75115b2408d.png)

Then we could see a path along with body that was sent from C2

![c00440eff1b05b114c5c8c730ccc6b36.png](../../../_resources/c00440eff1b05b114c5c8c730ccc6b36.png)
FYI, its base64 encoded but this question just asked for base64 string.
<details>
  <summary>Answer</summary>
<pre><code>/join, U3RvbmVHbGFyZSA=</code></pre>
</details>

>Q3) Try to mimic the server response. There is a script under the Tools section that you can use, but you will need to make some modifications before it works. Consider how the program locates the server and how you might redirect it to your script. Once this is done, the binary will extract multiple files. What is the name of the DLL that is extracted? (Format: Filename)

![c4b6fdfb80e60c9590e4351daae469be.png](../../../_resources/c4b6fdfb80e60c9590e4351daae469be.png)

First lets analyze this script first, then we can see that it will mimick C2 server by sending HTTP 200 response with string we found back to malware (this is edited script, you need to edit these 2 yourselves)

![42082d2d00d23d6a132f068e7bef6d07.png](../../../_resources/42082d2d00d23d6a132f068e7bef6d07.png)

Then do not forget to add this domain to our hosts file.

![7d6e282bbfec560adb6aef2cbb388754.png](../../../_resources/7d6e282bbfec560adb6aef2cbb388754.png)

Execute this script then execute malware again (this time with ProcMon capturing events), we could see that this script worked as intended.

![6e5a40fdeebde831116845e27f174c13.png](../../../_resources/6e5a40fdeebde831116845e27f174c13.png)

And we can also see `conhost.exe` under `spoolsv.exe` which is impossible in normal circumstance which make this a process created by malware.


![09933c7e1576578f1fb7911f83d4fd5e.png](../../../_resources/09933c7e1576578f1fb7911f83d4fd5e.png)

To make our life easier, add malware process ID and malware process name to our filter so we can only find it from those million events.

![e48d3f7be73808a570e9a99240cff583.png](../../../_resources/e48d3f7be73808a570e9a99240cff583.png)

Lets add PID of malware as parent process ID filter.

![6158016fdddbfd2daf2c3d9037b2d6a5.png](../../../_resources/6158016fdddbfd2daf2c3d9037b2d6a5.png)

Then we can finally see `rundll32.exe` (Q4) were used to executed `typhon.dll` under user temp folder.

<details>
  <summary>Answer</summary>
<pre><code>typhon.dll</code></pre>
</details>

>Q4) Which LOLBAS is leveraged to execute the DLL? (Format: LOLBAS Name)
<details>
  <summary>Answer</summary>
<pre><code>rundll32.exe</code></pre>
</details>

>Q5) During the first execution of the DLL, a specific function is called, and a file is dropped. What is the name of this function, and what is the name of the dropped file? (Format: Function,Filename)

![26a9ebbc4cd8c1fc73de820ef43ad4fa.png](../../../_resources/26a9ebbc4cd8c1fc73de820ef43ad4fa.png)

Since malicious dll was dropped on user temp folder than should the other files too which we can see other 2 files dropped on the same directory

![f04c211af9d507fd0a4e133823b6d02f.png](../../../_resources/f04c211af9d507fd0a4e133823b6d02f.png)

Navigate to this folder, we will see more files that were actually dropped by this malware.

![be47ea9cde26fb2cf2709edaa20e5c83.png](../../../_resources/be47ea9cde26fb2cf2709edaa20e5c83.png)

Inside "vipera" folder is a text file that log our keystroke (keylogger)

![4e125e71e9775696104a56a376593331.png](../../../_resources/4e125e71e9775696104a56a376593331.png)

Lets go back to see which command dropped `spoolsv.exe` then we can see a function that dropped this malware right here.

<details>
  <summary>Answer</summary>
<pre><code>yurei, spoolsv.exe</code></pre>
<pre><code></code></pre>
</details>

>Q6) The program replicates itself in a hidden directory. What is the name of the replicated file, and what is its MD5 hash? (Format: Filename,Hash)

![3f6ef06e1c4ce76581ed8a00a3829100.png](../../../_resources/3f6ef06e1c4ce76581ed8a00a3829100.png)

From user temp directory, We also found `dwm.exe` file that has the identical size of the malware and after calculated hash of both files, we can confirm that `dwm.exe` is indeed a replica of malware.
<details>
  <summary>Answer</summary>
<pre><code>dwm.exe, 2C21D810BDD449C3668092AC62B3B896</code></pre>
</details>

>Q7) Which LOLBAS does the binary use to execute the DLL in the background repeatedly, and what is the name of the scheduled task it creates? (Format: LOLBAS, TaskName)

![517d343620217f852fff7cf29aec1f20.png](../../../_resources/517d343620217f852fff7cf29aec1f20.png)
We can open Task Scheduler window to find out the answer of this question right away then we will see this task will execute every 2 minutes and the exe that responsible for task is `schtasks.exe`
<details>
  <summary>Answer</summary>
<pre><code>schtasks.exe, TenguTask</code></pre>
</details>

>Q8) After the command is executed repeatedly in the background, the program attempts to upload a file to a specific online storage service. What is the name of this service? (Format: Storage Service Name)

Intended way probably used strings on `typhon.dll` but I solved it by guessing😂, it was a dropbox
<details>
  <summary>Answer</summary>
<pre><code>dropbox</code></pre>
</details>

>Q9) To maintain persistence, under which registry key does the binary create an entry? (Format: Registry Key)

![787c5ad4d6697de61ca15fcb997f06eb.png](../../../_resources/787c5ad4d6697de61ca15fcb997f06eb.png)

Then we will see the registry key that will be added which is HKCU run key and the name of the key created under this key is "Typhoon" (Q10)

![b5ffa2943fa048311cb83c0a522c02de.png](../../../_resources/b5ffa2943fa048311cb83c0a522c02de.png)

The executable that added to this key is a replica of the malware inside user temp folder.

<details>
  <summary>Answer</summary>
<pre><code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run</code></pre>
</details>

>Q10) What is the name of the registry entry added? (Format: Entry Name)
<details>
  <summary>Answer</summary>
<pre><code>Typhon</code></pre>
</details>

![779c019e08d09f335a3cec4592d1dc5d.png](../../../_resources/779c019e08d09f335a3cec4592d1dc5d.png)

Another way that could aid this investigation is to install sysmon provides in Sysinternals folder.

![02cb37df48f85b30faf276868c744227.png](../../../_resources/02cb37df48f85b30faf276868c744227.png)

Which we could see that it also logged commands executed by this malware. so choose the tool you know might be the way that make this investigation easier.

![695c9360ce325960d4216bf2ceefab16.png](../../../_resources/695c9360ce325960d4216bf2ceefab16.png)
https://blueteamlabs.online/achievement/share/52929/241
* * *