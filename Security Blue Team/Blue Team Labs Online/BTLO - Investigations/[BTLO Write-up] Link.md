# [Blue Team Labs Online - Link](https://blueteamlabs.online/home/investigation/link-a070b619d0)

![700a5ae47bfe0bb504d3666cf0b6da9d.png](/resources/700a5ae47bfe0bb504d3666cf0b6da9d.png)

>Digital Forensics

>**Tags**: Process Explorer findstr certutil T1036 T1059
* * *
**Scenario**
“I am a crime journalist for a reputed news agency. I was taking some notes last night in my com-puter; however, I saw a news in my drafts folder was updated at the same time and that was not me. I suspect I have been hacked. Please help me.” That’s what she said. I have disabled internet and administrator access on the PC for now. Good luck with the investigation.
* * *
## Environment Awareness
### Evidence & Tool Discovery
![0e90f0fe66fd1a5ee0c3859c661800b7.png](/resources/0e90f0fe66fd1a5ee0c3859c661800b7.png)

We are investigating and infected machine which have something to do with notepad and the tool available for us are Process Explorer and CyberChef so lets dive in! 

***
## Investigation
>Q1) Where is the DLL “urlmon.dll” being loaded from in the ‘notepad.exe’ process? Do you see any suspicious DLL loaded in the process? (Format: path\to\urlmon.dll)

![51e287d23d8cd9c3ccadb4a6156393c8.png](/resources/51e287d23d8cd9c3ccadb4a6156393c8.png)

Open notepad program after Process Explorer then utilize "Find" feature to find this dll then we will have this url located in `C:\Windows\System32`

<details>
  <summary>Answer</summary>
<pre><code>C:\Windows\System32\urlmon.dll</code></pre>
</details>

>Q2) What is the process ID related to a DLL Injection attack? (Format: PID)

![7ff37585cb132dc8154af28655743be7.png](/resources/7ff37585cb132dc8154af28655743be7.png)

There is nothing to be concerned about when we reading text file but as soon as I opened notepad via this icon, a black screen shown up indicates that some commands must be executed.

![8fad2a50c391e217fa4717151112b7ce.png](/resources/8fad2a50c391e217fa4717151112b7ce.png)

Using process explorer to find out which command line was executed, we can see another `notepad.exe` was executed as process 14212 before the legitimate notepad was executed. 

<details>
  <summary>Answer</summary>
<pre><code>14212</code></pre>
</details>

>Q3) Where is the malicious DLL file located? (Format: drive:\path\to\malicious\dll)

![e82050ab8cac55a7509e70cfca0c4e55.png](/resources/e82050ab8cac55a7509e70cfca0c4e55.png)

Since we already have the the path of this suspicious URL then we can find it and use CyberChef to find some interesting strings

![25ebe8b4d07f48ab6dd4602f0032100f.png](/resources/25ebe8b4d07f48ab6dd4602f0032100f.png)

We can see that this file was set attribute to be hidden.

![833886cda60c7b027e0bb46ebde6980a.png](/resources/833886cda60c7b027e0bb46ebde6980a.png)

Once we open this file on CyberChef and searched for ".dll" string then we can see a dll that could be located on this system. 

![aaedf36da21db8ab710d4fc2d0d95de2.png](/resources/aaedf36da21db8ab710d4fc2d0d95de2.png)

There it is!

<details>
  <summary>Answer</summary>
<pre><code>C:\Users\BTLOTest\Links\getback.dll</code></pre>
</details>

>Q4) What is the IP of the attacker-owned server? (Format: X.X.X.X)

![99bf719277789cf8ff825f1403d5e5ad.png](/resources/99bf719277789cf8ff825f1403d5e5ad.png)

Now we can open dll we just found on CyberChef which we can see that there is base64 encoded PowerShell command ready to be executed once this dll is loaded.

![8fbe3fa149a6749b4aad549a2ab01de4.png](/resources/8fbe3fa149a6749b4aad549a2ab01de4.png)

After decoded it then we can see that it will attempt to create reverse shell connection to this IP address on port 13993
<details>
  <summary>Answer</summary>
<pre><code>3.110.164.126</code></pre>
</details>

https://blueteamlabs.online/achievement/share/52929/95
* * *
## Summary
An DLL Injection attempt was made to create a reverse shell connection to specific IP address every time `notepad` on the menu bar is launched.

###  IOC
- `74813c40eb293670c1646ec8b822b19e276da390212358a8c75c5e52cdc73d6b` (SHA256 of fake notepad)
- `8481026bddc4dde9040b171461400b839dfdf232f10454f02905e198a4792c9d` (SHA256 of injected dll)
- `3.110.164.126` (likely to be AWS IP address)
* * *