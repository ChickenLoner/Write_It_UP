# [Blue Team Labs Online - Replaced](https://blueteamlabs.online/home/investigation/replaced-43712c72e2)

![3723207d0377fa5fab1da6203deea54f.png](/resources/3723207d0377fa5fab1da6203deea54f.png)

>**Reverse Engineering**

>**Tags**: OSINT Visual Studio Code Text Editor T1027 T1105
* * *
**Scenario**
You thought you had seen it all when it comes to malware but today is different. You are presented with a fresh sample but it appears different from the others.
* * *
## Environment Awareness
### Evidence & Tool Discovery
![acdedc430850cdec30e54bbf7f9f896d.png](/resources/acdedc430850cdec30e54bbf7f9f896d.png)

We have a sample inside `Sample` folder located on the desktop and we have several tool with text editor capabilities such as VSCode and Sublime Text which mean this malware is not PE32 executable but some sort of scripting file.

***
## Investigation
>Q1) Look at the malware. Can you identify the language used? (Format: Language)

![c39026a03b2cde6d57e9f1ec06beb885.png](/resources/c39026a03b2cde6d57e9f1ec06beb885.png)

After opened sample in text editor, we can see that this sample utilized Visual Basic scripting language to execute arbitrary commands and we will need to deobfuscate them to understand what it does. 

<details>
  <summary>Answer</summary>
<pre><code>Visual Basic</code></pre>
</details>

>Q2) Decode Camtasia. What is the name of the Class used for retrieving the next stage and the associated method? (Format: Class, Method)

![1b55ba1269cdec93cb1903b021f59a3a.png](/resources/1b55ba1269cdec93cb1903b021f59a3a.png)

`Camtasia` variable is quite long but lets see how this variable will be used then we should be able to find decoding function that will make sense of this variable.

![d962b5c3c50db2734ff332debb02e722.png](/resources/d962b5c3c50db2734ff332debb02e722.png)

At line 25, we can see that there is "Replace" function being used to replace these long string to nothing and this explain why `Camtasia` variable is quite long.

![e13327893f97f424e54c826feb3a0aad.png](/resources/e13327893f97f424e54c826feb3a0aad.png)

We can use Find / Replace feature in text editor to replace those strings with nothing then we can finally see that this script use **WebClient** class and **DownloadData** method to fetch content from pastetext (Q3) and save it as PowerShell script then executed it 

<details>
  <summary>Answer</summary>
<pre><code>WebClient, DownloadData</code></pre>
</details>

>Q3) What is the domain and associated file the malware reaches out to? (Format: http://.../file)

![6ab408bb378c7e5cbd7b8ae25182f48a.png](/resources/6ab408bb378c7e5cbd7b8ae25182f48a.png)
<details>
  <summary>Answer</summary>
<pre><code>https://pastetext.net/raw/T00ez4me11</code></pre>
</details>

>Q4) Take note of the execution policy used by the PowerShell command. Conduct some research and list all execution policies available for PowerShell in Alphabetical order (Format: PolicyA, PolicyB, PolicyC...)

![8503a832b4aa8563ddd7a746bf972f67.png](/resources/8503a832b4aa8563ddd7a746bf972f67.png)

There are total of 7 execution policies that can be used to execute command via PowerShell

<details>
  <summary>Answer</summary>
<pre><code>AllSigned, Bypass, Default, RemoteSigned, Restricted, Undefined, Unrestricted</code></pre>
</details>

>Q5) Name the path to where the malware will be downloaded to (Including the file itself) (Format: Format: X:\..\..\file.ext)

![e08176783f6cc06895d3730c706433b7.png](/resources/e08176783f6cc06895d3730c706433b7.png)
<details>
  <summary>Answer</summary>
<pre><code>C:\Users\Public\BTLOvbs101.PS1</code></pre>
</details>

![761009eff911ffa3e9f25e0b2d317fe1.png](/resources/761009eff911ffa3e9f25e0b2d317fe1.png)
https://blueteamlabs.online/achievement/share/52929/102
* * *