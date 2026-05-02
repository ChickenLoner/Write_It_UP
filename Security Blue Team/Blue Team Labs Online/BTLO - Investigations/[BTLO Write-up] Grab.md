# [Blue Team Labs Online - Grab](https://blueteamlabs.online/home/investigation/grab-ec32e35935)

![313527870a0b8da59551de94eb159461.png](/resources/313527870a0b8da59551de94eb159461.png)

>Reverse Engineering

>**Tags**: Sysinternals UPX
* * *
**Scenario**
It’s Raining Tokens all Over. Users lost their discord tokens due to an active malware campaign. Your Company’s product community engagement manager’s laptop was also infected. Static Analysis of the malware sample didn’t reveal much about the behavior. Show your expertise in performing dynamic analysis and find the IoC’s.
* * *
## Investigation
>Q1) What is the name of the PowerShell script that is responsible for stealing tokens? (Format: filename.ext)

![3d2cce5ef647c46bfad6129795bed9d5.png](/resources/3d2cce5ef647c46bfad6129795bed9d5.png)

After reading scenario and took a look at what we have, there is no doubt that we will have to conduct dynamic malware analysis.

![48499961ad6be898572a8dbf2eb24032.png](/resources/48499961ad6be898572a8dbf2eb24032.png)

This lab gave us upx so I checked if this malware is packed with upx and of course it does.

![b5e442f37d06d2b59e2852ca7d63c6a2.png](/resources/b5e442f37d06d2b59e2852ca7d63c6a2.png)

 I think You need to unpack this malware but I did it anyway.

![6a8faae3401ba3e69871168cc900adeb.png](/resources/6a8faae3401ba3e69871168cc900adeb.png)

Extracted sysinternal tools then run process explorer and process monitor as Administrator then execute this malware as Administrator too.

![3f60c3ab1159c700c7a137e2e6467de3.png](/resources/3f60c3ab1159c700c7a137e2e6467de3.png)

After process was terminated by itself (confirmed by looking at process explorer) then we can go to "Tools" > "Process Tree" on process monitor which you will see process tree of this malware right here.

![e27f2c7badc2f520f6cec37d6f39c7f3.png](/resources/e27f2c7badc2f520f6cec37d6f39c7f3.png)

Take a look at commands of these processes then we will see this PowerShell script was executed at the bottom of this process tree.

<details>
  <summary>Answer</summary>
<pre><code>grabber.ps1</code></pre>
</details>

>Q2) What is the file size of the PowerShell script, in bytes? (Format: Size)

![a1d6755424cb995f41fdc91ca2a5a548.png](/resources/a1d6755424cb995f41fdc91ca2a5a548.png)

But then if we went to location where we found PowerShell script executed, we will not find anything so maybe this malware will delete all files so we will have to kill process as fast as we can to prevent this from happening but I want to try get everything I could from process monitor before I do that.

![cfccf62368ef7174406b2e26d4f4bab4.png](/resources/cfccf62368ef7174406b2e26d4f4bab4.png)

We still have a way to obtain size of this file via `powershell.exe` process right here.

<details>
  <summary>Answer</summary>
<pre><code>2277</code></pre>
</details>

>Q3) Submit the full webhook URL used to POST the stolen tokens (Format: https://domain.tld/something) 

![dc0b60e9401e1952e35f4a39f7579586.png](/resources/dc0b60e9401e1952e35f4a39f7579586.png)

I still could not give up yet so I want to see if we could really get webhook from process monitor so I went back to process tree and add cmd process and its children to include filter.

![02ebad780a2e1e67f9de4bbe309a7b59.png](/resources/02ebad780a2e1e67f9de4bbe309a7b59.png)

Then after took a look at environment variable of these process, I found discord webhook right here.

![1cd32c40af87bd84135d777441d45440.png](/resources/1cd32c40af87bd84135d777441d45440.png)

Open event properties to copy it, but since this url is too long for BTLO clipboard then you will have to separate it and copy each part to submit. 

<details>
  <summary>Answer</summary>
<pre><code>https://discord.com/api/webhooks/1139680955767471872/AazbHGNyN7wsXZCTpBNInq7LUGhCbmjVA0Hi5NG_fNv-DhVFLTgvxHs8g2hTFF_FDL63</code></pre>
</details>

>Q4) Submit the file format in which the stolen tokens were posted to the webhook URL (Format: FormatName)

![3df3b570521222f6f8c5357d5a800862.png](/resources/3df3b570521222f6f8c5357d5a800862.png)

Now its time for reflex training, execute malware again as Administrator then kill it as fast as you can then if you're fast enough then you should be able to see `grabber.ps1` that survived for deletion.

![276e2d9c2ab80adc5a37de55eb2c6072.png](/resources/276e2d9c2ab80adc5a37de55eb2c6072.png)

After opened it then we will see that it will use regex (Q7) to get token on infected system then convert it to JSON and send it to discord webhook.

<details>
  <summary>Answer</summary>
<pre><code>JSON</code></pre>
</details>

>Q5) What is the name of the bat file responsible for generating the above PowerShell script? (Format: filename.ext)

![4965b666833b31a9c28b77c75a4a0f3f.png](/resources/4965b666833b31a9c28b77c75a4a0f3f.png)

If we take a look at malware process tree again then you can see that after malware was executed, this command was executed first and I think that this bat script is responsible for creation of PowerShell (if you want to confirm, get your reflex and do it faster than you should be able to get this bat script but I gave up 🤣)

<details>
  <summary>Answer</summary>
<pre><code>abduct.bat</code></pre>
</details>

>Q6) What is the size of this bat file, in bytes? (Format: Size)

![71329a0796a2de8f08e12f0171e514a3.png](/resources/71329a0796a2de8f08e12f0171e514a3.png)

Use the same method from Q2 then we will have file size of this bat script
<details>
  <summary>Answer</summary>
<pre><code>6987</code></pre>
</details>

>Q7) Submit the regex pattern found in the sample which is used to look for Discord tokens (Format: RegexPattern) 
<details>
  <summary>Answer</summary>
<pre><code>[\w-]{24}\.[\w-]{6}\.[\w-]{27}|mfa\.[\w-]{84}</code></pre>
</details>

>Q8) What is the domain queried by the sample to get the public IP of the victim? (Format: sub.domain.tld)

![76765d1c7e1f3e6bb1af35660e754620.png](/resources/76765d1c7e1f3e6bb1af35660e754620.png)

`api.ipfy.org` is a free API service to get public IP address of device making this request and this malware does this probably for C2 purpose but this should be the end of our investigation.

<details>
  <summary>Answer</summary>
<pre><code>api.ipfy.org</code></pre>
</details>

![bf15b27f68d6aea372597a43e16b21c7.png](/resources/bf15b27f68d6aea372597a43e16b21c7.png)
https://blueteamlabs.online/achievement/share/52929/176
* * *