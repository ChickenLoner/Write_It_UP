# [HackTheBox Sherlocks - Pikaptcha](https://app.hackthebox.com/sherlocks/Pikaptcha)
![b3f4d6878c450e4ebeeb5f07168f3317.png](/_resources/b3f4d6878c450e4ebeeb5f07168f3317.png)
**Scenario:**
Happy Grunwald contacted the sysadmin, Alonzo, because of issues he had downloading the latest version of Microsoft Office. He had received an email saying he needed to update, and clicked the link to do it. He reported that he visited the website and solved a captcha, but no office download page came back. Alonzo, who himself was bombarded with phishing attacks last year and was now aware of attacker tactics, immediately notified the security team to isolate the machine as he suspected an attack. You are provided with network traffic and endpoint artifacts to answer questions about what happened.

* * *
## Background
Before we start doing some actions, lets learn how this challenge was inspired first!

![ac0e51bede498335e9b8cbf5928a6965.png](/_resources/ac0e51bede498335e9b8cbf5928a6965.png)
Around August while I was scrolling X for threat intel and keeping up with cybersec news then I found [this](https://x.com/g0njxa/status/1825940825400029483) legend posting threat intel about Lumam Stealer using Fake Captcha that hand holding user into running malicious powershell command via Run dialog box (`Win + R`) which will result in Lumma Stealer at the end.

![0baadae312e276cdaabf4069b0e625d0.png](/_resources/0baadae312e276cdaabf4069b0e625d0.png)
And it was kinda hyped for a while and John Hammond uploaded [YouTube](https://www.youtube.com/watch?v=lSa_wHW1pgQ) video in 17th Sep and even published [PoC](https://github.com/JohnHammond/recaptcha-phish) that could be used to duplicate this action

So what we could expected as forensic analyst?
- Browser History of a user visiting website that hosts malicious captcha 
- [RunMRU](https://medium.com/@boutnaru/the-windows-foreniscs-journey-run-mru-run-dialog-box-most-recently-used-57375a02d724) registry key of a user that executed any command via Run dialog box
- PowerShell History of that user
- Traffic to malicious site and C2 

Alright with these information we could get start with our investigation!

>Task 1: It is crucial to understand any payloads executed on the system for initial access. Analyzing registry hive for user happy grunwald. What is the full command that was run to download and execute the stager.

![eeb28ed990247c4885484e02db7ef06b.png](/_resources/eeb28ed990247c4885484e02db7ef06b.png)

This lab provided us with many registry hives and prefetch folder so we could start with RunMRU registry key of happy grunwald user.

![c695d04aab8dfb109be1d5b305d8c5d1.png](/_resources/c695d04aab8dfb109be1d5b305d8c5d1.png)

Open it with registry explorer or RegRipper will do just fine then we will have a command that was executed with Run dialog box right here along with execution time of this command! and you can see that its a powershell command that will download another powershell script to execute.

**My AntiVirus keep yelling at my note-taking app after pasted the command to this app so I will not put the answer of this question.

>Task 2: At what time in UTC did the malicious payload execute?

![15a9b62540d8cb7f218a51dc624b2d3d.png](/_resources/15a9b62540d8cb7f218a51dc624b2d3d.png)
<details>
  <summary>Answer</summary>
<pre><code>2024-09-23 05:07:45</code></pre>
</details>

>Task 3: The payload which was executed initially downloaded a PowerShell script and executed it in memory. What is sha256 hash of the script?

![c3957f5f0a11e7ba8662b45f38b2ec11.png](/_resources/c3957f5f0a11e7ba8662b45f38b2ec11.png)

This lab did not provide us with malicious PowerShell script that was downloaded but we still have pcapng file so we can filter for ps1 file and export it out of Wireshark.

![e537ef2d619a3b951de9c08178d291f0.png](/_resources/e537ef2d619a3b951de9c08178d291f0.png)
Use your hash calculator tool as your disposal, notice that this script is another PowerShell command with base64 encoded.
<details>
  <summary>Answer</summary>
<pre><code>579284442094e1a44bea9cfb7d8d794c8977714f827c97bcb2822a97742914de</code></pre>
</details>

>Task 4: To which port did the reverse shell connect?

![649dfd6fc032093fc49b8a7a265bc4e2.png](/_resources/649dfd6fc032093fc49b8a7a265bc4e2.png)
Decode base64 command that we can see that its a reverse shell command to 43.205.115.44 on port 6969  
<details>
  <summary>Answer</summary>
<pre><code>6969</code></pre>
</details>

>Task 5: For how many seconds was the reverse shell connection established between C2 and the victim's workstation?

![933f87cc8316be3bf7bc95c7e62ea6fe.png](/_resources/933f87cc8316be3bf7bc95c7e62ea6fe.png)

So we can filter for `tcp.port == 6969` and to calculate session time by deduct FIN,PSH,ACK packet that is the end of this connection and 3-way handshake that established the connection

![19e3e96019d32fc66c2d503ee15bba18.png](/_resources/19e3e96019d32fc66c2d503ee15bba18.png)

Easily solved by let ChatGPT write a script and calculate in itself.

<details>
  <summary>Answer</summary>
<pre><code>403</code></pre>
</details>

![53e20985051ccd66d3b2485f07e6f1c8.png](/_resources/53e20985051ccd66d3b2485f07e6f1c8.png)
Here is the script that was used to calculate duration of this session.

![315221935288aa605178f480ecf6863d.png](/_resources/315221935288aa605178f480ecf6863d.png)
Bonus: After the threat actor got a reverse shell, `whoami` and `ipconfig` were executed followed by downloading SharpHound script to temp folder to enumerate AD.

>Task 6: Attacker hosted a malicious Captcha to lure in users. What is the name of the function which contains the malicious payload to be pasted in victim's clipboard?

![b95b5d4b6c5c6503d78c0dd05ba81f97.png](/_resources/b95b5d4b6c5c6503d78c0dd05ba81f97.png)
Lets just assume that user downloaded PowerShell script from the same IP address that hosted fake captcha so I filtered by `!(http.user_agent == "Microsoft-Delivery-Optimization/10.0") && http.request.method == GET` (focus to add an IP address but that's fine) which we will have to take a look at index page on packet 57448

![c0eca775843db54c5052036d64fb605e.png](/_resources/c0eca775843db54c5052036d64fb605e.png)
Which we can see that a function that set clipboard and stores malicious PowerShell payload is `stageClipboard`

<details>
  <summary>Answer</summary>
<pre><code>stageClipboard</code></pre>
</details>

Thats concluded of this investigation!
![11ae985b5cd4670988acac91348a56f2.png](/_resources/11ae985b5cd4670988acac91348a56f2.png)
* * *
