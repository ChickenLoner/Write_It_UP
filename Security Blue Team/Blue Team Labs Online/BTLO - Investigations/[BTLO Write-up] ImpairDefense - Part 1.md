# [Blue Team Labs Online - ImpairDefense - Part 1](https://blueteamlabs.online/home/investigation/impairdefense-part-1-80e1af5822)

![6fe9fea7f3720e7c2fe78f623df784aa.png](/resources/6fe9fea7f3720e7c2fe78f623df784aa.png)

>Incident Response

>**Tags**: ProcMon T1070 T1562
* * *
**Scenario**
Analyse the procmon events of a malware activity which attempts to defeat some of the defences.
* * *
## Investigation Submission
>Q1) What is the malware process name?

![cd58ad6bcb3886dbe06179e72c6beb94.png](/resources/cd58ad6bcb3886dbe06179e72c6beb94.png)

This investigation only have CyberChef and Process Monitor (ProcMon) for us to investigate Log file saved from ProcMon so lets just straight up open it up!

![ca5e4915d1b4d90ef39a617a282ca768.png](/resources/ca5e4915d1b4d90ef39a617a282ca768.png)

Open process tree window by go to "Tools" -> "process tree" then we could see malware process tree right here and there were a lot of commands executed by this malware and most of them related to disable security features on infected host like the name of this investigation "Impair Defense"

<details>
  <summary>Answer</summary>
<pre><code>j.exe</code></pre>
</details>

>Q2) What is the first child process invoked by the malware?
<details>
  <summary>Answer</summary>
<pre><code>cmd.exe</code></pre>
</details>

>Q3) What is the first command used to clear the audit policies?

![088789122982e720228d695d1a8f33f9.png](/resources/088789122982e720228d695d1a8f33f9.png)

This malware use `auditpol` with `/clear` to clear audit policies and `/y` to confirm everything that will ask user when prompt this command on the CLI.
<details>
  <summary>Answer</summary>
<pre><code>auditpol /clear /y</code></pre>
</details>

>Q4) What is the command used to disable the firewall? 

![78d231df429a946b449781b9a871a294.png](/resources/78d231df429a946b449781b9a871a294.png)

This malware use `netsh advfirewall` to set every profiles on infected host to "off" effectively disable the firewall.
<details>
  <summary>Answer</summary>
<pre><code>netsh  advfirewall set allprofiles state off</code></pre>
</details>

>Q5) What is the PID of the event that removed Defender definitions?

![b335c5016f2f51d2d57ed6eb0a3e1415.png](/resources/b335c5016f2f51d2d57ed6eb0a3e1415.png)

Malware used [mpcmdrun.exe](https://learn.microsoft.com/en-us/defender-endpoint/command-line-arguments-microsoft-defender-antivirus) with `-RemoveDefinitions -All` to restore installed security intelligence to the original default set hence remove up-to-date malware signatures.

<details>
  <summary>Answer</summary>
<pre><code>6832</code></pre>
</details>

>Q6) What are the windows defender mp preferences enabled by the malware?

![91ee12e3bf72d896a0ea088b2af290b5.png](/resources/91ee12e3bf72d896a0ea088b2af290b5.png)

Malware spawned PowerShell to run `Set-MpPreference` to disable 5 security features of Windows Defender starting from
- `DisableRealtimeMonitoring` : Disables real-time protection
- `DisableScriptScanning` : Disables the scanning of scripts (like PowerShell or JavaScript) for malicious behavior
- `DisableBehaviorMonitoring` : Disables behavior monitoring, which is a feature that detects suspicious behavior patterns that might indicate a malware attack, even if the malware signature is not known.
- `DisableIOAVProtection` : Disables the scanning of files downloaded from the internet or other network sources.
- `DisableIntrusionPreventionSystem` : Disables the Intrusion Prevention System (IPS) feature

<details>
  <summary>Answer</summary>
<pre><code>DisableRealtimeMonitoring, DisableScriptScanning, DisableBehaviorMonitoring,
DisableIOAVProtection, DisableIntrusionPreventionSystem</code></pre>
</details>

>Q7) What are the logs cleared by the malware?

![bb0e1c2e39a1cd914f7ad21dee9e7c8d.png](/resources/bb0e1c2e39a1cd914f7ad21dee9e7c8d.png)
Malware use `wevutil` with `cl` option to clear 4 logs from Sysmon to System.
<details>
  <summary>Answer</summary>
<pre><code>Sysmon, Security, Application, System</code></pre>
</details>

![0ed3ca9b564b35a2cdf4a9ef31983258.png](/resources/0ed3ca9b564b35a2cdf4a9ef31983258.png)
https://blueteamlabs.online/achievement/share/52929/124
* * *