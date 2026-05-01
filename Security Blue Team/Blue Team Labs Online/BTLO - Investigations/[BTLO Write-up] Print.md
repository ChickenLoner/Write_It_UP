# [Blue Team Labs Online - Print](https://blueteamlabs.online/home/investigation/print-55373539b2)

![0f90951c1d3fec46fbe17397f1dea912.png](/resources/0f90951c1d3fec46fbe17397f1dea912.png)

The red team helped to create a vulnerable setup and a working exploit As a blue teamer, it's your turn to analyze the logs to identify the artifacts and submit them to the SOC team.

>**Incident Response**

>**Tags**: Wireshark Event Viewer BTL1 T1210 T1059
* * *
**Scenario**
Our security team came to know about the latest exploit on Windows Print Services. As you are part of the detection team you were asked to submit the artifacts to create detection rules. The red team helped to create a vulnerable setup and a working exploit.

As a blue teamer, it's your turn to analyze the logs to identify the artifacts and submit them to the SOC team.
* * *
## Environment Awareness
### Evidence & Tool Discovery
![30d9bb47808ab7b647567509d5820911.png](/resources/30d9bb47808ab7b647567509d5820911.png)

We have event logs and pcapng file within `Logs_PrintVulnerability`

For the tools, We have Wireshark and built-in event viewer to open these files so lets start our investigation.
***
## Investigation
>Q1) Submit the Domain name used by the red teamers for their test setup

![04bc4bb34d90a5e83555063c0cf4a400.png](/resources/04bc4bb34d90a5e83555063c0cf4a400.png)

There are total of 42 events within sysmon log but there is only 1 network connection event from this sysmon which we can see that redteam was using this domain for their test setup

<details>
  <summary>Answer</summary>
<pre><code>redteam.lab</code></pre>
</details>

>Q2) From the network traffic, what is the name of the file that is transferred via SMB?

![39c2f40d72e49e672dcafae80b0364dc.png](/resources/39c2f40d72e49e672dcafae80b0364dc.png)

After open network traffic, we can see that Red Team used SMB to transfer this dll from their share. 

<details>
  <summary>Answer</summary>
<pre><code>printevil.dll</code></pre>
</details>

>Q3) What is the C drive location where the file from the previous question is copied?

![5591fa88433571d19b8b99501695a512.png](/resources/5591fa88433571d19b8b99501695a512.png)

We can use event ID 11 (FileCreated) to find where the file was located/created on the system like this and this is a path well-known for [PrintNightmare](https://www.trendmicro.com/en_th/research/21/h/detecting-printnightmare-exploit-attempts-with-trend-micro-vision-one-and-cloud-one.html) vulnerability which is a local privilege escalation target print spooler service running as SYSTEM.

<details>
  <summary>Answer</summary>
<pre><code> C:\Windows\System32\spool\drivers\x64\3\New\printevil.dll </code></pre>
</details>

>Q4) What is the attacker's IP:Port for reverse shell?

![8430601a71b33254336f447cf60d710a.png](/resources/8430601a71b33254336f447cf60d710a.png)

From the event ID 3, we know that the red teamer was using this IP address and port 443 for reverse shell connection which we can see that the process responsible for this connection is `rundll32.exe` which is lolbin used to execute dll file and the dll file that was executed is the one we found from previous question.

<details>
  <summary>Answer</summary>
<pre><code>10.0.2.5:443</code></pre>
</details>

>Q5) Submit EventID, AccessMask, ShareName when Accountname="printuser", Sourceaddress=Attacker's IP and Relative Target Name is "spoolss"

![1cd8e82bda157e0268fd242fa477d5d8.png](/resources/1cd8e82bda157e0268fd242fa477d5d8.png)

We can open Security event log in event viewer and try to find for "spoolss" process which we can see this event has all the answers we are looking for. 

<details>
  <summary>Answer</summary>
<pre><code>5145, 0x3, \\*\IPC$ </code></pre>
</details>

>Q6) Submit Parent Command Line for the process WerFault.exe

![215f66bfb18d88c475e4790cad35a742.png](/resources/215f66bfb18d88c475e4790cad35a742.png)

`WerFault.exe` is Windows Error Reporting Fault which can be used to [deploy malware](https://www.bleepingcomputer.com/news/security/hackers-abuse-windows-error-reporting-tool-to-deploy-malware/#:~:text=WerFault%20is%20the%20standard%20Windows,and%20receive%20potential%20solution%20recommendations.) or create DLL with the same name as legitimate one for DLL sideloading attack but it also indicates application crash like this case.

<details>
  <summary>Answer</summary>
<pre><code>C:\Windows\System32\spoolsv.exe</code></pre>
</details>

>Q7) After getting the reverse shell, the attacker tried the command “whoami”, what will be the output of this command? Note: whoami displays user, group, and privileges information for the user who is currently logged on

![6e1ffe2feca17c2adfa3637ffbbee1d6.png](/resources/6e1ffe2feca17c2adfa3637ffbbee1d6.png)

Once PrintNightmare was successfully exploited, Red teamer will have a reverse shell of NT AUTHORITY\SYSTEM

<details>
  <summary>Answer</summary>
<pre><code>NT AUTHORITY\SYSTEM</code></pre>
</details>

![1137676d45ba1172a6c44d03ac036116.png](/resources/1137676d45ba1172a6c44d03ac036116.png)
https://blueteamlabs.online/achievement/share/52929/73
* * *
## Summary
Red teamer conducted a test on PrintNightmare vulnerability which is a local privilege escalation vulnerability that if success, it will result with SYSTEM privilege shell or FULL compromised on that Windows system.
* * *