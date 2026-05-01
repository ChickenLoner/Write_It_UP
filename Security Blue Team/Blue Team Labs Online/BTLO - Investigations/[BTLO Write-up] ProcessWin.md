# [Blue Team Labs Online - ProcessWin](https://blueteamlabs.online/home/investigation/processwin-a42f853814)

![ef1d54b6dbb04c373476d5c417a34467.png](/resources/ef1d54b6dbb04c373476d5c417a34467.png)

The provided evidence consists of a snapshot of running processes from different scenarios. Using the samples provided, answer the questions to understand the process activity.

>Incident Response

>**Tags**: Linux CLI Text Editor T1055
* * *
**Scenario**
The provided evidence consists of a snapshot of running processes from different scenarios. Using the samples provided, answer the questions to understand the process activity. It's important to do research too!

Note: Read the provided help.txt file.
* * *
## Investigation Submission
>Q1) Identify the suspicious relationship between a process and the parent process (Format: PPID, PID)

![abc7061d72fa728ecc03bbc006d52743.png](/resources/abc7061d72fa728ecc03bbc006d52743.png)

All files we need is located inside "Evidence" directory on the desktop and we only have 4 files so lets just right in. 

![d5ad75034844279ee885cfb0f75722e2.png](/resources/d5ad75034844279ee885cfb0f75722e2.png)

Read content of `Q1_2.txt` then we could see that it is the process tree output created by [PsList](https://learn.microsoft.com/en-us/sysinternals/downloads/pslist) and since we got the process tree than everything should be easy to figure out.

![e857704e829f8635a00054aae775d2d3.png](/resources/e857704e829f8635a00054aae775d2d3.png)

Then we will finally notice `lsass` under `explorer` which is impossible in normal circumstance since it should be the child process on `wininit.exe` and should be only 1 on the system.

<details>
  <summary>Answer</summary>
<pre><code>3916, 5756</code></pre>
</details>

>Q2) What is the legitimate parent process for the PID process found in Q1 (Format: process.exe)

![3308e958e16ca7f5a4cf9a244ca70d8f.png](/resources/3308e958e16ca7f5a4cf9a244ca70d8f.png)

You might notice legitimate `lsass.exe` process right here under `wininit.exe` which is the legitimate parent process of this `lsass.exe` according to Windows Process Genealogy.

![0f89dc43b0c8972528d73de44e4eff5c.png](/resources/0f89dc43b0c8972528d73de44e4eff5c.png)
<details>
  <summary>Answer</summary>
<pre><code>wininit.exe</code></pre>
</details>

>Q3) Identify the system process being executed from an anomalous location. Submit the process name and file path (Format: process.exe, drive:\path\to\process.exe)

![71a4b47c1fb7df5d7bd6fd4cce84202d.png](/resources/71a4b47c1fb7df5d7bd6fd4cce84202d.png)

After take a look at `Q3_4_5.txt` we might notice `services.exe` was executed under `System` folder which is not where its belong sinve it has has to be in `System32`.

<details>
  <summary>Answer</summary>
<pre><code>services.exe,C:\Windows\System\services.exe</code></pre>
</details>

>Q4) What is the legitimate parent process for the malicious process name found in Q3? (Format: process.exe) 

Use Windows process genealogy image then we could see that the legitimate parent process of `services.exe` is `wininit.exe` same as `lsass.exe` 
<details>
  <summary>Answer</summary>
<pre><code>wininit.exe</code></pre>
</details>

>Q5) What is the legitimate location of the malicious process name found in Q3? (Format: drive:\path\to\process.exe)

![7137728d9d4f88ec2772e2b6e17ad7d0.png](/resources/7137728d9d4f88ec2772e2b6e17ad7d0.png)

It has to be inside `System32` folder along with the rest of Windows critical processes.

<details>
  <summary>Answer</summary>
<pre><code>C:\Windows\System32\services.exe</code></pre>
</details>

>Q6) Submit the PID of the process that partially mimics a system process (Format: PID)

![23de97463702fb4c0d4b2669e74ba0cf.png](/resources/23de97463702fb4c0d4b2669e74ba0cf.png)

After open `Q6.txt` then we could see that there is one process partially mimics `svhost.exe` process right here.
<details>
  <summary>Answer</summary>
<pre><code>3396</code></pre>
</details>

>Q7) Identify the malicious process name from the provided process list (Hint: Focus on process names) (Format: PID)

![ac65d42ba4eaf1945b1b82ee6bd2e560.png](/resources/ac65d42ba4eaf1945b1b82ee6bd2e560.png)

This time, we found `lssas.exe` that mimics `lsass.exe`.

<details>
  <summary>Answer</summary>
<pre><code>1428</code></pre>
</details>

>Q8) Research the legitimate parent process name of svchost.exe (Format: process.exe)

![2180db6e178ee12245916eb7ef0d323a.png](/resources/2180db6e178ee12245916eb7ef0d323a.png)
`svchost.exe` is a child process of `services.exe` and we will find many of them on Windows system because they're responsible for running Windows services.
<details>
  <summary>Answer</summary>
<pre><code>services.exe</code></pre>
</details>

![8ea62cafc0dc3bcfa4865861dd334606.png](/resources/8ea62cafc0dc3bcfa4865861dd334606.png)
https://blueteamlabs.online/achievement/share/52929/135
* * *