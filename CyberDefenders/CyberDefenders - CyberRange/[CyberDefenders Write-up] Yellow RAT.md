# [CyberDefenders - Yellow RAT](https://cyberdefenders.org/blueteam-ctf-challenges/yellow-rat/)
Created: 08/10/2024 13:44
Last Updated: 09/10/2024 10:03
* * *
>**Category**: Threat Intel
* * *
**Scenario:**
During a regular IT security check at GlobalTech Industries, abnormal network traffic was detected from multiple workstations. Upon initial investigation, it was discovered that certain employees' search queries were being redirected to unfamiliar websites. This discovery raised concerns and prompted a more thorough investigation. Your task is to investigate this incident and gather as much information as possible.

**Tools**:
- VirusTotal

* * *
## Questions
>Q1: Understanding the adversary helps defend against attacks. What is the name of the malware family that causes abnormal network traffic?

![77ab9a54107d0690a30a82982c2713bb.png](../../_resources/77ab9a54107d0690a30a82982c2713bb.png)

This challenge gave us file hash of a malware so we can start by searching it on VirusTotal which we can see that popular threat label of this file is not match the answer format at all but at least we know that this is Jupyter Infostealer

And we could go to "Community" tab to find out the answer since there are so many community comments on this file.

![44b56fd968048f26d7821f107e27dcf1.png](../../_resources/44b56fd968048f26d7821f107e27dcf1.png)

After scrolling for a bit, now we got the name and also reference links to do our own research.

<details>
  <summary>Answer</summary>
<pre><code>Yellow Cockatoo RAT</code></pre>
</details>

>Q2: As part of our incident response, knowing common filenames the malware uses can help scan other workstations for potential infection. What is the common filename associated with the malware discovered on our workstations?

![9546c61bc66fdb296c82a4964268b132.png](../../_resources/9546c61bc66fdb296c82a4964268b132.png)

Take a look at file name again, it already matches answer format of this question

![b41c02fb6ef3c52e6c17ead458178151.png](../../_resources/b41c02fb6ef3c52e6c17ead458178151.png)

We can go to "Names" section in "Details" tab to see other names of this file but there is still only 1 that matches answer format.

<details>
  <summary>Answer</summary>
<pre><code>111bc461-1ca8-43c6-97ed-911e0e69fdf8.dll</code></pre>
</details>

>Q3: Determining the compilation timestamp of malware can reveal insights into its development and deployment timeline. What is the compilation timestamp of the malware that infected our network?

![e3c1a0c9c033f85abea6aebdb3bfe621.png](../../_resources/e3c1a0c9c033f85abea6aebdb3bfe621.png)

Most PE files often contains their complication timestamp in their PE header so if we keep scrolling down for a bit to "Portable Executable Info" then we will have complication timestamp of this file right here

<details>
  <summary>Answer</summary>
<pre><code>2020-09-24 18:26:47</code></pre>
</details>

>Q4: Understanding when the broader cybersecurity community first identified the malware could help determine how long the malware might have been in the environment before detection. When was the malware first submitted to VirusTotal?

![8c3521a553b833c9a87a2383813f685c.png](../../_resources/8c3521a553b833c9a87a2383813f685c.png)

Going up to "History" section then we can see that someone submitted this file to VirusTotal almost a month later after its compiled.

<details>
  <summary>Answer</summary>
<pre><code>2020-10-15 02:47:37</code></pre>
</details>

>Q5: To completely eradicate the threat from Industries' systems, we need to identify all components dropped by the malware. What is the file name dropped by the malware in the Appdata folder?

![6e818750945caffbd6a54dfa0cfc3c10.png](../../_resources/6e818750945caffbd6a54dfa0cfc3c10.png)

We need to change our intel source since VirusTotal did not catch file dropped by this malware.

![7faf6570ee77b7c98d4ff89bf82f9fe6.png](../../_resources/7faf6570ee77b7c98d4ff89bf82f9fe6.png)

We still have threat intel report from [Red Canary](https://redcanary.com/blog/threat-intelligence/yellow-cockatoo/) that already conducted malware analysis for us and here is the file that dropped in Appdata folder
<details>
  <summary>Answer</summary>
<pre><code>solarmarker.dat</code></pre>
</details>

>Q6: It is crucial to identify the C2 servers with which the malware communicates to block its communication and prevent further data exfiltration. What is the C2 server that the malware is communicating with?

![3f55374bba0b63e5ad5b67ff96b47de5.png](../../_resources/3f55374bba0b63e5ad5b67ff96b47de5.png)
Red Canary also noted C2 url for their audience to add them to blacklist so we can use this as the answer of this question too!
<details>
  <summary>Answer</summary>
<pre><code>https://gogohid.com</code></pre>
</details>

![b26a6f1857e958c6350944067b967573.png](../../_resources/b26a6f1857e958c6350944067b967573.png)
* * *
