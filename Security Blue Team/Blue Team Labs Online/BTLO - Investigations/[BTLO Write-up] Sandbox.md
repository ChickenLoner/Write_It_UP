# [Blue Team Labs Online - Sandbox](https://blueteamlabs.online/home/investigation/sandbox-63af9b6bf4)

![5cd9602d36f8223781ba80291749005d.png](/resources/5cd9602d36f8223781ba80291749005d.png)

>Reverse Engineering

>**Tags**: LiSa Sandbox Virus Total Command Line URLHaus
* * *
**Scenario**
For the past few weeks, you’ve been analysing files continuously and it’s starting to take its toll on you. After some thought, you realised that automating some of your analysis work could not only save time but avoid mistakes that can arise from the constant focusing while analysing. Analyse the samples provided on the sandbox provided.

Sandbox location: localhost:4242
* * *
## Investigation Submission
>Q1) What is the username for the creator of the sandbox on GitHub? (Format: Username)

![12fcdaf4af0b789a5a799c4d59761ad2.png](/resources/12fcdaf4af0b789a5a799c4d59761ad2.png)

We got 2 samples inside Samples directory on the desktop but we have to use them on Q2 so lets osint for this Q

![44c16e086615c22106d9da50787ca091.png](/resources/44c16e086615c22106d9da50787ca091.png)

If we searched for lisa sandbox then we will eventually find this [github repo](https://github.com/danielpoliakov/lisa) but we could not submit this username as the answer, maybe the username was changed?
 
![973e20144801c3c0815d6d98827da775.png](/resources/973e20144801c3c0815d6d98827da775.png)

Then I found someone posted this tool on r/Malware reddit which have different username which was accepted as the answer of this Q.

<details>
  <summary>Answer</summary>
<pre><code>danieluhricek</code></pre>
</details>

>Q2) Sample1: Analyse the sample using the sandbox. Is the binary stripped? What architecture is the sample based on and where is the entry point? (Format: Yes/No, Architecture, Entrypoint)

![7c7fe5e98a55ff4236a7bbb7fb7e46eb.png](/resources/7c7fe5e98a55ff4236a7bbb7fb7e46eb.png)

Lets navigate to lisa sandbox then go to "Submit file" > Select "binary" type > Select file then submit.

![f7e439932fb2213f181fa84c4a8006e6.png](/resources/f7e439932fb2213f181fa84c4a8006e6.png)

After submit, you will see this message appear and we will have to wait before our result will be shown on Results page

![c6e4e89b4526a3debd2ce6f46019339a.png](/resources/c6e4e89b4526a3debd2ce6f46019339a.png)

*I re-deployed my investigation machine

We can see that after a while, a result will be listed here and we can click task_id to view the result.

![8f7af101479bd3f895a30c661b3206c6.png](/resources/8f7af101479bd3f895a30c661b3206c6.png)

Lisa sandbox separate result into 4 report from Overview, Static Analysis, Dynamic Analysis and Network Analysis and we already architecture from this Overview report.

![389fb6386aa606288f470635cb0f4ef2.png](/resources/389fb6386aa606288f470635cb0f4ef2.png)

We can find the rest from Static Analysis report right here.

<details>
  <summary>Answer</summary>
<pre><code>no, x86, 4194708</code></pre>
</details>

>Q3) Sample1: The malware attempts to reach out to a C2 domain. Name the IP and port that it attempts to reach out to. Also, where is this C2 located? (Format: X.X.X.X, Port, Country)

![5eb21922b990978916801d77e9721829.png](/resources/5eb21922b990978916801d77e9721829.png)

We will find IP address of C2 from Syscalls under Dynamic Analysis report but do not confuse with this google IP address that connect to port 53 for DNS

![0e705581e276cb7253657ca097fdfe58.png](/resources/0e705581e276cb7253657ca097fdfe58.png)

Instead the IP address along with port is in the last page of Syscalls record.

![0509f7061e1eec7bc8f682a50eae8bb0.png](/resources/0509f7061e1eec7bc8f682a50eae8bb0.png)

But upon searching for the country, we will get Singapore which is not the correct answer of this question but why?

![49ec4f4b48ddc64a7c08aacc474045a7.png](/resources/49ec4f4b48ddc64a7c08aacc474045a7.png)

Well.. something has been changed so the answer is Gernamy
<details>
  <summary>Answer</summary>
<pre><code>194.163.34.162, 19001, Germany</code></pre>
</details>

>Q4) \Sample1: Examine the domain in URLHaus. What is the name of the shell script that is used to execute the malware on the victim machine and who reported the shell script to URLHaus? (Format: Script.ext, reporter)

![e37ab6b9ca54df48a97b120280f77de5.png](/resources/e37ab6b9ca54df48a97b120280f77de5.png)

I started by searching MD5 of this file on URLHaus which lead to this Malware URLs and the answer of this question is the only bash script from these URLs.
<details>
  <summary>Answer</summary>
<pre><code>Sakura.sh, geenensp</code></pre>
</details>

>Q5) Sample2: Analyse the PCAP with the sandbox. Two scans are noted in the anomalies section. Name them in alphabetical order (Format: Scan1, Scan2) 

![b634bc58ee1835f87f0b0a57a64f3a38.png](/resources/b634bc58ee1835f87f0b0a57a64f3a38.png)

Lets go back to submit page and submit pcap file.

![e2a622bd51f90238491a36b01c018a19.png](/resources/e2a622bd51f90238491a36b01c018a19.png)

There are a lot of "blacklisted_ip_access" anomalies but answers of this question come from the last page right here. 
<details>
  <summary>Answer</summary>
<pre><code>port_scan, syn_scan</code></pre>
</details>

>Q6) Sample2: A large exploit from 2021 is attempting to be exploited in the traffic with a base64 payload. What is the name of this vulnerability and the interface it’s exploiting? (Format: Vulnerability, Full name of the interface)

![a247258c3746917ad24e4607f5c026fb.png](/resources/a247258c3746917ad24e4607f5c026fb.png)

The most popular on the 2021 has to be Log4Shell vulnerability or we could see its vulnerability that exploit JNDI of log4j. 
<details>
  <summary>Answer</summary>
<pre><code>Log4j, Java Naming and Directory Interface</code></pre>
</details>

![5a61688fec77e0c9c64722902dd3fffc.png](/resources/5a61688fec77e0c9c64722902dd3fffc.png)
https://blueteamlabs.online/achievement/share/52929/109
* * *