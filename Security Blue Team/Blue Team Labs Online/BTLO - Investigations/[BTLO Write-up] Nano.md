# [Blue Team Labs Online - Nano](https://blueteamlabs.online/home/investigation/nano-75ac6a75ef)

![77c439d9bb41e56545af239ddbe6fe93.png](/resources/77c439d9bb41e56545af239ddbe6fe93.png)

The hacking group Nano is causing unusual network activity on critical servers.

>Security Operations

>**Tags**: RITA Zeek Zgrep TA0011
* * *
**Scenario**
The SOC detected unusual network activity from a critical server. Analysts believe the attack was by Nano by identifying these beaconing patterns and obfuscation techniques. Nano is a newly discovered hacking group that focuses on stealth and persistence. It uses custom obfuscated protocols that mimic legitimate traffic, making it challenging to detect using standard network monitoring tools. Your job is to understand and identify these patterns by looking through captured logs, which will help defend against such advanced threats in the future.
* * *
## Investigation Submission
>Q1) Looking at the RITA HTLM Report (Log_2V), what is the IP of the attacker’s C2 server? Provide the number of connections as well. (Format: IP Address, Connections)

After deployed investigation machine, lets take a look at what we have first

![d6cb44a7a1ceb6fd1a616e2dc383fd34.png](/resources/d6cb44a7a1ceb6fd1a616e2dc383fd34.png)

We have `Tools` and `Investigation` directories on the Desktop which provides us tools and files necessary to complete this investigation which we will deal with RITA reports and Zeek logs today!

![896052a440708ec70a75adda45b72d76.png](/resources/896052a440708ec70a75adda45b72d76.png)

Q1 asking for attacker's C2 server from RITA HTML Report so I opened `beacons.html` without a doubt since there must be high beaconing to an attacker's C2 server in short interval.

![a55314c426c01ba0cf4a4709174b43f3.png](/resources/a55314c426c01ba0cf4a4709174b43f3.png)
Then we could see that there is 1 particular IP address with 8440 connections with such relatively low interval so this is the attacker's C2 server we're looking for.
<details>
  <summary>Answer</summary>
<pre><code>138.197.117.74, 8440</code></pre>
</details>

>Q2) What is the cloud infrastructure being used for the C2 server? (Format: Infrastructure)

![ee8820a993a850bf7012ee03671155f7.png](/resources/ee8820a993a850bf7012ee03671155f7.png)
Lets search this IP address on VirusTotal then we will see that this IP address is owned by DigitalOcean which is one of most popular droplet provider that also infamous for threat actor to host their C2 with this provider.
<details>
  <summary>Answer</summary>
<pre><code>DigitalOcean</code></pre>
</details>

>Q3) Looking at the RITA User Agent report, what is the system that corresponds to the connection count in Q1? (Format: User Agent String)

![76572ffb7d21a740184a97b736917dcf.png](/resources/76572ffb7d21a740184a97b736917dcf.png)

Lets go to `User Agents` report then find any user-agent that have "Time Used" closed to 8440 which is the number of connection to C2 server

![4dd262c2f6b6235d4d125212848b13e9.png](/resources/4dd262c2f6b6235d4d125212848b13e9.png)

Then we will have this user-agent with 8439 Times Used which is 1 less than 8440 so this is the one we are looking for.

<details>
  <summary>Answer</summary>
<pre><code>Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)</code></pre>
</details>

>Q4) Let’s look at Log_1D, what is the low-profile subdomain with the absurd amount of requests? Provide the number of requests as well. (Format: Subdomain, Request)

![c3c50e24b9bed77399398084c6195d39.png](/resources/c3c50e24b9bed77399398084c6195d39.png)

Lets change our report to `dns.html` of Log_1D

![b487395161617c9639c7bebf1635fb7a.png](/resources/b487395161617c9639c7bebf1635fb7a.png)

And we can see that there is 1 domain (including its subdomain) that has absurd amount of requests

<details>
  <summary>Answer</summary>
<pre><code>cat.nanobotninjas.com, 82920</code></pre>
</details>

>Q5) In the Zeek logs (Log_1D), we can see a large number of DNS TXT record requests for a private IP for the subdomain found in Q4. List the IP. (Format: IP Address) 

![4e9748d48da6a5bd2cb2f1c00fd73f93.png](/resources/4e9748d48da6a5bd2cb2f1c00fd73f93.png)

Lets navigate to `Zeek Logs` directory then we will see that these log are compressed with gzip

![7f54d029bea06ef5bf6117c534450029.png](/resources/7f54d029bea06ef5bf6117c534450029.png)

We only interested in DNS but lets just decompress them all with `gunzip *.gz`

![b6dd1eea80564926494a9539edb3d573.png](/resources/b6dd1eea80564926494a9539edb3d573.png)
Now after using `grep "cat\.nanobotninjas\.com" ./* | less` we will see that there is 1 private IP address was requested with these weird subdomain that remind me of [dnscat2](https://github.com/iagox86/dnscat2) C2 which I was right about that (after submitted this in Q7)

<details>
  <summary>Answer</summary>
<pre><code>10.234.234.105</code></pre>
</details>

>Q6) This is an unusual activity. To avoid cached results on the intermediate DNS server(s), a certain value prepended to the subdomain is being changed. What is this value being changed? It seems like a Base 16 numbering system. (Format: value)

dnscat2 will use subdomain in "hex" to communicate with infected machine
<details>
  <summary>Answer</summary>
<pre><code>hex</code></pre>
</details>

>Q7) Judging from the logs (Log_1D), what tool was the attacker using? A tool to help C2s channel over the DNS protocol. (Format: tool)

We already know that its dnscat2 
<details>
  <summary>Answer</summary>
<pre><code>DNSCat2</code></pre>
</details>

![69f6d347ad8a65a9a5e0905e1742f3dd.png](/resources/69f6d347ad8a65a9a5e0905e1742f3dd.png)
https://blueteamlabs.online/achievement/share/52929/236
* * *