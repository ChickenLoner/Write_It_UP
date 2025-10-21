# [CyberDefenders - WebStrike](https://cyberdefenders.org/blueteam-ctf-challenges/webstrike/)
Created: 19/02/2024 12:45
Last Updated: 09/10/2024 00:21
* * *
>**Category**: Network Forensics
>**Tags**: Wireshark, PCAP, Exfiltration
* * *
**Scenario**: An anomaly was discovered within our company's intranet as our Development team found an unusual file on one of our web servers. Suspecting potential malicious activity, the network team has prepared a pcap file with critical network traffic for analysis for the security team, and you have been tasked with analyzing the pcap.

**Tools**: Wireshark
* * *
## Questions
> Q1: Understanding the geographical origin of the attack aids in geo-blocking measures and threat intelligence analysis. What city did the attack originate from?

![0bfe5bf1f85db637057150fb33299a0e.png](../../_resources/0bfe5bf1f85db637057150fb33299a0e.png)
![8cbb712ae14ca463f8c535ec5967ef5e.png](../../_resources/8cbb712ae14ca463f8c535ec5967ef5e.png)
After taking a look at pcap file, There are only 2 IP addresses were captured.
Which `117.11.88.124` is probably the client (attacker) and `24.49.63.79` is a web server
![718a357005c2dc6fb61ffc8eccf03f1e.png](../../_resources/718a357005c2dc6fb61ffc8eccf03f1e.png)
![1dfa993bfaa53fb62bc8ae67675515c1.png](../../_resources/1dfa993bfaa53fb62bc8ae67675515c1.png)
I used [iplocation](https://www.iplocation.net/ip-lookup) to find both of IP addresses, attack was from the China and the web server was on the US so the answer is
<details>
  <summary>Answer</summary>
<pre><code>Tianjin</code></pre>
</details>

> Q2: Knowing the attacker's user-agent assists in creating robust filtering rules. What's the attacker's user agent?

![55739d889fe7b2c4510c9cda0d12ccf9.png](../../_resources/55739d889fe7b2c4510c9cda0d12ccf9.png)
Follow HTTP or TCP stream of HTTP traffic, here is the user-agent of the attacker

<details>
  <summary>Answer</summary>
<pre><code>Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0</code></pre>
</details>

> Q3: We need to identify if there were potential vulnerabilities exploited. What's the name of the malicious web shell uploaded?

![a34b81b79b64cea0aedbf6435b443b7b.png](../../_resources/a34b81b79b64cea0aedbf6435b443b7b.png)
After browsing the website, the attacker found the upload page and used POST method to upload php reverse shell to the server which was a successful attempt.

<details>
  <summary>Answer</summary>
<pre><code>image.jpg.php</code></pre>
</details>

> Q4: Knowing the directory where files uploaded are stored is important for reinforcing defenses against unauthorized access. Which directory is used by the website to store the uploaded files?

![451b238b4d7fcd606f3e75b2d3bd293c.png](../../_resources/451b238b4d7fcd606f3e75b2d3bd293c.png)
The php reverse shell was uploaded to this directory as a link

<details>
  <summary>Answer</summary>
<pre><code>/reviews/uploads/</code></pre>
</details>

> Q5: Identifying the port utilized by the web shell helps improve firewall configurations for blocking unauthorized outbound traffic. What port was used by the malicious web shell?

Look at the content of php reverse shell, The port that was used is

<details>
  <summary>Answer</summary>
<pre><code>8080</code></pre>
</details>

![33a231c416857db796bca3938affcfeb.png](../../_resources/33a231c416857db796bca3938affcfeb.png)
Which the attacker successfully gained the reverse shell from the server.

> Q6: Understanding the value of compromised data assists in prioritizing incident response actions. What file was the attacker trying to exfiltrate?

![48447fe0b3561bfa69b94c38c4c7756b.png](../../_resources/48447fe0b3561bfa69b94c38c4c7756b.png)
<details>
  <summary>Answer</summary>
<pre><code>passwd</code></pre>
</details>

<div align=center>

![dc380c96026d53b7272c8f8601e24180.png](../../_resources/dc380c96026d53b7272c8f8601e24180.png)
</div>

* * *