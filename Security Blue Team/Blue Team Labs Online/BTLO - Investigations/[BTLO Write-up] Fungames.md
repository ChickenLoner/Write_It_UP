# [Blue Team Labs Online - Fungames](https://blueteamlabs.online/home/investigation/fungames-1a18b6a8f1)

![cde1131a3968dcefdec9abe4306446f0.png](/resources/cde1131a3968dcefdec9abe4306446f0.png)

>**Security Operations**

>**Tags**: Wireshark CyberChef VirusTotal TA0031 TA0010
* * *
**Scenario**
FunGames is an e-commerce platform for video games owned by FunTech Inc. and has become the target of a criminal who managed to obtain access credentials and exfiltrate some sensitive data. FunTech analysts provide the fugames.pcap file to analyze and retrieve all the pieces of information about the attack.
* * *
## Environment Awareness
![c2af8c15bc6d92873240bb9921b1f465.png](/resources/c2af8c15bc6d92873240bb9921b1f465.png)
Lets take a look at what we have, and we only have 1 pcap and Cyberchef on this machine so it should not be too complicated.
***
## Investigation 
>Q1) What is the IP address of the attacker who is performing the attack? (Format: X.X.X.X)

![5ad208c838cd145d778421ccb34e50ad.png](/resources/5ad208c838cd145d778421ccb34e50ad.png)
After opened pcap file in Wireshark and filtered for HTTP then we could see that IP address 192.168.8.130 conducted port scanning and nmap scripting engine on an IP address 192.168.8.142 (Q2)
<details>
  <summary>Answer</summary>
<pre><code>192.168.8.130</code></pre>
</details>

>Q2) What is the IP address of the victim? (Format: X.X.X.X)
<details>
  <summary>Answer</summary>
<pre><code>192.168.8.142</code></pre>
</details>

>Q3) Which attack was performed by the attacker? (Format: Attack Name)

![60a9bf03ae6c6fddc04151fea9131891.png](/resources/60a9bf03ae6c6fddc04151fea9131891.png)
After NSE script enumerate then we could see SQL injection attempt on `id` parameter in `/game_details.php` endpoint and it was conducted with sqlmap (Q4)
<details>
  <summary>Answer</summary>
<pre><code>SQLi</code></pre>
</details>

>Q4) It seems the attacker used a famous tool to perform the attack (Format: Tool)
<details>
  <summary>Answer</summary>
<pre><code>sqlmap</code></pre>
</details>

>Q5) In one of the packets, it is possible to view the victim's username and password (Format: Username, Password)

My assumption is the last SQLi request to the target server should be the one that an attacker successfully got everything he need.

![e8879f8df52cd5b4bdd6ad878127ea8b.png](/resources/e8879f8df52cd5b4bdd6ad878127ea8b.png)

So after scrolling to the bottom, we could see one HTTP request that asking for `exploit` file (Q6) but we will leave it as that for now and focus on the last SQL injection attempt right here.

![100553372cbada134de499169169dcd1.png](/resources/100553372cbada134de499169169dcd1.png)

Lets URL decode and try to understand this query before we proceed.

![d2594cab34f0ea48f3224babc8e1284e.png](/resources/d2594cab34f0ea48f3224babc8e1284e.png)

So this is UNION based SQL injection that will concatenate 6 columns from `fungames.users` and the output would be separate by 0x6b676c6e7064 

![25e04486edcc5b0c1486e05ba0f455de.png](/resources/25e04486edcc5b0c1486e05ba0f455de.png)
decode it then we will have "kglnpd" so we would not be confused when taking a look at an output of this command after replace this string with space or new-line.

![fb0014a364e9902c88b4e04876f899fc.png](/resources/fb0014a364e9902c88b4e04876f899fc.png)

Lets grab an output of this command right here.

![ea272fdd9668dc23902552cf3fd8c6d9.png](/resources/ea272fdd9668dc23902552cf3fd8c6d9.png)

Use "From HTML Entity" then replace "kglnpd" with any separator you like but in the end we should have these username and password right here.

<details>
  <summary>Answer</summary>
<pre><code>mjarovic, Ma77.J@r0v1c-2024</code></pre>
</details>

>Q6) Once the attacker obtained the victim's credentials he accessed the system via SSH. To gain root privileges, they transferred a file to the victim's machine. What is the name of the file? (Format: filename)

![7331836a5bd8fecbb803e5c6b223c5d4.png](/resources/7331836a5bd8fecbb803e5c6b223c5d4.png)

We already know which file that was transferred so lets export it out.

![bca356fa6d7c816d1020dd0e655f2b80.png](/resources/bca356fa6d7c816d1020dd0e655f2b80.png)

Then calculate SHA256 sum (Q7) then we could search on VirusTotal to identify which CVE (Q8) it exploit to gain root privilege.

<details>
  <summary>Answer</summary>
<pre><code>exploit</code></pre>
</details>

>Q7) What is the sha256 hash of the file above? (Format: SHA256)
<details>
  <summary>Answer</summary>
<pre><code>d8dd09b01eb4e363d88ff53c0aace04c39dbea822b7adba7a883970abbf72a77</code></pre>
</details>

>Q8) With which CVE is this type of vulnerability identified? (Format: CVE-XXXX-XXXX)

![503086de7c5ed9ae1aae55d02b2a13b3.png](/resources/503086de7c5ed9ae1aae55d02b2a13b3.png)

Now we could use SHA256 we just obtained to search on VirusTotal and we can see that there are 2 candidates here but the latest one is CVE-2024-1086

![0fd3fbaa885c0e6f32f4472bc55839f4.png](/resources/0fd3fbaa885c0e6f32f4472bc55839f4.png)

I also took a look at Names section that keep all the names of this file submitted to VirusTotal and it is confirmed that its CVE-2024-1086

<details>
  <summary>Answer</summary>
<pre><code>CVE-2024-1086</code></pre>
</details>

>Q9) After obtaining root privileges, it seems that the attacker exfiltrated sensitive data without transferring any files. Provide the string related to this data (Format: String)

![543e74b2f1fb01ad39fa109de1fd35ba.png](/resources/543e74b2f1fb01ad39fa109de1fd35ba.png)

We can filter out SSH traffic since we will not get anything from it so I used `ip.addr == 192.168.8.130 && frame.number > 133674 && !tcp.port22` then I found malformed dns query to attacker IP address and the same content is also seen in next packet that is ICMP but look like ICMP is not successful one.
<details>
  <summary>Answer</summary>
<pre><code>j4672616e6b204d696c6c7320313233343536373839313233343536372065787020646174652030382f32382063767620313233200a</code></pre>
</details>

>Q10) It seems that the string has been encoded. What data did the attacker manage to obtain through exfiltration? (Format: String)

![75b08e885fab5f5647c19f95cebbd383.png](/resources/75b08e885fab5f5647c19f95cebbd383.png)
Lets decode it then we can see that this is card number of Frank Mills that was exfiltrated via DNS
<details>
  <summary>Answer</summary>
<pre><code>Frank Mills 1234567891234567 exp date 08/28 cvv 123</code></pre>
</details>

>Q11) Provide the Mitre ID of this technique—in regard to the previous question (Format: TXXXX.xxx)

![982f6041c92608fdea183cd713a91e82.png](/resources/982f6041c92608fdea183cd713a91e82.png)
We know the protocol so we can just search it on MITRE then we will have [this](https://attack.mitre.org/techniques/T1071/004/) technique that is accepted by this question.
<details>
  <summary>Answer</summary>
<pre><code>T1071.004</code></pre>
</details>

![fb79326c4c3832ae919ba504585b29c6.png](/resources/fb79326c4c3832ae919ba504585b29c6.png)
https://blueteamlabs.online/achievement/share/52929/223
* * *
## Summary
An incident started from the attacker discovered Web server on port 80 and SSH port with `nmap` port scanning then started NSE script scanning on Web server which found a webpage vulnerable to SQL injection attack which the attacker used `sqlmap` to dump user credential from database and successfully connected to web server via SSH.

Then the attacker downloaded a binary file to exploit CVE-2024-1086 for local privilege escalation and ultimately exfiltrated data via DNS protocol.

### Timeline 
- 2024-06-19 16:34:03 : The attacker started port scanning.
- 2024-06-19 16:34:11 : The attacker first obversed interacted with the website and started Nmap Script Engine (NSE Script) scanning.
- 2024-06-19 16:34:37 : The attacker started using `sqlmap` on parameter `id` of `/game-details.php`
- 2024-06-19 16:35:10 : The attacker obtained user credential for SSH from `fungames.users` table
- 2024-06-19 16:35:22 : The attacker connected to the server via SSH
- 2024-06-19 16:35:54 : The attacker downloaded `exploit` file to the server 
- 2024-06-19 16:36:44 : The attacker attempted to exfiltrate data via DNS and ICMP.
- 2024-06-19 16:37:01 : The attacker terminated SSH session.
 
### IOCs
- `192[.]168[.]8[.]130`
- `d8dd09b01eb4e363d88ff53c0aace04c39dbea822b7adba7a883970abbf72a77` (SHA256 of `exploit`)
* * *