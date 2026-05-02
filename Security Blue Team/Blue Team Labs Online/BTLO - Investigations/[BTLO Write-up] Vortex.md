# [Blue Team Labs Online - Vortex](https://blueteamlabs.online/home/investigation/vortex-ffcd70d701)

![c302897c3efa7dc39039980c3625f0d1.png](/resources/c302897c3efa7dc39039980c3625f0d1.png)

Brianna noticed her workstation lagging and received a LinkedIn login attempt notification from an unfamiliar device. Worried, she reported to the IT help desk. Jake now investigates to find and collect IOCs.

>**Security Operations**

>**Tags**: Wireshark TCPdump CyberChef BTL1 T1566 T1204
* * *
**Scenario**
Jake, a Transgear Corp Incident Response analyst, delves into an alert from Brianna, who flagged unusual activity on her workstation. A week prior, enticed by an email promising Amazon gift cards, Brianna clicked a link, unknowingly downloading malware. This granted attackers access, enabling espionage: capturing credentials, file copying, and eavesdropping on video calls. Days later, Brianna noticed her workstation lagging and received a LinkedIn login attempt notification from an unfamiliar device. Worried, she reported to the IT help desk. Jake now investigates to find and collect IOCs.

Reference Blog: https://www.securityblue.team/blog/posts/understanding-smtp-traffic-in-plaintext-using-wireshark
* * *
## Environment Awareness
![639d01ccc0889eb40a8a2bc2a947682c.png](/resources/639d01ccc0889eb40a8a2bc2a947682c.png)
Lets see what we have, there is a note just in case we want to use Wireshark and tcpdump with root privilege and there is 1 pcap file on the desktop so we will have to dig into that file on Wireshark to complete this investigation.
***
## Investigation
>Q1) What time did the suspected user system/browser connect to the malicious website? (Format: XX:XX:XX:XXXXXX)

![447b018857b3b943ddee2de869e2268c.png](/resources/447b018857b3b943ddee2de869e2268c.png)
Afrer opened this pcap, First thing I noticed is HTTP request to download an image file from so-called malicious website so this image file has to be a trojan and 197.168.1.27 is Brianne's IP address.

![5a3a6727856a418a6d5b0be6ee4cb74f.png](/resources/5a3a6727856a418a6d5b0be6ee4cb74f.png)

I exported this file out, calculate MD5 sum then search it on VirusTotal which return malicious as verdict.

So which time we should submit? normally I would put timestamp when ACK packet after SYN,ACK was sent back to source IP who request to establish a connection.

but in this case, Q1 accepted timestamp of the SYN packet.

<details>
  <summary>Answer</summary>
<pre><code>22:51:00:243743</code></pre>
</details>

>Q2) What is Briana’s IP address? (Format: IP Address)
<details>
  <summary>Answer</summary>
<pre><code>192.168.1.27</code></pre>
</details>

>Q3) What is Briana’s MAC/Ethernet address? What is the vendor name for the MAC address? (Format: MAC, Vendor Name)

![06181f8a38ab4a5b243bda865c74a3cc.png](/resources/06181f8a38ab4a5b243bda865c74a3cc.png)
Take a look at packet inspection section then we will have MAC address and Vendor Name of this machine 
<details>
  <summary>Answer</summary>
<pre><code>bc:ea:fa:22:74:fb, Hewlett-Packard</code></pre>
</details>

>Q4) What is Briana’s Windows machine name? (Format: Machine Name)

![0550832e5a5061336f6c9f69c1a1dda5.png](/resources/0550832e5a5061336f6c9f69c1a1dda5.png)
While taking a look at statistic, I found  machine name of Brianna here in BROWSER protocol packet 

![6dfc0589c7da0642fefa7d89a77c8fcb.png](/resources/6dfc0589c7da0642fefa7d89a77c8fcb.png)
but intended way might probably inspect SMTP communication which is the data exfiltration method that the malware used to send collected data to an attacker.
<details>
  <summary>Answer</summary>
<pre><code>DESKTOP-WIN11PC</code></pre>
</details>

>Q5) What is Briana’s Windows username? (Format: Username)

![8f209a6da87e91c79ed0da08e77fd209.png](/resources/8f209a6da87e91c79ed0da08e77fd209.png)
After taking a look at SMTP conversation we can see that its authenticated as marketing@transger.in and sent a mail to zaritkt@arhitektondizajn.com (Q6) and the content of this mail is username and password (Q9) stored on Brianna machine

![9e47dbcf2d121d8b348c6fa024193577.png](/resources/9e47dbcf2d121d8b348c6fa024193577.png)

I putted it to CyberChef and make it look a little less confusing but we will eventually find username of Brianna here

<details>
  <summary>Answer</summary>
<pre><code>admin@windows11users.com</code></pre>
</details>

>Q6) What email address was the attacker sending data to? (Format: name@domain.tld)
<details>
  <summary>Answer</summary>
<pre><code>zaritkt@arhitektondizajn.com</code></pre>
</details>

>Q7) What type of CPU does Briana’s computer use? (Format: CPU Name) 

![f53a1e65d41e655c53b8ab3339211f53.png](/resources/f53a1e65d41e655c53b8ab3339211f53.png)
System information is the first on this mail which also included CPU and RAM (Q8) info right here

<details>
  <summary>Answer</summary>
<pre><code>Intel(R) Core(TM) i5-13600K CPU @ 5.10GHz</code></pre>
</details>

>Q8) How much RAM does Briana’s computer have—in GBs? (Format: XXGB)
<details>
  <summary>Answer</summary>
<pre><code>32GB</code></pre>
</details>

>Q9) What type of account login data was stolen by the attacker? (Format: Data1, Data2)
<details>
  <summary>Answer</summary>
<pre><code>Passwords, Usernames</code></pre>
</details>

>Q10) What are the username and password related to the Amazon account? (Format: Username, Password)

![a43d96d29bc1a0bd87eba2028edfa2ad.png](/resources/a43d96d29bc1a0bd87eba2028edfa2ad.png)
Lets search for "amazon" then we should have both username and password right here.
<details>
  <summary>Answer</summary>
<pre><code>admin@windows11users.com, 3Fo76#PTf4P$Im!9mkLso69e</code></pre>
</details>

>Q11) What username did Briana use to authenticate to webhostbox[.]net? Can you decode it? (Format: Username)

![0fcbaf6aac5bc1bbc3243c4fd350d173.png](/resources/0fcbaf6aac5bc1bbc3243c4fd350d173.png)

We already know username but lets confirm it by decoding these base64 strings along with password for Q12

![d2c35b7f4373c6099c46f0b7d099d9bd.png](/resources/d2c35b7f4373c6099c46f0b7d099d9bd.png)
Alright we got the right one, along with password that used to authenticate.
<details>
  <summary>Answer</summary>
<pre><code>marketing@transgear.in</code></pre>
</details>

>Q12) What password did Briana use to authenticate to webhostbox[.]net? Can you decode it? (Format: Password)
<details>
  <summary>Answer</summary>
<pre><code>M@ssw0rd#621</code></pre>
</details>

![7eadc40551e7237088a76aa6a7fe89af.png](/resources/7eadc40551e7237088a76aa6a7fe89af.png)
https://blueteamlabs.online/achievement/share/52929/227
* * *
## Summary
Brianna downloaded a malware then executed it resulting data collection on her machine then sending back to the attacker email address that including Brianna's system information and user credentials saved on her machine.

### Timeline 
- 2023-01-05 22:51:00 : A request was sent to download 
- 2023-01-05 22:51:30 : Data exfiltration via SMTP occurred
- 2023-01-05 22:53:09 : SMTP connection terminated

### IOCs
- `45[.]56[.]99[.]101`
- `zaritkt@arhitektondizajn[.]com`

* * *