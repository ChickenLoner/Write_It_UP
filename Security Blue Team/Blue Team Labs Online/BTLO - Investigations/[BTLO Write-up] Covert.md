# [Blue Team Labs Online - Covert](https://blueteamlabs.online/home/investigation/covert-e2186b776c)

![e927ec6504f8eb1067145639345579f8.png](/resources/e927ec6504f8eb1067145639345579f8.png)

>**Incident Response**

>**Tags**: Wireshark PowerShell Editor T1048.003 T1071.001
* * *
**Scenario**
We got you the network capture of one of the compromised Windows server. Investigate the traffic and figure out the attacker actions.
* * *
## Environment Awareness
### Evidence Discovery
![eb384cb904cf149c7c238d2ee85b9631.png](/resources/eb384cb904cf149c7c238d2ee85b9631.png)

Look like we only have pcap file as a sole evidence on this investigation so lets start the investigation right away by open this file on Wireshark.
***
## Investigation
>Q1) What is the domain name used in exfiltration? 

![d5c4c8482e8b8af811be230bc7daff67.png](/resources/d5c4c8482e8b8af811be230bc7daff67.png)

First, we can filter with `dns` for DNS traffic which we will see the suspicious domain that has base64 decoded subdomain.

![933384c6b860687104379a9a582d2f53.png](/resources/933384c6b860687104379a9a582d2f53.png)

Then we can use `dns && dns.qry.name contains "fakec2"` then we will see several DNS queries associated with this domain name and this is the answer we are looking for. 

<details>
  <summary>Answer</summary>
<pre><code>fakec2server.domain</code></pre>
</details>

>Q2) What are the passwords that has been exfiltrated? User stored the passwords in a file as of format: password1 site1 password2 site2 

![cf23fba2aade8736b61f090b86b63e3e.png](/resources/cf23fba2aade8736b61f090b86b63e3e.png)

Utilizing CyberChef then we can copy requested domains from pcap file then use "Find / Replace" to remove latter part which will only have base64 encoded string left then we can use "From Base64" to decode it 

And now we can see 2 passwords were exfiltrated via DNS.

<details>
  <summary>Answer</summary>
<pre><code>P@ssw0d!23, Admi@12345</code></pre>
</details>

>Q3) There are lot of suspicious traffic to the system before the exfiltration. From which IP do you see port scan traffic?

![09723cfc84747b5514c6129764c86577.png](/resources/09723cfc84747b5514c6129764c86577.png)

Since there are so many packets within this pcap file then we can use "Conversations" statistics and sort by port which we can see that 192.168.1.29 sent many packets start to port 1,2,3,4 and so on, indicating that this IP address was conducted port scanning on 192.168.1.11 

<details>
  <summary>Answer</summary>
<pre><code>192.168.1.29</code></pre>
</details>

>Q4) Attacker used a covert command execution over HTTP. Both command and its output are encrypted and stored in a variable/parameter in the format – parameter=<encrypted_data>. Find the parameter that was used in request from infected system to the c2 server

![88b26ca1daa0866720df1d1ae86f73e4.png](/resources/88b26ca1daa0866720df1d1ae86f73e4.png)

Look like the attacker discovered website running on the targeted system so the attacker conducted directory bruteforcing next which we will have to filter these out to find the traffic that we are looking for.

![9c83d6250bc05754dfe9de6e38d2ff0e.png](/resources/9c83d6250bc05754dfe9de6e38d2ff0e.png)

By filtering with `!(http.user_agent == "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)") && http.request.method == "GET"` and we will have only HTTP GET request which is not share the same user agent as the directory bruteforcing user agent. 

Then we can see the parameter `guid` was used to request something from 192.168.1.30 which likely to be a C2 server.

<details>
  <summary>Answer</summary>
<pre><code>guid</code></pre>
</details>

>Q5) Similarly, what is the parameter that was used in response?

![e5c2a742d4f41f9fa2bb2bb20923e18b.png](/resources/e5c2a742d4f41f9fa2bb2bb20923e18b.png)

After some research then we will eventually find that those HTTP communication are characteristics of Trevor C2 framework and Nasreddine's has a good [write-up](https://nasbench.medium.com/understanding-detecting-c2-frameworks-trevorc2-2a9ce6f1f425) about this framework here what he summarized about this C2 framework

"So basically this framework will clone any website and inject commands sent by the C2 within its body. The client will then read the command(s) execute them and send the results back to the server." - 
Nasreddine Bencherchali

![be196b376089fb6c15dcabd3f0c4bf9c.png](/resources/be196b376089fb6c15dcabd3f0c4bf9c.png)

This C2 framework is `oldcss` in the comment as default and the value assign to this parameter (in the comment) is the instruction/command for client to execute.

<details>
  <summary>Answer</summary>
<pre><code>oldcss</code></pre>
</details>

>Q6) Use some OSINT skills with these parameters and figure out the c2 framework that the attacker used.
<details>
  <summary>Answer</summary>
<pre><code>TreverC2</code></pre>
</details>

>Q7) Understand the encryption and working of the c2 communication and try to decrypt the commands and output. What is the first command sent by the attacker? 

![8af3318ed0af24f95bd6b383164a8f19.png](/resources/8af3318ed0af24f95bd6b383164a8f19.png)

One more thing to about this C2 is, its open-source C2 framework and its even hard-coded AES key

`Tr3v0rC2R0x@nd1s@w350m3#TrevorForget`

Then after more research, there is someone who created [decrypting script](https://abdelrahme.github.io/posts/uoftctf-2024/#illusion) for this C2 framework which was once used as a CTF challenge in UofTCTF 2024 

When decoded, it splits into:
- IV: The first 16 bytes of the decoded data.
- Ciphertext: The remaining bytes of the decoded data.

![1016543a972ed4fdd628b630fb30b491.png](/resources/1016543a972ed4fdd628b630fb30b491.png)

Lets use `ip.src==192.168.1.30 && http.response.code == 200 && frame.len != 832` filter to get HTTP response request from the attacker's C2 which contains the instruction for the victim to execute inside `oldcss` variable as shown on the image above.

![bf80db94c18f274b06826d13c271a7bb.png](/resources/bf80db94c18f274b06826d13c271a7bb.png)

I also modified the script to recursively run until I type "exit", then we can see that the first command sent by the attacker is `cd` (change directory) 

<details>
  <summary>Answer</summary>
<pre><code>cd</code></pre>
</details>

>Q8) Attacker created a text file and marked a infection ID in the system. What is the infection ID?

![ee5c7aa67f230cf97afd63ab363374f4.png](/resources/ee5c7aa67f230cf97afd63ab363374f4.png)

Since, we could not export the pcap file out of the investigation machine so we will have to manually copy the the value of each `oldcss` variable return from the attacker's C2 then we will finally have the ciphertext we need for this question in frame 278,541

![efe5e14f4545a17cfef55b5b22d24940.png](/resources/efe5e14f4545a17cfef55b5b22d24940.png)

Then we can see that the attacker echo the infection ID to a text file.

<details>
  <summary>Answer</summary>
<pre><code>003</code></pre>
</details>

>Q9) Attacker invoked a PowerShell script to do the data exfiltration. What is the name of the PowerShell script? 

![25b3d7f1725430c87e109c8b7412c935.png](/resources/25b3d7f1725430c87e109c8b7412c935.png)

Now after continue to decrypt more communication then we will finally have the one we are looking for in frame 397,656

![1c14123bb8a89543538a119cb740b7d1.png](/resources/1c14123bb8a89543538a119cb740b7d1.png)

Which is a PowerShell bypass execution policy command to execute `exfil.ps1` script which is the script responsible for data exfiltration via DNS we found on the Q1-2

<details>
  <summary>Answer</summary>
<pre><code>exfil.ps1</code></pre>
</details>

![38595dce2ee64fef59cf5be19722c6db.png](/resources/38595dce2ee64fef59cf5be19722c6db.png)
https://blueteamlabs.online/achievement/share/52929/79
* * *