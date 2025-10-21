# [CyberDefenders - Web Investigation](https://cyberdefenders.org/blueteam-ctf-challenges/web-investigation/)
Created: 20/03/2024 13:11
Last Updated: 20/03/2024 15:20
* * *
>**Category**: Network Forensics
>**Tags**: PCAP, Wireshark, sql
* * *
**Scenario:**
You are a cybersecurity analyst working in the Security Operations Center (SOC) of BookWorld, an expansive online bookstore renowned for its vast selection of literature. BookWorld prides itself on providing a seamless and secure shopping experience for book enthusiasts around the globe. Recently, you've been tasked with reinforcing the company's cybersecurity posture, monitoring network traffic, and ensuring that the digital environment remains safe from threats.

Late one evening, an automated alert is triggered by an unusual spike in database queries and server resource usage, indicating potential malicious activity. This anomaly raises concerns about the integrity of BookWorld's customer data and internal systems, prompting an immediate and thorough investigation.

As the lead analyst on this case, you are required to analyze the network traffic to uncover the nature of the suspicious activity. Your objectives include identifying the attack vector, assessing the scope of any potential data breach, and determining if the attacker gained further access to BookWorld's internal systems.

**Tools:**
- Wireshark
- Network Miner
* * *
## Questions
> Q1: By knowing the attacker's IP, we can analyze all logs and actions related to that IP and determine the extent of the attack, the duration of the attack, and the techniques used. Can you provide the attacker's IP?

I opened this pcap on Wireshark
![6582a0deebcfa7350c4fa51f63978405.png](../../_resources/6582a0deebcfa7350c4fa51f63978405.png)
There are a lot of HTTP conversations but I noticed this one because its a SQL injection attempt, so we got an attacker

<details>
  <summary>Answer</summary>
<pre><code>111.224.250.131</code></pre>
</details>

> Q2: If the geographical origin of an IP address is known to be from a region that has no business or expected traffic with our network, this can be an indicator of a targeted attack. Can you determine the origin city of the attacker?

![c6bbc397cce4338f6ce365a38bf69187.png](../../_resources/c6bbc397cce4338f6ce365a38bf69187.png)
Using [IPLocation](https://www.iplocation.net/ip-lookup), I've found that this IP address is located in Hebei (China)

<details>
  <summary>Answer</summary>
<pre><code>Shijiazhuang</code></pre>
</details>

> Q3: Identifying the exploited script allows security teams to understand exactly which vulnerability was used in the attack. This knowledge is critical for finding the appropriate patch or workaround to close the security gap and prevent future exploitation. Can you provide the vulnerable script name?

![9f003bb30421d6aa26ff6d0657c1e76e.png](../../_resources/9f003bb30421d6aa26ff6d0657c1e76e.png)
![30af4f518cd17e7650037e59da164977.png](../../_resources/30af4f518cd17e7650037e59da164977.png)
We can see that this php script is likely vulnerable to SQL injection attack

<details>
  <summary>Answer</summary>
<pre><code>search.php</code></pre>
</details>

> Q4: Establishing the timeline of an attack, starting from the initial exploitation attempt, What's the complete request URI of the first SQLi attempt by the attacker?

![8d475723a2bdf6dd82b0655a57aaac9c.png](../../_resources/8d475723a2bdf6dd82b0655a57aaac9c.png)
I wanted to know the regular query first so If we just queried with just `book`, We got no result
![37dffb918dc9095f4ffa75406607221c.png](../../_resources/37dffb918dc9095f4ffa75406607221c.png)
Scroll down a bit more, I saw HTTP status 200 with the same no result
![9b34e01b4129785b0158c4b19a7b60b7.png](../../_resources/9b34e01b4129785b0158c4b19a7b60b7.png)
Decoded URL-encoded string, then it made sense why the result is the same as queries with `book`, because it just added `AND TRUE` statement after it.

<details>
  <summary>Answer</summary>
<pre><code>/search.php?search=book%20and%201=1;%20--%20-</code></pre>
</details>

> Q5: Can you provide the complete request URI that was used to read the web server available databases?

question ask for the web server available database, that mean just True statement is not enough anymore, `UNION` operator might be used to combine result with [sys.databases](https://learn.microsoft.com/en-us/sql/relational-databases/system-catalog-views/sys-databases-transact-sql?view=sql-server-ver16) or [Information_schema](https://dev.mysql.com/doc/mysql-infoschema-excerpt/8.3/en/information-schema-introduction.html)
![ff4f1f671e854026a8c791278d03a7a2.png](../../_resources/ff4f1f671e854026a8c791278d03a7a2.png)
![ee0220b66f58ca50ebf6069ba9064e7b.png](../../_resources/ee0220b66f58ca50ebf6069ba9064e7b.png)
![a1c97dd4844cf43739491184ca1e4b95.png](../../_resources/a1c97dd4844cf43739491184ca1e4b95.png)
So I searched `schema` string, then finally obtained the answer

<details>
  <summary>Answer</summary>
<pre><code>/search.php?search=book%27%20UNION%20ALL%20SELECT%20NULL%2CCONCAT%280x7178766271%2CJSON_ARRAYAGG%28CONCAT_WS%280x7a76676a636b%2Cschema_name%29%29%2C0x7176706a71%29%20FROM%20INFORMATION_SCHEMA.SCHEMATA--%20-</code></pre>
</details>

> Q6: Assessing the impact of the breach and data access is crucial, including the potential harm to the organization's reputation. What's the table name containing the website users data?

![2a48686228ae85cb160b923f88713ed9.png](../../_resources/2a48686228ae85cb160b923f88713ed9.png)
![4ae389a27c44c082f00b9bb03034a8a5.png](../../_resources/4ae389a27c44c082f00b9bb03034a8a5.png)
Attacker successfully queries all tables of `bookworld_db` database
![144545bfd62924d55d1e979703c4cdf2.png](../../_resources/144545bfd62924d55d1e979703c4cdf2.png)
![373178640bd91d687c5064120a4026ff.png](../../_resources/373178640bd91d687c5064120a4026ff.png)
![2b91ab0cdb15758735d7d066a68a8333.png](../../_resources/2b91ab0cdb15758735d7d066a68a8333.png)
and the `customers` table contains information about users of this website

<details>
  <summary>Answer</summary>
<pre><code>customers</code></pre>
</details>

> Q7: The website directories hidden from the public could serve as an unauthorized access point or contain sensitive functionalities not intended for public access. Can you provide name of the directory discovered by the attacker? 

![a9aba74e46a3f5f2f037e3f7ad0ba787.png](../../_resources/a9aba74e46a3f5f2f037e3f7ad0ba787.png)
After attacker exploited SQL injection then he/she used gobuster attempting to find directory that supposed to be hidden on this website
![6c9d56860384c2826076c864535ba24c.png](../../_resources/6c9d56860384c2826076c864535ba24c.png)
Filtered by HTTP status 200, I finally found that attacker got accessed to `/admin/` directory

<details>
  <summary>Answer</summary>
<pre><code>/admin/</code></pre>
</details>

> Q8: Knowing which credentials were used allows us to determine the extent of account compromise. What's the credentials used by the attacker for logging in?

![cab8f1a66cfa40e5a54a6016b28ea736.png](../../_resources/cab8f1a66cfa40e5a54a6016b28ea736.png)
Knowing an attacker found `/admin/` page, I also found that login.php page and the POST request to the server mean an attacker tried to gain access to this admin page and he/she finally got accessed according to HTTP 302 then went straight to index.php

<details>
  <summary>Answer</summary>
<pre><code>admin:admin123!</code></pre>
</details>

> Q9: We need to determine if the attacker gained further access or control on our web server. What's the name of the malicious script uploaded by the attacker?

![33676ea0c92a50dd26bdc86c8d6a845e.png](../../_resources/33676ea0c92a50dd26bdc86c8d6a845e.png)
scrolled down a little after an attacker authenticated to an admin page, then look like he/she found an upload directory, but the method is GET so this is the malicious file that likely to be a PHP reverse shell script and attacker uploaded this to server then fetch it to execute the script.

So I wanted to confirmed when the attacker uploaded a file and you need to look for POST method to upload it to webserver so I needed to find which POST method associated with file
![6368eda8e24de04215840816e1a08a02.png](../../_resources/6368eda8e24de04215840816e1a08a02.png)
![4f1ac3e923311917c4ec0ac3778e1786.png](../../_resources/4f1ac3e923311917c4ec0ac3778e1786.png)
which I finally confirmed that on the index.php, attacker uploaded this php reverse shell script to the webserver

<details>
  <summary>Answer</summary>
<pre><code>NVri2vhp.php</code></pre>
</details>

![1a89a28ecc97569cc8cbfd880123ead2.png](../../_resources/1a89a28ecc97569cc8cbfd880123ead2.png)
***