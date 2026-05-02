# [Blue Team Labs Online - Breach](https://blueteamlabs.online/home/investigation/breach-9a698663aa)

![52631b97532488c796f7be73b313cb7d.png](/resources/52631b97532488c796f7be73b313cb7d.png)

Your mission is to use Wireshark to analyze the provided network capture files, detect signs of the Openfire vulnerability being exploited, and gather enough evidence to understand the nature of the breach.

>**Digital Forensics**

>**Tags**: Wireshark T1190
* * *
**Scenario**
TechNova Corp stands as a beacon of innovation in the heart of a thriving metropolis. With a diverse portfolio ranging from cutting-edge software solutions to revolutionary communication platforms, the company’s reputation is unmatched. At the center of its operations is an Openfire-powered messaging server, crucial for seamless internal communication. However, the security fortress around TechNova Corp is about to be tested.

Unbeknownst to the company's IT team, a group of hackers, known as ShadowHunters, has successfully exploited a critical vulnerability in the Openfire server (CVE-2023-32315), leading to a potential data breach. Your task is to step into the shoes of a cybersecurity analyst tasked with detecting and mitigating this breach before it causes irreparable damage.

Your mission is to use Wireshark to analyze the provided network capture files, detect signs of the Openfire vulnerability being exploited, and gather enough evidence to understand the nature of the breach. Pay close attention to the patterns and anomalies that might indicate malicious activity.
* * *
## Understand the exploit
![f0075c6670a564e8321c0d42b04a9b3a.png](/resources/f0075c6670a564e8321c0d42b04a9b3a.png)
Before we start investigate this case, we might need to understand what CVE-2023-32315 really is so here is a [blog wrote by Jacob Baines](https://vulncheck.com/blog/openfire-cve-2023-32315) that would help us learn what happened when we exploited this CVE.

![07433fe1db08d094a5f803703045732c.png](/resources/07433fe1db08d094a5f803703045732c.png)
To put it simply, it start from a path traversal that will access `user-create.jsp` endpoint which responsible for user creation then create admin user and login as admin user to upload openfire plugin file (.jar file) that is actually a webshell which will allow threat actor to execute any arbitrary commands as desired.

Now we know what to look for then we can start our investigation.

If you read my write-up before, this will sound familiar to you because I copied this part from that [write-up](https://medium.com/system-weakness/letsdefend-write-up-compromised-chat-server-36b73baabe09) since its the same CVE 😂
***
## Environment Awareness
### Evidence Discovery
![16682cc17ffc9c6502cdc44c789ac5cc.png](/resources/16682cc17ffc9c6502cdc44c789ac5cc.png)

We got 2 files inside Investigation directory, first is pcapng file and second is saved MITRE webpage html file (after taking a look, it giving user hint for Q5 and Q8 so if you stuck then you could take a look and find out the answer from it)

And after take a look at pcapng file icon, we can see that Wireshark was already installed on this machine.
***
## Investigation
>Q1) What is the CSRF token value for the first login request? (Format: Token Value)

![29e4e4be9b10a16706005d05502634c3.png](/resources/29e4e4be9b10a16706005d05502634c3.png)

Lets start by filter for `http.request.method == "POST"` for POST request to login page then we will have this CSRF token of this request and the server that hosted vulnerable Openfire is 192.168.18.155 

<details>
  <summary>Answer</summary>
<pre><code>VypyY6v0F1w8iNK</code></pre>
</details>

>Q2) What is the password of the first user who logged in? (Format: Password)

![eb4f666551dc1f47d0c3ce899562bdd9.png](/resources/eb4f666551dc1f47d0c3ce899562bdd9.png)
Take a look at the communication then we could see that this credential successfully logged in as `admin`
<details>
  <summary>Answer</summary>
<pre><code>adminnothere</code></pre>
</details>

>Q3) What is the first username that was created by the attacker? (Format: Username)

![6763c726325e201d98d93ffbde0f08f0.png](/resources/6763c726325e201d98d93ffbde0f08f0.png)
Lets find for request to vulnerable endpoint which we could see that `ix5768` is the first user that successfully created by 192.168.18.160 which is likely to be the attacker.
<details>
  <summary>Answer</summary>
<pre><code>ix5768</code></pre>
</details>

>Q4) How many accounts did the attacker create? (Format: Number) 

![cac95d7325cd6bca0fe052648700746f.png](/resources/cac95d7325cd6bca0fe052648700746f.png)
Take a look at another HTTP 200 response then we have another user that successfully created so there are 2 accounts that created by the attacker.
<details>
  <summary>Answer</summary>
<pre><code>two</code></pre>
</details>

>Q5) What is the MITRE technique ID for the above activity? (Format: XXXXX)

![55aeea7a95b553eae9a5549512082827.png](/resources/55aeea7a95b553eae9a5549512082827.png)
We know that this is [Create Account](https://attack.mitre.org/techniques/T1136/) then login to upload webshell as plugin so this MITRE Technique is the most fit in this case 
<details>
  <summary>Answer</summary>
<pre><code>T1136</code></pre>
</details>

>Q6) What is the username that the attacker used to log in to the admin panel? (Format: Username) 

![073b1cccbda350c9f6d9d7aa80acbfc5.png](/resources/073b1cccbda350c9f6d9d7aa80acbfc5.png)
Lets take a look at login request then authenticated after 2 accounts were created then we will have the account that an attacker used to upload webshell.
<details>
  <summary>Answer</summary>
<pre><code>v01zxk</code></pre>
</details>

>Q7) What is the name of the plugin that the attacker uploaded? (Format: Plugin Name)

![7b56ec60cf841ad5449f494d637cb3d1.png](/resources/7b56ec60cf841ad5449f494d637cb3d1.png)
Take a look at POST request to upload plugin endpoint then we will see that it was successfully uploaded and we just need to find out the name of this plugin.

![d9b4677f08705ed759365cf82d703a56.png](/resources/d9b4677f08705ed759365cf82d703a56.png)
Here is the plugin/filename that was uploaded.
<details>
  <summary>Answer</summary>
<pre><code>openfire-management-tool-plugin.jar</code></pre>
</details>

>Q8) What is the MITRE sub-technique ID for the above activity? (Format: XXXXX.XXX)

![121cf8c4bf41cacb7da7edc8f166472b.png](/resources/121cf8c4bf41cacb7da7edc8f166472b.png)
I was stumbled on this one for a while then the MITRE sub-technique that fit into this case is [Malicious File](https://attack.mitre.org/techniques/T1204/002/) not a webshell
<details>
  <summary>Answer</summary>
<pre><code>T1204.002</code></pre>
</details>

>Q9) What is the first command that the user executes? (Format: Command)

![9c90cf06856a00958ea9dc6a5099a492.png](/resources/9c90cf06856a00958ea9dc6a5099a492.png)
Lets continue to the flow which we can see that after webshell was uploaded then `whoami` was executed by an attacker.
<details>
  <summary>Answer</summary>
<pre><code>whoami</code></pre>
</details>

>Q10) Which tool did the attacker use to initiate the reverse shell? (Format: Tool)

![83a8d4f4742cdf6c7af74bc6aee52127.png](/resources/83a8d4f4742cdf6c7af74bc6aee52127.png)
Then followed by netcat reverse shell on port 8888 to 192.168.18.160
<details>
  <summary>Answer</summary>
<pre><code>netcat</code></pre>
</details>

>Q11) On which port is the attacker listening? (Format: Port)

![cf6fa0005dc93152c6ab50926604d1a8.png](/resources/cf6fa0005dc93152c6ab50926604d1a8.png)

We can use `tcp.port == 8888` to confirm our finding then we can see that an attacker successfully established reverse shell connection port 8888 as root

<details>
  <summary>Answer</summary>
<pre><code>8888</code></pre>
</details>

>Q12) What is the CVE of this vulnerability of Openfire? (Format: CVE-XXXX-XXXXX)

Scenario already gave us a CVE so its free point on this question
<details>
  <summary>Answer</summary>
<pre><code>CVE-2023–32315</code></pre>
</details>

![f3bfa38c04a00bce354d022b63766ff2.png](/resources/f3bfa38c04a00bce354d022b63766ff2.png)
https://blueteamlabs.online/achievement/share/52929/229
* * *
## Summary
The attacker exploited CVE-2023–32315 and successfully created 2 admin users then use 1 of these account to uploaded webshell and finally gained remote access to webserver with this webshell.

### Timeline 
- 2024-07-20 13:25:46 : The attacker made a first request to a website
- 2024-07-20 13:26:26 : The attacker started brute forcing to `/login.jsp`
- 2024-07-20 13:27:03 : The attacker exploited CVE-2023–32315, successfully created "ix5768" user
- 2024-07-20 13:27:14 : The attacker exploited CVE-2023–32315, successfully created "v01zxk" user
- 2024-07-20 13:27:31 : The attacker authenticated to website as "v01zxk" user
- 2024-07-20 13:27:46 : The attacker uploaded webshell plugin (`openfire-management-tool-plugin.jar`) to website
- 2024-07-20 13:28:03 : The attacker successfully executed first command on the webshell (`whoami`)
- 2024-07-20 13:28:25 : The attacker used webshell to execute netcat reverse shell connection to port 8888
- 2024-07-20 13:28:34 : The attacker executed first command on the server (`whoami`)
- 2024-07-20 13:28:43 : The attacker executed last seen executed command on the server (`uname -a`)

### IOCs
- `192[.]168[.]18[.]160`
- `4cc22c8064c713466edfb1fb367c1c7e166014a67e4db1a308c92a012dd2827a` (SHA256 of `openfire-management-tool-plugin.jar`)

* * *