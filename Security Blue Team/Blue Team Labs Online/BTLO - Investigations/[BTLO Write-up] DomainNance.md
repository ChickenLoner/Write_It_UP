# [Blue Team Labs Online - DomainNance](https://blueteamlabs.online/home/investigation/domainnance-befa8a1fd4)

![da6ed8b0e635afaae49dc19187ec284e.png](/resources/da6ed8b0e635afaae49dc19187ec284e.png)

A recently formed company working on mid scale workforce claimed to have a secure environment. Taking this as a challenge, a 13 year old kid tried to get into their environment and got succeded.

>Incident Response

>**Tags**: Wireshark Splunk
* * *
**Scenario**
A recently formed company working on mid scale workforce claimed to have a secure environment. Taking this as a challenge, a 13 year old kid tried to get into their environment and got succeded. You are onboarded based on your Incident Response skills to investigate.
* * *
## Environment Awareness
### Evidence & Tool Discovery
![d6089458610115cac8a8bf6306343f93.png](/resources/d6089458610115cac8a8bf6306343f93.png)

On this investigation machine, we will have to use event log available on the Splunk and given pcap file

![da5c2f8268355467748660af94f6bd20.png](/resources/da5c2f8268355467748660af94f6bd20.png)

We can access Splunk web interface via the firefox browser, as it already bookmarked for us but for some reason it didn't start so we have to start it manually 

![92ea4baf4b8f321abcc56579877fdb53.png](/resources/92ea4baf4b8f321abcc56579877fdb53.png)

To start splunk manually, we have to be a root then go to `/opt/splunk/bin` and run `./splunk start`, it will take a while we will see that the splunk web interface is ready at the end of the result.

![5f1762752b371266ee99ab7a75422387.png](/resources/5f1762752b371266ee99ab7a75422387.png)

Now we can access to splunk web interface, which we can see that there are 4 log sources available for us and Sysmon is likely to be my go-to for this one.

***
## Investigation Submission
>Q1) The attacker tried logging into the vulnerable webserver. Can you find the correct credentials that logged in the attacker? (Format: username:password)

When we talking about authentication on the webserver, Windows log won't catch this so we have to filter for POST request to login page and the HTTP Status is likely to be 302 (Found and redirect)

![3e2e4b8d6db422559d212b3c93850d02.png](/resources/3e2e4b8d6db422559d212b3c93850d02.png)

Which we can see that all of these seen in the packet 210 which attacker authenticated to the webserver with this credential and from the path we know that this is DVWA (Damn Vulnerable Web Application) which designed to practice vulnerabilities of web application.

<details>
  <summary>Answer</summary>
<pre><code>admin:password</code></pre>
</details>

>Q2) What is the IP of Attacker Machine while interacting with Webserver? (Format: X.X.X.X)

![3e2e4b8d6db422559d212b3c93850d02.png](/resources/3e2e4b8d6db422559d212b3c93850d02.png)

From the above image, we know that the attacker authenticated with this credential from an IP address 192.168.1.13

<details>
  <summary>Answer</summary>
<pre><code>192.168.1.13</code></pre>
</details>

>Q3) The Attacker was able to execute commands on the WebServer. How many commands were executed? (Format: Count)

![0841a5cb42d3078b99d003818085a836.png](/resources/0841a5cb42d3078b99d003818085a836.png)

After authenticated to webserver then the attacker went to `/dvwa/vulnerabilies/exec` which is designed to test command injection vulnerability so the attacker utilized this to execute 6 commands

![fd5a27310b06e73ded8f137a22108c80.png](/resources/fd5a27310b06e73ded8f137a22108c80.png)

Commands that the attacker utilized are 
- `cat /etc/passwd` to check user of the webserver
- `pwd` to print current working directory
- `ls /var/www/dvwa` to list files from `/var/www/dvwa` directory
- `ls -la /var/www/dvwa` to list all files including hidden files from `/var/www/dvwa` directory
- `cat /var/www/dvwa/.credentials.txt` to read credential file on the webserver
- `nmap -sC -sV 10.0.2.0/24` to find the other hosts on the same network

<details>
  <summary>Answer</summary>
<pre><code>6</code></pre>
</details>

>Q4) The Attacker found a useful file in the WebServer. What is the name of the File as mentioned? (Format: filename.extension)

![1e2cbfde82a2bde3f1ad7db2c637d2c0.png](/resources/1e2cbfde82a2bde3f1ad7db2c637d2c0.png)

From the previous question, we found that the attacker found credential file on the webserver.

<details>
  <summary>Answer</summary>
<pre><code>.credentials.txt</code></pre>
</details>

>Q5) What important data is present inside the file? (Format: Xxxx Xxxxx : Xxxxxxxx)

![2b4a524677e49d06a1df7e1c9ebc3656.png](/resources/2b4a524677e49d06a1df7e1c9ebc3656.png)

We could take a look at the HTTP response of previous command which we can see the credential that was leaked to the attacker right here.

<details>
  <summary>Answer</summary>
<pre><code>Mike Tyson : Pa55w0rd</code></pre>
</details>

>Q6) What is the Internal Network Subnet that Attacker found and scanned? (Format: X.X.X.X/XX)

![fd5a27310b06e73ded8f137a22108c80.png](/resources/fd5a27310b06e73ded8f137a22108c80.png)

We found that the last command that was executed by the attacker is to scan for internal network with nmap.

<details>
  <summary>Answer</summary>
<pre><code>10.0.2.0/24</code></pre>
</details>

>Q7) Using the help of Splunk, What is the Domain Name of the AD Environment? (Format: domain.tld)

![66b479c9163f0a0d93bfb32da9a0d338.png](/resources/66b479c9163f0a0d93bfb32da9a0d338.png)

Utilized username we got from Q5 then we could use it to query on splunk which we could see that there are only 3 events returned with query but at least we got the domain name of this AD environment right here.

<details>
  <summary>Answer</summary>
<pre><code>highlysecured.tech</code></pre>
</details>

>Q8) A user account “mtyson” downloaded a few files into one of the systems. What's the name of the system? (Format: ComputerName)

![4228254182c9d4dbc39a162d21a6615c.png](/resources/4228254182c9d4dbc39a162d21a6615c.png)

Lets remove the query from previous question and create a query with this user.

![b36589dee7a57bdddabf920367ee0667.png](/resources/b36589dee7a57bdddabf920367ee0667.png)

After queried with mtyson user, then we can see that there is only 1 computer workstation this user had interaction with.

<details>
  <summary>Answer</summary>
<pre><code>DESKTOP-2FII9FV</code></pre>
</details>

>Q9) What is the first file that was downloaded onto the system? Provide the Original & Final Name with extension (Format: ActualName, GivenName)

![0ef550b2703fb98e8c0029d750cab58d.png](/resources/0ef550b2703fb98e8c0029d750cab58d.png)

Since Sysmon log is available to us then I simply searched for `cmd` expected that when attacker connected to the workstation then the attacker would receive a shell as `cmd.exe` or `powershell.exe` and the first thing I noticed after add `cmd` to my query is mimikatz usage for golden ticket attack. 

![35b08b71dc0b07fcfb54cbea2fcb3525.png](/resources/35b08b71dc0b07fcfb54cbea2fcb3525.png)

But this question want us to hunt for the downloaded file so I checked the CommandLine field to check if any command that resemble this activity and I found that the attacker used PowerShell to download PowerShell version of mimikatz and saved as `TroubleShooter.ps1`

<details>
  <summary>Answer</summary>
<pre><code>Invoke-Mimikatz.ps1, Troubleshooter.ps1</code></pre>
</details>

>Q10) What One-Liner command was used by Attacker to dump credentials? (Format: Command)

![6e90f8d914f1fff75924522cdbdc50a8.png](/resources/6e90f8d914f1fff75924522cdbdc50a8.png)

Then after successfully downloaded mimikatz, the attacker used it to dump logon password.

<details>
  <summary>Answer</summary>
<pre><code>powershell -Command '. .\Troubleshooter.ps1 ; Invoke-Mimikatz -Command "privilege::debug" ; Invoke-Mimikatz -Command "sekurlsa::logonpasswords"'</code></pre>
</details>

>Q11) The attacker also downloaded a CompiledBinary and stored it under a legitimate looking name. What is the name under which the file was saved? (Format: Filename.ext)

![8b7a2d152ef581dc4b2ccab77fdf067f.png](/resources/8b7a2d152ef581dc4b2ccab77fdf067f.png)

This time, I focused my hunt to `certutil` which I found that it was used to download Rubeus and saved it as `svch0st.exe`

<details>
  <summary>Answer</summary>
<pre><code>svch0st.exe</code></pre>
</details>

>Q12) The attacker claims to have successfully performed lateral movement. What ticket was used to execute the pass-the-ticket attack? (Format: Ticket Name)

![39fa3bbda97d4e8b107ccafb83bb9987.png](/resources/39fa3bbda97d4e8b107ccafb83bb9987.png)

From the Q9, we know that beside PowerShell version of mimikatz, the compiled version of mimikatz was also used to create golden ticket (Q13) and if we took a look at commandLine field again then we could see that mimikatz was also used to pass-the-ticket attack right here.

<details>
  <summary>Answer</summary>
<pre><code>0-60a10000-mtyson@krbtgt~HIGHLYSECURED.TECH-HIGHLYSECURED.TECH.kirbi</code></pre>
</details>

>Q13) It is believed that the attacker has achieved domain-wide compromise. What technique was used? (Format: Xxxxxx Xxxxxx)

![bbab6ef2440e5fd595c68a3e2a639914.png](/resources/bbab6ef2440e5fd595c68a3e2a639914.png)

Golden Ticket is a forged Kerberos Ticket-Granting Ticket (TGT), allowing an attacker to impersonate any user (even privileged accounts like domain administrators) within a domain so being able to create this golden ticket mean the domain is severely compromised at this point.

<details>
  <summary>Answer</summary>
<pre><code>Golden Ticket</code></pre>
</details>

>Q14) What command was used to perform the attack? (Format: Command)
<details>
  <summary>Answer</summary>
<pre><code>mimikatz.exe  "kerberos::golden /user:mtyson /domain:highlysecured.tech /sid:S-1-5-21-2778836013-2025790062-2140220986-1108 /krbtgt:31d6cfe0d16ae931b73c59d7e0c089c0 /id:500 /ptt"</code></pre>
</details>

![e014b8e4134711785e72f30836a9393b.png](/resources/e014b8e4134711785e72f30836a9393b.png)
https://blueteamlabs.online/achievement/share/52929/215
* * *