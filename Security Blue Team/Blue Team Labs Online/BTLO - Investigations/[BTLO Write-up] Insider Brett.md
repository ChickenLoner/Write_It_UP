# [Blue Team Labs Online - Insider Brett](https://blueteamlabs.online/home/investigation/insider-brett-f4852caac0)

![3e1fc8960cef3dbff65ec7c1be8a0664.png](/resources/3e1fc8960cef3dbff65ec7c1be8a0664.png)

We have identified that one of our IT contractors was the likely culprit of a recent incident.

>**Incident Response**

>**Tags**: nmap Metasploit
* * *
**Scenario**
Thanks for offering to help, Defender, we appreciate it!

As we discussed earlier, Initech’s CISO, Milton Waddams, CISSP, CISM, was the victim of a blackmail attempt requesting payment of 50 BTC. We have identified that one of our IT contractors (Brett Hart) was the likely culprit, but we just don’t know how he managed it as he was only a standard user.

We managed to collect some artifacts from a folder called “Hacking” on his Kali Virtual Machine and we’ve put these into the Investigation folder for you to take a look at.

We’ve been assured by Milton that the environment is employing all the best practices and is “unhackable”. Please can you investigate and let us know your feedback?
* * *
### Evidence Discovery
![900f8d31cbd2e200fd3df3f3135a98c4.png](/resources/900f8d31cbd2e200fd3df3f3135a98c4.png)
Lets take a look at what we have first, we have 2 image files and 4 text files and after review their names look like its artifacts left by nmap, metasploit and some password cracking tool.
***
### Tool Discovery 
Since we are dealing with just text file so we only have build-in Notepad, Notepad++ and CyberChef on this investigation machine
***
## Investigation
>Q1) What time was the nmap scan initiated? (Format: XXX XXX DD HH:MM:SS YYYY)

![fba1d073505f60aedb658e45a7103043.png](/resources/fba1d073505f60aedb658e45a7103043.png)

Lets start by `scan.txt` first since this is the one that is the most fitting for nmap result and I was right, its an output from nmap that target network range of `192.168.25.0/24` with stealth scan, NSE with smb and ldap focus, enumerate version and make it fast with T5 flag

And without scrolling, we already obtained answers from Q1 to Q4.

<details>
  <summary>Answer</summary>
<pre><code>Thu Apr 11 07:10:24 2024</code></pre>
</details>

>Q2) What is the full nmap command that ran? (Format: nmap command here)
<details>
  <summary>Answer</summary>
<pre><code>nmap -sS --script *smb*,*ldap* -sV --version-all -T5 -oN scan.txt 192.168.25.0/24</code></pre>
</details>

>Q3) What is the MAC address of the first responding IP? (Format: xx:xx:xx:xx:xx:xx)
<details>
  <summary>Answer</summary>
<pre><code>00:50:56:F4:3C:76</code></pre>
</details>

>Q4) What is the domain as determined by the LDAP scripts? (Format: string.tld)
<details>
  <summary>Answer</summary>
<pre><code>initech.local</code></pre>
</details>

>Q5) What is the dnsHostName? (Format: string.string.tld)

![7f0264498b45c9a3c0b80b7e91af9b40.png](/resources/7f0264498b45c9a3c0b80b7e91af9b40.png)
Now lets search for dns then we will have dnsHostName detected from LDAP scanning.
<details>
  <summary>Answer</summary>
<pre><code>voenmeh-d0f286a.initech.local</code></pre>
</details>

>Q6) Which enabled accounts had passwords guessed by the SMB brute force script? (Format: string, string)

![7092e323acbcfbbd4067e4f13bf68c99.png](/resources/7092e323acbcfbbd4067e4f13bf68c99.png)
Scroll down until we found `smb-brute` script then we should see 2 enabled accounts were successfully guessed by `smb-brute` script and along with that `smb-enum-sessions` also found active SMB sessions from 192.168.25.130 as MILTON-WADDAMS (Q7) user so if I were the attacker then I would use psexec module in metasploit and get a reverse shell.
<details>
  <summary>Answer</summary>
<pre><code>IT, milton-waddams</code></pre>
</details>

>Q7) What is the IP of the connecting machine in the active SMB session, and when did they log in? (Format: xx.xx.xx.xx, YYYY-MM-DDTHH:MM:SS)
<details>
  <summary>Answer</summary>
<pre><code>192.168.25.130, 2024-04-11T10:47:17</code></pre>
</details>

>Q8) What exploit did the attacker use in msfconsole? (Format: something/something/something/something)

![3742516721d0c5ff4c42906c8c6c631c.png](/resources/3742516721d0c5ff4c42906c8c6c631c.png)
Lets see if the attacker actually used psexec to obtain reverse shell, we could see that he actually search for `psexec` inside metasploit which confirm my instinct.

![37c6c4a7d52adf971212f22455f0f89a.png](/resources/37c6c4a7d52adf971212f22455f0f89a.png)

After select modules and setting required options then he executed it then metasploit will login as milton-waddamns user and uploaded reverse shell payload (Q9) which return metepreter shell back to the attacker at the end of this exploit.

<details>
  <summary>Answer</summary>
<pre><code>exploit/windows/smb/psexec</code></pre>
</details>

>Q9) What was the name of the uploaded payload? (Format: name.extension)
<details>
  <summary>Answer</summary>
<pre><code>VdMXyqeN.exe</code></pre>
</details>

>Q10) What is the title of the open Window in the first grabbed screenshot? (Format: Window Name)

![899ad7ae4bbac13e566c7fccf65f11af.png](/resources/899ad7ae4bbac13e566c7fccf65f11af.png)

meterpreter has a command that can be used to take a screenshot which is `screenshot` which we can see that the attacker not just took screenshot but also use `hashdump` to dump NTLM hash then crack it later hence 2 files we did not investigate yet.

![feaea992dd89292a9306755facdbe564.png](/resources/feaea992dd89292a9306755facdbe564.png)

Open the first screenshot took my the attacker then we could see that its an AD users and computers management window. 

<details>
  <summary>Answer</summary>
<pre><code>Active Directory Users and Computers</code></pre>
</details>

>Q11) What file did the attacker upload and where? (Format: name.extension, c:\path\to\folder)

![b7bb9d10dac207561edd01bbc9db4e12.png](/resources/b7bb9d10dac207561edd01bbc9db4e12.png)
After taking first screenshot, The attacker uploaded a text file to compromised user's desktop to it could be see right away after this user login and we can also see a second screenshot was taken after that too. 
<details>
  <summary>Answer</summary>
<pre><code>WARNING.txt, C:\Documents and Settings\milton-addams\Desktop</code></pre>
</details>

>Q12) What is the BTC address in the second grabbed screenshot? (Format: address)

![2cbafda446a7cb117f1910a904ac215e.png](/resources/2cbafda446a7cb117f1910a904ac215e.png)
Look like user opened a text file uploaded by the attacker and its a blackmail that telling user to transfer money into this BTC address.
<details>
  <summary>Answer</summary>
<pre><code>mpMKeox8YRcvwEVMuigWmGnJpMJVFhL683</code></pre>
</details>

>Q13) What tool is CRACKED.txt the output of? (Format: tool)

![a34cd7fefc292be13055bf3e1032f3ad.png](/resources/a34cd7fefc292be13055bf3e1032f3ad.png)
Lets take a look at this file then we could see the answer of Q14 and familiar format if you used John The Ripper before.

![d62253342a0b248a51baeb7c8da768ec.png](/resources/d62253342a0b248a51baeb7c8da768ec.png)
But if you didn't know then you could search for the first line on the internet which will tell you the answer right away.
<details>
  <summary>Answer</summary>
<pre><code>John the ripper</code></pre>
</details>

>Q14) What is the password for Brett? (Format: password)
<details>
  <summary>Answer</summary>
<pre><code>VERYSECURE!</code></pre>
</details>

![1bc7e330e582d5538ec7913d06810a3f.png](/resources/1bc7e330e582d5538ec7913d06810a3f.png)
https://blueteamlabs.online/achievement/share/52929/214
* * *
## Summary
An insider threat conducted port scanning on `192.168.25.0/24` subnet which discovery "milton-waddams" credential and used that to gain remote access to `192.168.25.136` which he dumped NTLM hash, took several screenshots, uploaded warning into this system and tried to capture a keystroke before exit and cracked NTLM hash with John The Ripper that obtained 2 more passwords of "IT", "Sales" 

### Timeline 
-  2024-04-11 07:10:24 UTC-4 : An insider started nmap scanning.
-  2024-04-11 07:13:36 UTC-4 : Nmap scanning done.
-  2024-04-11 07:56:54 UTC-4 : Meterpreter session opened on Metasploit

* * *