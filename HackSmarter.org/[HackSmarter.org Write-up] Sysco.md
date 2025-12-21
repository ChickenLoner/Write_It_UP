# [HackSmarter.org - Sysco](https://www.hacksmarter.org/courses/18876893-1afd-443f-b448-0681b13e86ec/take)

![8552d0ee47f2e022b4b9a698686e8112.png](/resources/8552d0ee47f2e022b4b9a698686e8112.png)

## Table of Contents

- [Abstract](#abstract)
- [Scope and Objective](#scope-and-objective)
- [Enumeration](#enumeration)
- [Obtaining jack.dowland credential via AS-REP Roasting attack](#obtaining-jackdowland-credential-via-as-rep-roasting-attack)
- [Discovery of roundcube to Password cracking of Cisco router configuration](#discovery-of-roundcube-to-password-cracking-of-cisco-router-configuration)
- [Initial Access as lainey.moore](#initial-access-as-laineymoore)
- [Discovery of greg.shields user via Putty shortcut file](#discovery-of-gregshields-user-via-putty-shortcut-file)
- [Privilege Escalation via Group Policy immediated task](#privilege-escalation-via-group-policy-immediated-task)

***
## Abstract 
Sysco is an easy Windows Active Directory machine involving both web element and active directory side while also have some niche router technology blend in as well.

We start off with nothing, only website running on port 80 can give us clue where we can get 4 different full name from the website and with the help of [username-anarchy](https://github.com/urbanadventurer/username-anarchy), we will be able to generate list of usernames and to prove their validity, we can use them with NetExec to conduct AS-REP Roasting attack and then recover password of "jack.dowland" user from cracking.

Directory bruteforcing on the website reveals roundcube, a webmail client where we can use credential of "jack.dowland" to login and discover Cisco router configuration file where its store crackable password of "lainey.moore" which leads us to the foothold on the domain controller since this user is a member of both "Remote Management Users" and "Remote Desktop Users"

On the documents folder of "lainey.moore" lies to putty shortcut file that will automatically connect to `netadmin@10.0.0.1` but as the password of "greg.shields" user was also discovered there.

The "greg.shields" user is a member of "Group Policy Creator Owners" group which can do pretty much everything on the default domain policy which linked to SYSCO.LOCAL domain by default and we can completely compromise the machine by creating immediated task to add controlled user to local administrator group.

## Scope and Objective
Sysco is a Managed Service Provider that has tasked you to perform an external penetration testing on their active directory domain. You must obtain initial foothold, move laterally and escalate privileges while evading Antivirus detection to obtain administrator privileges.

**Objectives and Scope**
The core objective of this external penetration test is to simulate a realistic, determined adversary to achieve Domain Administrator privileges within Sysco's Active Directory (AD) environment. Starting from an external position, we will focus on obtaining an initial foothold, performing lateral movement, and executing privilege escalation while successfully evading Antivirus (AV) and other security controls. This is a red-team exercise to find security weaknesses before a real attacker does.

## Enumeration

I will start with rustscan since it is faster than nmap and VPN connection can tolerate this much of traffic unlike HTB. (I could not use rustscan could not be used on HTB) and we can see a lot of port opening on this machine as expected since this is the domain controller and beside that we can also see that there is a website running on port 80
```
rustscan -a sysco -- -A
```
![699e628e172698ca58afd7bdd2a8e05e.png](/resources/699e628e172698ca58afd7bdd2a8e05e.png)

We can look at the certificate of service such as RDP to get the domain and hostname and add them to our hosts file

![ad342b4a7a48fa78ce3c8acbd3c00d0b.png](/resources/ad342b4a7a48fa78ce3c8acbd3c00d0b.png)

Since no credential was provided, I will use NetExec to check for Anonymous authentication and guest account if it could be used and in this case, Anonymous authentication is not allowed and guest account is disabled.

![fa085f22a0f44e98015ec42933f51c3d.png](/resources/fa085f22a0f44e98015ec42933f51c3d.png)

Looking at the website, we can see that it is hosting with Apache and the programming language that used to built this is PHP which is non-standard since Windows Server often have IIS to host the website

![6b9aed584ca5f879cf0b0eb2978db68b.png](/resources/6b9aed584ca5f879cf0b0eb2978db68b.png)

The website is more like a static webpage to display company profile and we can submit something via contact form but my focus will be on the 4 employees of this company here

![d31c7ac65bce15b12da2945c823e7ecd.png](/resources/d31c7ac65bce15b12da2945c823e7ecd.png)

## Obtaining jack.dowland credential via AS-REP Roasting attack

After putting 4 full name of employees into a text file, I will use [username-anarchy](https://github.com/urbanadventurer/username-anarchy) to create many various version of usernames and then we can use tool like kerbrute to check the valid domain user from generated list

```
/opt/username-anarchy/username-anarchy -i hero > A.txt
```

I will use NetExec to check both its validity and AS-REP Roastable user in one go and we can see that we have 1 hash of "jack.dowland" returns

```
uv run nxc ldap DC01.SYSCO.LOCAL -u A.txt -p '' --asreproast as.txt
```
![c4fbbd67f17afa33c512ecb64d5fd2d5.png](/resources/c4fbbd67f17afa33c512ecb64d5fd2d5.png)

By cracking the hash with `rockyou.txt`, we can now retrieve "musicman1" as cleartext password of this user 
```
john --wordlist=/usr/share/wordlists/rockyou.txt as.txt
```
![7deafffba264f1e922747c33653c48d8.png](/resources/7deafffba264f1e922747c33653c48d8.png)
![f6d7129a45897b561c0ec2c0544fd026.png](/resources/f6d7129a45897b561c0ec2c0544fd026.png)

Since we have valid domain credential now, I will also pull a valid domain user list to a new text file first so if I obtained a new hash or a password then I can only spray on the valid domain user 

```
uv run nxc ldap DC01.SYSCO.LOCAL -u 'jack.dowland' -p 'musicman1' --users-export user.txt
```
![6ae88c41045a9ca0c69971f2fe39110d.png](/resources/6ae88c41045a9ca0c69971f2fe39110d.png)

Next, I check for non-standard share if we can have access to any of them but look like there is none

![d2b54a72365b9ee8947cc3ce5943a07d.png](/resources/d2b54a72365b9ee8947cc3ce5943a07d.png)

I use rusthound to retrieve domain information and that can be used to visualize the dangerous relationship between each domain object on the bloodhound.

```
rusthound-ce -d SYSCO.LOCAL -u 'jack.dowland' -p 'musicman1' -z
```
![10eea67a3a11964a8c60d11b8ba8fc6d.png](/resources/10eea67a3a11964a8c60d11b8ba8fc6d.png)

By using saved query "Shortest Path to Domain Admins", I can see that if i were able to compromise "greg.shields" user, which is a member of "Group Policy Creator Owners" user that can do anything to DEFAULT DOMAIN POLICY

![ac64ff972de2be7013535a7e530d8bab.png](/resources/ac64ff972de2be7013535a7e530d8bab.png)

## Discovery of roundcube to Password cracking of Cisco router configuration

Since I hit the deadend on the domain side, I use feroxbuster to bruteforce directory which reveals `/roundcube` path indicating webmail client on the server.

```
feroxbuster -u http://SYSCO.LOCAL/ -n --auto-tune -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt
```
![27d9d672aabdf4db23974d4b497cd4c9.png](/resources/27d9d672aabdf4db23974d4b497cd4c9.png)
![d9d15015f9a859e6b8990e3f1d46390d.png](/resources/d9d15015f9a859e6b8990e3f1d46390d.png)

By using credential of "jack.dowland", we can now check his inbox and sent box which we will see that he sent router configuration file configured by "lainey.moore" to him to let him fix the issue

![fda5f304015d5e475e05bfe5b83208f4.png](/resources/fda5f304015d5e475e05bfe5b83208f4.png)

And by downloading the attachment file, we can see that this router configuration is belong to Cisco router where also have secret 5 cisco encrypted password here as well

![bdc1de645913822a2060dcca09239a8a.png](/resources/bdc1de645913822a2060dcca09239a8a.png)

We can go to [example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes) of hashcat to find the mode number we can use to crack it 

![f755bdcfe68dd9342f69e340105babf7.png](/resources/f755bdcfe68dd9342f69e340105babf7.png)

Using the same wordlist, we can now retrieve "Chocolate1" password which probably belong to  "lainey.moore" 

```
hashcat -m 500 ciscohash --wordlist /usr/share/wordlists/rockyou.txt
```
![c2a6011c0525f621fee76d1f06ba3186.png](/resources/c2a6011c0525f621fee76d1f06ba3186.png)

## Initial Access as lainey.moore

By spraying password on all valid domain users, we can see that this password is indeed belongs to  "lainey.moore" user

```
uv run nxc smb DC01.SYSCO.LOCAL -u user.txt -p 'Chocolate1'
```
![889d19fb08f6d079f0f40540a5763fa2.png](/resources/889d19fb08f6d079f0f40540a5763fa2.png)

This user is a member of both "Remote Management Users" and "Remote Desktop Users" group so we can either use RDP or WinRM to gain foothold on this machine

![3b66b5e5a4ad3e7518231148a5f75ad9.png](/resources/3b66b5e5a4ad3e7518231148a5f75ad9.png)

NetExec does not do a really good job via RDP since it will only perform Network Level Authentication (NLA) check but I can still see that I can pretty much run commands via WinRM indicates by "Pwn3d!" sign

![8f3224d9b9e9f035384eef0d03e78ea6.png](/resources/8f3224d9b9e9f035384eef0d03e78ea6.png)

To check if we can RDP into the machine, we can also use [RDPChecker](https://github.com/Hypnoze57/RDPChecker) which actually authenticate to the machine and established session before returning the result to us

![5c3e8160eb6577ef038d7120408af9a9.png](/resources/5c3e8160eb6577ef038d7120408af9a9.png)

Now I will use evil-winrm-py to foothold and loot user flag located on the desktop of this user

```
evil-winrm-py -i DC01.SYSCO.LOCAL -u lainey.moore -p 'Chocolate1'
```
![7a105939db4e8f9a9ec19161105e0957.png](/resources/7a105939db4e8f9a9ec19161105e0957.png)

## Discovery of greg.shields user via Putty shortcut file

There is a suspicious shortcut file on the Documents folder of this user so we will download it extract useful information from it on our machine

```
download "Putty - HS Router login.lnk" .
```
![39f57d16c2de1907696e15d561c92081.png](/resources/39f57d16c2de1907696e15d561c92081.png)

Shortcut file can be configued to execute command on its own and by using `lnkinfo`, we can extract some juicy information from it which reveals that there is an SSH credential used to connect to "10.0.0.1" host as "netadmin" using "5y5coSmarter2025!!!" as password

```
lnkinfo Putty\ -\ HS\ Router\ login.lnk
```
![8ae7843b08684df41c070926a2754ac6.png](/resources/8ae7843b08684df41c070926a2754ac6.png)

After spraying this password, we can now take control of "greg.shields" user

```
uv run nxc smb DC01.SYSCO.LOCAL -u user.txt -p '5y5coSmarter2025!!!'
```
![b516ca188574ae45be18f1cf917aeb79.png](/resources/b516ca188574ae45be18f1cf917aeb79.png)

## Privilege Escalation via Group Policy immediated task

As we already discovered that "greg.shields" user is a member of "Group Policy Creator Owners" group which can do pretty much everything on the default domain policy which linked to SYSCO.LOCAL domain by default and we can completely compromise the machine by creating immediated task to add controlled user to local administrator group.

![4323a94274b77ed3a8106139eb99e607.png](/resources/4323a94274b77ed3a8106139eb99e607.png)

First, let's get the GPO ID first and we can obtain it via GpoPath or the first CN of Distinguished Name here

![703de7bdab06607b95966d66a062f221.png](/resources/703de7bdab06607b95966d66a062f221.png)

There are several tools that can abuse GPO by creating immediated task but most of them required local access and likely to be detected by Windows Defender so I will go with [pyGPOAbuse](https://github.com/Hackndo/pyGPOAbuse) which do the same job but remotely

```
python pygpoabuse.py SYSCO.LOCAL/greg.shields:'5y5coSmarter2025!!!' -gpo-id 31B2F340-016D-11D2-945F-00C04FB984F9 -command 'net localgroup administrators greg.shields /add' -f
```
![03054aa2bff4d9bd3b65358df9c34bf2.png](/resources/03054aa2bff4d9bd3b65358df9c34bf2.png)

After a job created to add our controlled user to local administrators group, in normal context we might need to wait for like half an hour for it to apply but as "greg.shields" is also a member of both "Remote Management Users" and "Remote Desktop Users", I will use evil-winrm-py to connect to the machine as "greg.shields" and force apply the group policy

```
evil-winrm-py -i DC01.SYSCO.LOCAL -u 'greg.shields' -p '5y5coSmarter2025!!!'
gpupdate /force
```
![712190da131cc01d5eeda9abb17bf739.png](/resources/712190da131cc01d5eeda9abb17bf739.png)
![e979ec44a0440ac61d62eb255a01d394.png](/resources/e979ec44a0440ac61d62eb255a01d394.png)

Now we can reconnect and loot root flag located on the desktop of administrator user

![1c4910e3f4da88e1af1f653ff8fbf89b.png](/resources/1c4910e3f4da88e1af1f653ff8fbf89b.png)

And we are done :D

***
