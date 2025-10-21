# [CyberDefenders - MrRobot](https://cyberdefenders.org/blueteam-ctf-challenges/mrrobot/)
Created: 05/06/2024 19:35
Last Updated: 08/06/2024 16:47
* * *
>Category: Endpoint Forensics
>Tags: Memory Forensic, Phishing, RAT, Volatility, R-Studio, T1048, T1005, T1016, T1003.002, T1055, T1060, T1204, T1566.001, T1021
* * *
**Scenario**:
An employee reported that his machine started to act strangely after receiving a suspicious email for a security update. The incident response team captured a couple of memory dumps from the suspected machines for further inspection. Analyze the dumps and help the SOC analysts team figure out what happened!

**Tools**:
- [Volatility2](https://github.com/volatilityfoundation/volatility)
- [Volatility3](https://github.com/volatilityfoundation/volatility)
- [Rstudio](https://www.r-studio.com/)
* * *
## Questions
> Q1: Machine:Target1 What email address tricked the front desk employee into installing a security update?

![3a571c113d0f511d91d1e834761e39ae.png](../../_resources/3a571c113d0f511d91d1e834761e39ae.png)

First we need to determine which volatility profile we should use on this memory dump then after determine which profile to use then we're good to fo

![7cb9fea83d85965be57e67dcee024112.png](../../_resources/7cb9fea83d85965be57e67dcee024112.png)

I started off with `vol.py -f Target1-1dd8701f.vmss --profile=Win7SP1x86_23418 pstree` to find if there any outlook process or email client process that were running while this memory dump was taken and there is

![dd2be8a53bda8913bcce93a30a6f1691.png](../../_resources/dd2be8a53bda8913bcce93a30a6f1691.png)

Then I used `vol.py -f Target1-1dd8701f.vmss --profile=Win7SP1x86_23418 handles -p 3196 | grep "File"` to find if there is any files that we can dump like ost files or cache files and you can see that there are ost files that we can dump from this memory dump

![6cdc2179fc51bbfdb7445dcd5fee1b14.png](../../_resources/6cdc2179fc51bbfdb7445dcd5fee1b14.png)

Lets dump all ost files using `vol.py -f Target1-1dd8701f.vmss --profile=Win7SP1x86_23418 dumpfiles -n -u -r ost$ -D /tmp/robot`

![8a87b8fa0ad5306b5991bf8d3a74f9f7.png](../../_resources/8a87b8fa0ad5306b5991bf8d3a74f9f7.png)

`find . -type f -exec pffexport -m all -f all "{}" \;`

I found this command from some write-ups which is really useful, it will find all PST and OST files used by Microsoft Outlook and use pffexport to extract data from these files and lastly we will have a directory that is an output from pffexport

![97857f1c98890909a106a8101cae9a97.png](../../_resources/97857f1c98890909a106a8101cae9a97.png)

Find for Headers then we will have an email of suspected sender

![66e475dcc919d59d019d30fc4a3dd291.png](../../_resources/66e475dcc919d59d019d30fc4a3dd291.png)

```
th3wh1t3r0s3@gmail.com
```

> Q2: Machine:Target1 What is the filename that was delivered in the email?

![22387c51c27925fedac520cff47eff9b.png](../../_resources/22387c51c27925fedac520cff47eff9b.png)

Read `Message.html` we can see a file was sent as url for user to download this file from his browser

```
AnyConnectInstaller.exe
```

> Q3: Machine:Target1 What is the name of the rat's family used by the attacker?

![46651a41c49930777ead05837ea6fe1a.png](../../_resources/46651a41c49930777ead05837ea6fe1a.png)

Lets find this file with `vol.py -f Target1-1dd8701f.vmss --profile=Win7SP1x86_23418 filescan | grep "AnyConnectInstaller.exe"` then we will have bunch of them here

![af6dc78274961912231f3c6dfa2ea09c.png](../../_resources/af6dc78274961912231f3c6dfa2ea09c.png)

I dumpped one of them with `vol.py -f Target1-1dd8701f.vmss --profile=Win7SP1x86_23418 dumpfiles -Q 0x000000003e0bc5e0 -D /tmp/robot/` then generate md5 hash to search on VirusTotal

![a92a04ead3bdb4068cb0e7bf5669de53.png](../../_resources/a92a04ead3bdb4068cb0e7bf5669de53.png)

![9229cdf0e980b399751e4ef7248fc37d.png](../../_resources/9229cdf0e980b399751e4ef7248fc37d.png)

We will have dat and image files, both of them are malicious but there are the same malware since we dumpped from the same physical address

![b27f8387e18754d48c205c431a797315.png](../../_resources/b27f8387e18754d48c205c431a797315.png)

I had to go to Community tab to finally figure out that it is XtreamRAT

```
XTREMERAT
```

> Q4: Machine:Target1 The malware appears to be leveraging process injection. What is the PID of the process that is injected?

![bd0ebdfc46afa45be0e5388bebe512d1.png](../../_resources/bd0ebdfc46afa45be0e5388bebe512d1.png)

Go to Shell Commands and Processes Injected section under Behavior tab then we can see that a legitimate process like iexplore is the target of this process injection

![3cbc8ad5cccdac8001fa8380ba2c7dbf.png](../../_resources/3cbc8ad5cccdac8001fa8380ba2c7dbf.png)

I used `vol.py -f Target1-1dd8701f.vmss --profile=Win7SP1x86_23418 pstree` to identify its pid of this process

```
2996
```

> Q5: Machine:Target1 What is the unique value the malware is using to maintain persistence after reboot?

![76acb8e844aa337ec689da7cda196bd8.png](../../_resources/76acb8e844aa337ec689da7cda196bd8.png)

I found this on Registry Keys Set then we can see that it was set persistence under sevaral registry keys under the name of MrRobot which is a name of a show and theme of this lab

```
MrRobot
```

> Q6: Machine:Target1 Malware often uses a unique value or name to ensure that only one copy runs on the system. What is the unique name the malware is using?

I recommened you to read this - [Malware Detection Avoidance through Mutexes](https://www.grin.com/document/1138722) to understand how mutex will prevent the same malware from being executed again if it already executed on the same system

![0e437475c55c5a205ea76d7e513005bf.png](../../_resources/0e437475c55c5a205ea76d7e513005bf.png)

So we will have to find for mutex created from this malware under Behavior tab then we will have this `fsociery0.dat` which is the one we're looking for 

![481807195c8fe361e423900f63a9c8bb.png](../../_resources/481807195c8fe361e423900f63a9c8bb.png)

Or we can use `vol.py -f Target1-1dd8701f.vmss --profile=Win7SP1x86_23418 handles -p 2996 | grep -i "mutant"` to find mutex from memory dump directly

```
fsociety0.dat
```

> Q7: Machine:Target1 It appears that a notorious hacker compromised this box before our current attackers. Name the movie he or she is from.

I guessed it was MrRobot but I was wrong now I need to take a hint which tell me to use R-studio so lets do it

![08ad0885d1a9de51c06a103ab1cc1094.png](../../_resources/08ad0885d1a9de51c06a103ab1cc1094.png)

Then we can see that zerocool user was there when this memory dump was captured

![9fe2fc57aae7714c319e1d70e682ae56.png](../../_resources/9fe2fc57aae7714c319e1d70e682ae56.png)

Which is from Hackers movie

```
hackers
```

> Q8: Machine:Target1 What is the NTLM password hash for the administrator account?

![f908e3c75948dff4fe482c8c2b6ffdea.png](../../_resources/f908e3c75948dff4fe482c8c2b6ffdea.png)

Used `vol.py -f Target1-1dd8701f.vmss --profile=Win7SP1x86_23418 hashdump` to dump both LM and NTLM hashes of all users it could catch on this machine

Then the rightest one is the NTLM while the middle is LM

```
79402b7671c317877b8b954b3311fa82
```

> Q9: Machine:Target1 The attackers appear to have moved over some tools to the compromised front desk host. How many tools did the attacker move?

![29488fc59c0cd874e41829d9371bddb1.png](../../_resources/29488fc59c0cd874e41829d9371bddb1.png)

Eariler from pstree plugin, I found that cmd process were running so I used `vol.py -f Target1-1dd8701f.vmss --profile=Win7SP1x86_23418 consoles` to look into which commands that were executed on cmd and look like an attacker have these 4 exe files but look like 4 is not the right answer so we need to look into each one of them

![00dbb43596460033d5b6f1b031c4a2bf.png](../../_resources/00dbb43596460033d5b6f1b031c4a2bf.png)

`nbtscan.exe` is NETBIOS nameserver scanner

![aaaefa4878a3cfd9e0dafe6e3c91fed1.png](../../_resources/aaaefa4878a3cfd9e0dafe6e3c91fed1.png)

`Rar.exe` is winrar executable to compress and decompress files

![bc5c339e4be1628c85e9b85bd37e9eea.png](../../_resources/bc5c339e4be1628c85e9b85bd37e9eea.png)

but `wce.exe` and `getlsasrvaddr.exe` are from found on the same github repo so we can count them as 1 tool

![736e22a98a3c74590578291c274ba9b6.png](../../_resources/736e22a98a3c74590578291c274ba9b6.png)

`wce.exe` can be used for acitivity related to authentication on Windows sytem

![c8d4439c2aca2f2e9a902fa9d24b511a.png](../../_resources/c8d4439c2aca2f2e9a902fa9d24b511a.png)

while `getlsasrvaddr.exe` is used to get lsas process virtual address as it names imply 

```
3
```

> Q10: Machine:Target1 What is the password for the front desk local administrator account?

![d0238145e21a34689d173252d5d975e8.png](../../_resources/d0238145e21a34689d173252d5d975e8.png)

An attacker used `wce.exe` to "Dump cleartext passwords stored by the digest authentication package" so we also obtained cleartext password of front desk local admin here

```
flagadmin@1234
```

> Q11: Machine:Target1 What is the std create data timestamp for the nbtscan.exe tool?

![506f37bf8c29cae5c8ea7e9894b40c49.png](../../_resources/506f37bf8c29cae5c8ea7e9894b40c49.png)

Used `vol.py -f Target1-1dd8701f.vmss --profile=Win7SP1x86_23418 mftparser | grep -i "nbtscan"` to find a timestamp from MFT directly

```
2015-10-09 10:45:12 UTC
```

> Q12: Machine:Target1 The attackers appear to have stored the output from the nbtscan.exe tool in a text file on a disk called nbs.txt. What is the IP address of the first machine in that file?

![777349483993ffbc2dcf4b770db4f207.png](../../_resources/777349483993ffbc2dcf4b770db4f207.png)

Find physical address with filescan then dump it to display content inside of it 
```
10.1.1.2
```

> Q13: Machine:Target1 What is the full IP address and the port was the attacker's malware using?

![5b8a0e10d3bbde32c60e129499f919ae.png](../../_resources/5b8a0e10d3bbde32c60e129499f919ae.png)

Used `vol.py -f Target1-1dd8701f.vmss --profile=Win7SP1x86_23418 netscan | grep -i "iexplore"` to display connection associated with iexplore process only

```
180.76.254.120:22
```

> Q14: Machine:Target1 It appears the attacker also installed legit remote administration software. What is the name of the running process?

![978aed09a2a9081379f103de8ac5f003.png](../../_resources/978aed09a2a9081379f103de8ac5f003.png)

From pstree plugin output, we also see that Teamviewer was also running on this system

```
TeamViewer.exe
```

> Q15: Machine:Target1 It appears the attackers also used a built-in remote access method. What IP address did they connect to?

![29e7e06fd9dea8897846c157e94af7c7.png](../../_resources/29e7e06fd9dea8897846c157e94af7c7.png)

used netscan plugin again then find for microsoft built-in remote access tool then we have this `mstsc.exe` which used for RDP connection

```
10.1.1.21
```

> Q16: Machine:Target2 It appears the attacker moved latterly from the front desk machine to the security admins (Gideon) machine and dumped the passwords. What is Gideon's password?

![8d9cbd2f62f295441ce58bbd20d4b003.png](../../_resources/8d9cbd2f62f295441ce58bbd20d4b003.png)

We will also need to determine volatility profile for this memory dump which we can use the same profile we just used from previous dump

![b990ea12f8c9bfb8541ef18795d28b0e.png](../../_resources/b990ea12f8c9bfb8541ef18795d28b0e.png)

Used `vol.py -f target2-6186fe9f.vmss --profile=Win7SP1x86_23418 pstree` then we can see outlook and cmd were running 

![802af58d48ae9e832767cdcebe0e4d3e.png](../../_resources/802af58d48ae9e832767cdcebe0e4d3e.png)

I'm interested by cmd so I used `vol.py -f target2-6186fe9f.vmss --profile=Win7SP1x86_23418 consoles` and we can see that an attacker used `wce.exe` to dump cleartext password of Gideon to `w.tmp`

![260f3f0e69beb21ae3a5a3fad0a3bc46.png](../../_resources/260f3f0e69beb21ae3a5a3fad0a3bc46.png)

Next we will use `vol.py -f target2-6186fe9f.vmss --profile=Win7SP1x86_23418 filescan | grep -i "w.tmp"` to find physical address of this file to dump

![104a2dc2d80f8338b143f6bea828b893.png](../../_resources/104a2dc2d80f8338b143f6bea828b893.png)

Then dump it with `vol.py -f target2-6186fe9f.vmss --profile=Win7SP1x86_23418 dumpfiles -Q 0x000000003fcf2798 -D /tmp/robot/`

```
t76fRJhS
```

> Q17: Machine:Target2 Once the attacker gained access to "Gideon," they pivoted to the AllSafeCyberSec domain controller to steal files. It appears they were successful. What password did they use?

![f9f66caa76e655ab2beccf632d63eb43.png](../../_resources/f9f66caa76e655ab2beccf632d63eb43.png)

From console history,we can see that an attacker used rar to compress a file with password

![548f267072178ed89eb3277c970d3179.png](../../_resources/548f267072178ed89eb3277c970d3179.png)

Lets ChatGPT explain each arguments for us

```
123qwe!@#
```

> Q18: Machine:Target2 What was the name of the RAR file created by the attackers?
```
crownjewlez.rar
```

> Q19: Machine:Target2 How many files did the attacker add to the RAR archive?

![c563b91b6266c1994e2f749baec64ec6.png](../../_resources/c563b91b6266c1994e2f749baec64ec6.png)

We need to dump process that was used to create rar archive, first lets grab this PID

![b3831aa9fe1bf8eaac84df29065b2057.png](../../_resources/b3831aa9fe1bf8eaac84df29065b2057.png)

Then use `vol.py -f target2-6186fe9f.vmss --profile=Win7SP1x86_23418 memdump -p 3048 -D /tmp/robot/` 

![9007865d033aea263c9b01e05db01302.png](../../_resources/9007865d033aea263c9b01e05db01302.png)

we all know that this archive aims to archive all text file inside crownjewel directory so I will use `strings -el /tmp/robot/3048.dmp | grep "crownjewel" | grep ".txt"` to find those text files and it worked like a champ

![be885ebae002fd3e154a8ce0a3b6b7e2.png](../../_resources/be885ebae002fd3e154a8ce0a3b6b7e2.png)

```
3
```

> Q20: Machine:Target2 The attacker appears to have created a scheduled task on Gideon's machine. What is the name of the file associated with the scheduled task?

![c4b779bb576a6a70d340dd413c9fb372.png](../../_resources/c4b779bb576a6a70d340dd413c9fb372.png)

You can use R-studio to navigate to `'\Windows\System32\Tasks\'` and find for suspicious schedule task but if you're using volatilty like me then we will use `vol.py -f target2-6186fe9f.vmss --profile=Win7SP0x86 filescan | grep '\\Windows\\System32\\Tasks\\'` to list all files inside task directory and this `At1` task looking out of place for me

![a71d4cb0e76098079e59887aca9ffe52.png](../../_resources/a71d4cb0e76098079e59887aca9ffe52.png)

So I dumped it with `vol.py -f target2-6186fe9f.vmss --profile=Win7SP0x86 dumpfiles -Q 0x000000003fc399b8 -D /tmp/robot/task/` then we can see it was set to execute a bat script, so this one is the task we're looking for

```
1.bat
```

> Q21: Machine:POS What is the malware CNC's server?

![aa13bf1d6aaf2619fc46134ff7f66c9b.png](../../_resources/aa13bf1d6aaf2619fc46134ff7f66c9b.png)

This memory dump is still using the same profiles as other 2

![e52f3b0bfba68b0872a135d06c81ea06.png](../../_resources/e52f3b0bfba68b0872a135d06c81ea06.png)

From other memory dumps we know that a process that was injected is `iexplore.exe` so we will use `vol.py -f POS-01-c4e8f786.vmss --profile=Win7SP0x86 netscan` and looking for `iexplore`

```
54.84.237.92
```

> Q22: Machine:POS What is the common name of the malware used to infect the POS system?

![aa5c4f8347538da50573b8afb91b884c.png](../../_resources/aa5c4f8347538da50573b8afb91b884c.png)

![84b9040cf23699ac6ad1a61d68c73617.png](../../_resources/84b9040cf23699ac6ad1a61d68c73617.png)

Lets use `vol.py -f POS-01-c4e8f786.vmss --profile=Win7SP0x86 malfind -p 3208 -D /tmp/robot/` to dump it, we can see that it has 4d5a or MZ as magic number which mean its an executable file we're looking for

![eb2814e7e37ee76ac3954d863eac260d.png](../../_resources/eb2814e7e37ee76ac3954d863eac260d.png)

Search it hash on VirusTotal then we will have its common name

```
Dexter
```

> Q23: Machine:POS In the POS malware whitelist. What application was specific to Allsafecybersec?

![990be0b9caf43047dd76eb67269714c4.png](../../_resources/990be0b9caf43047dd76eb67269714c4.png)

I used strings and grep to use for exe then we can see that this exe file looking out of place here and turn out its the file we're looking for 

```
allsafe_protector.exe
```

> Q24: Machine:POS What is the name of the file the malware was initially launched from?

![04998be2d2430c55032ae32eb8b426b5.png](../../_resources/04998be2d2430c55032ae32eb8b426b5.png)

I used strings to search for C2 server from memory dump directly then we can see that suspicious file url was sent to POS with email 

```
allsafe_update.exe
```

![3b0491aa271516b19d1918aa1c4e5e54.png](../../_resources/3b0491aa271516b19d1918aa1c4e5e54.png)
* * *
