# [CyberDefenders - Ulysses](https://cyberdefenders.org/blueteam-ctf-challenges/ulysses/)
Created: 23/05/2024 19:05
Last Updated: 13/06/2024 12:19
* * *
>Category: Endpoint Forensics
>Tags: Memory Forensic, Disk Forensic, Volatility, Autopsy, T1498, T1048, T1071, T1110, T1133, T1059, T1190
* * *
**Instructions**:
- Uncompress the lab (pass: **cyberdefenders.org**), investigate this case, and answer the provided questions.
- Use the [latest version of Volatility](https://github.com/volatilityfoundation/volatility), place the attached Volatility profile "**Debian5_26.zip**" in the following path *volatility/volatility/plugins/overlays/linux*, and verify the profile is listed there as in the following [screenshot](https://cyberdefenders.org/static/img/vol.png).
 
* * *
A Linux server was possibly compromised, and a soc analyst is required in order to understand what really happened. Hard disk dumps and memory snapshots of the machine are provided in order to solve the challenge.

**Challenge Files**:
- victoria-v8.kcore.img: memory dump done by dd’ing /proc/kcore.
- victoria-v8.memdump.img: memory dump done with memdump.
- Debian5_26.zip: volatility custom Linux profile.
 
**Supportive Tools**:
- [Volatility](https://github.com/volatilityfoundation/volatility)
- [010 Editor](https://www.sweetscape.com/download/010editor/)
- [Autopsy](https://www.autopsy.com/download/)
* * *
## Questions
> Q1: The attacker was performing a Brute Force attack. What account triggered the alert?

![099fe0c023b7afb604676fa31c084f3b.png](../../_resources/099fe0c023b7afb604676fa31c084f3b-1.png)
First we need to move zip profile to overlay directory then we can start our investigation

Look like memory file can't be used to solve this question, we gonna need to retrieve log files from disk image
![181f49d0b465410233a4afce80df8371.png](../../_resources/181f49d0b465410233a4afce80df8371-1.png)
Lucky for us that auth.log is not large so we can catch the right account that was brute forced right away
```
ulysses
```

> Q2: How many were failed attempts there?

![645ae5837636463ab753a027f1b689a2.png](../../_resources/645ae5837636463ab753a027f1b689a2-1.png)
Filtered by "failed" but there are 33 of them which is not the correct answer so we have to minus 1 that not related to brute force attack which is this one
```
32
```

> Q3: What kind of system runs on the targeted server?

![46e9434b140637443d7b3fdf94f42d30.png](../../_resources/46e9434b140637443d7b3fdf94f42d30-1.png)
Find `/etc/issues`, then you will have the answer
```
Debian GNU/Linux 5.0
```

> Q4: What is the victim's IP address?

![633bd8fd29426a1e5ea8d69c7bb725e5.png](../../_resources/633bd8fd29426a1e5ea8d69c7bb725e5-1.png)

We already know which profile to use so lets use `vol.py -f victoria-v8.memdump.img --profile=LinuxDebian5_26x86 linux_netstat` to display all connections from this memory dump and We can see the private IP address this system used here

![2dc777158c602fb5ff9d3c1665f53eca.png](../../_resources/2dc777158c602fb5ff9d3c1665f53eca-1.png)

Another way to find this answer is to find `/var/lib/dhcp3/dhclient.eth0.leases`  that store DHCP lease information for the eth0 network interface

```
192.168.56.102
```

> Q5: What are the attacker's two IP addresses? Format: comma-separated in ascending order

![476f120e04faf4e3eba1dbbd705cce9c.png](../../_resources/476f120e04faf4e3eba1dbbd705cce9c-1.png)

Result from previous netstat scan, we can see that there are connections this these 2 IP addresses, one on port 4444 and 8888 which might be reverse shell connection and one is from smtp port to an attacker IP address 

```
192.168.56.1,192.168.56.101
```

> Q6: What is the "nc" service PID number that was running on the server?

![311a8890141aa973f44375c0ce9abb86.png](../../_resources/311a8890141aa973f44375c0ce9abb86-1.png)

Use `vol.py -f victoria-v8.memdump.img --profile=LinuxDebian5_26x86 linux_pslist` to list all process or you can go back to netstat plugin result which also tells us the same PID

```
2169
```

> Q7: What service was exploited to gain access to the system? (one word)

![72ecf2b83c21eeeb870ff54b438be156.png](../../_resources/72ecf2b83c21eeeb870ff54b438be156-1.png)

I didn't know where to find but I got a hint that its related to SMTP port that we discovered from netstat scan 

So I tried to search relevant information about an attacker IP address using this command `grep -F -l -r "192.168.56.1"`, which landed me with 3 files that caught my interest 

![4e550587a6771396b9af07d2af9d740f.png](../../_resources/4e550587a6771396b9af07d2af9d740f-1.png)

First is root's bash history and as you can see that there are several commands related to exim4 which is a mail traffer agaent on Linux 

![3a3013948652687012d26ac9314409c1.png](../../_resources/3a3013948652687012d26ac9314409c1-1.png)

I investigated `mainlog` first, It does look like an attacker exploited RCE vulnerability of exam4 

![0dd19d9023e941660d0eb5c79d602711.png](../../_resources/0dd19d9023e941660d0eb5c79d602711-1.png)

But if you also investigated `injectlog`
```
exim4
```

> Q8: What is the CVE number of exploited vulnerability?

![ca39606084a60bda4e66b24d4bf105a5.png](../../_resources/ca39606084a60bda4e66b24d4bf105a5-1.png)
we know the version of exim4 and it results in RCE so we can search for CVE with just this information thus landed me with this exploit database [script](https://www.exploit-db.com/exploits/16925) and it was found along his brother CVE-2010-4345 for local privilege escaltion
```
CVE-2010-4344
```

> Q9: During this attack, the attacker downloaded two files to the server. Provide the name of the compressed file.

![6040e3fd1e3f7e35eccd817791bc3a8a.png](../../_resources/6040e3fd1e3f7e35eccd817791bc3a8a-1.png)
```
rk.tar
```

> Q10: Two ports were involved in the process of data exfiltration. Provide the port number of the highest one.

![476f120e04faf4e3eba1dbbd705cce9c.png](../../_resources/476f120e04faf4e3eba1dbbd705cce9c-1.png)
Result from netstat plugin told us that an attacker made a several connection to infected host
```
8888
```

> Q11: Which port did the attacker try to block on the firewall?

Since we couldn't find anything on bash history so I shifted my attention to tmp directory that we found eariler that an attacker dropped some files here
![d11f19c209902ab5f87a6df85a80459e.png](../../_resources/d11f19c209902ab5f87a6df85a80459e-1.png)
We got a pearl script and tar file on tmp directory 
![9a712943f5fca16359104d014167d51f.png](../../_resources/9a712943f5fca16359104d014167d51f-1.png)
pearl script is an exploitation script for CVE-2020-4345 so its not what we're looking for
![6e39e8220bcf35b842d65736fdaa2a04.png](../../_resources/6e39e8220bcf35b842d65736fdaa2a04-1.png)
use `tar -xf rz.tar` to extract it then you will have a directory contains 5 files 
![79ed5636bca559b78418e25fb73b5f4e.png](../../_resources/79ed5636bca559b78418e25fb73b5f4e-1.png)
`vars.sh` contains 2 variables and look like this is what we're looking for but we need to find which script that used this file
![fa28951263b96d5da3a3556aad53ca24.png](../../_resources/fa28951263b96d5da3a3556aad53ca24-1.png)
Then what I opened `install.sh`, It was right there 

Command that create a rule on IPTable to drop any packet that coming to port 45295
```
45295
```


![67193c3d6213a7f657b195d5a2d970d6.png](../../_resources/67193c3d6213a7f657b195d5a2d970d6-1.png)
* * *

Special Thanks to this [write-up](https://ahmed-naser.medium.com/ulysses-blue-team-challenge-walkthrough-write-up-5cbe24b6942f) that guided me to finish this lab when i was stucked on Q7.