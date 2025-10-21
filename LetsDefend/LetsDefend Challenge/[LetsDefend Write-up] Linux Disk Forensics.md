# [LetsDefend - Linux Disk Forensics](https://app.letsdefend.io/challenge/linux-disk-forensics)
Created: 02/04/2024 15:26
Last Updated: 03/04/2024 08:48
* * *
<div align=center>

**Linux Disk Forensics**
![abe071d88d084c77ace70eacd04e06d7.png](../../_resources/abe071d88d084c77ace70eacd04e06d7.png)
</div>
Dean downloaded a cracked software application from an unofficial source and subsequently discovered that his personal data has been leaked. An investigation is now underway to determine the cause of the data leak and mitigate any potential damage.

**Evidences:**`C:\Users\LetsDefend\Desktop\L34K.7z`
* * *
## Start Investigation
> What distribution system was used by the victim, including its version?

We can see which linux distro of this system by reading `/etc/issue` content
![907660c8df72eeb10c5838f51b12cc5f.png](../../_resources/907660c8df72eeb10c5838f51b12cc5f.png)
```
Ubuntu 22.04.2 LTS
```

>What is the SHA256 hash of the crack file that was downloaded?

![ee7292fa0ee4a6f6e7e8822235cedfc8.png](../../_resources/ee7292fa0ee4a6f6e7e8822235cedfc8.png)
There is only 1 user directory, most of directories are empty except for Desktop which have a ELF file there
![08115fe11dc381dc1d384a2d266cde2a.png](../../_resources/08115fe11dc381dc1d384a2d266cde2a.png)
Export the file and calculate hash the way you want.
```
d73e103c7a980417aefb2683e315180d76bd75eccefbff57802bf97c5efd75fb
```

> What is the IP address and port used by the attacker?
**Answer Format:** IP:Port

![454b6290974b93b7fc415d30c93d3b0b.png](../../_resources/454b6290974b93b7fc415d30c93d3b0b.png)
I used `strings` for this question and it was very effective, we can see that this file aimed to compress google chrome's data to `dean_data.tar` then send to a specific IP address using netcat, it was designed for this user only.
```
192.168.229.129:201
```

> What is the specific tool or software employed by the attacker?
```
netcat
```

> Which was the year of the last use of the Dean account?

![c6494e99434a4f69ede62c641edbc130.png](../../_resources/c6494e99434a4f69ede62c641edbc130.png)
Lastest Updated on `auth.log` is 2023 so its 2023
```
2023
```

* * *
## Summary
The cracked software that was downloaded is a malware that designed especially to collect Google Chrome data of Dean then send them back using netcat.

<div align=center>

![5de6b55d400c508ec8c299cbdf329221.png](../../_resources/5de6b55d400c508ec8c299cbdf329221.png)
</div>

* * *
