# [HackTheBox Sherlocks - APTNightmare-2](https://app.hackthebox.com/sherlocks/APTNightmare-2)
![0a8ae8cb5fae3e72d3f61498bd3e0d7e.png](../../../_resources/0a8ae8cb5fae3e72d3f61498bd3e0d7e.png)
## Scenario

Upon completing the server recovery process, the IR team uncovered a labyrinth of persistent traffic, surreptitious communications, and resilient processes that eluded our termination efforts. It's evident that the incident's scope surpasses the initial breach of our servers and clients. As a forensic investigation expert, can you illuminate the shadows concealing these clandestine activities?
* * *
![6eb02c40717fffdf298542321a25972a.png](../../../_resources/6eb02c40717fffdf298542321a25972a.png)

We got memory dump along with profile so we can import this profile first then we cab start doing memory forensics with Volatility 2

![1ae5198f2859e37ce5ae443fcf9f66b4.png](../../../_resources/1ae5198f2859e37ce5ae443fcf9f66b4.png)

I'm using Remnux so I used `cp Ubuntu_5.3.0-70-generic_profile.zip /opt/volatility/volatility/plugins/overlays/linux` command to import this profile then after confirmed with `vol.py --info | grep Ubuntu` then we should be able to see this profile thats mean we are ready to use this profile with given memory dump

>Task 1: What is the IP and port the attacker used for the reverse shell?

![f38b66ddc88be34ca7d05da15f7cd56e.png](../../../_resources/f38b66ddc88be34ca7d05da15f7cd56e.png)

First I used `vol.py -f dump.mem --profile=LinuxUbuntu_5_3_0-70-generic_profilex64 linux_pstree` to display process tree and expect for low hanging fruit such as obviously uncommon process name but I only found this which I think it should be process call to dump the memory image.

![ee02194cb88cafcfeb53daf84b9fab0d.png](../../../_resources/ee02194cb88cafcfeb53daf84b9fab0d.png)

I got to the point after failing to determine suspicious process with `vol.py -f dump.mem --profile=LinuxUbuntu_5_3_0-70-generic_profilex64 linux_netstat | grep TCP | grep ESTABLISHED` command then we can see that bash process with PID 

```
10.0.2.6:443
```

>Task 2: What was the PPID of the malicious reverse shell connection?

![177a0cc3df064fe845911da6c47907cd.png](../../../_resources/177a0cc3df064fe845911da6c47907cd.png)

I went back to process tree again to find out that this plugin could not get the parent process of this process.

![361d29306c02125fe16d5ea0e9137829.png](../../../_resources/361d29306c02125fe16d5ea0e9137829.png)

Then I went with `linux_psscan` that will list all processes that existed on the system even terminated one which I finally found that there was a bash with PID 3632 running on this system and this PID is the one we are looking for.

```
3632
```

>Task 3: Provide the name of the malicious kernel module.

![7178d89e4bd9ebd7cc76b4d0b956c11e.png](../../../_resources/7178d89e4bd9ebd7cc76b4d0b956c11e.png)

I used `vol.py -f dump.mem --profile=LinuxUbuntu_5_3_0-70-generic_profilex64 linux_hidden_modules` command to find hidden modules first and if it didn't find anything then I would go with `linux_modscan` but the result from the command shows that there is 1 hidden module on this system while it was running 

![bbdca541a812559a559481ed100b037d.png](../../../_resources/bbdca541a812559a559481ed100b037d.png)

By looking at its name and conducted a little bit of research then we could tell that this module tried to masquerade as nfnetlink module which is a legitimate module of netfilter.

```
nfentlink
```

>Task 4: What time was the module loaded?

![e9d736d2590926ec1145b8fe6e3b510f.png](../../../_resources/e9d736d2590926ec1145b8fe6e3b510f.png)

`vol.py -f dump.mem --profile=LinuxUbuntu_5_3_0-70-generic_profilex64 linux_enumerate_files > files.txt`

![a0b3cbca7086f9255df592eb8c9e6532.png](../../../_resources/a0b3cbca7086f9255df592eb8c9e6532.png)

To find out about this, I used `vol.py -f dump.mem --profile=LinuxUbuntu_5_3_0-70-generic_profilex64 linux_find_file -i 0xffff98ea5a732fa8 -O kern.log` to dump `kern.log` file which contains log kernel-related event including module loaded 

![2b2f2624a52e02ea7ad31b33cac71ced.png](../../../_resources/2b2f2624a52e02ea7ad31b33cac71ced.png)

...

```
2024-05-01 20:42:57
```

>Task 5: What is the full path and name of the malicious kernel module file?

![e359f02e3f54b0f621f66e8bd17c26cf.png](../../../_resources/e359f02e3f54b0f621f66e8bd17c26cf.png)
`strings dump.mem | grep nfnetlink`

![2d34ea6495817ae45281efb7ab0eb3fe.png](../../../_resources/2d34ea6495817ae45281efb7ab0eb3fe.png)

![93471bfb782a365f6b2101de8f215147.png](../../../_resources/93471bfb782a365f6b2101de8f215147.png)

```
/lib/modules/5.3.0-70-generic/kernel/drivers/net/nfnetlink.ko
```

>Task 6: Whats the MD5 hash of the malicious kernel module file?

![6c394d58001a8017199ccf1cba51ba62.png](../../../_resources/6c394d58001a8017199ccf1cba51ba62.png)

I used `vol.py -f dump.mem --profile=LinuxUbuntu_5_3_0-70-generic_profilex64 linux_find_file -i 0xffff98ea266b5a68 -O malicious_nfnetlink.ko` to dump malicious module from the memory then use `md5sum` to get the MD5 hash of this file

![1ee67ed80026d12857ef44eeeebdb7f3.png](../../../_resources/1ee67ed80026d12857ef44eeeebdb7f3.png)

Then if we searched for this hash on [VirusTotal](https://www.virustotal.com/gui/file/3cdf556862470b38503f79d9d35e21008b11f19639a92538ee14dceaea228817), we can see that we got the right module

```
35bd8e64b021b862a0e650b13e0a57f7
```

>Task 7: What is the full path and name of the legitimate kernel module file?

![53b56049462803eb300596fc157531dc.png](../../../_resources/53b56049462803eb300596fc157531dc.png)

We know that there are 2 `nfnetlink.ko` on this system and we already got the malicious one so the other one is definitely the legitimate one.

```
/lib/modules/5.3.0-70-generic/kernel/net/netfilter/nfnetlink.ko
```

>Task 8: What is the single character difference in the author value between the legitimate and malicious modules?

![f12c41e82a1502a7644708a47c5fe7c4.png](../../../_resources/f12c41e82a1502a7644708a47c5fe7c4.png)

I used `strings` to find interesting strings from this module which we can see the bash command responsible for reverse shell and the author of this module and if we take a look carefully at the email part then we would see that its missing an i for netfilter 

![534f5972475cbf7056f6d2f82766cfe1.png](../../../_resources/534f5972475cbf7056f6d2f82766cfe1.png)

Even google putted this character for us when we searched it.

```
i
```

>Task 9: What is the name of initialization function of the malicious kernel module?

![aa6f6c1f51d5e8fbd0c247c9893947a0.png](../../../_resources/aa6f6c1f51d5e8fbd0c247c9893947a0.png)

Lets decompile this module on Ghidra which reveal that source file with `nfentlink.c` and `nfentlink.mod.c` as an attempted to masquerade as legitimate netfilter module.

![ce81944716dd65ae2863c98b575f5126.png](../../../_resources/ce81944716dd65ae2863c98b575f5126.png)

Then after Ghidra successfully decompiled `init_module` function, we could 

```
nfnetlink_init
```

>Task 10: There is a function for hooking syscalls. What is the last syscall from the table?

![720a4f5f81626b98481ba020028b2096.png](../../../_resources/720a4f5f81626b98481ba020028b2096.png)
```
__x64_sys_kill
```

>Task 11: What signal number is used to hide the process ID (PID) of a running process when sending it?

![ebcd50890407204aeb9286047d1be292.png](../../../_resources/ebcd50890407204aeb9286047d1be292.png)
```
64
```

https://labs.hackthebox.com/achievement/sherlock/1438364/857
* * *
