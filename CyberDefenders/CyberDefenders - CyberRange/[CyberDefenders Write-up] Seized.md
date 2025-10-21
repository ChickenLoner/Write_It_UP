# [CyberDefenders - Seized](https://cyberdefenders.org/blueteam-ctf-challenges/seized/)
Created: 05/06/2024 04:48
Last Updated: 05/06/2024 20:15
* * *
>Category: Endpoint Forensics
>Tags: Memory Forensic, Volatility, Rootkit, CentOS, CyberChef, T1063, T1053
* * *
**Instructions**:
- Uncompress the lab (pass: **cyberdefenders.org**), investigate this case, and answer the provided questions.
- Use the [latest version of Volatility](https://github.com/volatilityfoundation/volatility), place the attached Volatility profile "**Centos7.3.10.1062.zip**" in the following path *volatility/volatility/plugins/overlays/linux*.
* * *
Using Volatility, utilize your memory analysis skills as a security blue team analyst to Investigate the provided Linux memory snapshots and figure out attack details.

**Supportive Tools**:
- [Volatility](https://github.com/volatilityfoundation/volatility)
- [CyberChef](https://gchq.github.io/CyberChef/)
- [grep](https://www.cyberciti.biz/faq/howto-use-grep-command-in-linux-unix/)
* * *
## Questions
> Q1: What is the CentOS version installed on the machine?

![6fe093d639d1566b5b50e29dbd5f8c84.png](../../_resources/6fe093d639d1566b5b50e29dbd5f8c84.png)
First we need to import volatility profile by moving profile provided by this lab to plugin/overlays/linux then we're good to go

![c57fbc066604ddaa35d5bb5e312a2b18.png](../../_resources/c57fbc066604ddaa35d5bb5e312a2b18.png)

I tried using linux_banners plugin but it didn't work so we will have to use `grep -a "Linux release" dump.mem` which is the old school way to obtain Linux Distro version from memory dump

```
7.7.1908
```

> Q2: There is a command containing a strange message in the bash history. Will you be able to read it?

![c7d888552b0894e89eb9738c20122d1a.png](../../_resources/c7d888552b0894e89eb9738c20122d1a.png)

We will use `vol.py -f dump.mem --profile=LinuxCentos7_3_10_1062x64 linux_bash` to display bash history stored on this memory dump which we can see that there is a flag in base64 encoded here and there are 2 git clone command, 1 is PythonBackup which look like a python script to create a snapshot and later is LiME (Linux Memory Extractor) 

```
shkCTF{l3ts_st4rt_th3_1nv3st_75cc55476f3dfe1629ac60}
```

> Q3: What is the PID of the suspicious process?

![8b2c16b4edcba8eb4cf067306ae0d7b4.png](../../_resources/8b2c16b4edcba8eb4cf067306ae0d7b4.png)

We will use `vol.py -f dump.mem --profile=LinuxCentos7_3_10_1062x64 linux_pstree` to display process tree so we can see them in whole picture and the result shows us really interesting story

It means that netcat was used to established a connection to the attacker, likely to be a reverse shell then a bash process under python was likely to be shell stabilizer created with python so the attacker will have more stable and functional interactive shell which lead to vim process 

```
2854
```

> Q4: The attacker downloaded a backdoor to gain persistence. What is the hidden message in this backdoor?

![a929cac996667f20e68b89f7c9de0882.png](../../_resources/a929cac996667f20e68b89f7c9de0882.png)

We will need to go to this github repo and find hidden message inside of it

![03ba8ee6f377c13c35bf96fcc6df3071.png](../../_resources/03ba8ee6f377c13c35bf96fcc6df3071.png)

This wget system execution was found on `snapshot.py`

![948f396a0149f8f589d256e6ed8fb3fc.png](../../_resources/948f396a0149f8f589d256e6ed8fb3fc.png)

Followed it then we will have second flag in base64 and this backdoor which will run netcat in the background to open port 12345 and if a connection was established to this port then it will have bash shell to interact with this system 

![872aa59c0444076b5a71b0a58cfa7c2d.png](../../_resources/872aa59c0444076b5a71b0a58cfa7c2d.png)

```
shkCTF{th4t_w4s_4_dumb_b4ckd00r_86033c19e3f39315c00dca}
```

> Q5: What are the attacker's IP address and the local port on the targeted machine?

![b3a37ab7f7af90bf27fd1997cf58ae1c.png](../../_resources/b3a37ab7f7af90bf27fd1997cf58ae1c.png)

Using `vol.py -f dump.mem --profile=LinuxCentos7_3_10_1062x64 linux_netstat` then wait..... for a while then we will have these connections as we should expected port 12345 to establish a connection to an attacker IP address

```
192.168.49.1:12345
```

> Q6: What is the first command that the attacker executed?

![e33c841a4fb819a053f852b5d15e754a.png](../../_resources/e33c841a4fb819a053f852b5d15e754a.png)

Using `vol.py -f dump.mem --profile=LinuxCentos7_3_10_1062x64 linux_psaux` then we can see that I was right about shell stabilizer 

```
python -c import pty; pty.spawn("/bin/bash")
```

> Q7: After changing the user password, we found that the attacker still has access. Can you find out how?

![f32ce31e9a6f09c1b645c0d8b49ab685.png](../../_resources/f32ce31e9a6f09c1b645c0d8b49ab685.png)
The attacker used vim to edit `/etc/rc.local` which will be executed by system at the end of boot sequence so the attacker might established another backdoor here

![6c5cbcaf0a73c9f638f74b05e40c6689.png](../../_resources/6c5cbcaf0a73c9f638f74b05e40c6689.png)

Lets dump it with `vol.py -f dump.mem --profile=LinuxCentos7_3_10_1062x64 linux_dump_map -D /tmp/Seized/ -p 3196`, then we will have a lot to look for

![e59d6cf028e1650290cabc138b367f70.png](../../_resources/e59d6cf028e1650290cabc138b367f70.png)

Use `strings /tmp/Seized/*.vma | grep -i 'rc.local'`, then we will have this third flag and a clue about other persistence mechanism that an attacker added to `rc.local` which is added his SSH public key to k3vin user authorized key directory so an attacker can still use ssh to connect to this machine after chaning user password 

```
shkCTF{rc.l0c4l_1s_funny_be2472cfaeed467ec9cab5b5a38e5fa0}
```

> Q8: What is the name of the rootkit that the attacker used?

![865c6fb3ff55b0faa68c2a8c7fbc7a66.png](../../_resources/865c6fb3ff55b0faa68c2a8c7fbc7a66.png)

We will have to use this plugin and find for HOOKED in symbol field 

![ba49c35ed708dc024222757d1ce69ae9.png](../../_resources/ba49c35ed708dc024222757d1ce69ae9.png)

Using `vol.py -f dump.mem --profile=LinuxCentos7_3_10_1062x64 linux_check_syscall | grep "HOOKED"` then we will have the name of this rootkit

```
sysemptyrect
```

> Q9: The rootkit uses crc65 encryption. What is the key?

![0b004f92d63d28b570ad6696af27efd0.png](../../_resources/0b004f92d63d28b570ad6696af27efd0.png)

We will have to use `vol.py -f dump.mem --profile=LinuxCentos7_3_10_1062x64 linux_lsmod -P` to print lists of loaded kernel modules with parameter then we will have this crc65_key loaded under rootkit 

```
1337tibbartibbar
```

![13f645d83ed1b4b237218e9710efdc65.png](../../_resources/13f645d83ed1b4b237218e9710efdc65.png)
* * *
