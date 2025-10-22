# [TryHackMe - IronShade](https://tryhackme.com/room/ironshade)
![3e2b04b1a031d1e46b8dfa9dbcd63ff7.png](../../_resources/3e2b04b1a031d1e46b8dfa9dbcd63ff7.png)
***
**Incident Scenario**
Based on the threat intel report received, an infamous hacking group, **IronShade**, has been observed targeting Linux servers across the region. Our team had set up a honeypot and exposed weak SSH and ports to get attacked by the APT group and understand their attack patterns. 

You are provided with one of the compromised Linux servers. Your task as a Security Analyst is to perform a thorough compromise assessment on the Linux server and identify the attack footprints. Some threat reports indicate that one indicator of their attack is creating a backdoor account for persistence.

**Challenge**
Investigate the server and identify the footprints left behind after the exploitation.

***
>What is the Machine ID of the machine we are investigating?

![29b2818d9c7dbbf5f6b57a546d1ffbde.png](../../_resources/29b2818d9c7dbbf5f6b57a546d1ffbde.png)

After we started the machine, we can open a terminal and read the file `/etc/machine-id` to get Machine ID of the machine we are investigating.

```
dc7c8ac5c09a4bbfaf3d09d399f10d96
```

>What backdoor user account was created on the server?

![e47706785d76cfe627187d7313069e44.png](../../_resources/e47706785d76cfe627187d7313069e44.png)

We can take a look at the suspicious user from `/etc/passwd` file which we can see the user with uid 1001 that misspelled from microservice and is the only user that is only beside ubuntu and root so this is the one.

```
mircoservice
```

>What is the cronjob that was set up by the attacker for persistence?

![34768cc245e875b796325a754bca8082.png](../../_resources/34768cc245e875b796325a754bca8082.png)

I took a loot at `/var/spool/cron/crontab` directory which I found the cronjob of root that will executed `printer_app` from backdoor user home directory every reboot.

![d6b218fedcdeeb0aefed37d55aa7c3b7.png](../../_resources/d6b218fedcdeeb0aefed37d55aa7c3b7.png)

We can see that the file is ELF 64-bit binary and disassembly is out of scope of this room so I'm gonna leave it at that.

![0b0733689fbfc39d3903893e4f8633f7.png](../../_resources/0b0733689fbfc39d3903893e4f8633f7.png)

But we also have to check when this file was created on 6th August 2024 so we can use this timestamp as the baseline of our investigation.

```
@reboot /home/mircoservice/printer_app
```

>Examine the running processes on the machine. Can you identify the suspicious-looking hidden process from the backdoor account?

![dc8f7fc103858912a4b4900d4209d946.png](../../_resources/dc8f7fc103858912a4b4900d4209d946.png)

By using `ps aux | grep mircoservice`, we can see 2 binary were executed from home directory of backdoor user and one of them was located on the hidden directory and the file itself was also hidden as well.

![71756b4958d0cc65ebc1dd71971e87d2.png](../../_resources/71756b4958d0cc65ebc1dd71971e87d2.png)

We can see that this file is also ELF 64-bit binary as well.

![5753146654e03f1eda10366c19099e83.png](../../_resources/5753146654e03f1eda10366c19099e83.png)

The creation timestamp also within the same date as the first file we found.

![b052591ed3e6e18c8782c840a26aa888.png](../../_resources/b052591ed3e6e18c8782c840a26aa888.png)

I went to the `.tmp` directory and found another 2 files on this directory, the first one is C script and the other file is another ELF binary.

![9b4615c72ff0e080fe396b8a900705b3.png](../../_resources/9b4615c72ff0e080fe396b8a900705b3.png)

C script just happened to have to same name as the hidden process and we can see that this is simple keylogger but it does not save to a file or send it over a network.

```
.strokes
```

>How many processes are found to be running from the backdoor account’s directory?

![10fabab8bbf1bd7b990bfba1575618f4.png](../../_resources/10fabab8bbf1bd7b990bfba1575618f4.png)

We already know that there are 2 processes running from the backdoor's home directory but we can also use `Select pid, name, parent,path from processes where path LIKE "%mirco%";` on osquery to confirm that as well.

```
2
```

>What is the name of the hidden file in memory from the root directory?

![75f9117019c763f180ca4ba3d11d08b8.png](../../_resources/75f9117019c763f180ca4ba3d11d08b8.png)

Since we already started osquery then we can proceed with `SELECT filename, path, directory, size, type FROM file WHERE path LIKE '/.%';` to get hidden file which we can see that `.systmd` is really stand out here and it just happened to have the same name as one of the file we found from backdoor user directory as well. 

![eee3fd495d04adefbbbc81d1fb2bb591.png](../../_resources/eee3fd495d04adefbbbc81d1fb2bb591.png)

Its also in the root directory so this is the one we are looking for.

```
.systmd
```

>What suspicious services were installed on the server? Format is service a, service b in alphabetical order.

![41224bb931741974d3e3dd9423af622c.png](../../_resources/41224bb931741974d3e3dd9423af622c.png)

I went to `/etc/systemd/system` directory to find any service that were edited/created on 6th August which I found that `backup.service` is the first one that we will have to check it out.

![b5732a8b49466658dc05750605150670.png](../../_resources/b5732a8b49466658dc05750605150670.png)

By inspecting this service, we can see that it will execute `sys_backup` from backdoor user directory so this is one of backdoor services we are looking for.

![04473b9d59317ed012a638f269540fe5.png](../../_resources/04473b9d59317ed012a638f269540fe5.png)

Another one is `strokes.service` which we can see the similar naming convention to `.strokes` binary we found from the running process.

![2a5538210dd9f417ed14424af8ed3104.png](../../_resources/2a5538210dd9f417ed14424af8ed3104.png)

And as we can guess, it will execute `.strokes` from the backdoor user directory and its the service responsible for running process we found as well.

```
backup.service,strokes.service
```

>Examine the logs; when was the backdoor account created on this infected system?

![5f4641bcf9c69f497a28a6b394a2c05e.png](../../_resources/5f4641bcf9c69f497a28a6b394a2c05e.png)

Alright we will now have to check out `/var/log` directory but there are so many log files were compressed so we can use `gunzip ./*` to gunzip it all.

![a7016f0c5da0475dd0d2714929cd96ad.png](../../_resources/a7016f0c5da0475dd0d2714929cd96ad.png)

And now we can use grep to search for the trace of this user which we can see that even though we did not find `useradd` binary being used but we can see the first appearance of this user on 5th Auguest, just 1 day before the creation date of those backdoor we discovered.

```
Aug  5 22:05:33
```

>From which IP address were multiple SSH connections observed against the suspicious backdoor account?

![25e44665d2a7f4f9e6553b02f0ff16bf.png](../../_resources/25e44665d2a7f4f9e6553b02f0ff16bf.png)

Now we can focus on this user with keyword "Failed" to focus on failed attempts to authenticate as this user which we can see that there is only a single IP trying to authenticate as backdoor user.

```
10.11.75.247
```

>How many failed SSH login attempts were observed on the backdoor account?

![196ac9712cda18ac6bee992c0108b043.png](../../_resources/196ac9712cda18ac6bee992c0108b043.png)

Even though there are only 6 lines return from this but remember that there are another repeated attempt from the same IP address so total attempts to this backdoor account is 8.

![9d1c07cbd91c3a6616e9d7f6de91d280.png](../../_resources/9d1c07cbd91c3a6616e9d7f6de91d280.png)

Here the breakdown from ChatGPT.

```
8
```

>Which malicious package was installed on the host?

![e9845c48aaf96beb6c1420e43330aead.png](../../_resources/e9845c48aaf96beb6c1420e43330aead.png)

We can use `grep " install " /var/log/dpkg.log` to list all installed packages from dpkg log which we can see that there is only a single package installed on 6th August.

![3388094e7c21bf6c53d5e6738bbd22b0.png](../../_resources/3388094e7c21bf6c53d5e6738bbd22b0.png)

We can use `dpkg -L pscaner` to list binary dropped from this package which we can see that `scanner` is the binary installed from this package.

![e6b7632c86c8f87034df27789ae96e4b.png](../../_resources/e6b7632c86c8f87034df27789ae96e4b.png)

Then we can use `dpkg -s pscanner` to display metadata of this package and we can see the secret code for next question and the one that really stood out is the Maintainer "johnnyEng" (Johnny English) 😆
 
```
pscanner
```

>What is the secret code found in the metadata of the suspicious package?
```
{_tRy_Hack_ME_}
```

![be52c3bf291e212bac8a4560862fbc87.png](../../_resources/be52c3bf291e212bac8a4560862fbc87.png)

And now we are done!
***