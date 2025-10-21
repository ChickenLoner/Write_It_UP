# [CyberDefenders - Hacked](https://cyberdefenders.org/blueteam-ctf-challenges/hacked/)
Created: 02/05/2024 11:20
Last Updated: 02/05/2024 23:33
* * *
>Category: Endpoint Forensics
>Tags:Disk Forensic, FTK Imager, R-Studio, JohnTheRipper, CMS, T1219, T1548, T1136, T1059, T1110.001, T1078
* * *
A soc analyst has been called to analyze a compromised Linux web server. Figure out how the threat actor gained access, what modifications were applied to the system, and what persistent techniques were utilized. (e.g. backdoors, users, sessions, etc).

**Tools**:
- [FTKImager](https://accessdata.com/products-services/forensic-toolkit-ftk/ftkimager)
- [R-studio recovery](https://www.r-studio.com/)
- [Guide: mounting challenge disk image on Linux.](https://bwiggs.com/posts/2021-07-25-cyberdefenders-hacked/)
- [last command](https://www.baeldung.com/linux/last-command#:~:text=The%20last%20command%20displays%20information,data%20source%20to%20generate%20reports.)
- [unshadow](https://manpages.ubuntu.com/manpages/bionic/man8/unshadow.8.html)
- [JohnTheRipper](https://www.openwall.com/john/)
- [RockYou](https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt)
* * *
## Questions
> Q1: What is the system timezone?

![56c3bd396fa5752e0da080f41014275c.png](../../_resources/56c3bd396fa5752e0da080f41014275c.png)
We got Linux disk to work with and the partition we will be investigating is `VulnOSv2-vg-root`
![df86487f788b6a55f229650e14b53751.png](../../_resources/df86487f788b6a55f229650e14b53751.png)
A file that store timezone information is `/etc/timezone`
```
Europe/Brussels
```

> Q2: Who was the last user to log in to the system?

![7f698f9fd746a2b506045993b19941f6.png](../../_resources/7f698f9fd746a2b506045993b19941f6.png)
I asked ChatGPT how we can investigate the last user logged in on Linux, it provides us several ways and the first thing to look for is `/var/log/wtmp`
![d004a730c04172d40d50aed2c23abaf8.png](../../_resources/d004a730c04172d40d50aed2c23abaf8.png)
On FTK Imager, click `View file in plain text` then we can read content of this file and you can see that user mail is the last user that logged in to this system
![b418bb52ba4d9888fcb3e75741f37e22.png](../../_resources/b418bb52ba4d9888fcb3e75741f37e22.png)
Another way is to check auth log at `/var/log/auth.log` for SSHD event
![6be99fc0d1381ed8d10b3dcefc1565f0.png](../../_resources/6be99fc0d1381ed8d10b3dcefc1565f0.png)
```
mail
```

> Q3: What was the source port the user 'mail' connected from?

![fb16d50c259685b43ae73387c2e4b288.png](../../_resources/fb16d50c259685b43ae73387c2e4b288.png)
From the previous question, we know that mail user was using SSH to login to this system so Inside `auth.log` we will filter for "Accepted password" then you will got a source IP address and port of this connection 
```
57708
```

> Q4: How long was the last session for user 'mail'? (Minutes only)

![3229ddb93e291a7e2401b8459006ff76.png](../../_resources/3229ddb93e291a7e2401b8459006ff76.png)
Check for SSHD session opened and closed, it almost 1 minute so the answer is 1 
```
1
```

> Q5: Which server service did the last user use to log in to the system?

![568e63124cbe84c027e30333825dfed2.png](../../_resources/568e63124cbe84c027e30333825dfed2.png)
We know that user connected to a system using SSH so SSHD is doing it job to handle it
![634dcfab5d16b822b0d48f4e40823ab2.png](../../_resources/634dcfab5d16b822b0d48f4e40823ab2.png)
Here is an explaination of SSHD by ChatGPT
```
sshd
```

> Q6: What type of authentication attack was performed against the target machine?

![1044b929ee81570ba53ebad977b33309.png](../../_resources/1044b929ee81570ba53ebad977b33309.png)
Still in `auth.log` scroll up a little bit we can see several authentication failure happened sevaral events in a short time which mean an attacker was bruteforcing `root` user password
```
brute-force
```

> Q7: How many IP addresses are listed in the '/var/log/lastlog' file?

![8da5f715e9238c340761158ef6354f1a.png](../../_resources/8da5f715e9238c340761158ef6354f1a.png)
There are 2 unique IP addresses logged in `lastlog`
```
2
```

> Q8: How many users have a login shell?

![5071f5a1c8dbe2b0cc8b0bf5c38b5a10.png](../../_resources/5071f5a1c8dbe2b0cc8b0bf5c38b5a10.png)
Go to `/etc/passwd` to see how many user have permission to use `/bash` shell and there are 5 of them
```
5
```

> Q9: What is the password of the mail user?

![a9999cc36d57e8ad06267045cf5d471a.png](../../_resources/a9999cc36d57e8ad06267045cf5d471a.png)
A file that store passwords is `/etc/shadow` but it was encrypted using sha512crypt, you can use hashcat or JohnTheRipper to crack this file
![497fbf9da68c88c8e154cb91967fe909.png](../../_resources/497fbf9da68c88c8e154cb91967fe909.png)
My VM doesn't meet the requirement to use hashcat so I'll use John to crack this but first we need to use unshadow to reveal an actual shadow file by using `unshadow passwd shadow >> unshadow.txt`
![69eda4543806b447b2ede0864e8e7b94.png](../../_resources/69eda4543806b447b2ede0864e8e7b94.png)
Then using john with rockyou wordlist to bruteforce passwords inside this unshadow file with `john --wordlist=rockyou.txt unshadow.txt`
As you can see, both php and mail user has the same password
```
forensics
```

> Q10: Which user account was created by the attacker?

![74dd39dcf615f8ab3586754a1091139f.png](../../_resources/74dd39dcf615f8ab3586754a1091139f.png)
back to `auth.log` then find for `useradd` command, and the result shows that php was added by root and added to sudo group
```
php
```

> Q11: How many user groups exist on the machine?

![2acf3d2230948b5c21a3e5a37b65d94d.png](../../_resources/2acf3d2230948b5c21a3e5a37b65d94d.png)
A file that hold information about all the groups on Linux system is `/etc/group`
![372a9c6b7ab45b7222c3bbdc5bdee316.png](../../_resources/372a9c6b7ab45b7222c3bbdc5bdee316.png)
Count the lines, we got 58 groups on this system
```
58
```

> Q12: How many users have sudo access?

![17beabc30e1d600b8dec0f41eefa8cda.png](../../_resources/17beabc30e1d600b8dec0f41eefa8cda.png)
We can confirmed that which group have the sudo privilege by reading `/etc/sudoers` and the the only group that has this privilege is "sudo"
![e49575238811497f047f992910072c22.png](../../_resources/e49575238811497f047f992910072c22.png)
back to `/etc/group` and find for "sudo" group, we got 2 users on this group
```
2
```

> Q13: What is the home directory of the PHP user?

![9c2711060ef69b70cf4585c8d98a11d8.png](../../_resources/9c2711060ef69b70cf4585c8d98a11d8.png)
Go to `/etc/passwd`, it also store the home directory of each user and PHP user got this directory as a home directory 
```
/usr/php
```

> Q14: What command did the attacker use to gain root privilege? (Answer contains two spaces).

![bdb3ac60cf5f0bf59fe65455c8bd07ac.png](../../_resources/bdb3ac60cf5f0bf59fe65455c8bd07ac.png)
An attacker accessed this system as mail user so get mail user home directory from `/etc/passwd` 
![652739220b6f4934901fbdf7b8a628a7.png](../../_resources/652739220b6f4934901fbdf7b8a628a7.png)
Then read bash history, as we know from previous question that mail is in sudo group which mean an attacker can just use sudo to switch user to root directly
```
sudo su -
```

> Q15: Which file did the user 'root' delete?

![7bfa4800ef16f8db0d3bf45a88a4965b.png](../../_resources/7bfa4800ef16f8db0d3bf45a88a4965b.png)
Go to root home directory to read bash history
inside `/tmp/` directory, there is a C script that was deleted and if you ever practice pentesting then you will feel familiar with this filename as it coming from Exploit-DB
```
37292.c
```

> Q16: Recover the deleted file, open it and extract the exploit author name.

![51dc6d40811205c9a73214cffb4cb164.png](../../_resources/51dc6d40811205c9a73214cffb4cb164.png)
We can just searching for this [script](https://www.exploit-db.com/exploits/37292) online
![1de79a07ac51485379c7f765f1f69a12.png](../../_resources/1de79a07ac51485379c7f765f1f69a12.png)
There it is, the same script from Exploit-DB

But if you want to solve this question as the lab was designed for You need to mounting this evidence file (E01 could be mount directly to our file system)
![fe3c0b16533268fe4b3a16b62df8f55d.png](../../_resources/fe3c0b16533268fe4b3a16b62df8f55d.png)
Go to "File" -> "Image Mounting"
![29dcba61beac9adc7ad8b6d7b68dd3b2.png](../../_resources/29dcba61beac9adc7ad8b6d7b68dd3b2.png)
Select Image file then click "Mount"
![94641068723b203d018df864fa4d396a.png](../../_resources/94641068723b203d018df864fa4d396a.png)
Now install R-Studio (Recovery tool not a R language IDE) and scan the largest partition that had the file that was deleted
![dcedc0383a91807efa61d1e18f1bcca6.png](../../_resources/dcedc0383a91807efa61d1e18f1bcca6.png)
After scanning process is finished, you will find This (Recognized) scanning result below Virtual Storage you just scanned
![0e485f98ee60957ef514c6d965365dae.png](../../_resources/0e485f98ee60957ef514c6d965365dae.png)
Click "Show Files"
![adea1c7799d80ac048bc29ed19415b28.png](../../_resources/adea1c7799d80ac048bc29ed19415b28.png)
Go to `/tmp/` directory and you will see all recoverable deleted files which including our C script, Tick a file then Click "Recover"
![b42b22caab3cdf8171dde80f514cfb73.png](../../_resources/b42b22caab3cdf8171dde80f514cfb73.png)
Open C script and you will find author was written at the top as comment 
![dac8297c64f00f172a3dee2c2cb3b7b7.png](../../_resources/dac8297c64f00f172a3dee2c2cb3b7b7.png)
Don't forget to Unmount all images
```
Rebel
```

> Q17: What is the content management system (CMS) installed on the machine?

![dc599b4d1d7a2050e78d5a9eefb80823.png](../../_resources/dc599b4d1d7a2050e78d5a9eefb80823.png)
The word installed mean CMS was installed via apt or dkpg so I went to `/var/log/apt/history.log` which I found drupal7 was installed using apt
```
drupal
```

> Q18: What is the version of the CMS installed on the machine?

![6c80f3e344c5b00970d00c425a58f122.png](../../_resources/6c80f3e344c5b00970d00c425a58f122.png)
Relying on apt history log is not enough to exact version so dpkg which is a package management system (`/var/log/dpkg.log`) will revealing more in depth about the exact CMS version that was installed 
```
7.26
```

> Q19: Which port was listening to receive the attacker's reverse shell?

We got an attacker IP address that connected to this system so It will come in handy on this question, We know that an attacker accessed to this system using ssh but is there other way for it?
![8652c7c3e03c8b777078bdeef22096df.png](../../_resources/8652c7c3e03c8b777078bdeef22096df.png)
A clue from precious question telling me that web server might be the initial access of this attack
![3aae271c6027e9653671fd300c378433.png](../../_resources/3aae271c6027e9653671fd300c378433.png)
And the webserver log should be found in `/var/log/apache2/access.log` because I didn't find nginx or any web server software other than apache2
![c170b71cf9aa6d1c544a60fab8e4a70e.png](../../_resources/c170b71cf9aa6d1c544a60fab8e4a70e.png)
Searching by an IP address of an attacker, my hypothesis is proving to be right 
![59b491303366484e31ae8baa4c98c5a1.png](../../_resources/59b491303366484e31ae8baa4c98c5a1.png)
One of this log contained `eval()` and `base64_decode` in the url which mean an attacker conducted XSS attack to exploit this website
![0e6e9399ab65aa6679326e90b60044ba.png](../../_resources/0e6e9399ab65aa6679326e90b60044ba.png)
Decode URL properly 
![fb3564900e7f1c538ccba360eba875eb.png](../../_resources/fb3564900e7f1c538ccba360eba875eb.png)
Then grab only base64 strings to decode, which we finally found out that it is a reverse shell script to connect to an attacker IP address at port 4444
```
4444
```

![0bf7902e0a530bf8081d96f50a57ee1d.png](../../_resources/0bf7902e0a530bf8081d96f50a57ee1d.png)
* * *
