# [LetsDefend - Malicious WordPress Plugin](https://app.letsdefend.io/challenge/malicious-wordpress-plugin)
Created: 07/06/2024 13:41
Last Updated: 10/06/2024 23:19
* * *
<div align=center>

**Malicious WordPress Plugin**
![cd7691a2c3e9964242503ba99d97bcfe.png](/_resources/cd7691a2c3e9964242503ba99d97bcfe.png)
</div>
Our WordPress website has been hacked; however, it's yet unclear how exactly. The most likely explanation is that a plugin that was installed on the website had a remote code execution vulnerability. By taking advantage of this flaw, the attacker gained illegal access to the server's operating system.

**File Location**: /root/Desktop/ChallengeFile/Wordpress.pcapng
* * *
## Start Investigation
>What is the IP address of the WordPress server?

![ae12d028f606ac1aeb69952d05cb0775.png](/_resources/ae12d028f606ac1aeb69952d05cb0775.png)

We know that WordPress server might used HTTP protocol so just filter for HTTP protocol that we will have an IP address that hosted WordPress.

```
192.168.204.128
```

>Two attackers were attempting to compromise our environment. What is the IP address of the first attacker based on time?

![e3c1d2347a3266eec00536bfc755ce56.png](/_resources/e3c1d2347a3266eec00536bfc755ce56.png)

I scrolled down for a bit then I found WPScan user-agent which mean an attacker used wpscan to enumerate this wordpress site.

```
192.168.204.132
```

>What are the versions of the Apache and PHP servers deployed in our environment? <br>
**Answer Format**: ApacheVersion_PHPversion

![d89caefcacb969873a3f6fb9886c8970.png](/_resources/d89caefcacb969873a3f6fb9886c8970.png)

Follow TCP/HTTP stream then we will have Server Information right here.

```
2.4.58_8.2.12
```

>During enumeration, the attacker tried to identify users on the site. How many users got enumerated?

![01e8d18a60825922e054b573e8d2ee80.png](/_resources/01e8d18a60825922e054b573e8d2ee80.png)

I tried to find for some url that indicating user on this site and look like "author" should be the one

![edbed6e243fb07247da8a09c447c1973.png](/_resources/edbed6e243fb07247da8a09c447c1973.png)

Then we can see that after searching with "author" as strings on these http packets, there are 10 HEAD request for 10 authors but only 3 GET request were made

![95b4d80928763b17eac01783cfe0f74d.png](/_resources/95b4d80928763b17eac01783cfe0f74d.png)

Follow HEAD request of author 1 to do which kind of response that an attacker receive and look like wpscan actually used HEAD to find out if that user is actually existed and we can see author 1 username here too 

![cea067260742169d9cf46a4cd665afd9.png](/_resources/cea067260742169d9cf46a4cd665afd9.png)
Same with author 2 which mean GET request were used to confirm the result of HEAD request so this 3 users were enumerated by wpscan

```
3
```

>After enumeration, a brute force attack was launched against all users. What is the name of the page used for the brute force attack? <br>
**Answer Format**: pagename.extension

![fe37cd06a497ebdc0e2d1150a8cd22d9.png](/_resources/fe37cd06a497ebdc0e2d1150a8cd22d9.png)

Finding for HTML Form and POST requests, we can see that there are several attempts to bruteforce something on this webpage

```
xmlrpc.php
```

>The attacker successfully gained access to one of the accounts. What are the username and password for that account? <br>
**Answer Format**: username:password

![4eca4347d9a028d6fbf2baa152021c43.png](/_resources/4eca4347d9a028d6fbf2baa152021c43.png)

Followed the webpage communication that were bruteforced, we can see that this string is used to tell user that the credential is not correct

![da62737e1861ae2a5d809853ca7bb9fd.png](/_resources/da62737e1861ae2a5d809853ca7bb9fd.png)

Next lets use filter `frame contains "xmlrpc" && !frame contains "incorrect Username or password"` to find any response that is not have those string and look like we have one

![af9e67b3b7b0f9c7eacf223d6a1532a1.png](/_resources/af9e67b3b7b0f9c7eacf223d6a1532a1.png)

```
demomorgan:demomorgan
```

>There was a vulnerable plugin that the attacker exploited. What is the name of the plugin?

![dad0b26b41fe5402d18ac0fda8cb3ae5.png](/_resources/dad0b26b41fe5402d18ac0fda8cb3ae5.png)

search for plugin in http communication that we can see that this particular url was exploited for RCE

```
canto
```

>What is the CVE number associated with that plugin?

![f7d486cf0140da52b6d818c76f16da32.png](/_resources/f7d486cf0140da52b6d818c76f16da32.png)

Search on google about this plugin RCE then we have [this POC](https://github.com/leoanggal1/CVE-2023-3452-PoC) explaining how it worked and the pattern does look like we found on Wireshark

```
CVE-2023-3452
```

>What is the C2 server IP address of the attacker?
```
172.26.211.155
```

>What is the name of the function that the attacker tested the exploit with?

![3759f91d8e753657060259d199dc0113.png](/_resources/3759f91d8e753657060259d199dc0113.png)

This could be found using `http contains "admin.php"` since malicious script will be added to `admin.php` file

```
phpinfo()
```

>What is the name and version of the attacker's server? <br>
**Answer Format**: name/version

![721d999512b85d35ef81bedff8ffbe6f.png](/_resources/721d999512b85d35ef81bedff8ffbe6f.png)

```
Python/3.10.12
```

>What is the username that was logged on during the attack, including the domain?

![cc7bac04eb24be2ff4cc823d5216a7a2.png](/_resources/cc7bac04eb24be2ff4cc823d5216a7a2.png)

Remember `whoami` command that were executed earlier?, go back to it to see how server response back then we will have user who hosted this wordpress website which is also an administrator of this machine 

```
desktop-2r3ar22\administrator
```

>The attacker attempted to upload a reverse shell. What is the IP address and port number? <br>
**Answer Format**: IP:PORT

![96b2cdd25fc0039ee07da20ef85ae4d7.png](/_resources/96b2cdd25fc0039ee07da20ef85ae4d7.png)

back to `admin.php` and try to find for reverse shell commands

```
172.26.211.155:1234
```

>What command posed an obstacle during the process of the reverse shell?

![a35bf54f47b3c7998ca72c77e21fa793.png](/_resources/a35bf54f47b3c7998ca72c77e21fa793.png)

After confirming that an attacker tried to establish connection on port 1234 then we can filter and follow the tcp stream

![f337dbb5bab42ada4e146cbed61017ed.png](/_resources/f337dbb5bab42ada4e146cbed61017ed.png)

```
uname
```

* * *
## Summary

On this challenge, we use Wireshark to discover how an attacker exploited vulnerable wordpress plugin which lead to remote code execution and reverse shell on web server.

Here is what happened
- An attacker used WPscan to find vulnerable plugin and enumerate users
- An attacker launched bruce force attack on `xmlrpc.php` to gain access to user account
- An attacker found canto plugin vulnerable
- An attacker used sqlmap to attack this web server (unsuccessful)
- An attacker exploited CVE-2023-3452 which is unauthenticated remote code execution vulnerability from testing to successfully gain a reverse shell
- An attacker couldn't execute `uname` after established a connection then a connection torn down

<div align=center>

![fa1cd2bbcd777f386c77b137a746ecb7.png](/_resources/fa1cd2bbcd777f386c77b137a746ecb7.png)
</div>

* * *
