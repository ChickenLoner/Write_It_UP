# [LetsDefend - Malicious Web Traffic Analysis](https://app.letsdefend.io/challenge/malicious-web-traffic-analysis)
Created: 06/08/2024 18:14
Last Updated: 07/08/2024 18:31
* * *
<div align=center>

**Malicious Web Traffic Analysis**
![cdd4fcf49e0f037731c1fda166226c06.png](../../_resources/cdd4fcf49e0f037731c1fda166226c06.png)
</div>
During a cybersecurity investigation, analysts have noticed unusual traffic patterns that may indicate a problem. We need your help finding out what's happening, so give us all the details.

**File Location**: /root/Desktop/ChallengeFile/capture.7z
* * *
## Start Investigation
>What is the IP address of the web server?

![47fbca3dcce4f27644456a33a3fbfb3b.png](../../_resources/47fbca3dcce4f27644456a33a3fbfb3b.png)

After opened provided pcap file, first thing we could see is RDP traffic between `197.32.212.121` and `10.1.0.4` but we could not confirm yet that both IP has something to do web server

![9d1835422ace3f47273e4741845d5012.png](../../_resources/9d1835422ace3f47273e4741845d5012.png)

But when I filtered for `http` and 1 of these IP address, we can see that there are some sort of bruteforce attack happening and `10.1.0.4` is our web server.

```
10.1.0.4
```

>What is the IP address of the attacker?
```
197.32.212.121
```

>The attacker first tried to sign up on the website, however, he found a vulnerability that he could read the source code with. What is the name of the vulnerability?

![bc0dc286b0fd564298e542d164f8af87.png](../../_resources/bc0dc286b0fd564298e542d164f8af87.png)

We need to inspect each POST request to `/register/register.php` to find any indicator that related to specific vulnerability

![99adedc02c1d3ceac4058c43b438790b.png](../../_resources/99adedc02c1d3ceac4058c43b438790b.png)

Which we will eventually found one right there, Its XXE vulnerability which allow the attacker to get the source code in base64

```
xxe
```

>There was a note in the source code, what is it?

![2856ad49511678f566d5bcd546669860.png](../../_resources/2856ad49511678f566d5bcd546669860.png)

Decode base64 we got then we can see that there is a comment telling us to submit it as the answer

```
yougotme
```

>After exploiting the previous vulnerability, the attacker got a hint about a possible username. What is the username that the attacker found?

![f10dad677b9d5e09828b2fab3e826f9b.png](../../_resources/f10dad677b9d5e09828b2fab3e826f9b.png)

Most of failed bruteforce attacks resulting in 200 HTTP Response so we have to find anything that has different size or different HTTP Status Code and we will find one with 302 HTTP Response

![b3065c088b07d82eb17b3c770d3b2540.png](../../_resources/b3065c088b07d82eb17b3c770d3b2540.png)

Inspect it then we can see credential that successfully logged in to this website

```
admin
```

>The attacker tried to brute-force the password of the possible username that he found. What is the password of that user?
```
fernando
```

>Once the attacker gained admin access, they exploited another vulnerability that led the attacker to read internal files that were located on the server. What payload did the attacker use?

![572af47c70120665f70c25b63f57e932.png](../../_resources/572af47c70120665f70c25b63f57e932.png)

I found this weird request that look like Local File Inclusion (LFI) vulnerability had been tested 

![75fd0d01b07884a0ff70eec858f46dc2.png](../../_resources/75fd0d01b07884a0ff70eec858f46dc2.png)

We can see that the attacker attempted to exploit LFI vulnerability to read `/etc/passwd` file

![eaecda2cb9299f99bef17eca2a8ce8e7.png](../../_resources/eaecda2cb9299f99bef17eca2a8ce8e7.png)

And it was successful

![c6cbd1854d6c7031b64e2f32f47f09b2.png](../../_resources/c6cbd1854d6c7031b64e2f32f47f09b2.png)

Use URL Decode to get the answer for submission

```
../../../../../../../../../../../../../../../etc/passwd
```

>The attacker was able to view all the users on the server. What is the last user that was created on the server?

![5dd4e161e2fa2077eb98f36a016562d7.png](../../_resources/5dd4e161e2fa2077eb98f36a016562d7.png)
```
a1l4mFTW
```

>The attacker also found an open redirect vulnerability. What is the URL the attacker tested the exploit with?

![76a5cbf2d8302c0445049e7d71321c2d.png](../../_resources/76a5cbf2d8302c0445049e7d71321c2d.png)

We can see that `https://evil.com/` was tested on `/dashboard/redirect.php?url=` and looking at HTTP Response code, this exploit was successful

```
https://evil.com/
```

* * *
## Summary
On this challenge, we investigated web attack via pcap file and here is what we found
- The attacker using XXE vulnerability to get php source code which vulnerable to XXE attack and also gave a hint to an attacker that "admin" username is existed and should be able to bruteforce for admin's password
- The attacker successfully bruteforced admin's password and logged in as an "admin" user to website
- The attacker successfully exploited local file inclusion vulnerability on `file` variable in `dashboard.php` revealing content of `/etc/passwd`
- Lastly, the attacker successfully exploited open redirect vulnerability on `url` variable in `redirect.php` redirecting to `evil.com`

<div align=center>

![6a9a2cea0497765206996605d511104a.png](../../_resources/6a9a2cea0497765206996605d511104a.png)
</div>

* * *
