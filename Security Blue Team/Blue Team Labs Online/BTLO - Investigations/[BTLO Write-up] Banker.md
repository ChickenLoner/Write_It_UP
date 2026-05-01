# [Blue Team Labs Online - Banker](https://blueteamlabs.online/home/investigation/banker-c7964ff8ce)

![98be74de024d1e3ffb8225dc4379b4e9.png](/resources/98be74de024d1e3ffb8225dc4379b4e9.png)

You’ve encountered a user's machine which was compromised by Cridex Ransomware from a phishing email.

>**Incident Response**

>**Tags**: Volatility2 Linux CLI T1566.002
* * *
**Scenario**
You’ve encountered a user's machine which was compromised by Cridex Ransomware from a phishing email. This is a notoriously older banking trojan that can create backdoors on their targets in order to steal financial information.

You’ve been tasked to run a basic forensic investigation on the memory dump from the machine.
* * *
## Environment Awareness
### Evidence & Tool Discovery
![c0ac946e5f26d6f59706d5923a06e09a.png](/resources/c0ac946e5f26d6f59706d5923a06e09a.png)

There is an investigation directory on the Desktop of investigation machine which contains a memory dump that we will use to investigate and we also have volatility located at `/usr/share/volatility` directory which likely to be volatility 2
***
## Investigation
>Q1) Using the imageinfo plugin, what are the two suggested profiles? (Format: Profile1, Profile2)

![00ab6c4ad2294d6b13818cb810688963.png](/resources/00ab6c4ad2294d6b13818cb810688963.png)

To make this investigation easier, you can add `/usr/share/volatility` to PATH or copy identical memory dump to `/usr/share/volatility` just like me and then we can easily determine suitable profile for this image with `python vol.oy -f banker.vmem imageinfo`

<details>
  <summary>Answer</summary>
<pre><code>WinXPSP2x86, WinXPSP3x86</code></pre>
</details>

>Q2) What is the Image local date and time? (Format: YYYY-MM-DD HH:MM:SS -XXXX)

![6f9599fcba66b144a5e24af70ce583e6.png](/resources/6f9599fcba66b144a5e24af70ce583e6.png)

`imageinfo` plugin also get image local date and time for us which we can see that this image was using UTC-4 timezone but we won't have to worry about timezone here since volatility will convert every timezone its recognized to UTC+0

<details>
  <summary>Answer</summary>
<pre><code>2012-07-21 22:45:08 -0400</code></pre>
</details>

>Q3) What is the process ID of reader_sl.exe? (Format: XXXX)

![fefbd0079b2d42653c602942346ccf5a.png](/resources/fefbd0079b2d42653c602942346ccf5a.png)

After we determined which profile to use then we can use process related plugin like `pslist`, `psscan`, `psxview` or `pstree` to list all processes that was running at the time that this memory image was taken which we can see that there is a suspicious process running as a child process of `explorer.exe` and based on the scenario, this process is likely to be Cridex Ransomware from phishing email that was executed by a user

<details>
  <summary>Answer</summary>
<pre><code>1640</code></pre>
</details>

>Q4) What is the Create Time of this process? (Format: YYYY-MM-DD HH:MM:SS)

![655c7b77d2ed9e5b064509c36c8e536c.png](/resources/655c7b77d2ed9e5b064509c36c8e536c.png)

We can see the create time of this process here

<details>
  <summary>Answer</summary>
<pre><code>2012-07-22 02:42:36</code></pre>
</details>

>Q5) What is the process ID of explorer.exe? (Format: XXXX)

![9ebd0ad1c2a67275b728427122dc6cd9.png](/resources/9ebd0ad1c2a67275b728427122dc6cd9.png)

<details>
  <summary>Answer</summary>
<pre><code>1484</code></pre>
</details>

>Q6) You want to look for any inbound and outbound connections from this dump. Note netscan will not work here. What is the first IP Address you see? (Format: X.X.X.X)

![6617f924123466ae9360ce8382d18958.png](/resources/6617f924123466ae9360ce8382d18958.png)

Since we could not use `netscan` plugin then we have to go with alternative plugin that can be used to find connections including terminated and thats plugin is `connscan` which we can see that there is 2 suspicious IP addresses were connected by explorer process on port 8080 (Q7)

<details>
  <summary>Answer</summary>
<pre><code>41.168.5.140</code></pre>
</details>

>Q7) What port is being used for communication? (Format: port)
<details>
  <summary>Answer</summary>
<pre><code>8080</code></pre>
</details>

>Q8) Looks like the explorer process was pinging out to this remote IP. Lets dig down into it further. Dump the memory for explorer.exe's child process, look for the same IP Address in the dump, lets see if we can find anything more. What is the User-Agent being used by the machine? (Format: Something/X.X)

![f6d584bb8a2e32696f4368850668d30b.png](/resources/f6d584bb8a2e32696f4368850668d30b.png)

To dump a process with memory and strings (not just executable), we have to use `memdump` plugin like this to dump it which we can see that its attempt to connect to an IP address we found on Q6 

![1f48f1fa0bc81ac9c236f3bb8136df1f.png](/resources/1f48f1fa0bc81ac9c236f3bb8136df1f.png)

Knowing that then we can just grep for "User-Agent" to obtain the user agent utilized by explorer process like this

<details>
  <summary>Answer</summary>
<pre><code>Mozilla/5.0</code></pre>
</details>

>Q9) Using strings on the dumped process, how many banking domains are found within URLs? (Format: X)

![581fd1309722694f9ad99e237971359c.png](/resources/581fd1309722694f9ad99e237971359c.png)

We can use `strings 1484.dmp | grep "https://" ` to find any banking domain within this process then we will see 2 banking domain from chase and tdbank right here (Q10)

<details>
  <summary>Answer</summary>
<pre><code>2</code></pre>
</details>

>Q10) What are the two domain names of the online banking portals? (Format: https://subdomain.domain.tld, https://...) 
<details>
  <summary>Answer</summary>
<pre><code>https://chaseonline.chase.com, https://onlinebanking.tdbank.com</code></pre>
</details>

![c940bd018206d7f715fd0ea2622f9a03.png](/resources/c940bd018206d7f715fd0ea2622f9a03.png)
https://blueteamlabs.online/achievement/share/52929/144
* * *
