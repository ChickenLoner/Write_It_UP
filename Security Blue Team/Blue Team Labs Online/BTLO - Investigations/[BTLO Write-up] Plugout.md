# [Blue Team Labs Online - Plugout](https://blueteamlabs.online/home/investigation/plugout-5867673d85)

![06b19789ce79b73924ac7a1baab804ac.png](/resources/06b19789ce79b73924ac7a1baab804ac.png)

Oh dear, it's happened again! Our corporate blog has been defaced to show pictures of kittens and balloons. Maybe it’s something to do with that recent vulnerability on WordPress?

>**Incident Reponse**

>**Tags**: CVE-2024-2879 Notepad++ Log Analysis T1190
* * *
**Scenario**
Oh dear, it's happened again! Our corporate blog has been defaced to show pictures of kittens and balloons. Please can you help us determine what has happened? Maybe it’s something to do with that recent vulnerability on WordPress? Inside the Logs directory is the access.log and the mysql.log, hopefully this helps get to the bottom of what has happened.
* * *
## Environment Awareness
### Evidence and Tool Discovery
![c17131092c1a5505e8660a25471c45dc.png](/resources/c17131092c1a5505e8660a25471c45dc.png)
We have `access.log` and `mysql.log` and the tool we have are Notepad++ and Cyberchef so we might want to URL decode with Cyberchef and open log file in Notepad++ 
***
## Investigation
>Q1) What is the IP address of the attacker who is performing enumeration? (Format: x.x.x.x)

![2654eef0e7505f4e6e92a8ab1702b55b.png](/resources/2654eef0e7505f4e6e92a8ab1702b55b.png)
After opened `access.log` then we can see that there is one IP address that started scanning the website with wpscan (Q2) and the first request that was successful is POST request to `/xmlrpc.php` endpoint which responsible for enabling remote publishing and interactions with the WordPress site.
<details>
  <summary>Answer</summary>
<pre><code>146.70.188.168</code></pre>
</details>

>Q2) What is the user-agent of the tool used? (Format: User Agent)
<details>
  <summary>Answer</summary>
<pre>WPScan v3.8.25 (https://wpscan.com/wordpress-security-scanner)<code></code></pre>
</details>

>Q3) With this tool, what is the timestamp & HTTP VERB of the first 200 response code? (Format: timestamp, VERB)
<details>
  <summary>Answer</summary>
<pre><code>04/Apr/2024:08:50:49 +0000, POST</code></pre>
</details>

>Q4) What is second IP address used by the attacker? (Format: x.x.x.x)

![6d11ff8e148f3872daa96bafe58ba4fc.png](/resources/6d11ff8e148f3872daa96bafe58ba4fc.png)
After finished with wpscan then the attacker used sqlmap to exploit `admin-ajax.php` for SQL injection from another IP address.
<details>
  <summary>Answer</summary>
<pre><code>149.78.184.202</code></pre>
</details>

>Q5) What is the database, table, and columns the attacker is trying to dump? (Format: db, tbl, column1, column2)

![7ace56bebd78e14de4712b7dc889bf07.png](/resources/7ace56bebd78e14de4712b7dc889bf07.png)
Lets use CyberChef to decode URL then we can see that it tried to dump user_login and user_pass from wp.wp_users.
<details>
  <summary>Answer</summary>
<pre><code>wp, wp_users, user_login, user_pass</code></pre>
</details>

>Q6) It looks like the attackers VPN dropped, what is the attackers true IP? (Format: x.x.x.x)

![77208795beee44c982da7bc9e71df39f.png](/resources/77208795beee44c982da7bc9e71df39f.png)
After scrolling for a while then we could see a different IP address using the same user-agent to exploit the same endpoint that's mean VPN of the attacker dropped and its reveal an actual IP address of the attacker.
<details>
  <summary>Answer</summary>
<pre><code>86.6.229.12</code></pre>
</details>

>Q7) What database, table, and columns does the attacker try to dump whilst off VPN? (Format: db, tbl, column1, column2, column3)

![1bbcc0e48da4c9910282db29d14fd3e0.png](/resources/1bbcc0e48da4c9910282db29d14fd3e0.png)
After taking a look at these requests from an actual IP address of the attacker, its query the different database from previous phrase and this time, the attacker tried to dump User, Password and Host from mysql.user 
<details>
  <summary>Answer</summary>
<pre><code>mysql, user, Password, User, Host</code></pre>
</details>

>Q8) What table is being queried at the point of injection? (Format: tbl_name)

![df090299f55fa43fb0f27f89a2412226.png](/resources/df090299f55fa43fb0f27f89a2412226.png)
Lets take a look at `mysql.log` to see an actual query that was supposed to be then we could see that this query was supposed to query from wp_layerslider table but sqlmap took advantage of it by added another time-based SQL query to mysql.user (exploitation of [CVE-2024-2879](https://github.com/herculeszxc/CVE-2024-2879))
<details>
  <summary>Answer</summary>
<pre><code>wp_layerslider</code></pre>
</details>

>Q9) Sqlmap creates a payload to test time-based injection. How many seconds does it sleep for on the first found check, and what is the string it adds before the final close bracket? (Format: x, string)

![50e592e7234d00ac66d45b0a5f4e702a.png](/resources/50e592e7234d00ac66d45b0a5f4e702a.png)
For this question, we have to look back at the first time that time-based SQL injection is successful which we can see that in red rectangular frame, the first request took 5 seconds before another request was received as the SQL query (`SLEEP(5)`) that's mean time-based SQL injection was confirmed at this point.
<details>
  <summary>Answer</summary>
<pre><code>5, GCvo</code></pre>
</details>

>Q10) At what time did the attacker successfully login to WordPress? (Format: timestamp)

![94f8c084f929a6cd49c224e8092546f2.png](/resources/94f8c084f929a6cd49c224e8092546f2.png)
Now lets assume that the attacker successfully dumped everything he need then we can skip all those SQLi attack request and focus on POST request to login page which you can see that the attacker successfully logged in to WordPress and redirect to wp-admin at this time.
<details>
  <summary>Answer</summary>
<pre><code>04/Apr/2024:09:07:00 +0000</code></pre>
</details>

>Q11) What was the name of the plugin activated after being uploaded earlier? (Format: plugin)

![dd30f4f5504011c44ba72bfe8a33891a.png](/resources/dd30f4f5504011c44ba72bfe8a33891a.png)
Then we could also see that the attacker uploaded plugin that contain webshell (Q12) which let the attacker executed 4 system commands from `ls` to `ip addr show`.
<details>
  <summary>Answer</summary>
<pre><code>Security-Tool-v1</code></pre>
</details>

>Q12) What is the path to the web shell? (Format: path) 
<details>
  <summary>Answer</summary>
<pre><code>/wp-content/plugins/Security-Tool-v1/SWebTheme.php</code></pre>
</details>

>Q13) What is the URL to the GitHub repo that the shell originates from? (Format: url)

![63ebf7e4ecb1b9c386f8d5c5c9168244.png](/resources/63ebf7e4ecb1b9c386f8d5c5c9168244.png)
After searching the webshell path on Google then I found this [github repository](https://github.com/wetw0rk/malicious-wordpress-plugin) came out on top so I took a look at it.

![1fc330249a1dc6d53344f5c1aeeea331.png](/resources/1fc330249a1dc6d53344f5c1aeeea331.png)
Then I found that its the same webshell/plugin that used on this incident so we found where the shell originates from.
<details>
  <summary>Answer</summary>
<pre><code>https://github.com/wetw0rk/malicious-wordpress-plugin</code></pre>
</details>

![502d10d63f7e1b4a07b673d954e7b6e1.png](/resources/502d10d63f7e1b4a07b673d954e7b6e1.png)
https://blueteamlabs.online/achievement/share/52929/200
* * *
## Summary
The attacker used `wpscan` to find vulnerabilities of wordpress website which found CVE-2024-2879 (Unauthenticated SQL injection vulnerability) which the attacker used sqlmap to dump user credentials from `mysql.user` and logged in to wordpress website and uploaded web shell which successfully executed system commands via web shell.

### Timeline
- 2024-04-04 08:50:26 : The attacker first observed interact with website
- 2024-04-04 08:50:48 : The attacker started enumerate website with `wpscan`
- 2024-04-04 08:52:07 : The attacker started using `sqlmap` on `/wp-admin/admin-ajax.php?action`
- 2024-04-04 09:07:00 : The attacker authenticated to website
- 2024-04-04 09:17:47 : The attacker uploaded web shell to the website
- 2024-04-04 09:19:19 : The attacker successfully executed first command via web shell

### IOCs
- `146[.]70[.]188[.]168`
- `149[.]78[.]184[.]202`
- `86[.]6[.]229[.]12`

***