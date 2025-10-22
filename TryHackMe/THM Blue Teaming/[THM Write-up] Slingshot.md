# [TryHackMe - Slingshot](https://tryhackme.com/room/slingshot)
![1dde743207407c1f73620eb70691cefc.png](/resources/1dde743207407c1f73620eb70691cefc.png)
***
Slingway Inc., a leading toy company, has recently noticed suspicious activity on its e-commerce web server and potential modifications to its database. To investigate the suspicious activity, they've hired you as a SOC Analyst to look into the web server logs and uncover any instances of malicious activity.

To aid in your investigation, you've received an Elastic Stack instance containing logs from the suspected attack. Below, you'll find credentials to access the Kibana dashboard. Slingway's IT staff mentioned that the suspicious activity started on **July 26, 2023**.

By investigating and answering the questions below, we can create a timeline of events to lead the incident response activity. This will also allow us to present concise and confident findings that answer questions such as:
- What vulnerabilities did the attacker exploit on the web server?
- What user accounts were compromised?
- What data was exfiltrated from the server?
***
![f8b21e22db6dc08ec4404c6c54221180.png](/resources/f8b21e22db6dc08ec4404c6c54221180.png)

After accessing ElasticSearch/Kibana, We can change the time range from 15 minutes to 15 years (You can make it precisely select July 26 2023) and then inspect the log we have which look like we only have access logs from Mod Security WAF for total of 3028 events and what special about this log?

Mod Security access log we have contains content of the HTTP body which we can use for our investigation later so lets out further ado, lets start our investigation.

>What was the attacker's IP?

![a02ad860fefd756e0dddc4e898cc797a.png](/resources/a02ad860fefd756e0dddc4e898cc797a.png)

First thing we can do it inspect each field to find for low hanging fruit and we definitely got one here, The **User-Agent** indicates that there are **directory bruteforce/fuzzing** happened by **Gobuster**, **Password bruteforcing by Hydra** which both combines got over **78%** of all logs and not even mentioned the bottom User-Agent which indicates **Nmap Scripting Engine scanning** as well.

![5b4f4e617a7f0b71513d934d720cd2ca.png](/resources/5b4f4e617a7f0b71513d934d720cd2ca.png)

Just completely filtered for any user-agent (in my case, i used `request.headers.User-Agent:Mozilla/5.0 (Gobuster)`) which we will see the remote address is an IP address from the internal network so the attack was conducted within the internal network.

```
10.0.2.15
```

>What was the first scanner that the attacker ran against the web server?

![048bbd9ce9f41cc317a34e2a9d0785de.png](/resources/048bbd9ce9f41cc317a34e2a9d0785de.png)

We know that Nmap Scripting engine was used to scan for the website based on this user-agent.

![ac1d1afc7e67a75d1ab34c4a4cffc320.png](/resources/ac1d1afc7e67a75d1ab34c4a4cffc320.png)

By filtering for this user-agent only, we got total of 29 events which is quite small compare to total amount of events we have.

```
nmap scripting engine
```

>What was the User Agent of the directory enumeration tool that the attacker used on the web server?
```
Mozilla/5.0 (Gobuster)
```

>In total, how many requested resources on the web server did the attacker fail to find?

![68cfb43a92bf6cce39188e68d5b68c47.png](/resources/68cfb43a92bf6cce39188e68d5b68c47.png)

The server will response back with HTTP Status 404 not found so we can use `response.status:404 AND transaction.remote_address:10.0.2.15` query to get all events that response back with HTTP Status 404 which we could see that we got 1867 events in total from this remote IP address.

```
1867
```

>What is the flag under the interesting directory the attacker found?

![da4e886f94b157d01269f720af60d668.png](/resources/da4e886f94b157d01269f720af60d668.png)

Now we just adjusted our query to excluded request with HTTP Status 404 which then we will have all requests from Gobuster that is not return with 404 (it means the attacker found these.) and then we could see that the attacker (including us) found flag from the backup path right here.

```
a76637b62ea99acda12f5859313f539a
```

>What login page did the attacker discover using the directory enumeration tool?

![4ecfc19d290290c15986c1517aa85c45.png](/resources/4ecfc19d290290c15986c1517aa85c45.png)

Keep exploring all the paths that the attacker found from Gobuster then we could see that the attacker also found admin login page but the HTTP response is 401 which mean its not authorized (authentication needed).

```
/admin-login.php
```

>What was the user agent of the brute-force tool that the attacker used on the admin panel?

![bda5816e1643bb1b1b9874bb9f90548e.png](/resources/bda5816e1643bb1b1b9874bb9f90548e.png)

We know that a Hydra was used to bruteforce something and now it filled the gap we found, the attacker used hydra to bruteforce admin login page.

```
Mozilla/4.0 (Hydra)
```

>What flag was included in the file that the attacker uploaded from the admin directory?

![3fc3bf9004df4deec52de716c3e69aed.png](/resources/3fc3bf9004df4deec52de716c3e69aed.png)

So if we added the Hydra user-agent to our query and also focus on HTTP Status that is not 401 then we will have 1 Successful attempt from the attacker at 14:29:04 right there.

![71cd3d3fe14f6d1a270a4665b6963369.png](/resources/71cd3d3fe14f6d1a270a4665b6963369.png)

Now I added the path to my query and removed Hydra user-agent to see when the attacker gonna log in which we could see that the attacker authenticated to the website as admin 9 seconds after Hydra successfully found the valid credential.

![a3553ece846636f3da4bdf798beb58d3.png](/resources/a3553ece846636f3da4bdf798beb58d3.png)

Now we inspected the log, we could see that Mod Security log also logged all HTTP headers which including Authorization header which is used for Basic Authentication as well.

![8b5d9b049311b34e72f47f6aee079d03.png](/resources/8b5d9b049311b34e72f47f6aee079d03.png)

Basic Authentication just happened to encoded both username and password with base64 so we can easily decode it right this to get the credential used to authenticate to admin login page.

```
admin:thx1138
```

>What flag was included in the file that the attacker uploaded from the admin directory?

![f25753586fc8009451eb5fff6e61b8f7.png](/resources/f25753586fc8009451eb5fff6e61b8f7.png)

Now we followed what happened after the attacker successfully accessed admin page, and we could see that the attacker uploaded webshell via upload page that can only be accessed by admin.

![6fb87a9f2770b73b606371bf5cd40341.png](/resources/6fb87a9f2770b73b606371bf5cd40341.png)

Remember what I said about Mod Security log also stores HTTP body content? We will have to use this to find the flag that is hidden in the comment of the webshell right here!

```
THM{ecb012e53a58818cbd17a924769ec447}
```

>What was the first command the attacker ran on the web shell?

![f63b6f2b5d206a91d23361d10abc46f9.png](/resources/f63b6f2b5d206a91d23361d10abc46f9.png)

After successfully uploaded webshell, the attacker used it to execute several commands from `whoami`, `pwd`, `ls` and `which nc` but nothing more command got executed via this webshell after this.

```
whoami
```

>What file location on the web server did the attacker extract database credentials from using **Local File Inclusion**?

![249e0568c996a7b5a174a1983cf252f5.png](/resources/249e0568c996a7b5a174a1983cf252f5.png)

Keep going to log then we can see that the attacker found LFI vulnerability on `page` variable from `/admin/settings.php` page. 

![fd4052bec8a4a4cb4b229d862a7afec3.png](/resources/fd4052bec8a4a4cb4b229d862a7afec3.png)

The attacker then leveraged the vulnerability to obtain credential database credential that commonly defined in `config-db` file which can make a website connect to mysql database seamlessly.

```
/etc/phpmyadmin/config-db.php
```

>What **directory** did the attacker use to access the database manager?

![ba51a563a0deda905d7c6eda20794b9c.png](/resources/ba51a563a0deda905d7c6eda20794b9c.png)

As we kept digging, we could see that the attacker really obtained the database credential from config file which can be used to authenticate to phpadmin.

```
/phpmyadmin
```

>What was the name of the database that the attacker **exported**?

![0ce8dd2a7a5636d1a482a97872b78126.png](/resources/0ce8dd2a7a5636d1a482a97872b78126.png)

After authenticated to phpmyadmin, the attacker then interacted with `credit_card` table from `customer_credit_cards` database.

![8af71d93e205426803203f3ab8aaf30f.png](/resources/8af71d93e205426803203f3ab8aaf30f.png)

The attacker then also exported this database as seen in the image above. 

```
customer_credit_cards
```

>What flag does the attacker **insert** into the database?

![414aaf2b377f77b3cb870c9205b7bf56.png](/resources/414aaf2b377f77b3cb870c9205b7bf56.png)

When we inserted something to the website, we commonly utilized HTTP POST Method so I added `http.method:POST` query to reduce the output which we can see that import endpoint was requested here.

![e70133154b4bd813739c0034b95c39a8.png](/resources/e70133154b4bd813739c0034b95c39a8.png)

By take a look at the log, we can see that the attacker inserted 1 record of credit card information to `credit_cards` table but the URL encoding make it a little bit hard to read.

![b374c7d2a3c7d3bdf4a96c07f6d8ff29.png](/resources/b374c7d2a3c7d3bdf4a96c07f6d8ff29.png)

Do not worry, an AI get our back! the attacker insert a flag to the `credit_cards` table so we can copy it and submit it.

```
c6aa3215a7d519eeb40a660f3b76e64c
```

![3819f6e8ca09a6911547e57d1241b04c.png](/resources/3819f6e8ca09a6911547e57d1241b04c.png)

And now we are done!

![a4bf14f9a0d483a59af229b870076f6e.png](/resources/a4bf14f9a0d483a59af229b870076f6e.png)
https://tryhackme.com/chicken0248/badges/advanced-elk
***