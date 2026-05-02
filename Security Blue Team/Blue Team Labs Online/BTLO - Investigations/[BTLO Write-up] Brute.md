# [Blue Team Labs Online - Brute](https://blueteamlabs.online/home/investigation/brute-3ddc042479)

![2d8f2fd731b06102272e669d3c3dade9.png](/resources/2d8f2fd731b06102272e669d3c3dade9.png)

A server hosting our soon-to-be website is acting odd and it is redirecting away from our website.

>Incident Response

>**Tags**: Notepad++ MySQL T1595.003 T1110.003 T1136.001 T1021.001
* * *
**Scenario**
Hey Defender, thanks for getting back to us!

A server hosting our soon-to-be website is acting odd and it is redirecting away from our website. We have also noticed a strange database-related account on the machine that we've disabled as nobody remembers setting it up.

I am not too certain about the exact details of the server setup, but this is what I do know:

- FileZilla Server is on there

- Xampp is on there

- It has a database running

- Notepad++ is on there.

Can you take a look and let us know what is happening here?
* * *
## Investigation
>Q1) What is the user agent of the tool used to scan the web server? (Format: string/version)

![f12635bc2259e7544a319df1b5c3ae86.png](/resources/f12635bc2259e7544a319df1b5c3ae86.png)

After deployed investigation, we left with note on the desktop with the same message as investigation scenario so lets take a look at web application access log first.

![095ca4e13ac4bd24573ba1cdcd3f64f7.png](/resources/095ca4e13ac4bd24573ba1cdcd3f64f7.png)

Go to C drive then we should be able to see xampp folder right here.

![cc76833587a847b99bc8f008732b472d.png](/resources/cc76833587a847b99bc8f008732b472d.png)

Alternative way to navigate to log folder directly is to click "Logs" botton in XAMPP Control Panel.

![8285a8b832de442bcbe67fc7e0a6e301.png](/resources/8285a8b832de442bcbe67fc7e0a6e301.png)

Now we are in `C:\xampp\apache\logs` folders that has `access.log` and `error.log` that can be used for our investigation so lets open them with NotePad++

![854db3c34136fde4edf65e1fec66ccbc.png](/resources/854db3c34136fde4edf65e1fec66ccbc.png)

First thing I noticed that this IP address used nmap script engine to enumerate website but that's not the answer this question expected so we need to keep goin

![57903f4bc6571a6292d405c1552df516.png](/resources/57903f4bc6571a6292d405c1552df516.png)

Then we will finally see that this website was bruteforced by feroxbuster for file discovery.

<details>
  <summary>Answer</summary>
<pre><code>feroxbuster/2.10.1</code></pre>
</details>

>Q2) At what time did the attacker (not the tool) retrieve the file that contained the username for the compromised service? (Format: dd/mmm/yyyy:hh:mm:ss)

![e5037e9a8e9857b000a5ef2112c1f76a.png](/resources/e5037e9a8e9857b000a5ef2112c1f76a.png)

Scroll down to the bottom after scanning is done then we should be able to see different user-agent from the same IP address accessed `README.md` so lets find out what's inside this file

![a94dd076cbed09cc59a08dc997b378e9.png](/resources/a94dd076cbed09cc59a08dc997b378e9.png)

`htdocs` is where user stores all files that would display on the website which we will see `README.md` inside this folder too. 

![da37894af22ab799f53076bad65de6bf.png](/resources/da37894af22ab799f53076bad65de6bf.png)

Then we could see that ftp username was exposed from here so it also confirmed timestamp of this question.

<details>
  <summary>Answer</summary>
<pre><code>26/Jan/2024:10:59:53</code></pre>
</details>

>Q3) What was the username of the account used to compromise the service? (Format: Username)
<details>
  <summary>Answer</summary>
<pre><code>ptfftp1010</code></pre>
</details>

>Q4) At what time did the attacker successfully login & what was the session number? (Format: yyyy-mm-ddThh:mm:ss, xxx)

![29910286c493427f2e6560f35dc5f58e.png](/resources/29910286c493427f2e6560f35dc5f58e.png)

Lets go to Filezilla log then open it in NotePad++

![a76d5e29c4c0dbbe150328ae7c2b85c5.png](/resources/a76d5e29c4c0dbbe150328ae7c2b85c5.png)

After search for exposed username, we will see a lot of authentication attempt to access FTP service.

![a20ea1206b720fc232738e8fee671fa4.png](/resources/a20ea1206b720fc232738e8fee671fa4.png)

We can skip to Line 1239, this is where the attacker successfully authenticated to FTP and with FTP session 140.

<details>
  <summary>Answer</summary>
<pre><code>2024-01-26T11:30:37, 140</code></pre>
</details>

![4660fa1e457bd2725de54b4ac82b5f53.png](/resources/4660fa1e457bd2725de54b4ac82b5f53.png)

the attacker renamed original index page to `index.php.hacked` then uploaded `index.php` and `1ndex.php` before disconnected.

![6abfb98b41c0198aa04a866df36ed67d.png](/resources/6abfb98b41c0198aa04a866df36ed67d.png)

Here is the original index page.

![2235be256adf9ae3fb4e717fdd9fc3c0.png](/resources/2235be256adf9ae3fb4e717fdd9fc3c0.png)

new `index.php` will redirect user to amazon page use for the next question.

![cb71f3b14be038de6ca0f93c421b24ea.png](/resources/cb71f3b14be038de6ca0f93c421b24ea.png)

this is where the attacker could execute command on the server and even upload files so we can call this a webshell.

>Q5) What the ISBN-13 associated with the website defacement? (Format: xxx-xxxxxx)

![2235be256adf9ae3fb4e717fdd9fc3c0.png](/resources/2235be256adf9ae3fb4e717fdd9fc3c0.png)

Alright we know that this amazon url is safe so lets browse it on our web browser

![54a5fb645b2e3f8437c509d8e332e352.png](/resources/54a5fb645b2e3f8437c509d8e332e352.png)

Then we could get ISBN-13 of this book right here.

<details>
  <summary>Answer</summary>
<pre><code>978-0434022083</code></pre>
</details>

>Q6) What two commands did the attacker run in the web shell to create a backdoor user? (URL decoded, replace any + with a space) (Format: Command1, Command2)

![1e35f8215b7cdbe4275c714fe92b3109.png](/resources/1e35f8215b7cdbe4275c714fe92b3109.png)

We know that `1ndex.php` is a webshell so the attacker created backdoor user via this webshell.

![b1b00020b98996a3c8f97455e2d56ff3.png](/resources/b1b00020b98996a3c8f97455e2d56ff3.png)

URL decode then we can copy these commands and submit.

<details>
  <summary>Answer</summary>
<pre><code>net user /add mysql-user mysql-user, net localgroup administrators mysql-user /add</code></pre>
</details>

>Q7) What is the CreationTime of this users profile? (Format: M/DD/YYYY HH:MM:SS <AM/PM>)

![fc459720974b60e7a6779b4597e292ef.png](/resources/fc459720974b60e7a6779b4597e292ef.png)

I tried to open Security log but it won't let me open it so I have to copy timestamp of the second command from previous question and let ChatGPT convert to event log format for me.

![e1cfaca26090c156fc54fe20941d4c60.png](/resources/e1cfaca26090c156fc54fe20941d4c60.png)

There is it.

<details>
  <summary>Answer</summary>
<pre><code>1/26/2024 11:40:15 AM</code></pre>
</details>

>Q8) What is the table name for the application admins? (Format: xx_xxx_xxxxxx)

![09ad8a6958c3b93495836beb844b17a5.png](/resources/09ad8a6958c3b93495836beb844b17a5.png)

Go to `data` folder located in `C:\xampp\xampp\mysql` then we could see that this webserver is using InnoDB as storage engine and the folder that might catch your interest right away is `newsupercoolapp` which is a folder represent the database of this website.

![50daa0e6acedc972bb5e85293360aa2d.png](/resources/50daa0e6acedc972bb5e85293360aa2d.png)

Inside this folder we can see ibd (InnoDB data) file which stores data of `zz_app_admins` table in `newsupercoolapp` database

<details>
  <summary>Answer</summary>
<pre><code>zz_app_admins</code></pre>
</details>

>Q9) What is the email address of Harold Bishop? (Format: mailbox@domain.tld)

![8ba822fc33177d4995597925c5831f55.png](/resources/8ba822fc33177d4995597925c5831f55.png)

I don't bother access phpmyadmin so I opened this file on CyberChef and got the email address of Harold Bishop from here.

<details>
  <summary>Answer</summary>
<pre><code>hbishop@aol.com</code></pre>
</details>

>Q10) What SQL query did the attacker run against all users in the applications admin table? (Format: `<statement> <table> <clause> <field>=<value>;`)

![40b342d17fe338b51b96fd3d0d7b02e4.png](/resources/40b342d17fe338b51b96fd3d0d7b02e4.png)

There is one log file that stores SQL query that is this file so lets open it and find out which command can affect all users.

![51b9d4cf00617db161c534d17f3de239.png](/resources/51b9d4cf00617db161c534d17f3de239.png)

Then we should be able to find that after attacker got everything from `zz_app_admins` with `select *` query then 2 update statements were made which will set active value in both tables (`t_users` and `zz_app_admins`) to 0 

<details>
  <summary>Answer</summary>
<pre><code>update zz_app_admins set active=0</code></pre>
</details>

![eec29b1769a12600b1cf9c95edcfc76d.png](/resources/eec29b1769a12600b1cf9c95edcfc76d.png)
https://blueteamlabs.online/achievement/share/52929/190
* * *