# [Blue Team Labs Online - HUNT3R](https://blueteamlabs.online/home/investigation/hunt3r-e329432fc3)

![3b54a0722f730a4972d31043fc8feafc.png](/resources/3b54a0722f730a4972d31043fc8feafc.png)

As a part of routine threat hunting activities, web logs are retrieved any analysed by the security team. Can you find anything?

>Incident Response

>**Tags**: Linux CLI/Terminator Sublime Text 2 OSINT Gnumeric CyberChef T1584.006
* * *
**Scenario**
As a part of routine threat hunting activities, web logs are retrieved any analysed by the security team. Can you find anything? Use your command-line skills, along with an analytical approach to identify malicious activity and gather attack information.

Reading Material:
https://stackoverflow.com/questions/14618326/how-to-import-a-text-log-file-into-a-excel-columns (this wont work fully, but it does work!)
* * *
## Investigation Submission
>Q1) What is the IP address of the web server, and what is the FQDN? (Format: X.X.X.X, https://domain.tld)

![ec0031761e19ded6a166505666848c80.png](/resources/ec0031761e19ded6a166505666848c80.png)

We only have log file to investigate so lets open terminal and make use of our log parsing skills!

![f6fa024dc891bd0ae045688d0960cd20.png](/resources/f6fa024dc891bd0ae045688d0960cd20.png)

Lets start this by determining an IP address of this webserver and FQDN by using head command with log then we should be able to get both of them right here.

<details>
  <summary>Answer</summary>
<pre><code>194.77.176.185, https://DicksonUnited.co.uk/</code></pre>
</details>

>Q2) Investigate the logs to identify what is expected traffic, and what isn't. What is the source IP related to malicious activity? (Format: X.X.X.X)

![213a501567d8b221a27a2336a5cc2cb1.png](/resources/213a501567d8b221a27a2336a5cc2cb1.png)

Next I used `cut -d " " -f 5 iis-log-dump.log | sort | uniq` to identify weird endpoint then I saw these weird endpoint that likely to be file discovery attempts by the threat actor. 

![d371d8f0c66138e0ac693b3d8355d941.png](/resources/d371d8f0c66138e0ac693b3d8355d941.png)

So I grabbed one of them and search it for an IP address which turn out to be the right answer of this question.

<details>
  <summary>Answer</summary>
<pre><code>200.10.209.169</code></pre>
</details>

>Q3) Use OSINT tools to find the country associated with this IP (Format: Country Name) 

![e780dbb8f6aebfb884a6b557677953f9.png](/resources/e780dbb8f6aebfb884a6b557677953f9.png)

After use [IPlocation](https://www.iplocation.net/) to find out the country associated with this IP address then you can see that its in Ecuador.
<details>
  <summary>Answer</summary>
<pre><code>Ecuador</code></pre>
</details>

>Q4) What is the user-agent string used by the malicious actor? (Format: User-agent)

![2cf6fe9a0d58864f24a309dc6509edb5.png](/resources/2cf6fe9a0d58864f24a309dc6509edb5.png)
Go back to the result from grep command to get user-agent but you have to copy it twice since its too long for BTLO clipboard to be parsed in a single time.
<details>
  <summary>Answer</summary>
<pre><code>Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/78.0.3904.108+Safari/537.36</code></pre>
</details>

>Q5) How many lines in the log file reference the malicious IP address? (Format: Number of Lines)

![08947696a1e9c287de1d5c8bb4db7e84.png](/resources/08947696a1e9c287de1d5c8bb4db7e84.png)
We can grep this IP address then pipe it to `wc -l` to count all lines from grep command then we would have all lines in the log file reference to this malicious IP address.
<details>
  <summary>Answer</summary>
<pre><code>833</code></pre>
</details>

>Q6) Which request made by the malicious IP resulted in a successful connection? Provide the URL that was accessed (including the FQDN) (Format: https://domain.tld/somethinghere)

![512cf6497d7335e63a0db603a3ecbc93.png](/resources/512cf6497d7335e63a0db603a3ecbc93.png)
Lets use `grep "200.10.209.169" iis-log-dump.log | grep ' 200 '` to get all HTTP request with HTTP Status 200 then we will only have this 1 line that threat actor had accessed.
<details>
  <summary>Answer</summary>
<pre><code>https://DicksonUnited.co.uk/4/settings.tgz</code></pre>
</details>

>Q7) What is the timestamp for this successful request? (Format: YYYY-MM-DD HH:MM:SS)

![73c9cdbd8bd1ded30c5865e346943199.png](/resources/73c9cdbd8bd1ded30c5865e346943199.png)

Get the timestamp of this request right here.

<details>
  <summary>Answer</summary>
<pre><code>2022-10-17 18:18:59</code></pre>
</details>

>Q8) Looking at only requests for this IP, based on the timestamps of the first and last events, what was the duration of the attack in seconds? (Format: Seconds Duration)

![a42c9a739dddad7e72305240d748ba23.png](/resources/a42c9a739dddad7e72305240d748ba23.png)

We can use `head -n 1` along with `tail -n 1` to get the first and the last request from this IP address then we can calculate duration between this 2 timestamp easily since its not long.
<details>
  <summary>Answer</summary>
<pre><code>16</code></pre>
</details>

>Q9) How many URIs accessed by this IP are unique? (Format: Number of Unique URIs

![9455a8e885b734c1c952a7415173b800.png](/resources/9455a8e885b734c1c952a7415173b800.png)

For this question I used `grep "200.10.209.169" iis-log-dump.log | cut -d " " -f 5 | sort | uniq | wc -l` to list all URIs accessed by this IP address then sort and remove duplicate and lastly count all the lines remains.
<details>
  <summary>Answer</summary>
<pre><code>653</code></pre>
</details>

>Q10) How many unique source IPs are observed within the log file? (including the malicious IP) (Format: Count of Unique IPs)

![2b7b6b66639129e73880597ca2bacae7.png](/resources/2b7b6b66639129e73880597ca2bacae7.png)

I used `cut -d " " -f 9 iis-log-dump.log | sort | uniq | wc -l` for this question to list all unique sender IP addresses to this website.
<details>
  <summary>Answer</summary>
<pre><code>243</code></pre>
</details>

![560e403d8c61488a89d26a5dcfaf09d0.png](/resources/560e403d8c61488a89d26a5dcfaf09d0.png)
https://blueteamlabs.online/achievement/share/52929/127
* * *