# [Blue Team Labs Online - MiddleMayhem](https://blueteamlabs.online/home/investigation/middlemayhem-aa3c27f5d1)

![4a01b4339e377826aeb6c1f45d94b97b.png](/resources/4a01b4339e377826aeb6c1f45d94b97b.png)

>**Incident Response**

>**Tags**: NextJS Splunk
* * *
**Scenario**
The security team at MiddleMayhem Inc. has detected unusual network traffic to their admin portal, but no security breaches have been confirmed. Your SOC team has been provided with SIEM logs from the incident. Analyze the attack pattern to determine how attackers bypassed authentication, gained remote code execution, and moved laterally through the network.
* * *
## Environment Awareness
### Evidence & Tool Discovery

![f5ef6b2f13ac06de4a51edc5b17f380b.png](/resources/f5ef6b2f13ac06de4a51edc5b17f380b.png)

After deployed an investigation machine, we do not have much thing on our side beside the Splunk web interface and the website that was the target of this incident so we can interact with the website directly as well

![c4c0cbcd03f9a5d64e56b488a287b8a7.png](/resources/c4c0cbcd03f9a5d64e56b488a287b8a7.png)

We can now access Splunk web interface which after applied `index=*` and select time range to all time we will have 88,932 events combine from webapp and `auth.log` but we only have 50 events from `auth.log`, and it telling us that this event involves in SSH as well.

Beside this this investigation was released due to the popularity of Next.js middleware bypass vulnerability so we will need to understand this vulnerability first which I already prepared the blog post for you to read right [here](https://zhero-web-sec.github.io/research-and-things/nextjs-and-the-corrupt-middleware) 

Long Story short, Next.js use middleware to handle authorization such as admin to access authorized endpoint so this vulnerability present the oppotunity to bypass this middleware and jump straight to those endpoints by sending `x-middleware-subrequest` HTTP header with the right value (based on Next.js version)

Now lets start our investigation.

* * *
## Investigation
>Q1) Access the Website in the browser, present it in the bookmark, and identify the JavaScript framework and version used.

![9cf2463444e4b566196bd146934f9447.png](/resources/9cf2463444e4b566196bd146934f9447.png)

Since we can access to the website directly which after scrolling to the bottom, we have Next.js version right here and we can also see sitemap, robots and admin portal on this website, so all recipe for Next.js middleware bypass are here. 

<details>
  <summary>Answer</summary>
<pre><code>Next.js, 15.0.0</code></pre>
</details>

>Q2) Using Splunk, Find the attacker’s IP address

![8bfab9394e241d38c435d0e33f0ba248.png](/resources/8bfab9394e241d38c435d0e33f0ba248.png)

Knowing which HTTP header will be used to bypass middleware, we can simply use the following query `index=* source="webapp.csv" x-middleware-subrequest | sort by _time` to filter all events which this header which we can see that not just an attempt to bypass to `/admin` endpoint which required authentication, the attacker also uploaded bash reverse shell (`shell.sh`) to `/api/upload` endpoint as well and both request came from the same IP address.

![9dd34443624c0322bc440c787be71510.png](/resources/9dd34443624c0322bc440c787be71510.png)

One more thing to notice is the value in the header which according to [Project Discovery blog post](https://projectdiscovery.io/blog/nextjs-middleware-authorization-bypass), it matches the correct value to bypass Next.js version 13.2.0 or later.

<details>
  <summary>Answer</summary>
<pre><code>218.92.0.204</code></pre>
</details>

>Q3) Analyze the SIEM logs to determine how many unique URIs were accessed by the attacker.

![5eb8bea8003c6d0098dfedf4c8201bf5.png](/resources/5eb8bea8003c6d0098dfedf4c8201bf5.png)

We have 2 different query that could be use to find out about this, first is the `stats count by http.request.uri` and the second is `dedup` which both will get down to the same number which is 9930 different endpoints that where bruteforced by the attacker. 

<details>
  <summary>Answer</summary>
<pre><code>9930</code></pre>
</details>

>Q4) Explore the site and identify two specific locations that could reveal internal structures or potential access points not meant for public eyes. Provide the two relative URLs.

![31d4d2ce4114dddc81c9cdd10ecf9368.png](/resources/31d4d2ce4114dddc81c9cdd10ecf9368.png)

The keyword here is "potential access points not meant for public eyes", and as we already found out the existence of `robots.txt` which is used to telling search engine's crawler to not index these endpoints which we get 2 endpoints from this file right here, both endpoint served as an initial access to upload reverse shell script as we discovered from Q2.

<details>
  <summary>Answer</summary>
<pre><code>/admin, /admin/file-upload</code></pre>
</details>

>Q5) Based on the Framework and Version, what recent CVE could be used to bypass authorization?

![87c854c2f13b2ca5ff13c64843c29644.png](/resources/87c854c2f13b2ca5ff13c64843c29644.png)

This Next.js middleware bypass vulnerability was assigned CVE number of CVE-2025-29927

<details>
  <summary>Answer</summary>
<pre><code>CVE-2025-29927</code></pre>
</details>

>Q6) Find the relevant HTTP header in the SIEM logs that indicates CVE exploitation. Provide the header name.

![7f816c36e6fb40ea15b9acb70c363477.png](/resources/7f816c36e6fb40ea15b9acb70c363477.png)

As we already talked and discovered what header being used to bypass middleware, its `x-middleware-subrequest` which was designed to use internally and the present of this header uses to "know if the middleware should be applied or not"

<details>
  <summary>Answer</summary>
<pre><code>x-middleware-subrequest</code></pre>
</details>

>Q7) What interesting URI did the attacker access after exploiting the CVE?

![8bfab9394e241d38c435d0e33f0ba248.png](/resources/8bfab9394e241d38c435d0e33f0ba248.png)

As we already discovered that `/api/upload` was used to upload `shell.sh` that will connect to 113.89.232.157 on port 31337 with netcat upon execution

<details>
  <summary>Answer</summary>
<pre><code>/api/upload</code></pre>
</details>

>Q8) The attacker tried uploading a reverse shell. Find out the IP and port to which the target would connect once the connection is established.

![bf68c8e0a127bdf49b58a77c85b5d19f.png](/resources/bf68c8e0a127bdf49b58a77c85b5d19f.png)

We know that after uploading reverse shell script, the attacker has to invoke this script in order to execute it and receive reverse shell so we could use `index=* shell.sh` which we can see that it will uploaded to `/uploads/shell.sh`

![8041bedc7b350d68700f852604850914.png](/resources/8041bedc7b350d68700f852604850914.png)

Then we could also use `index=* 113.89.232.157 31337` query to filter for any event which this IP address and port which reveals incomplete 3-way handshake (SYN from server to C2 but RST, ACK from C2) and thats mean this connection was not established successfully due to C2 address sent RST packet back to victim.

<details>
  <summary>Answer</summary>
<pre><code>113.89.232.157:31337</code></pre>
</details>

>Q9) After compromising the WebApp server, the attacker attempted lateral movement. Identify the technique used, as recorded in the SIEM logs.

Somehow the attacker successfully compromised 172.217.164.174 despite what we discovered from previous question so now we have to look at the other source since we know that we have `auth.log` as other log source so it must be SSH 

![a830781ffd4537250db2ddd122b22719.png](/resources/a830781ffd4537250db2ddd122b22719.png)

Which I used `index=* source="/home/dbserv/auth.log" ssh | sort by _time` to filter all events with "ssh" keyword and we will see that there is an brute force attack happened during the incident so the attacker attempted to gain access via SSH after compromised 172.217.164.174

<details>
  <summary>Answer</summary>
<pre><code>SSH Brute Force</code></pre>
</details>

>Q10) Identify the user account that achieved successful lateral movement to another server.

![511134c1ed25977a48f0cc59bbc814e6.png](/resources/511134c1ed25977a48f0cc59bbc814e6.png)

Then we can see that at the end, the attacker successfully connected to the target via SSH as dbserv user.

<details>
  <summary>Answer</summary>
<pre><code>dbserv</code></pre>
</details>

![87b968f2d5f965e8ce7d2f860bccc725.png](/resources/87b968f2d5f965e8ce7d2f860bccc725.png)
https://blueteamlabs.online/achievement/share/52929/259
* * *