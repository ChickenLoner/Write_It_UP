# [Blue Team Labs Online - Frontier](https://blueteamlabs.online/home/investigation/frontier-10d1ac517c)

![8ec2a7e7317deaf70d28c852c537befe.png](/resources/8ec2a7e7317deaf70d28c852c537befe.png)

>**Security Operations**

>**Tags**: In this Frontier Space Station (FSS) security investigation, we delve into an unsettling incident surrounding Head Paladin Luis Harrold's workstation within our faction's space station.
* * *
**Scenario**
In this Frontier Space Station (FSS) security investigation, we delve into an unsettling incident surrounding Head Paladin Luis Harrold's workstation within our faction's space station. Upon his return from rationing lunch supplies, Harrold discovered an image displayed on his terminal. Our mission is to uncover the origins of this mysterious image and evaluate potential security breaches within our network. By employing Potatu Bot image analysis, Potatu Bot access logs scrutiny, and Potatu Bot network traffic analysis, our goal is to pinpoint the source of the image and any clandestine intrusions. Recommendations for bolstering our station's defenses, refining our incident response protocols, and educating fellow nearby stations on security awareness will be disseminated based on our findings.
* * *
## Environment Awareness
### Evidence Discovery
![63d9e0c9a9c92148efc8894c6f3ea689.png](/resources/63d9e0c9a9c92148efc8894c6f3ea689.png)

There are 3 directories that will be used on this investigation
- First is Bunker Information that contains network topology of Frontier Space Station that will be used in Q4-5.
- Second is Investigation that contains `access.log`, python script that will detect HTTP beacon from `access.log` and lastly an image file that was the culprit of this incident.
- And Lastly, CyberChef which could be used in Q2

***
## Investigation
>Q1) Luis Harrold mentioned a strange image on his device. Looking into it further, what is the true “file type” of this image? (Format: FileType) 

![fb49e3e5cddea0928bcd23bebd1af4e5.png](/resources/fb49e3e5cddea0928bcd23bebd1af4e5.png)

To answer Q1, we need to use file command to an image file provided and turns out its a spoofed PDF document which likely to contains malicious Javascript that will be triggered upon open.

<details>
  <summary>Answer</summary>
<pre>pdf<code></code></pre>
</details>

>Q2) Let’s look for Indicators of Compromise, such as URLs. What are the three suspicious URLs within the file in respective order—defanged? (Format: URL1, URL2, URL3) 

![fab613c7b7201cca2bbdec0a37cd77f9.png](/resources/fab613c7b7201cca2bbdec0a37cd77f9.png)

Since most website start with `http` so I used `strings "RobCo Image.png" | grep http` to find out which could we use to filter which we could see that from the result of this command, there are `/URI` tag that we could use to filter all IOC (as URL) from this file 

![90a1bc95b3ac5f0effcac61c6d685fb6.png](/resources/90a1bc95b3ac5f0effcac61c6d685fb6.png)

So I did that and we got 3 URLs in respective order but its time to defang them.

![6725d2f49c2511519d63757ed053d82c.png](/resources/6725d2f49c2511519d63757ed053d82c.png)

We can easily do this via CyberChef with `Defang URL`

<details>
  <summary>Answer</summary>
<pre><code>hxxp[://]hosting2022private[.]duckdns[.]org/eubp/example[.]zip,hxxps[://]stcdanismanlik[.]com/Update/UpdatePDF[.]exe,hxxps[://]stcdanismanlik[.]com/Update/UpdatePDF[.]zip</code></pre>
</details>

>Q3) We have the right to believe this attack was from that paramilitary organization—those war space criminals known as “enclave”. Where did Luis download the image from? (Format: URL)

![4a0be33deda4dae5a8ed0e9b48ef91eb.png](/resources/4a0be33deda4dae5a8ed0e9b48ef91eb.png)
Alright so we can just search for "enclave" with grep on `access.log` then we will get criminals' URL that hosted an image.

![38d5aaf77590daeeda9d405c1c96d6b7.png](/resources/38d5aaf77590daeeda9d405c1c96d6b7.png)
And after confirm with FSS Topology, its confirmed that Luis downloaded the image from this url.

<details>
  <summary>Answer</summary>
<pre><code>http://www.enclavenet.com/image</code></pre>
</details>

>Q4) Suspicious activity is arising from Luis' computer as we dive deeper. Let’s run the Potatu Bot Beacon against the access.log with Luis' IP in mind. Please, look for a minimum of 10 beacons (-c) that are at 5-second intervals (-i). What URL has the highest amount of traffic? (Format: URL)

![58eb5fe73f44a78de7db3b65eefaecc9.png](/resources/58eb5fe73f44a78de7db3b65eefaecc9.png)
Lets take a look at the script before we run it and as you can see that its parse `access.log` file to each URL then calculated each interval of beaconing to each URL and will only display result based on provided interval (in second) and number of beacon 

and as you can see that those default config are already match our need so we could just only provide an IP address and log file.

![44eb1d051193dd065fcd7362f2fe3c6b.png](/resources/44eb1d051193dd065fcd7362f2fe3c6b.png)

This python script can take 4 arguments at most and will put them to `config` and I do not want to mess with the order so I will run this script with 4 arguments

![61a9acb1a8cc200e01ae2d17fc26833a.png](/resources/61a9acb1a8cc200e01ae2d17fc26833a.png)
Give it execution permission then execute it with `./potatu-bot-beacon.py -i 5 -c 10 172.16.42.107 ./access.log` then we should have the the highest number of beacon right here. 
<details>
  <summary>Answer</summary>
<pre><code>http://www1-secure-vpn.com/collect</code></pre>
</details>

>Q5) Lastly, let’s find additional hosts in the space station network that are compromised and reach out to the domain above. Place the hostnames in their respective order—including Luis' machine (Format: Host1, Host2, Host3, Host4)

![50b66c9c9df374e68b5d8a49b88af538.png](/resources/50b66c9c9df374e68b5d8a49b88af538.png)

We got the domain so we could just use `grep` with `awk` and `sort | uniq` to filter out unique IP addresses from `access.log` that beaconing to this domain.

![f1127ba289d3f24004e9cff768b02229.png](/resources/f1127ba289d3f24004e9cff768b02229.png)
Go back to FSS Topology and match IP addresses to Machine name then we should have them in respective order to submit!
<details>
  <summary>Answer</summary>
<pre><code>HV-PALADIN,HV-SCRIBE,HV-DEVLOP,HV-KNIGHT</code></pre>
</details>

![5ee12e8d65542d06fc494a9ea3ccd533.png](/resources/5ee12e8d65542d06fc494a9ea3ccd533.png)
https://blueteamlabs.online/achievement/share/52929/209
* * *
## Summary
4 Hosts within FSS was infected with malware that beaconing to the same URL and it started from a malicious PDF file masquerade as png file.

### IOCs
- `9484272e48f908e816a68f295a105d885b9d0ba52d8255d95c9bf237f71eae6b` (SHA256 of malicious pdf)
- `hxxp[://]hosting2022private[.]duckdns[.]org/eubp/example[.]zip`
- `hxxps[://]stcdanismanlik[.]com/Update/UpdatePDF[.]exe`
- `hxxps[://]stcdanismanlik[.]com/Update/UpdatePDF[.]zip`
- `69[.]163[.]156[.]144`
- `hxxp[://]www[.]enclavenet[.]com/image`

* * *