# [Blue Team Labs Online - Haunted](https://blueteamlabs.online/home/investigation/haunted-dfa349d2bb)
<div align=center>

![afd61e4ac70179815c6d90bc7430fe19.png](/resources/afd61e4ac70179815c6d90bc7430fe19.png)

</div>
One of the company's websites has been defaced, raising alarms. Collaborate with other analysts to uncover the identity of the adversary and assess the situation.

>Threat Intelligence
>**Tags**: exiftool, officemalscanner, CyberChef
* * *
**Scenario**
Haunted Company Inc., a long-established Credit Reporting Agency, has been successfully operating in major financial hubs such as New York, London, and Tokyo. As a privately owned entity without external investors, the company has maintained consistent client satisfaction and steady earnings reports. With plans for expansion, the management has decided to take the company public, and the Initial Public Offering (IPO) is scheduled to occur within the next few days.

However, a crisis emerged just as the IPO date approaches. One of the company's websites has been defaced, raising alarms. Shortly after, it is discovered that the company's Tokyo server has come under attack. Concerned about the timing and the potential damage to the company’s reputation, the management is determined to identify the threat actor behind this attack and understand the breach mechanism to create detection before the IPO.

As a Threat Intelligence Analyst, you are tasked with collaborating with other analysts to uncover the identity of the adversary and assess the situation.

Available External and Internal Threat Intelligence:

New York(External: Business Commonality): Report on the 2017 GenX Breach, a major cyber attack on a leading Credit Reporting Agency. London(Internal Intelligence: Adversary Analysis): Analysis report for Haunted Company Inc., including Asset-Threat Mapping and adversary analysis featuring FIN7, APT27, Twisted Spider, and TG-3390, all of which are known to target the finance sector. Tokyo(Cyber Activity Attribution): Malware analysis from the compromised server, providing critical insights into the tools used during the attack.

* * *
## Investigation Submission
![d745165c8600dc12ddfeb9b152fc2c1d.png](/resources/d745165c8600dc12ddfeb9b152fc2c1d.png)

After deployed an investigation machine, we will see "Investigation" folder on the desktop that stores files and tools that will be used for our investigation and it seem like we got 2 text files to read then lets start with `README.txt` first.

![26efa16879e4ed3662d918eb6fdc6463.png](/resources/26efa16879e4ed3662d918eb6fdc6463.png)

Then we will be presented with the scenario and a link to html page.

![46a5c97afc989ba0a4d07559f2d34ab0.png](/resources/46a5c97afc989ba0a4d07559f2d34ab0.png)

`DecodeME.txt` file contains base64 strings and before we decode it, lets access link provided in `README.txt` first.

![bdec07fd9e90cac6672207be8b0935ee.png](/resources/bdec07fd9e90cac6672207be8b0935ee.png)

So we have to decode base64 and put it in this box and submit it.

![9a7dd6c83831fa5ef3dd6f183fd23824.png](/resources/9a7dd6c83831fa5ef3dd6f183fd23824.png)

Upon decoding base64 strings, we see that its a HTML code so I guess we have to submit it to combine 2 HTML code from website and this decode HTML code together to make it functional.

![d8946ee5b2650cbd05f0f99e32ff05be.png](/resources/d8946ee5b2650cbd05f0f99e32ff05be.png)

After submit it, threat intel feed will be displayed and we will see a lot of bat flying around along with 3 markers displayed on the map waiting to be clicked (And this site became so laggy after we rendered them.)

![ce30e24a2c10ab8d0bf0f08c50911d4f.png](/resources/ce30e24a2c10ab8d0bf0f08c50911d4f.png)

Without a choice, I have to read HTML code we just decoded then I found that those 3 markers represented New York, London and Tokyo threat intel.

![9ee6242b38d4edfdf2bacd885225a1c7.png](/resources/9ee6242b38d4edfdf2bacd885225a1c7.png)

Scroll down for a bit which we can see that after we click those markers, we will download these 3 files so lets download them all.

![2bcfc78e566930f71ce3d0bff806bcfc.png](/resources/2bcfc78e566930f71ce3d0bff806bcfc.png)

Now lets extract all the files to it respective folders.

![2d84473e9a04332a5a0341f36396cabb.png](/resources/2d84473e9a04332a5a0341f36396cabb.png)

We can extract 2 files but only Tokyo IOC is password protected so we will have to figure it out somehow.

>Q1) In 2017, a well-known company was attacked. What is the name of the company, its country of origin, and its business model? (Format: XxxX Xxxxxxxxx, XX, Xxxxx Xxxxxxxxx Xxxxxx)

![082b77c9e821d11f72ffe688d7ce0ee9.png](/resources/082b77c9e821d11f72ffe688d7ce0ee9.png)

We know that London has report on the 2017 GenX breach which might related to this question so lets open it.

![c917806d900e0603a483aa37f260b513.png](/resources/c917806d900e0603a483aa37f260b513.png)

Then we could see the name of this company, its country and business model right here.

<details>
  <summary>Answer</summary>
<pre><code>GenX Financial, US, Credit Reporting Agency</code></pre>
</details>

>Q2) According to the data breach summary, one of their critical assets was compromised, and they later discovered a vulnerability in one of their public-facing applications. What type of weakness was exploited to breach their network? (Format: Axxxxxxxxxx Vxxxxxxxxxxxxx)

Then after reading through this report, you might notice this breach was caused by unpatched vulnerability specifically for CVE-2017-5638

![f2f07f8b48ab8e0cb5f69d4bf86b1014.png](/resources/f2f07f8b48ab8e0cb5f69d4bf86b1014.png)

Which is [Apache Struts vulnerability](https://www.blackduck.com/blog/cve-2017-5638-apache-struts-vulnerability-explained.html) which is an "application vulnerability" that lead to remote command injection attack or RCE.

<details>
  <summary>Answer</summary>
<pre><code>Application Vulnerability</code></pre>
</details>

>Q3) How long did this breach go undetected? What was the Mean Time to Detect (MTTD)? (Format: XX days)

![dd696c08d612f410ea8134d66e1b492a.png](/resources/dd696c08d612f410ea8134d66e1b492a.png)

You can get an answer of this question right here.
<details>
  <summary>Answer</summary>
<pre><code>76 days</code></pre>
</details>

>Q4) What application was targeted by the attacker? What vulnerability was exploited, and where is this application located within the network? (Format: Xxxxxx Xxxxxx, CVE-XXXX-XXXX, XXXX)

![5f4603004da40a2bd0efc5e369c76c7c.png](/resources/5f4603004da40a2bd0efc5e369c76c7c.png)

We already know that its CVE-2017-5638 of Apache Structs but which system was affected? after reading Incident Scope then we can see its in ACIS environment.

<details>
  <summary>Answer</summary>
<pre><code>Apache Struts, CVE-2017-5638, ACIS</code></pre>
</details>

>Q5) The attackers exfiltrated millions of records. How many consumer details were estimated to be exposed, and how was this data left from the premises and through which channel was the data exfiltrated? (Format: XXX Million, xxxxxxxxx)

![4e4af07b073b3dcda9ca5d6cef95eef3.png](/resources/4e4af07b073b3dcda9ca5d6cef95eef3.png)

Approximate number of personal and financial information that was stolen is around 150 million right here.

![22093b18d190ff7afd57b1f91ade976b.png](/resources/22093b18d190ff7afd57b1f91ade976b.png)

And because of digital certificate, it allowed the attackers to exfiltrate data via encrypted network traffic.
<details>
  <summary>Answer</summary>
<pre><code>150 Million, encrypted</code></pre>
</details>

>Q6) Later, during the investigation, a flaw was discovered in their ACIS code rendering system. What were these flaws? (Format: XXX Xxxxxxxxx, Xxxxxxxx Xxxxxx Xxxxxx Xxxxxxxxx)

![d2ae368f488be48be284f9b729348feb.png](/resources/d2ae368f488be48be284f9b729348feb.png)

From Incident Scope, it was mentioned that ACIS code has several vulnerabilities and that include IDOR and SQL Injection.
<details>
  <summary>Answer</summary>
<pre><code>SQL injection, Insecure Direct Object Reference</code></pre>
</details>

>Q7) What file was inserted during the attack, and which country did the attack originate from? (Format: XXX, Xxxxx)

![ddeaf232e05f7d7874b2497745ac5ef5.png](/resources/ddeaf232e05f7d7874b2497745ac5ef5.png)

GenX observed that a suspicious IP address owned by a German ISP but leased to a Chinese provider so the country is China and the file inserted during the attack is JSP file which exploited SQL injection attack to deliver it. 

<details>
  <summary>Answer</summary>
<pre><code>jsp, china</code></pre>
</details>

>Q8) It is said that if a specific network security technique had been properly implemented, the attacker likely would have failed to accomplish their mission. What is this technique called? (Format: Nxxxxxx Sxxxxxxxxxxx)

![bf99128f5c739418644c7c6493477866.png](/resources/bf99128f5c739418644c7c6493477866.png)

Go to Threat Vectors section which we can see that this company did not implement network segmentation which can reduce scope of the breach and limited what the attackers could do in a single network segment.

<details>
  <summary>Answer</summary>
<pre><code>network segmentation</code></pre>
</details>

>Q9) Adversary Analysis, this one group in particular as being involved in numerous attacks, including an attack on a medical research company during COVID-19. What is the name of this threat group (according to MITRE), what threat vector do they use, what is their country of origin, and what is their motivation? (Format: XXXX, Xxxxxxxxxx, Xxxxxx, Xxxxxxxxx)


![3cea8818d43e54a29bd3e7cdcf6b5137.png](/resources/3cea8818d43e54a29bd3e7cdcf6b5137.png)

Lets learn more about 2 adversaries provided by this investigation.

![00c0cb61465eb6419af53e7c56dd9f16.png](/resources/00c0cb61465eb6419af53e7c56dd9f16.png)

First adversary that we are going to learn is FIN7

![52464be9878254fe4f19c104f8a26dd5.png](/resources/52464be9878254fe4f19c104f8a26dd5.png)

Which is Russia speaking threat group that mean they must originated from Russia and they used ransomware to conduct several high-profile campaigns and also utilized double extortion technique that will ask for more money to not exposed private files to public so their motive is financial gain.

<details>
  <summary>Answer</summary>
<pre><code>FIN7, Ransomware, Russia, Financial</code></pre>
</details>

>Q10) Investigating the other threat group. What is the APT number assigned to this group? What is the name of the specific operation that involved dropping web shells on SharePoint servers? In what year was this group first observed, and what is their possible motivation? (Format: APTXX, XxxxxXxxxx Xxxxxx Xxxxxxxxxx, XXXX, Xxxxxxxxx)

![35bc3580ef82a1e581e9104515e7e03d.png](/resources/35bc3580ef82a1e581e9104515e7e03d.png)

Lets take a look APT27 this time.

![0bbee2aabc53451f6f3373991956199b.png](/resources/0bbee2aabc53451f6f3373991956199b.png)

Then we can see that this group was first seen in 2020 and their campaigns aimed to stole sensitive data including Intellectual property and other important documents which make their motive "espionage" and the operation that involved dropping web shells on SharePoint servers is SharePoint Server Compromise.

<details>
  <summary>Answer</summary>
<pre><code>APT27, SharePoint Server Compromise, 2010, espionage</code></pre>
</details>

>Q11) Haunted Company Inc. in Tokyo is under cyber attack. Based on the IOCs that were provided (hint: BAT!), what attack vectors did the threat actor use? (Format: Sxxxxx Exxxxxxxxxx, Wxxxxxxx)

Its time to find Tokyo IOC zip password, lets take a look at what we have
- "Look out for bats!" from `README.txt`
- exiftool provided

So I guessed that we will get more file from clicking those bats. 

![0980784ac93f8d05280014718a547e12.png](/resources/0980784ac93f8d05280014718a547e12.png)

So I read HTML code from base64 decode again then which I can see that these bats have eventListener waiting to be clicked.

![93331d222c0e545204947c9b3379dd8b.png](/resources/93331d222c0e545204947c9b3379dd8b.png)

And if we clicked 5 of them, new image will be displayed

![4d0f6eb9b531b7869b2e236966c46295.png](/resources/4d0f6eb9b531b7869b2e236966c46295.png)

This is an image to download.

![469af061117f745663d40dd0603b0c40.png](/resources/469af061117f745663d40dd0603b0c40.png)

Then we can see Title metadata of this image does look like a password but it couldn't be used to unzip `Tokyo_IOC.zip`

![0b39983cb8d3539b571f7f50e36b7e1c.png](/resources/0b39983cb8d3539b571f7f50e36b7e1c.png)

So this time I had to inspect page source which revealed everything about this page including this file that will be downloaded if image has been downloaded via legitimate way (clicking those annoying bats)

![dcb54e3fcd414e458f784dc867a0e1f4.png](/resources/dcb54e3fcd414e458f784dc867a0e1f4.png)

Well since we already know a path then we can download it then use password obtained via exiftool to extract file inside of it.

![4140f52dddb472cb51a51cbaafbbde42.png](/resources/4140f52dddb472cb51a51cbaafbbde42.png)

Which is a password that can extract `Tokyo_IOC.zip`.

![29380923e9f7949ef95ef1205b138640.png](/resources/29380923e9f7949ef95ef1205b138640.png)

Now we have 2 files from these 2 folders left to be analyzed.

![23f2b05bad43ebe5dc01a580e4666b8b.png](/resources/23f2b05bad43ebe5dc01a580e4666b8b.png)

First file is Rich Text Format (rtf) file which was created by Microsoft Word and known for being abused to embedded malware and the way we could deliver this is to use something like "phishing" or "social engineering"

![ae973530bed483be226948657c4b4980.png](/resources/ae973530bed483be226948657c4b4980.png)

This one is aspx file which is a "webshell".

<details>
  <summary>Answer</summary>
<pre>social engineering, webshell<code></code></pre>
</details>

>Q12) One of the IOCs contains shellcode. Use a tool and review the output to identify the offset of the PEB (Process Environment Block). (Hint: Output + OSINT!) (Format: 0x..) 

![9427c81e44163702264ade31b5d8e404.png](/resources/9427c81e44163702264ade31b5d8e404.png)

For those who do not know what PEB is and why we have to find it, PEB holds information about the process's execution and it also provides direct, low-level access to crucial information about the process without needing to call higher-level API functions, which could be monitored or intercepted by security tools and since we have OfficeMalScanner which also comes with RTFScan so we will have to use it to retrieve offset of the PEB like this.

<details>
  <summary>Answer</summary>
<pre><code>0xcc</code></pre>
</details>

>Q13) Based on the intelligence gathered, which threat group was responsible for the cyberattack on Haunted Company Inc.? What is the name of the malware they used to compromise Tokyo's infrastructure? (Hint: OSINT!) (Format: Xxxxxx Xxxxx-XXXX, XxxxxXxxxxxx)

![d45388dc2985df0033f2097e3b603342.png](/resources/d45388dc2985df0033f2097e3b603342.png)

First, I searched rtf file hash on VirusTotal which reveals CVE related to this exploit and we can also see that there are a lot of community comments about this file.

![8c517f4853fd6ab813c111972a5e5552.png](/resources/8c517f4853fd6ab813c111972a5e5552.png)

Then we can see that this file is used by APT27.

![74d60370fed3f5c6315d30cc8c085ce1.png](/resources/74d60370fed3f5c6315d30cc8c085ce1.png)

And the webshell is also known as ChinaChopper.

![4efbc04541ed101fa6bf5a84d12a9ba2.png](/resources/4efbc04541ed101fa6bf5a84d12a9ba2.png)

Remember Adversary Analysis? APT27 also known as Threat-Group-3390 which used ChinaChopper (aspx file / webshell we found) as their tool.
<details>
  <summary>Answer</summary>
<pre><code>Threat Group-3390, ChinaChopper</code></pre>
</details>

>Q14) It seems the attacker leveraged a weakness in Tokyo's infrastructure. What is the latest CVE for this version that the threat actor exploited, and what type of attack was it? (Format: CVE-XXXX-XXXXX, XXX)

![cd428b15c337e67ebedd4ee3baca321f.png](/resources/cd428b15c337e67ebedd4ee3baca321f.png)

For this one, we have to take a look at this company's assets to find out which asset exposed to which latest CVE and it might has to be RCE one.

![7bcd5b747bd88f59aa9ca6c7ac6cdf4b.png](/resources/7bcd5b747bd88f59aa9ca6c7ac6cdf4b.png)

Then we can see that we have Apache Struts 2 and Microsoft Exchange for Application Servers.

![32131c336d5139ad6ce4ab744315e0c0.png](/resources/32131c336d5139ad6ce4ab744315e0c0.png)

Then we will see another Apache Struts 2 CVE for RCE discovered on 2023 that is the answer of this question.

<details>
  <summary>Answer</summary>
<pre><code>CVE-2023-50164, RCE</code></pre>
</details>

![de30a2fb86344d10130f4512ad6313bf.png](/resources/de30a2fb86344d10130f4512ad6313bf.png)
https://blueteamlabs.online/achievement/share/52929/242
* * *