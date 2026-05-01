# [Blue Team Labs Online - Indicators](https://blueteamlabs.online/home/investigation/indicators-3e65f599bd)

![e23da040d106902b9b4471cc61c8fc8e.png](/resources/e23da040d106902b9b4471cc61c8fc8e.png)

>Digital Forensics

>**Tags**: PowerShell Text Editor Exiftool MalwareBazaar VirusTotal BTL1 T1105
* * *
**Scenario**
A suspicious file was found on one of our servers. Use your technical analysis skills to retrieve various indicators that can be used for hunting.
* * *
## Environment Awareness
### Evidence & Tool Discovery
![60bba1fd651514aa546b25ddcf3703cd.png](/resources/60bba1fd651514aa546b25ddcf3703cd.png)

We have a sample file inside `Retrieved Sample` folder located on the desktop which we only have CyberChef and Exiftool available for us 

***
## Investigation
>Q1) What is the filename and file syze in KB? (Format: filename, sizeinKB)

![c75a02030d22d1ced151a48aea230d84.png](/resources/c75a02030d22d1ced151a48aea230d84.png)

To get an answer of this question, we can right click on the sample and select "properties" to open file properties window which we can see some information about the sample including file size of this file right here.

<details>
  <summary>Answer</summary>
<pre><code>sh4, 98.6</code></pre>
</details>

>Q2) Using exiftool, what is the file type? (Format: filetype) 

![93d6ee441b90fa2049e4fd19106764a6.png](/resources/93d6ee441b90fa2049e4fd19106764a6.png)

open cmd or PowerShell from exiftool folder or we can copy exiftool executble to `Retrieved Sample` folder for easy usage but ultimately, we will have to execute it on the sample which reveal the actual file type of this file which is ELF executable which is an executable file that can be executed on Linux.

<details>
  <summary>Answer</summary>
<pre><code>ELF executable</code></pre>
</details>

>Q3) Using exiftool, what is the CPU architecture and CPU type? (Format: CPU Arch, CPUType)

![10dbcbeaa97715e18b2e6e4f2a845a92.png](/resources/10dbcbeaa97715e18b2e6e4f2a845a92.png)

exiftool also provides us with additional information such as CPU architecture and CPU Type of a system that compiled this executable file.

<details>
  <summary>Answer</summary>
<pre><code>32 bit, SuperH</code></pre>
</details>

>Q4) Research Zone Identifiers and PowerShell's Get-Content cmdlet. Using this we can find out the exact URL this file was downloaded to the system from. Submit the full URL (Format: https://domainOrIP/resource)

![d0574cf94638a24bed0b5c9d6528ad4f.png](/resources/d0574cf94638a24bed0b5c9d6528ad4f.png)

To retrieve the content of Zone.Identifier, we can use `Get-Content -Path .\sh4:Zone.Identifier` which reveal that this file was downloaded from internet which was hosted on this website
<details>
  <summary>Answer</summary>
<pre><code>http://2.56.57.49/sh4</code></pre>
</details>

>Q5) Retrieve the SHA256 hash of the malicious file, submit the first 5 characters (Format: XXXXX)

![9202fdb976325e894dc2f1675904d671.png](/resources/9202fdb976325e894dc2f1675904d671.png)

Since we already launched PowerShell then we can continue to calculate file hash with `Get-FileHash` cmdlet like this

<details>
  <summary>Answer</summary>
<pre><code>11B73</code></pre>
</details>

>Q6) Using the hash value, on your host system search for the full hash on MalwareBazaar. How many YARA rules have triggered on this sample? (Format: X)

![3ad423bfabc62d96ea91d128d0343b59.png](/resources/3ad423bfabc62d96ea91d128d0343b59.png)

Use SHA256 we just obtained to browse for sample on [MalwareBazaar](https://bazaar.abuse.ch/browse.php?search=sha256%3A11b73397473aa2786d4f1e0a556f557cfe2729b194a3e64d38e245428198be56) database like this which reveal that this file is actually Mirai botnet (Q7)

![350e4d769b637af7dd8c2ecc633d55db.png](/resources/350e4d769b637af7dd8c2ecc633d55db.png)

Visit this database entry then we can see that there are total of 6 YARA rules that matched this sample. 

<details>
  <summary>Answer</summary>
<pre><code>6</code></pre>
</details>

>Q7) Using the hash value, on your host system search for the full hash on VirusTotal. Based on the detections page, some vendors are flagging this file as it is related to a botnet. What is the name of the botnet? (Format: BotnetName)

![e3a154985dc6c69f534c83604324f3f9.png](/resources/e3a154985dc6c69f534c83604324f3f9.png)

additionally, we can also search sample file hash on VirusTotal and its also return the same result that this sample is a Miral botnet
<details>
  <summary>Answer</summary>
<pre><code>Mirai</code></pre>
</details>

>Q8) Open the sample using Notepad.exe. How many unique User-Agent values are found? (Format: X)

![39776cd98c50a26373fcf30e16c4e7c7.png](/resources/39776cd98c50a26373fcf30e16c4e7c7.png)

We can use CyberChef with RegEx like this `^.*User-Agent.*$` combines with unique to display total of 8 unique User-Agent value from this sample
<details>
  <summary>Answer</summary>
<pre><code>8</code></pre>
</details>

>Q9) Still using Notepad, an IP address is referenced multiple times with different files being hosted. Search for 'http://IPHERE' on VirusTotal and look at the Details page (if it is not shown here, try other sites such as Shodan). What is the server framework in use? (Format: Framework)

![de19af4ef3c2414c4f0c42197c4fcb0d.png](/resources/de19af4ef3c2414c4f0c42197c4fcb0d.png)

We can use Extract IP Addresses recipe to automatically extract IP addresses from the sample which we can see that beside an IP address we found on Q4, there is other IP address that we need to check up.

![7337d115f84cdf625ebe7d6ed01b19ba.png](/resources/7337d115f84cdf625ebe7d6ed01b19ba.png)

By utilizing VirusTotal, we can see that this server was using Apache to host the website.

<details>
  <summary>Answer</summary>
<pre><code>Apache</code></pre>
</details>

>Q10) Still using Notepad, one GET request references a domain name instead of the IP. What is the domain name and the file it's hosting? (Format: sub.domain.tld/file) 

![d50aafe9498249d0cecbc7d8d9de96b5.png](/resources/d50aafe9498249d0cecbc7d8d9de96b5.png)

Lets remove all the recipe and just search for GET request which we can see that there is one domain that will be requested by this sample to retrieve `arm7` file and execute it

<details>
  <summary>Answer</summary>
<pre><code>a.tigoinari.tk/arm7</code></pre>
</details>

>Q11) What command is being executed after downloading a file to make it executable? (Format: Command)

![68f977a5ba72721c4ec3f8984179bd15.png](/resources/68f977a5ba72721c4ec3f8984179bd15.png)

But before this file can be executed, it will need to grant with execute permission but this sample will grant it with 777 with is full read-write-execute for all users and all groups
<details>
  <summary>Answer</summary>
<pre><code>chmod 777</code></pre>
</details>

>Q12) What folder is the actor storing file downloads in? (Format: /folder/)

![dc828247f2cb0f1acc73999b3e1a9f51.png](/resources/dc828247f2cb0f1acc73999b3e1a9f51.png)

From Q10, we can see that the downloaded file will be stored in `/tmp` then execute it

<details>
  <summary>Answer</summary>
<pre><code>/tmp/</code></pre>
</details>

![e133f9c588ea0f741e8657db939111e7.png](/resources/e133f9c588ea0f741e8657db939111e7.png)
https://blueteamlabs.online/achievement/share/52929/104
* * *
## IOCs
- `11b73397473aa2786d4f1e0a556f557cfe2729b194a3e64d38e245428198be56`
- `2[.]56[.]57[.]49`
- `188[.]166[.]41[.]194`
- `a[.]tigoinari[.]tk`

* * *