# [Blue Team Labs Online - Beacon](https://blueteamlabs.online/home/investigation/beacon-8efaf9028c)

![a4e1f954e2b3dbf4327e852d2f3664b1.png](/resources/a4e1f954e2b3dbf4327e852d2f3664b1.png)

>Incident Response

>**Tags**: CyberChef Oledump Cobalt Strike Configuration Extractor and Parser Verify Cobalt Strike Python3.7 Linux CLI
* * *
**Scenario**
Our payments department has received a suspicious Excel document. Analyse the file to identify and retrieve any indicators of compromise for threat hunting.
* * *
## Environment Awareness
### Evidence & Tools Discovery
![e2592c91deaa3b38ad564ce710221d81.png](/resources/e2592c91deaa3b38ad564ce710221d81.png)

We got excel document in malware directory and tools that we could use in tools directory and looking from these tools, we will have to use oledump to identify malicious macro/payload inside excel document then use `getshellcode.py` to extract payload from it then use Cobalt Strike Configuration Extrator to find out about configuration of that payload so the payload that we gonna analyze is Cobalt Strike beacon!
***
## Investigation
>Q1) What is the SHA-256 file hash value of the Excel document? (Format: SHA256)

![9ecce571b7d66506b74add669ec792b5.png](/resources/9ecce571b7d66506b74add669ec792b5.png)

First to finish this question, lets calculate SHA256 hash of excel document.

<details>
  <summary>Answer</summary>
<pre><code>01dac009a652c9f592a6ea6003daaa2e198b4761240a89af5b5bf80d737e2e25</code></pre>
</details>

>Q2) What are the streams which contain VBA macros (list lowest to highest)? (Format: stream, stream, stream)

![3f4a6ad9048ff9a3d543f3ac8d9232b5.png](/resources/3f4a6ad9048ff9a3d543f3ac8d9232b5.png)

After executing `python oledump.py invoice.xlsm` (I moved it to Tools directory) then we should be able to see that there are 3 macros on this document as indicated by M (stand for Macro) sign.

![1ff10820859160904185afaf644fe24a.png](/resources/1ff10820859160904185afaf644fe24a.png)

We could dig a little bit futher by identify each stream with `-s $stream -v` then we could see that malicious payload is in stream 4.

![bd5f287ebd64e157ef1c2ac34ee569f7.png](/resources/bd5f287ebd64e157ef1c2ac34ee569f7.png)
The payload is base64 encoded that stores in 47 `Invoices` functions and it will be concatenate to `sInvoices` and pass to `Invoices` variable at the end of the function.

![4eb9dcbdf6736bb5afcf2aea1a8bd7d8.png](/resources/4eb9dcbdf6736bb5afcf2aea1a8bd7d8.png)

stream 3 is just containing text in `Mergers` function so I didn't take a screenshot but stream 6

Be careful when submit answer, we know that object 3, 4 and 6 contain macros but it has to be perfectly matched answer format (unlike newer lab on BTLO that will just accept whatever format as long as we put the right value)

<details>
  <summary>Answer</summary>
<pre><code>A3, A4, A6</code></pre>
</details>

>Q3) What is the name of the Excel code module which contains the encoded strings? (Format: ModuleName)

![1bf134f5a5dc8acf69e27cf0b4038d56.png](/resources/1bf134f5a5dc8acf69e27cf0b4038d56.png)
We already confirmed that base64 encoded payload is in stream 4 so lets get module name of this stream.
<details>
  <summary>Answer</summary>
<pre><code>Receivables</code></pre>
</details>

>Q4) What is the extracted payload's SHA-256 file hash value? (Format: SHA256)

Its time for `getshellcode.py` but before we executed, we have to know what it does first!

![63ac06c21a945db2d390998f98b568f4.png](/resources/63ac06c21a945db2d390998f98b568f4.png)

So it will get all base64 encoded string with regex specify for provided excel document and we have to specify an output file to store extracted payload. 

![5dc04f95ac070ee0d0c06032a414016f.png](/resources/5dc04f95ac070ee0d0c06032a414016f.png)
After extracted base64 encoded payload then we can use `cat  base64_payload | base -d > payload` to get the actual payload and calculate SHA256 hash out of it (you might get base64: invalid input error but the operation will be success nontheless)
<details>
  <summary>Answer</summary>
<pre><code>fe143d2a4e74094c076bd72bd144ee1cfb4764bb62545a252113bff470011123</code></pre>
</details>

>Q5) Check the file hash on VirusTotal. What command-and-control framework is this shellcode for? (Format: C2 Name)

![5d39f02165d8737f42b5475b261c59d5.png](/resources/5d39f02165d8737f42b5475b261c59d5.png)
We already know that we will analyze Cobalt Strike beacon so the answer is not that hard to obtain for this one 😄
<details>
  <summary>Answer</summary>
<pre><code>cobalt strike</code></pre>
</details>

>Q6) Using available tools determine what is the beacon type? (Format: beacontype)

![93b043e632959357affe0bad34643a02.png](/resources/93b043e632959357affe0bad34643a02.png)
Lets use Cobalt Strike Configuration Extractor to extract cobalt strike configuration of this payload then we will have this beautify output as json like this and the answer of this question is the first key of this output (this machine doesn't have jq so I'll use this image for the rest of remaining questions)
<details>
  <summary>Answer</summary>
<pre><code>HTTPS</code></pre>
</details>

>Q7) What is the domain and the port the beacon communicates to? (Format: domain.tld, port)

![47477f376af431efd401b27c03a4cb98.png](/resources/47477f376af431efd401b27c03a4cb98.png)
Hostname and port stores these information, you can also get the answer of this question by analyzing VirusTotal report too.
<details>
  <summary>Answer</summary>
<pre><code>aicsoftware.com, 757</code></pre>
</details>

>Q8) What is the sleeptime and jitter values of the beacon? (Format: sleeptime, jitter)

![cdd8e194ae5c93297c7d0da747bcc00e.png](/resources/cdd8e194ae5c93297c7d0da747bcc00e.png)
<details>
  <summary>Answer</summary>
<pre><code>62518, 37</code></pre>
</details>

>Q9) What is the license id? (Format: license_id)

![f7a85cb95f96733e048e972b3cef2e23.png](/resources/f7a85cb95f96733e048e972b3cef2e23.png)
<details>
  <summary>Answer</summary>
<pre><code>305419776</code></pre>
</details>

>Q10) Identify the software version? (hint: use the MD5 hash of the stub value) (Format: Full name including version number and date. Hint: copy the line in front of the #)

![df6b5af1cf2d185c23f02e1cc26a5d10.png](/resources/df6b5af1cf2d185c23f02e1cc26a5d10.png)

To find out Cobalt Strike version that generated this beacon, We gonna follow this [url](https://www.elastic.co/security-labs/extracting-cobalt-strike-beacon-configurations) to get SHA256 hash of cobalt strike jar and search it on verify.cobaltstrike.com

![33565794ef2d073dc929d0c0d862fcc7.png](/resources/33565794ef2d073dc929d0c0d862fcc7.png)

Alright, first we need to get stub field content

![502f0262e74a78f644f22251afc1b9a1.png](/resources/502f0262e74a78f644f22251afc1b9a1.png)

base64 decode then convert it to hex without delimiter then we will get MD5 hash of cobalt strike jar file

![b5f01f2fd648b14d39896e149324332d.png](/resources/b5f01f2fd648b14d39896e149324332d.png)

Search it on VirusTotal then we will have SHA256 of this file.

![4a6688e541e000334bbc1384b483ea0e.png](/resources/4a6688e541e000334bbc1384b483ea0e.png)

And lastly, search it on https://verify.cobaltstrike.com/ to get software version including released date.

<details>
  <summary>Answer</summary>
<pre><code>Cobalt Strike 4.2 (November 6, 2020)</code></pre>
</details>

![2157435493b9eed51920f50d11a3c5ea.png](/resources/2157435493b9eed51920f50d11a3c5ea.png)
https://blueteamlabs.online/achievement/share/52929/174
* * *