# [Blue Team Labs Online - 1down](https://blueteamlabs.online/home/investigation/1down-7c5cdf8988)

![ab713dfefd055d51c662ffc7a7ce2760.png](/resources/ab713dfefd055d51c662ffc7a7ce2760.png)

Onenote files were being used as a new way of malware delivery. On a Friday evening, the malware analysis team received two samples for analysis and asked for an IOC report.

>**Reverse Engineering**

>**Tags**: OnenoteAnalyzer CyberChef Text Editor DecoderTool T1587.001
* * *
**Scenario**
Onenote files were being used as a new way of malware delivery. On a Friday evening, the malware analysis team received two samples for analysis and asked for an IOC report. Sample1 was assigned to you and Sample2 was partially analyzed and provided with some helpful tool to proceed with further analysis. Now it’s your duty to work on both the samples.

Note: Samples were placed on Desktop. S1 means Sample1 and S2 means Sample2
* * *
## Environment Awareness
### Evidence & Tool Discovery
![1b6a7dc686b523b7fa3db3ed0b198cef.png](/resources/1b6a7dc686b523b7fa3db3ed0b198cef.png)

There are 2 folders inside `Samples` folder located on the desktop which we can see that `s1` folder it contains a single OneNote file while `s2` folder contains files and folders that extracted from OneNote file by OneNoteAnalyser and also `scrdec18-VC8.exe` which is a Windows Script Decoder that can be used to decode JScript

***
## Investigation
>Q1) S1: Submit the creation date of the sample (Format: DD-MM-YYYY)

![f76eccf935eaf855a19364a14f4f943f.png](/resources/f76eccf935eaf855a19364a14f4f943f.png)

We can easily do this by right click on sample 1 and select "Properties" to display properties of this file which also included Created timestamp of this file

![3f67c15af77f2f230535820cb99e7609.png](/resources/3f67c15af77f2f230535820cb99e7609.png)

Alternatively, we can use `OneNoteAnalyzer` to parse OneNote file like this which will also extract metadata of this file such as Title, Author(Q2), Creation and last modified timestamp

This tool not just extracting metadata from OneNote file but also extracted images, text, hyperlinks and attachments which we will have to analyze them on Q3

<details>
  <summary>Answer</summary>
<pre><code>23-02-2023</code></pre>
</details>

>Q2) S1: Submit the author name of the sample (Format: Author Name)

![3f67c15af77f2f230535820cb99e7609.png](/resources/3f67c15af77f2f230535820cb99e7609.png)
<details>
  <summary>Answer</summary>
<pre><code>Cysec Humans</code></pre>
</details>

>Q3) S1: Submit the extension of the files that were embedded in onenote that were responsible to download an additional payload (Format: .extension)

![63fa4967efac7c53ba9b63dcdbf32c0d.png](/resources/63fa4967efac7c53ba9b63dcdbf32c0d.png)

We got quite a few attachments that were extracted from sample 1 but all of them are HTA file which is also a popular extension that could be used to execute arbitrary system command via VBscript

<details>
  <summary>Answer</summary>
<pre><code>.hta</code></pre>
</details>

>Q4) S1: Submit the name of the scripting language used in embedded files to download additional files (Format: ScriptingLanguageName)

![c7b8a1ab828d325bb6889e03ff21593c.png](/resources/c7b8a1ab828d325bb6889e03ff21593c.png)

Before analyzing these HTA files, lets confirm something with a little bit of checksum which we can see that these 8 files have the same identical hash which mean they are the same file

![aab1ec6232bc1b78c3b3d928342c5439.png](/resources/aab1ec6232bc1b78c3b3d928342c5439.png)

After open this file, we can see that VBscript is utilized to execute system command as we suspected.

<details>
  <summary>Answer</summary>
<pre><code>vbscript</code></pre>
</details>

>Q5) S1: Above script tries to download 2 additional files. Submit the filenames after download (Format: filename1.ext, filename2.ext)

![d37c77c1fca713fc03847a2f2354fd58.png](/resources/d37c77c1fca713fc03847a2f2354fd58.png)

We can see that once user open OneNote file, it will trigger PowerShell command to download additional payloads from C2 server (Q6) and executed them 
<details>
  <summary>Answer</summary>
<pre><code>invoicebyceo.one, services.bat</code></pre>
</details>

>Q6) S1: Network team requested to submit the domain that is hosting the malicious files. Submit the domain (Format: https://domain.tld)

![bbcc79f01f4cadd91ce3b80af1baad96.png](/resources/bbcc79f01f4cadd91ce3b80af1baad96.png)
<details>
  <summary>Answer</summary>
<pre><code>https://qcbicholasjaurcx.ca/</code></pre>
</details>

>Q7) S2: Submit the name of the embedded file responsible to download additional files (Format: filename.ext)

![9fae9ef0769bb3717d939c9f81df9c88.png](/resources/9fae9ef0769bb3717d939c9f81df9c88.png)

Since we do not need to extract anything then we can jump to attachment folder directly then we can see that this file is likely to download additional file but we need to confirm that first  

![c7571b6577ddf3652a3ab53d272effc7.png](/resources/c7571b6577ddf3652a3ab53d272effc7.png)

We do not need to use Helpful decoder tool that BTLO team provides us since we can just use CyberChef to decode it

![26659114486cf7b3cf38c3176497f2f3.png](/resources/26659114486cf7b3cf38c3176497f2f3.png)

Which we can see that it will create bat script from whatever these hexadecimal decode to

![5a28698cebfc94ea57eb9c6be58cf4de.png](/resources/5a28698cebfc94ea57eb9c6be58cf4de.png)

After convert it to ASCII, we can see that it will use PowerShell to download additional file from C2 server (Q8 & Q9), execute it then remove it once it successfully executed

<details>
  <summary>Answer</summary>
<pre><code>Open.jse</code></pre>
</details>

>Q8) S2: Submit the full URI responsible o download additional malware (Format: http://X.X.X.X/path/filename.ext)

![5a28698cebfc94ea57eb9c6be58cf4de.png](/resources/5a28698cebfc94ea57eb9c6be58cf4de.png)
<details>
  <summary>Answer</summary>
<pre><code>http://105.211.3.34/FAZ/270331.gif</code></pre>
</details>

>Q9) S2: Submit the filename of the file after downloading onto the PC from above URI (Format: filename.ext)
<details>
  <summary>Answer</summary>
<pre><code>bTFzQLdki.tmp</code></pre>
</details>

![976c177f128a3e08b5b9470e61a91804.png](/resources/976c177f128a3e08b5b9470e61a91804.png)
https://blueteamlabs.online/achievement/share/52929/137
* * *
## Summary
On this investigation, we analyzed 2 malicious onenote samples that embedded with hta and jse files with will download additional payloads from C2 server and executed them.

### IOCs
- `05bc6720d42960a922ad97de4e7207e0901aa80162f85094c4aa1faf940d5579` (SHA256 of sample 1)
- `4304a3393a62dc65ac1af5829e665abbdd037fd7df040fcc5b18bb4dbb87eeaf` (SHA256 of hta attachment)
- `2700f979a9130272a5d21a35533a9b41d20681eba19b1ccb659582a54f724d42` (SHA256 of jse attachment)
- `qcbicholasjaurcx[.]ca`
- `105[.]211[.]3[.]34`

* * *