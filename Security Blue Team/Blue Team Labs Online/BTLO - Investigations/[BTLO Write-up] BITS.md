# [Blue Team Labs Online - BITS](https://blueteamlabs.online/home/investigation/bits-0a4e5c7f01)

![3df5b8c92913501461e5d897e18b9a5b.png](/resources/3df5b8c92913501461e5d897e18b9a5b.png)

Using BitsParser from FireEye to retrieve BITS jobs, can you help the SOC identify persistence actions conducted on a compromised host?

>**Incident Response**

>**Tags**: BitsParser CMD Sublime Text T1197
* * *
**Scenario**
Using BitsParser from FireEye to retrieve BITS jobs, can you help the SOC identify persistence actions conducted on a compromised host?

Reading Material:
[FireEye Blog Post](https://www.mandiant.com/resources/attacker-use-of-windows-background-intelligent-transfer-service)
[BitsParser GitHub Page](https://github.com/fireeye/BitsParser)
* * *
## Environment Awareness
### Evidence & Tool Discovery
![e8f385328b5f4d793166d2525e8ddec5.png](/resources/e8f385328b5f4d793166d2525e8ddec5.png)

We have tool needed for this investigation ready inside `Investigation` folder located on the Desktop and the tool that we will have to use is BitsParser which can parse BitsAdmin artifacts from Windows system, and since there is no other artifacts provides then it mean we have to parse BitsAdmin artifacts from the investigation machine directly

Note that we also have CyberChef and Sublime text so if you are comfortable with sublime text when analyzing text/json file then you can open the output of BitsParser using sublime text

***
## Investigation
>Q1) A popular GitHub Repo for Windows privilege escalation is WinPEAS. Can you find any file downloads for winPEAS.bat in the BitsParser output? What is the associated job name? (Format: BITSJobName)

![494346b01b55e4c17106afc23d231d2b.png](/resources/494346b01b55e4c17106afc23d231d2b.png)

To start BitsParser, we can just simply run `python BitsParser.py` which will automatically parsed bitsadmin artifacts with default settings (if you have `%ALLUSERSPROFILE%\Microsoft\Network\Downloader` collected from other machine then you might need to use `-i` for that)

But look like we got a little bit of Syntax warning here

![48362382637375c99b6b7083a1cb1425.png](/resources/48362382637375c99b6b7083a1cb1425.png)

To fix this, open the script and edit this line of code from `is not` to `!=`

![bd945b50eae1b2b1434ba551df6d6c7a.png](/resources/bd945b50eae1b2b1434ba551df6d6c7a.png)

Now to carve all deleted records too then we have to use `python BitsParser.py --carveall > bits.json` then we should have `bits.json` ready to be analyzed

![2b8543ed8853ab05af6724a898f73a80.png](/resources/2b8543ed8853ab05af6724a898f73a80.png)

Open an output file in any text editor you preferred then search for winpeas which you can see that there are more than 1 Job that related to the string "winPEAS"

![a9105262d77547fb0d19429301208999.png](/resources/a9105262d77547fb0d19429301208999.png)

Then we can see the jobname that responsible for downloading `winPEAS.bat` file right here.

![313adda102520b5512d3fb19bc254dd7.png](/resources/313adda102520b5512d3fb19bc254dd7.png)

Alternatively to BitsParser, Windows also logged BitsAdmin event under "Applications and Services" -> "Microsoft" -> "Bits-Client" and we can also find the same result from this log.
<details>
  <summary>Answer</summary>
<pre><code>privesctools</code></pre>
</details>

>Q2) What is the Creation Time of this job? (Format: YYYY-MM-DDTHH:MM:SSZ)

![29bd5e4e73aca2a388ec60e06c17ec3d.png](/resources/29bd5e4e73aca2a388ec60e06c17ec3d.png)

You can find the Creation time of this job right here. (its already parsed)

<details>
  <summary>Answer</summary>
<pre><code>2022-01-07T13:32:19Z</code></pre>
</details>

>Q3) BITS can be used to download files from other systems. What is the IP address that originally hosted the file downloaded to the victim machine? (Format: X.X.X.X)

![62f77702657c8813fffa80d36292062f.png](/resources/62f77702657c8813fffa80d36292062f.png)

From the "SourceURL", we can see that this file was hosted from the other machine inside the internal network.

<details>
  <summary>Answer</summary>
<pre><code>10.0.12.228</code></pre>
</details>

>Q4) What is the folder and filename used when this file was downloaded to the victim machine? (Format: \\folder\\file.extension)

![e9cf5970c329d69bc8ee5342a01263fe.png](/resources/e9cf5970c329d69bc8ee5342a01263fe.png)

We can check "DestFile" for this which is the destination file path of this job once it successfully downloaded.

<details>
  <summary>Answer</summary>
<pre><code>\\Music\\WindowsUpdater.bat</code></pre>
</details>

>Q5) Is there any evidence of other files that include the string "winPEAS"? What is the original filename? Make sure the DownloadByteSize or TransferByteSize is greater than 0 to identify a successful download/transfer. (Format: filename.extension)

![7f5adaec8d07b41d17130928f11332de.png](/resources/7f5adaec8d07b41d17130928f11332de.png)

Beside bat file and zip file we just found earlier, there is also an executable file that was downloaded using BitsAdmin which is a compiled winPEAS executable for 64-bit system. 

<details>
  <summary>Answer</summary>
<pre><code>winPEASx64.exe</code></pre>
</details>

>Q6) What is the folder and filename used when this second file was downloaded to the victim machine? (Format: \\folder\\file.extension)

![5f79565b043bdd8357602f085e8ee197.png](/resources/5f79565b043bdd8357602f085e8ee197.png)

Check "DestFile" for this.

<details>
  <summary>Answer</summary>
<pre><code>\\Music\\WindowsUpdater.exe</code></pre>
</details>

>Q7) What is the file size in bytes of this file? (Hint: Look at the DownloadByteSize or TransferByteSize)

![f891324402706972697f1a350aa5bde2.png](/resources/f891324402706972697f1a350aa5bde2.png)

<details>
  <summary>Answer</summary>
<pre><code>1930752</code></pre>
</details>

>Q8) The SOC saw network connections to Github in the web proxy. What is the username of the account doing this, and what is the attempted source URL? (Format: Username, https://sourceurl.tld/path)

![32d817535472f119ef9b55a0096cf207.png](/resources/32d817535472f119ef9b55a0096cf207.png)

We can search for "github" string which leads us to whole PEASS-ng main branch being downloaded by BTLO user
<details>
  <summary>Answer</summary>
<pre><code>BTLO, https://github.com/carlospolop/PEASS-ng/archive/refs/heads/master.zip</code></pre>
</details>

![3f5a199b02609d6665476e689a15cf10.png](/resources/3f5a199b02609d6665476e689a15cf10.png)
https://blueteamlabs.online/achievement/share/52929/33
* * *