# [Blue Team Labs Online - KikiPass](https://blueteamlabs.online/home/investigation/kikipass-7d6e11a95b)

![1fed4e899468358887aff87ddac87e55.png](/resources/1fed4e899468358887aff87ddac87e55.png)

One of our employees had all his social media accounts stolen, even though he was storing his passwords in a very secure place.

>Digital Forensics

>**Tags**: Volatility 3 Sysinternals Notepad++
* * *
**Scenario**
One of our employees had all his social media accounts stolen, even though he was storing his passwords in a very secure place with a hard-to-guess, complicated password. He doesn't know exactly what happened, so we took a dump of his memory. Your job is to figure out how that happened. (He has a suspicion that someone might have gained access to his office computer and tampered with some files.)
* * *
## Environment Awareness
### Evidence & Tools Discovery
![75223299473724eac084f7b3db0faa54.png](/resources/75223299473724eac084f7b3db0faa54.png)

Lets review what we got first, this machine provides us with volatility 3, Notepad++, CyberChef, Sysinternals suite and memory dump for investigation so lets jump right in.
***
## Investigation Submission
>Q1) What is the build number of the machine? (Format: XXXXXX)

![208bd0bf87b81105f031759a8465b54e.png](/resources/208bd0bf87b81105f031759a8465b54e.png)
Lets start with `windows.info` plugin which reveal system information and we can find build number of this system right here.
<details>
  <summary>Answer</summary>
<pre><code>17763</code></pre>
</details>

>Q2) What is the application name that is used to store passwords? (Format: filename.exe)

![f72b8d7470792c818a725a337e117e59.png](/resources/f72b8d7470792c818a725a337e117e59.png)
My guess would be KeePass but I still have to use `windows.pstree` just to make sure that it is indeed KeePass that was running on this machine during dumping process.
<details>
  <summary>Answer</summary>
<pre><code>KeePass.exe</code></pre>
</details>

>Q3) What is the version of the application? (Format: Version)

My first thought is to dump process and use `strings` to determine version of KeePass but KeePass should have config file that stores information including version number of installed version.

![2038ebad2c4d6340d69118be8e92fd59.png](/resources/2038ebad2c4d6340d69118be8e92fd59.png)

But I could not pipe output of `windows.filescan` plugin into a text file due to "charmap" codec can't encoded characters so I have to enable "Beta: Use Unicode UTF-8 for worldwide language support" right here then restart machine to make it work. 

![6fdaf096b69d93cfc9ec56f9736ea545.png](/resources/6fdaf096b69d93cfc9ec56f9736ea545.png)

Now after successfully piped output of `windows.filescan` plugin to text file then we could use Notepad++ to find all "KeePass" paths that we might want to look at and this config file is my first target to dump.

![394be509579ccedf7c00ab47dd24b95b.png](/resources/394be509579ccedf7c00ab47dd24b95b.png)

Dump it with `windows.dumpfiles` and I noticed that even if volatility yelling at me for an error but the file was still dumped nonetheless.

![e88fe86127208389f053be4f4135fd24.png](/resources/e88fe86127208389f053be4f4135fd24.png)

Open this file then we will have KeePass version as expected.

<details>
  <summary>Answer</summary>
<pre>2.53<code></code></pre>
</details>

>Q4) What is the CVE number that is associated with that version? (Format: CVE-XXXX-XXXXX)

![f8546a8392fa10150b5cd2020eec200d.png](/resources/f8546a8392fa10150b5cd2020eec200d.png)

After searching for this version on Google, the top result is the [PoC of CVE-2023-24055](https://github.com/alt3kx/CVE-2023-24055_PoC) that could let an attacker to obtain cleartext password since KeePass configuration file can be modified in a default installation.

<details>
  <summary>Answer</summary>
<pre><code>CVE-2023-24055</code></pre>
</details>

>Q5) What is the full path of the file that is vulnerable? (Format: C:\path\to\vulnerable\file.extension)

![6b254d14cff73367eddd07ae340abf7a.png](/resources/6b254d14cff73367eddd07ae340abf7a.png)
Lets take a look at this PoC then we will have a path to look out in filescan text file.

![5587a021b8003fa3e3537017a3bc2651.png](/resources/5587a021b8003fa3e3537017a3bc2651.png)

We got 2 xml config file in total but the one that allowed an attacker to exploit this CVE is this path.

<details>
  <summary>Answer</summary>
<pre><code>C:\Users\Administrator\AppData\Roaming\KeePass\KeePass.config.xml</code></pre>
</details>

>Q6) What is the name of the trigger that is being used by the attacker? (format: String)

![9326949bed8958ca579712898f847ddf.png](/resources/9326949bed8958ca579712898f847ddf.png)

We got virtual address of writable xml config file then lets dump it out.

![699cd7d2e182a577b8aa1ee33297924b.png](/resources/699cd7d2e182a577b8aa1ee33297924b.png)
Then we will find trigger name right here.
<details>
  <summary>Answer</summary>
<pre><code>test</code></pre>
</details>

>Q7) What is the full URI and method that the attacker used in the malicious command? (Format: URI, Method)

![430a6786db74897722bdf9b2205680c8.png](/resources/430a6786db74897722bdf9b2205680c8.png)
Scrolling down to line 71 then we could see that after victim open keepass database and doing some activities then this PowerShell command will be executed and it will exfiltrate cleartext password stores in tmp file to C2 server using HTTP GET method
<details>
  <summary>Answer</summary>
<pre><code>http://172.22.170.17:8000/$var,GET</code></pre>
</details>

>Q8) What is the exact time that this malicious command was executed? (Format: MM-DD-YYYY HH:MM:SS XX)

![b0f48af659f06161451dcddfed36c38e.png](/resources/b0f48af659f06161451dcddfed36c38e.png)

I found PowerShell event log is available for dump so I dumped it.

![d07e34be3d9d35a35a61f9d472bedf0d.png](/resources/d07e34be3d9d35a35a61f9d472bedf0d.png)
Open it then we can see the timestamp that PowerShell command was executed resulting in exfiltration of cleartext password.
<details>
  <summary>Answer</summary>
<pre><code>12-31-2023 11:33:02 AM</code></pre>
</details>

>Q9) What is the username and password of the victim on Facebook? (Format: username, password)

![16f17f9227e2ec1f929a971e085f0664.png](/resources/16f17f9227e2ec1f929a971e085f0664.png)

Lets get virtual address of tmp file that stores cleartext password then dump it.

![a11689393c9fbc73e5f50063d4c3cfaa.png](/resources/a11689393c9fbc73e5f50063d4c3cfaa.png)
![996a7f1ee84d91843bd2820f80f466ed.png](/resources/996a7f1ee84d91843bd2820f80f466ed.png)

After dumping this file out then we can see both username and password in cleartext stores in this file as expected and here is the Facebook credential. 
<details>
  <summary>Answer</summary>
<pre><code>a1l4m, facebookPASSWORD1!</code></pre>
</details>

>Q10) How many credentials does the attacker get access to? (Format: Number)

![a8e91546211c7caedf8204a24eae25fe.png](/resources/a8e91546211c7caedf8204a24eae25fe.png)
I filtered for "ProtectInMemory" which returned with 6 hits but the last 2 hits are KeePass sample password so we will have 4 credentials at the end (Facebook,Instagram,LinkedIn,CIA).
<details>
  <summary>Answer</summary>
<pre><code>4</code></pre>
</details>

![3587b71c204e32d3b227536cb93db133.png](/resources/3587b71c204e32d3b227536cb93db133.png)
https://blueteamlabs.online/achievement/share/52929/193
* * *