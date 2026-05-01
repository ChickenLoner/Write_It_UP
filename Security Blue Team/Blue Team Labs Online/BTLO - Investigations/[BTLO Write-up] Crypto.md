# [Blue Team Labs Online - Crypto](https://blueteamlabs.online/home/investigation/crypto-a198b21c7a)

![2cbe343e7431b13e57be3b1ae810903c.png](/resources/2cbe343e7431b13e57be3b1ae810903c.png)

After a number of Windows servers saw a large CPU spike, can you identify what's happened based on a suspicious PowerShell script found on each system?

>Incident Response

>**Tags**: Wireshark PowerShell Analysis Volatility Grep T1053.005 T1496 T1059.004
* * *
**Scenario**
After a number of Windows servers saw a large CPU spike, can you identify what's happened based on a suspicious PowerShell script found on each system?

You have been provided with the script, a PCAP from one of the affected servers, and a memory dump.

The Volatility profile needed is Win10x64_17134.
* * *
## Investigation Submission
>Q1) What is the IP address of the malicious server? (Format: X.X.X.X)

![1d1eed57e4742a5ea7b7ad9052094df3.png](/resources/1d1eed57e4742a5ea7b7ad9052094df3.png)

We have memory dump, pcapng file and a powershell script to be analyzed but since this question is asking for IP address of malicious server that mean we have to start with pcapng file.

![5bac9e68100b8dc008e5a1cebe0ec99c.png](/resources/5bac9e68100b8dc008e5a1cebe0ec99c.png)

next I went to "File" -> "Export" -> "HTTP..." since I expected malicious server to host something and victim system downloaded and executed it which I found this exe file quite interesting.

![ef7fcbc7d0a282e4218a3e4b0bd01127.png](/resources/ef7fcbc7d0a282e4218a3e4b0bd01127.png)

And this public IP address is the correct answer of this question, so we got the right file for Q2 too!
<details>
  <summary>Answer</summary>
<pre><code>80.71.158.96</code></pre>
</details>

>Q2) The script downloads an executable from this malicious IP, what is the name of it? (Format: filename.extension)
<details>
  <summary>Answer</summary>
<pre><code>wxm.exe</code></pre>
</details>

>Q3) Where are the executables files stored, and what are they renamed to? (Format: folder\file.ext, folder\file.ext)

Its time to analyze PowerShell script that share the same name as malicious executable file.

![e16b3a5eb9a8d5d25b5cf7b79fdb7209.png](/resources/e16b3a5eb9a8d5d25b5cf7b79fdb7209.png)

Then after reading this script ,we can see that this script is likely responsible for the traffic on Q1 which will download malicious PE from Q2 to this AppData and Temp directories and we can also see it executes exe from Temp directory which these weird parameters and make a file in AppData persistence by creating a task and add it to run key. 

<details>
  <summary>Answer</summary>
<pre><code>AppData\network02.exe, TMP\network02.exe</code></pre>
</details>

>Q4) What are the names of any scheduled tasks created for persistence? (Format: Name1, Name2)

![9ceee5f248cfbdd0697c29ccfaf1ee75.png](/resources/9ceee5f248cfbdd0697c29ccfaf1ee75.png)

Look like there is not just 1 but 2 task for both files and they will be executed every minute.
<details>
  <summary>Answer</summary>
<pre><code>BrowserUpdate, Browser2Update</code></pre>
</details>

>Q5) Research XMRig command-line options. What is the username and password used by the attacker? (Format: username, password) 

![6e3cddd6820d04efe2aca4828a7e6174.png](/resources/6e3cddd6820d04efe2aca4828a7e6174.png)

We can read the documentation of [XMRig](https://xmrig.com/docs/miner/command-line-options) to understand what happened so the file that was downloaded is XMRig and we can see that -u and -p are used to specify username and password for mining server.

![57d0d9e6e349dcb5e445b7e4f8c64c24.png](/resources/57d0d9e6e349dcb5e445b7e4f8c64c24.png)

Then we will have both values right here.

<details>
  <summary>Answer</summary>
<pre><code>46E9UkTFqALXNh2mSbA7WGDoa2i6h4WVgUgPVdT9ZdtweLRvAhWmbvuY1dhEmfjHbsavKXo3eGf5ZRb4qJzFXLVHGYH4moQ, x</code></pre>
</details>

>Q6) To prevent outbound connections, other than the malicious server, what IPs or URLs should be blocked? (Don’t include ports, and list them in the order they appear) (Format: address, address...)

![3669b159a2ba9be80b596bddefd1ecf9.png](/resources/3669b159a2ba9be80b596bddefd1ecf9.png)

From XMRig documentation, we can see that -o is used to specify URL of mining server.

![a9ada2c3047ecb467ace57f947cdc50d.png](/resources/a9ada2c3047ecb467ace57f947cdc50d.png)

This script will set these 4 addresses as mining servers so blocking them would be the best choice here.
<details>
  <summary>Answer</summary>
<pre><code>b.oracleservice.top, 198.23.214.117, 51.79.175.139, 167.114.114.169</code></pre>
</details>

>Q7) Investigating the PCAP, retrieve a copy of the executable downloaded by the script. What are the first 5 characters of the SHA256 hash? (Format: XXXXX)

![5e427c2275631477514694bcbba3c99c.png](/resources/5e427c2275631477514694bcbba3c99c.png)
After export a file then we can use `sha256sum` to calculate SHA256 hash of this file like this.
<details>
  <summary>Answer</summary>
<pre><code>366b3</code></pre>
</details>

>Q8) Review the strings in this executable. What version of XMRig is being deployed? (Format: X.XX.X)

![862add3c1b81d762162c6f9da2cc2e12.png](/resources/862add3c1b81d762162c6f9da2cc2e12.png)

To make my life easier, I used `grep -Eo '[0-9]\.[0-9]{2}\.[0-9]'` to grab anything close to answer format which landed me with the correct answer right here (6.16.2)
<details>
  <summary>Answer</summary>
<pre><code>6.16.2</code></pre>
</details>

>Q9) What is the web server framework, version, and OS being used by the malicious server? (Format: Framework/X.XX.X (OS))

![ee01abff6e84c2e4d23a045e6c9fe8a5.png](/resources/ee01abff6e84c2e4d23a045e6c9fe8a5.png)

Go back to pcapng file where the XMRig exe was downloaded then we can see the web server framework along with version and OS right here.
<details>
  <summary>Answer</summary>
<pre><code>nginx/1.14.0 (Ubuntu)</code></pre>
</details>

>Q10) What is the process ID of the cryptominer when executed on the system? (Format: PID)

![06d0894e44c301797e06185f3e030dc8.png](/resources/06d0894e44c301797e06185f3e030dc8.png)

I used `python vol.py -f memdump.mem --profile=Win10x64_17134 pstree` to make it easier to digest and we can see PID of cryptominer process under powershell process along with the time that this cryptominer was executed (Q11)
<details>
  <summary>Answer</summary>
<pre><code>6688</code></pre>
</details>

>Q11) What time was this process started on the victim system? (Format: YYYY-MM-DD HH:MM:SS UTC+XXXX)
<details>
  <summary>Answer</summary>
<pre><code>2022-03-16 02:05:57 UTC+0000</code></pre>
</details>

>Q12) Use the Volatility filescan plugin and grep to identify the two final executables. What are the two physical offset values within the memory dump? (Format: 0x0000.... 0x0000...)

![42aee8a87008dd9313c17780be3fcdf2.png](/resources/42aee8a87008dd9313c17780be3fcdf2.png)
I used `python vol.py -f memdump.mem --profile=Win10x64_17134 filescan > filescan.txt` to pipe all filescan plugin output to a text file then use grep to display only XMRig exe file then we will have both offset ready to submit.
<details>
  <summary>Answer</summary>
<pre><code>0x0000d98ce600e080, 0x0000d98ce73048f0</code></pre>
</details>

![5ce063cb0d08645fd9087d164e8b33d2.png](/resources/5ce063cb0d08645fd9087d164e8b33d2.png)
https://blueteamlabs.online/achievement/share/52929/99
* * *