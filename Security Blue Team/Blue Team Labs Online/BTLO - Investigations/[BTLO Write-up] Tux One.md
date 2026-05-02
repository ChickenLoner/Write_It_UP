# [Blue Team Labs Online - Tux One](https://blueteamlabs.online/home/investigation/memory-bd0a597422)

![5e7812382ab2864994fb05f280c28a34.png](/resources/5e7812382ab2864994fb05f280c28a34.png)

It is your task to conduct some basic Linux Memory Analysis on the provided Image sample collect any evidence of malicious behaviour detected.

>Digital Forensics

>**Tags**: Volatility3 T1059.006 T1105
* * *
**Scenario**
A biotech startup has recently fallen victim to a cyber attack. The attackers managed to breach the company's network and move laterally on a victims system.

The small IT team eventually were able to dump the memory and take the users system offline for investigation.

The purpose and motives behind the attack are still unknown, making it a significant challenge to investigate and mitigate. They’ve taken a snapshot of the system, it is your task to conduct some basic Linux Memory Analysis on the provided Image sample collect any evidence of malicious behaviour detected.

- It is recommended you use Volatility 3 for this task however you may use any other suitable technique to analyse this memory dump

- When running Volatiltiy3, ensure you place the attached JSON file under `volatiltiy3/volatility3/symbols/linux` (make a directory and name it ‘linux’ if it is non-existnant)

- To run Vol3, use the command "python3.7 vol.py" when inside the Volatility3 directory.
* * *
## Investigation
>Q1) What version of Linux is the machine running? (Format: Something XX.XX)

![c1cd0767cb7d55d6738e8b030513825a.png](/resources/c1cd0767cb7d55d6738e8b030513825a.png)

Taking a look at what we have, we have symbol table file (as json) and memory image along with tools like Volatility 3 and CyberChef.

![935d8edf4fc7027e529ccccffee0a6b3.png](/resources/935d8edf4fc7027e529ccccffee0a6b3.png)

Lets start by importing symbol table to volatility by moving it or copying it to `/volatility3/symbols/linux/` 

![573288db9ed41b0b7e1180ad96a3f0fe.png](/resources/573288db9ed41b0b7e1180ad96a3f0fe.png)

Now we should be able to run `python3.7 vol.py -f ../TuxOne/system.mem banners.Banners` to grab banner of this memory image (it will take a while for volatility to load symbol for the first time) then we will have version of this Linux machine right here.

<details>
  <summary>Answer</summary>
<pre><code>Ubuntu 18.04</code></pre>
</details>

>Q2) What is the name of the victims machine? (Format: name)

![52ac787dd607ffd3076fc0f15b6746de.png](/resources/52ac787dd607ffd3076fc0f15b6746de.png)
I didn't know which plugin will get me hostname of linux machine so I used `strings` with `grep "hostname"` to get an answer of this question.
<details>
  <summary>Answer</summary>
<pre><code>nik-thumbo</code></pre>
</details>

>Q3) It looks like the attacker was attempting to call back to another internal IP that has been compromised, What is the IP of the server? (Format: x.x.x.x)

![e955c4390015761ce8bc28b97cd266bf.png](/resources/e955c4390015761ce8bc28b97cd266bf.png)
Now the output of  `python3.7 vol.py -f ../TuxOne/system.mem linux.bash` command will be the main source of our answer from Q3 to Q7 so after we ran it, we will see this IP address is another internal IP address that was being compromised.  
<details>
  <summary>Answer</summary>
<pre><code>192.168.100.186</code></pre>
</details>

>Q4) What is the name of the python payload being installed, and what port was it retrieved from? (Format: name.py, portnumber)

![40a6a8a72d924b9ce13596b3d43efa4c.png](/resources/40a6a8a72d924b9ce13596b3d43efa4c.png)

After taking a look at these commands, we could see that the attacker tried to download file from another compromised machine then install beautifulsoup4 then executed that downloaded python script. 

<details>
  <summary>Answer</summary>
<pre><code>ragdoll.py, 8888</code></pre>
</details>

>Q5) The attacker also pulled some files down from another machine using the SCP command. Whats the name of the directory they pulled the files from? (Format: directoryname)

![8e6044364725cd4df52ad2c3878df496.png](/resources/8e6044364725cd4df52ad2c3878df496.png)

An attacker used `scp` to download all files from 3viL directory from 212.71.512.115 

<details>
  <summary>Answer</summary>
<pre><code>3viL</code></pre>
</details>

>Q6) What is the name of the .mp4 file being downloaded? (Format: file.mp4)

![8b841ad4b622760f12b3f9074c38289c.png](/resources/8b841ad4b622760f12b3f9074c38289c.png)
The attacker used `wget` to download this mp4 file from digital ocean droplet and we can also wee this weird base64 string being pipe into `privpyscript.py` which also indicate that the attacker tried to escalate the privilege on this system.
<details>
  <summary>Answer</summary>
<pre><code>Slow1.mp4</code></pre>
</details>

>Q7) One of those files was a file named privpyscript.py. What is the name of the subprocess that the script is trying to load? (Format: /something/something)

![46b9fa527d497da3406a757d24218a23.png](/resources/46b9fa527d497da3406a757d24218a23.png) 
Decode base64 string then we got from the previous question then we will have sub process to execute `/bin/bash` and this might indicate that an attacker tried to elevate privilege by abusing service or task running in higher privilege to execute this script.
<details>
  <summary>Answer</summary>
<pre><code>/bin/bash</code></pre>
</details>

![f2d89d2749ececed25810014252d3ed5.png](/resources/f2d89d2749ececed25810014252d3ed5.png)
https://blueteamlabs.online/achievement/share/52929/149
* * *