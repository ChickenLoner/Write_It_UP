# [Blue Team Labs Online - UNDRGRND-N3RD](https://blueteamlabs.online/home/investigation/undrgrnd-n3rd-90819e167e)

![9c2792059ab2332a610b6d9f6e4485b5.png](/resources/9c2792059ab2332a610b6d9f6e4485b5.png)

Unfortunately, this time he downloaded a malicious file. Our protagonist noticed this after realizing that an unfamiliar file had been uploaded to his system.

>**Digital Forensics**

>**Tags**: Autopsy Pestudio CyberChef T1204.002
* * *
**Scenario**
Matt Jarovic is a nerd who works at FunGames, a company that sells video games and gaming products. He spends his time playing video games and browsing online forums looking for new content to entertain himself.

His passion and his skills at work have enabled him to grow professionally; after submitting his application to FunTech Inc., he received the news of being just hired.

Despite the joy of this achievement, nothing has changed in his routine. Like every day after work, he comes back home and starts looking for new content to download.

Unfortunately, this time he downloaded a malicious file. Our protagonist noticed this after realizing that an unfamiliar file had been uploaded to his system.

Worried about being a victim of cybercrime, he took advantage of his fresh position at FunTech to give his computer to an analyst for a careful investigation.
* * *
## Environment Awareness
### Evidence Discovery
![b46dbd450676c3455f1e03239c1b5fac.png](/resources/b46dbd450676c3455f1e03239c1b5fac.png)

On the desktop of the investigation machine, there is an `Investigation` folder that contains all evidences required for this investigation that included
- Disk image
- Autopsy case
- A zip file that contains malicious file inside

***
### Tool Discovery and Preparation
![b645df0efb8905d50b55541848684e28.png](/resources/b645df0efb8905d50b55541848684e28.png)

On the desktop of the investigation machine, there is also a `Tools` folder that contains tools that can be used for our investigation that are
- Autopsy
- Cyberchef
- Pestudio

![d9f8fbc3bdc8ad035969c48d2a810a6a.png](/resources/d9f8fbc3bdc8ad035969c48d2a810a6a.png)

To start an investigation, click `.aut` file (autopsy case) which will load a case in Autopsy.

![b497678b81e1e18010390061a638a094.png](/resources/b497678b81e1e18010390061a638a094.png)

Now we are ready for this investigation

***
## Investigation 
>Q1) What is the PC Name? (Format: string)

![0c3890f082bf8825b47760728ca2933d.png](/resources/0c3890f082bf8825b47760728ca2933d.png)

To find out the PC Name, Autopsy already parsed this information for us under "Data Artifacts" -> "Operating System Information" right here.

<details>
  <summary>Answer</summary>
<pre><code>DESKTOP-O7J8DHI</code></pre>
</details>

>Q2) What is the Username and SID of the victim? (Format: string, string)

![1baa9ca9cdf51a4458e444b1d812364e.png](/resources/1baa9ca9cdf51a4458e444b1d812364e.png)

SID of a normal user usually end with "-1001" so if we take a look at "OS Accounts", we can see that there is only one normal user on this system which is "mjarovic"

<details>
  <summary>Answer</summary>
<pre><code>mjarovic, S-1-5-21-3166198198-1568267185-750487557-1001</code></pre>
</details>

>Q3) What is the website from which the malicious file was downloaded? (Format: http://something/something/something/something/file.ext)

![c09039b04ceed7b5ea34f650b93c09af.png](/resources/c09039b04ceed7b5ea34f650b93c09af.png)

We can go to "Data Artifacts" -> "Web Downloads" to find out all file download history that Autopsy parsed including its Zone.Identifier which stores that Url that hosted downloaded file 

which we can see the identical filename we found inside `Investigation` folder so we can copy the content of URL field to answer this question.

<details>
  <summary>Answer</summary>
<pre><code>http://underground-n3rd.gg/games/zsnes/download/zsnes.zip/<code></pre>
</details>

>Q4) The downloaded file appears to be password-protected; what is the password? (Format: password)

![61b29b6d02f99cd4de676f288b9263af.png](/resources/61b29b6d02f99cd4de676f288b9263af.png)

Then after we extracted `zsnes.zip`, we can see that there are 2 files within this zip file and the `README.txt` contains instruction for user and also passwords right here
<details>
  <summary>Answer</summary>
<pre><code>R3Tr0g@m1ng</code></pre>
</details>

>Q5) What is the name of the malicious file? (Format: file.ext)

![6433d35c314b7abe9efec789bdadac34.png](/resources/6433d35c314b7abe9efec789bdadac34.png)

This is the content inside another zip file claiming to be a Games & Softwares

![0ac1ab3332b7ff83bab8cb0f061609e7.png](/resources/0ac1ab3332b7ff83bab8cb0f061609e7.png)

As soon as we extracted it using password from `README.txt`, Microsoft Defender will quarantine it which we can see that it detected this file as Meterpreter which is a payload for Metasploit framework

<details>
  <summary>Answer</summary>
<pre><code>zsnes.exe</code></pre>
</details>

>Q6) Now that the malicious file has been identified, it needs to be analyzed. Open Pestudio. What is the hash value? (Format: SHA256)

![76d4fb5091857f2c012e95fcf9484b9a.png](/resources/76d4fb5091857f2c012e95fcf9484b9a.png)

We must disable Virus & threat protection of Windows Defender first.

![b8b32e1eaf6126c625459c36d98f36cb.png](/resources/b8b32e1eaf6126c625459c36d98f36cb.png)

Now after extracted meterpreter payload from zip file, use pestudio to analyze it which we can see SHA256 of this file right here.

<details>
  <summary>Answer</summary>
<pre><code>d478feb0d497f4290060a973aec5338b1d547efc5bd17b9ade5d189fd85e85e1</code></pre>
</details>

>Q7) It seems that the file has been encrypted. What is the entropy and the name of the malicious file? (Format: x.xxx, .ext)

![a7a2f1cb5ce81e8df264787f81e502cc.png](/resources/a7a2f1cb5ce81e8df264787f81e502cc.png)

To find out about this, lets go to sections which display all properties of each file sections of this file which we can see that the entropy of ".fhfz" section is over 6 that mean it must has been packed or encrypted.
<details>
  <summary>Answer</summary>
<pre><code>6.040, .fhfz</code></pre>
</details>

>Q8) What are the permissions of the malicious file? (Format: string, string)

![a7a2f1cb5ce81e8df264787f81e502cc.png](/resources/a7a2f1cb5ce81e8df264787f81e502cc.png)

We can also see that ".fhfz" section have write and execute permission.

<details>
  <summary>Answer</summary>
<pre><code>write, execute</code></pre>
</details>

>Q9) By analyzing deeper the malicious file, you can obtain the attacker's IP address. Through which protocol is the attacker communicating and on which port? (Format: protocol://x.x.x.x:port)

![5b5fcc34f549be5ad629e4924b297b89.png](/resources/5b5fcc34f549be5ad629e4924b297b89.png)

Utilized strings from pestudio, we can see that it will connect to 192.168.8.130 on port 4444 (reverse shell)
<details>
  <summary>Answer</summary>
<pre><code>tcp://192.168.8.130:4444</code></pre>
</details>

>Q10) The attacker has ensured persistence on the victim's system. What is the name of the file that guarantees this persistence? (Format: string)

![21b8e75ce397243ed658c6b08b6ecbc1.png](/resources/21b8e75ce397243ed658c6b08b6ecbc1.png)

There are 2 popular ways to gain persistence on Windows which are Windows Schedule Task and Run registry key which we can see un-readable registry key was created under Run registry key of a user which will execute vbs file from User's Temp folder.

<details>
  <summary>Answer</summary>
<pre><code>JtNbiQWjYBz</code></pre>
</details>

>Q11) What is the real name of the file and where is it stored? (Format: C:\path\to\something\file.ext)

![43b35d7791ab77bd0b0dd80c4d06668c.png](/resources/43b35d7791ab77bd0b0dd80c4d06668c.png)

After navigated to Temp directory of this user, we can see the content of this script by just simply clicking it which we can also see that it will execute something that was encoded in base64.

![ea53593246cfc57c5b416032a5c39ccc.png](/resources/ea53593246cfc57c5b416032a5c39ccc.png)

After decoding it, we can see its an PE32 executable file

![f1b8a421f7f8c6f29a94e2793f7b2ff4.png](/resources/f1b8a421f7f8c6f29a94e2793f7b2ff4.png)

We can see that its not the same file as `zsnes.exe` as well.

<details>
  <summary>Answer</summary>
<pre><code>C:\Users\mjarovic\AppData\Local\Temp\rIPnsjhr.vbs</code></pre>
</details>

>Q12) Before the attack, the victim received an email containing sensitive information. What is the subject of the email and who sent it? (Format: string, email)

![f3bafd561cf8b786aa2207704cb0f7a7.png](/resources/f3bafd561cf8b786aa2207704cb0f7a7.png)

Go back to Autopsy under "Data Artifacts" -> "E-Mail Messages" -> "Default ([Default])" -> "Default (2)", we can see 2 emails with identical subject and message sent to the victim and the only different here is the Date Received of both emails. 

<details>
  <summary>Answer</summary>
<pre><code>Junior Sales Manager application, j.phillips@funtech.gg</code></pre>
</details>

>Q13) What is the PC name and IP address of the sender? (Format: string, x.x.x.x)

![fb1a77a245e1d6a299f80ad73b687821.png](/resources/fb1a77a245e1d6a299f80ad73b687821.png)

Lets focus on the first one and go to "Strings" section under "Text" to display email header which we can see both PC name and IP address of the sender from "Recieve" header

<details>
  <summary>Answer</summary>
<pre><code>funtech-pc1, 192.168.8.144</code></pre>
</details>

>Q14) On which day and at what time was the email sent? (Format: xxx, x xxx xxxx HH:MM:SS) 

![99b26839f5f363e39d27db93f0dce1eb.png](/resources/99b26839f5f363e39d27db93f0dce1eb.png)

If we take a look at this, it says that this email was sent at Mon, 1 Jul 2024 23:55:42 CEST (UTC +2)

![1d46e385699c097b14a49c7e686ac1f1.png](/resources/1d46e385699c097b14a49c7e686ac1f1.png)

But from the "Recieve" header, we can see the timestamp is slightly faster than it displayed from previous image. (but the answer accepted the first one, so lets just go with that)

<details>
  <summary>Answer</summary>
<pre><code>Mon, 1 Jul 2024 23:55:42</code></pre>
</details>

>Q15) In the email was attached a file. What is the name? (Format: file.ext) 

![ead9618f423e8c55f6abd716c8995d1a.png](/resources/ead9618f423e8c55f6abd716c8995d1a.png)

We can see that a pdf file was sent as an attachment of this email right here

![3842bd7e97dd572ee4697ce25585abb4.png](/resources/3842bd7e97dd572ee4697ce25585abb4.png)

Here is another way to obtain the attachment filename.

<details>
  <summary>Answer</summary>
<pre><code>MattJarovic-FunTech.pdf</code></pre>
</details>

>Q16) What are the credentials provided for the new domain and the email password? (Format: domain username, domain password, email password)

![ffba314104410e5b8060782527ccebc7.png](/resources/ffba314104410e5b8060782527ccebc7.png)

Lets go to the location of this file, we can see that this file contains user credential for computer (domain account) and email.

![eb07fa0f119782785eec949f3cbf0ca5.png](/resources/eb07fa0f119782785eec949f3cbf0ca5.png)

We can also found this file inside user's `Documents\work` folder

<details>
  <summary>Answer</summary>
<pre><code>m.jarovic, FunTech.SalesManager2024, email.funtech.gg</code></pre>
</details>

>Q17) The attacker likely found and exfiltrated the victim's identity document while browsing through the user's directories. What is the name of the file, and what is the victim's city of residence and date of birth? (Format: file.ext, string, xx-xx-xxxx)

![d8a6b371ad463412b145ee54cb5bb8a3.png](/resources/d8a6b371ad463412b145ee54cb5bb8a3.png)

Under user's `Documents\Personal` folder, we can see that there is a digital copy of the victim ID card within this folder.

<details>
  <summary>Answer</summary>
<pre><code>matt-id.jpg, San Francisco, 26-05-1990</code></pre>
</details>

>Q18) At the end of the attack, it appears that a file was uploaded as a signature to claim the attack. What is the name of the file in question, and when was it uploaded? (Format: file.ext, xxxx-xx-xx, HH:MM:SS)

![2ec6e663df4721d99b9cc43b60b5f80b.png](/resources/2ec6e663df4721d99b9cc43b60b5f80b.png)

Under user's `Documents\Games` folder that user extracted meterpreter payload from zip file, we can see that there is an image located here and the Created Time is also happened after the attacker accessed sensitive files on this system.

<details>
  <summary>Answer</summary>
<pre><code>cyberbat.jpg, 2024-07-03, 15:33:15</code></pre>
</details>

>Q19) Given that the attacker has obtained sensitive information related to the previously analyzed data, it is possible to suppose who might be the next victim. What is the domain that will be attacked? (Format: domain)

![daa07756fe93e0193accefeb5898aa3f.png](/resources/daa07756fe93e0193accefeb5898aa3f.png)

Since the attacker already established persistence within this system and also obtained user credential of this domain then the attacker might come back then attack another user / machine within the same domain.

<details>
  <summary>Answer</summary>
<pre><code>funtech.gg</code></pre>
</details>

![d0d760abd1748c8907d7366fa5ea2b3f.png](/resources/d0d760abd1748c8907d7366fa5ea2b3f.png)
https://blueteamlabs.online/achievement/share/52929/226
* * *
## Summary
Matt Jarovic downloaded and interacted with a zip file contains malicious file then executed it which is actually a meterpreter payload that created remote shell connection to the attacker which the attacker gained access to this his system, obtain Matt's ID card and credentials for his domain account and email, uploaded proof of compromised and lastly, established persistence on user's Run registry which can come back to continue to compromise funtech.gg domain later.

### Timeline 
- 2024-07-03 15:26:32 : Matt Jarovic downloaded and interacted with a zip file contains malicious file.
- 2024-07-03 15:31:37 : Matt Jarovic unzipped a zip file.
- 2024-07-03 15:32:00 : Matt Jarovic executed malicious file.
- 2024-07-03 15:32:34 : The attacker accessed `matt-id.jpg`
- 2024-07-03 15:32:57 : The attacker accessed pdf file contains credentials of user.
- 2024-07-03 15:33:15 : `cyberbat.jpg` was created.
- 2024-07-03 15:34:05 : A persistence was created under Matt Jarovic user run registry key.

### IOCs
- `underground-n3rd[.]gg`
- `d1b650e7d3dffffc00ca4fe2a1137dfe45adc114bc33988926ab098e0801a53d` (SHA256 of `zsnes.zip`)
- `c1d25471af85b089c6c631f51117cca076b0e516e01c312752d5e1a3d27f40e0` (SHA256 of `zsnes-LatestV1.51.zip`)
- `d478feb0d497f4290060a973aec5338b1d547efc5bd17b9ade5d189fd85e85e1` (SHA256 of `zsnes.exe`)
- `fc3f303d53a8017b1a7c6d3e66f9fb4d3fac62731952bfb5e574f260260238b6` (SHA256 of binary created by `rIPnsjhr.vbs`)
- `c7f5bef776dec41d3924636265ef7f4e2ed1c913711b9232a9d3375a41f3057c` (SHA256 of `cyberbat.jpg`)
- `192[.]168[.]8[.]130`

* * *