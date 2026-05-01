# [Blue Team Labs Online - Ben](https://blueteamlabs.online/home/investigation/ben-51902563fd)

![7278264dadc6492c2a5b835b86e03d4c.png](/resources/7278264dadc6492c2a5b835b86e03d4c.png)

Ben received a phishing email and an attachment explaining to him a New Salary Negotiation process at the company.

>**Reverse Engineering**

>**Tags**: Noriben Kernel EML Viewer FTK Imager T1566.002 T1056.001
* * *
**Scenario**
Ben was working very hard at FaanG industries to get a maximum percentage of the hike. He was talking about this with his HR as well. While he was preparing for a Salary Negotiation meeting, Ben received a phishing email and an attachment explaining to him a New Salary Negotiation process at the company. This resulted in the theft of the super-secret Database credentials of Ben. Necessary remediation steps were taken to reduce the damage. CISO advised the security team to study Ben’s case, analyze the Evidence and prepare an Awareness workshop with technical details of the attack. Evidence and the necessary analysis tools were placed on the Desktop. Note: If prompted for Admin Privileges choose BTLOPlayer account.
* * *
## Environment Awareness
### Evidence & Tool Discovery
![c072643095807b0167ad8f339906d50f.png](/resources/c072643095807b0167ad8f339906d50f.png)

There is a note on the desktop that telling us that all evidences needed for this investigation is located in `CollectedEvidence` folder and we have [Noriben](https://github.com/Rurik/Noriben) and Kernel EML Viewer as tools to analyze all evidences provide.

We also have FTK Imager, LibreOffice and Adobe Acrobat DC shortcuts on the desktop so lets keep that in mind and it might come in handy later

***
## Investigation
>Q1) Submit the subject line of the phishing email (Format: Subject String)

![9590c67f3c986f085751c49768fa7d18.png](/resources/9590c67f3c986f085751c49768fa7d18.png)

We can use Kernel EML Viewer to open eml file which we can see that the subject of this email right here.

<details>
  <summary>Answer</summary>
<pre><code>Salary Renegotiations</code></pre>
</details>

>Q2) Submit the FROM and TO addresses of the phishing email (Format: FromMailbox@domain.tld, ToMailbox@domain.tld)

![9b6278b3decf4c094f42e3952dccf18f.png](/resources/9b6278b3decf4c094f42e3952dccf18f.png)

We can see that the attacker make it appear as this email was sent from HR to Ben so he would follow what the attacker want him to do.

<details>
  <summary>Answer</summary>
<pre><code>HR_Engineer@faang.com, Ben_Engineer@faang.com</code></pre>
</details>

>Q3) Submit the download link observed in the email attachment (Format: https://www.domain.tld/path/something)

![2507c69c6e5ecab5a021e2e1ef8df59c.png](/resources/2507c69c6e5ecab5a021e2e1ef8df59c.png)

We will have to decode body part of this email with base64 to read the message that was sent to Ben

![fd2988974e72ed6aaccaaa7b34ecd679.png](/resources/fd2988974e72ed6aaccaaa7b34ecd679.png)

Every investigation system came with CyberChef so we can use it to decode which we can see that the attacker wanted Ben to review pdf attachment. 

![2a7c79f656aefd46c29a5802632fa52c.png](/resources/2a7c79f656aefd46c29a5802632fa52c.png)

After we opened pdf document then we can see that its a cheap trick that will trick user to click the bottom which lead to specific URL.

<details>
  <summary>Answer</summary>
<pre><code>https://www.dropbox.com/s/3dqft1ays1ltgrg/NewSalaryNegotiation.uue?dl=1</code></pre>
</details>

>Q4) Submit the extension of the file that will be downloaded when the malicious link is clicked (format: .extension) 

![a21dfa20fe28729f0841d5d3fe4df85c.png](/resources/a21dfa20fe28729f0841d5d3fe4df85c.png)

We already have the file that Ben was supposed to download right here and we can see that its using UUE file extension to contains another file inside.

![38a679ca9795bb6cfd34f38040d906d4.png](/resources/38a679ca9795bb6cfd34f38040d906d4.png)

And that file is a PE32 executable masquerade as pdf file.

<details>
  <summary>Answer</summary>
<pre><code>.uue</code></pre>
</details>

>Q5) Submit the Mutex used by the malware sample (Format: {mutex})

![a1cec7a9b68da42c7c7af9e890a8313a.png](/resources/a1cec7a9b68da42c7c7af9e890a8313a.png)

Lets fire up Noriben with `python Noriben.py` and now our sandbox should be ready for a malware to be detonated.

![3aaff0d491f2351c5903878654910d6f.png](/resources/3aaff0d491f2351c5903878654910d6f.png)

After we detonated fake pdf file, we can see that this file created a new registry as Mutex

<details>
  <summary>Answer</summary>
<pre><code>{WEQ2-67R1-YUU3-EEQ2-TY74}</code></pre>
</details>

>Q6) The malware replicated itself in two locations to maintain persistence. Submit both locations according to the timeline - so submit the first file then the second file (Format: C:\path\file.ext, C:\path\file.ext)

![a4fca91c2820106e6203ff0340f4b890.png](/resources/a4fca91c2820106e6203ff0340f4b890.png)

Take a look at file activities then we can see that there are 2 suspicious PE32 executable were created and after review their SHA256 hash, its identical to the one we just executed.

<details>
  <summary>Answer</summary>
<pre><code>C:\Users\BTLOTest\AppData\Local\Microsoft\Windows\History\salaryhike\explorer.exe, C:\Users\BTLOTest\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Microsoft Corporation.exe</code></pre>
</details>

>Q7) Name of the file created by the malware sample to store recorded keystrokes from the victim machine (Format: filename.extension)

![9c311a0df8620b1ee1695554007f4708.png](/resources/9c311a0df8620b1ee1695554007f4708.png)

One thing we might notice that there is one more suspicious file created inside one of folder we found from previous question but we can not access this folder directly via Microsoft Explorer

![50dd3f6dcebd121314a5c275f8c6d9fa.png](/resources/50dd3f6dcebd121314a5c275f8c6d9fa.png)

But its not the case when we can use FTK imager to open this folder, you can see that the tmp file we just found is a log file for keystrokes.

<details>
  <summary>Answer</summary>
<pre><code>explorer.exe.tmp</code></pre>
</details>

>Q8) Submit the command-and-control server IP address, and the port used for communication (Format: X.X.X.X:Port)

![5bf67efe6088b880fd28c7fc55e078b4.png](/resources/5bf67efe6088b880fd28c7fc55e078b4.png)

Noriben used Procmon to analyze behavior of malware and saved Procmon log (PML) every time it executed so we can just open this log with Procmon and display only Network activity which we can see C2 server IP address and port from a copied of fake pdf as shown.

<details>
  <summary>Answer</summary>
<pre><code>107.189.29.181:5005</code></pre>
</details>

![4257a82b1dd0e37162233f4011f06851.png](/resources/4257a82b1dd0e37162233f4011f06851.png)
https://blueteamlabs.online/achievement/share/52929/96
* * *