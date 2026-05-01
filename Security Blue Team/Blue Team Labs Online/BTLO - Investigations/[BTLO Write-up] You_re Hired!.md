# [Blue Team Labs Online - You're Hired!](https://blueteamlabs.online/home/investigation/youre-hired-cdd1edad1d)

![c0938f99c821a39797bcd817128da7bd.png](/resources/c0938f99c821a39797bcd817128da7bd.png)

While performing proactive hunting at one of our corporate customers, the threat hunting team escalated some cyclic, beaconing-like, network activity originating from one of their endpoints.

>**Incident Response**

>**Tags**: ILSPY CyberChef PEStudio Event Viewer Log Parser 2.2 T1041
* * *
**Scenario**
While performing proactive hunting at one of our corporate customers, the threat hunting team escalated some cyclic, beaconing-like, network activity originating from one of their endpoints. Your job is to analyze the provided forensic artifact sources for evidence of compromise, analyze the initial infection vector, confirm the extent of the threat actor activity on the endpoint, and leverage your threat intelligence skills to learn more about the TTPs of the observed threat actor.
* * *
## Environment Awareness
### Evidence & Tool Discovery
![b25c9e63230b64c1b7587b827168a79c.png](/resources/b25c9e63230b64c1b7587b827168a79c.png)

Look like we have several tools used for malware analysis and log parser which set a tone for this investigation that we have to dig into a log and analyze malware to complete this challenge

And as you might notice that we got csv output of ShellBag inside "artifacts_for_investigation" and iso file along with its Zone Transfer. 

![f0f22ba3f7a22976bd1af53f08f25183.png](/resources/f0f22ba3f7a22976bd1af53f08f25183.png)

Inside "artifacts" folder, there are 4 more files which 3 of them are Windows event log and 1 is registry file probably used for Q3
***
## Investigation
>Q1) What was the name of the first malicious file downloaded, and where was it downloaded from? (Format: Filename.extension, https://subdomain.domain.tld)

![7e0f5376db3d6c3fe63da53630712855.png](/resources/7e0f5376db3d6c3fe63da53630712855.png)

Since we only have ISO file right here so it must be a malware that was downloaded and we can find out where was it downloaded from Zone Transfer like this.
<details>
  <summary>Answer</summary>
<pre><code>megacorp-assessment.iso, https://web.whatsapp.com</code></pre>
</details>

>Q2) What is the drive letter that the user mounted the malicious disk image to, and what time did the user open the folder within the malicious disk image? (Format: Drive Letter, YYYY-MM-DD HH-MM-SS)

![bc7c203ef1fad2ad6adf2db91bb57821.png](/resources/bc7c203ef1fad2ad6adf2db91bb57821.png)

Take a look at ShellBag output then we will see drive letter that was mounted and access date right here.

<details>
  <summary>Answer</summary>
<pre><code>E, 2022-11-15 02-47-14</code></pre>
</details>

>Q3) What is the UserAssist key and text corresponding to the execution of the malicious executable found within the registry? (Use the executable name exactly as it appears in the UserAssist Key) (Format: Full path of UserAssist Key, executable name)

![fd9f43655b941ea553428ad979517b0c.png](/resources/fd9f43655b941ea553428ad979517b0c.png)

Lets open registry file with Notepad then go to UserAssist key which store path of each program but stored in ROT13 and we need to decode it back to the original path to identify which one we should put as an answer.

![25c236c50b3cbab65edb611a43b4a686.png](/resources/25c236c50b3cbab65edb611a43b4a686.png)

Then we will find this `PuTTY.exe` under drive E which is the one we are looking for but we have to submit the path as it was encoded with ROT13.

<details>
  <summary>Answer</summary>
<pre><code>HKEY_USERS\S-1-5-21-1364132338-2865866078-2738210552-1000\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count,R:\\nffrffzrag zngrevnyf\\ChGGL.rkr</code></pre>
</details>

>Q4) What is the MD5 hash of the malicious executable contained within the malicious disk image? (Format: MD5Hash)

![3160678a95160ea6e2771da13cd74ba5.png](/resources/3160678a95160ea6e2771da13cd74ba5.png)

Lets extract ISO file then we can see that there is a text file attempt to trick user into running this malicious putty executable file.

![456f7e2512f992472125da936f25fd1d.png](/resources/456f7e2512f992472125da936f25fd1d.png)

Lets calculate MD5 hash using pestudio or any native tool you prefered.

<details>
  <summary>Answer</summary>
<pre><code>2b06dd8ada98f0020aa20befa73de197</code></pre>
</details>

>Q5) What is the PDB Path stored within the malicious executable? (Format: Drive:\Path\To\Symbols.pdb)

![b5ba7d87ab3df21bfed5009d62d8fd6f.png](/resources/b5ba7d87ab3df21bfed5009d62d8fd6f.png)

Since we're already in pestudio, go to "Indicator" to get PDB path of this executable right here.

<details>
  <summary>Answer</summary>
<pre><code>D:\a\_work\1\s\artifacts\obj\win-x86.Release\corehost\apphost\standalone\apphost.pdb</code></pre>
</details>

>Q6) The malicious executable is a decryptor and in memory loader for an encrypted backdoor payload. What is the URL it downloads the encrypted payload from, the AES encryption key and initialization vector (IV)? (Format: https://domain.tld/resource, AES key, AES IV)

![0e57dc35424cabaeb6803bc84e5194ca.png](/resources/0e57dc35424cabaeb6803bc84e5194ca.png)

Since we have dnSpy and ILspy then lets decompile this then we can see URL that will be contacted and downloaded encrypted payload, AES key and IV right here. 

<details>
  <summary>Answer</summary>
<pre><code>http://turnscor.com/wp-includes/contact.php, D(G+KbPeShVmYq3t6v9y$B&E)H@McQfT, 8y/B?E(G+KbPeShV</code></pre>
</details>

>Q7) What was the C2 framework from which this in memory loader code was taken? (Hint: use OSINT) (Format: C2 Framework) 

![b2dfab952eea43e0cb5afce7049458a9.png](/resources/b2dfab952eea43e0cb5afce7049458a9.png)

By searching for beaconing domain then we will find out that the TTP we are discovered align with DPRK according to Google Mandiant and this is beaconing domain for Sliver C2 framework.

<details>
  <summary>Answer</summary>
<pre><code>Sliver</code></pre>
</details>

>Q8) What is the protocol and domain used for the backdoor’s C2 communication? (Format: Network protocol, FQDN)

![608325caf86f613907e7e888a160f7d0.png](/resources/608325caf86f613907e7e888a160f7d0.png)

Since we already have sysmon log so lets open it which we will see that this weird domain was queried from `cmd.exe`.

![267247f8c65b4541fce8c205af7aca15.png](/resources/267247f8c65b4541fce8c205af7aca15.png)

Then ultimately contacted on port 443 (https)

<details>
  <summary>Answer</summary>
<pre><code>https, hurricanepub.com</code></pre>
</details>

![3a52f92d068c3edcfaaf4fc47597389e.png](/resources/3a52f92d068c3edcfaaf4fc47597389e.png)

Then we can see that after established a connection then `whoami` was executed.

>Q9) What is the command line of the first process executed by the threat actor through the backdoor session? (Copy and paste the full command line as it appears in the log) (Format: binary.exe arguments)

![038e5c25a67b2fbb239f84426d83855b.png](/resources/038e5c25a67b2fbb239f84426d83855b.png)

Looking back where it all started then we can see the timestamp that `PuTTY.exe` was executed right here.

![47e9da5dafe8152693e41ed7ce89e8b0.png](/resources/47e9da5dafe8152693e41ed7ce89e8b0.png)

Then after that `whoami /all` was executed to retrieve all relevant information about current user.

<details>
  <summary>Answer</summary>
<pre><code>whoami.exe /all </code></pre>
</details>

>Q10) What process name and PID does the malware inject itself into? (Format: Process name, PID) 

![2835655f9ad2104ffcc1e0f73438e5d1.png](/resources/2835655f9ad2104ffcc1e0f73438e5d1.png)

We know that `cmd.exe` was the one that created a connection to C2 then lets confirm it with sysmon event ID 8 (CreateThread) which we can confirm that `cmd.exe` is the process we are looking for. 
<details>
  <summary>Answer</summary>
<pre><code>cmd.exe, 3340</code></pre>
</details>

>Q11) After injecting into the new process, the threat actor spawns an interactive shell for the host. What is the command line for this interactive shell? (Copy and paste the full command line as it appears in the log) (Format: C:\Path\To\Binary.exe arguments) 

![f56bbdc1531f9e56a49fa0738bae3375.png](/resources/f56bbdc1531f9e56a49fa0738bae3375.png)

Then after that the threat actor used this command to spawn PowerShell that make it more interactive and easier to use then cmd

<details>
  <summary>Answer</summary>
<pre><code>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoExit -Command [Console]::OutputEncoding=[Text.UTF8Encoding]::UTF8</code></pre>
</details>

>Q12) What is the command-line used for listing the domain controllers in the environment, and what Active Directory security group was queried? (Copy and paste the full command line as it appears in the log) (Format: Command line, security group name)

![36b0206b979f6832e09ca0abda6fc44f.png](/resources/36b0206b979f6832e09ca0abda6fc44f.png)

After that the threat actor proceeded with command like `whoami /all` and `ipconfig /all` to gain information about infected system then finally use `nltest` command to list domain trusts for the current domain. 

![f430520996a171c4d7a462a47ed88991.png](/resources/f430520996a171c4d7a462a47ed88991.png)

Then proceed to list domain controller of blinkr.corp domain

![b9b1f4e80b9c77c009bc36a81ebf624c.png](/resources/b9b1f4e80b9c77c009bc36a81ebf624c.png)

After that `net group "Domain Admins"` was executed to list member of Domain Admins group hence the second answer of this question.

<details>
  <summary>Answer</summary>
<pre><code> "C:\Windows\system32\nltest.exe" /dclist:blinkr.corp , Domain Admins</code></pre>
</details>

![5684304c2fd48d58aa836fe89869bab9.png](/resources/5684304c2fd48d58aa836fe89869bab9.png)

Then after a while, this command was executed by the threat actor, ultimately dumped lsass process.

>Q13) Based on open-source intelligence, are there any known threat actors whose techniques and infrastructure overlap with the activity observed on this host? If so, what is the name of this group and which nation-state nexus do they belong to? (Hint: Google dorks are your friend) (Format: Threat group name, Country)

![281913b2490b4881dc6f4e14ab13f6d3.png](/resources/281913b2490b4881dc6f4e14ab13f6d3.png)
First I searched for domain found in `PuTTY.exe` which lead to this [VirusTotal community](https://www.virustotal.com/gui/domain/turnscor.com/community) tab that contains this url in so many graph but the one that instantly caught my interest is this "NK WhatsApp Phishing" Threat Graph

![1cff2fb4414f018c95f3a445502aead2.png](/resources/1cff2fb4414f018c95f3a445502aead2.png)

We can see that it contains many IOC we found so far and even article related to this threat actor group from North Korea.

![4d97de01c2f3687c6d28a9c88d368603.png](/resources/4d97de01c2f3687c6d28a9c88d368603.png)

And this threat actor group is UNC4034 that named by Mandiant.

<details>
  <summary>Answer</summary>
<pre><code>UNC4034, North Korea</code></pre>
</details>

![562febb24bf0cbf82614e2c58d88b0c5.png](/resources/562febb24bf0cbf82614e2c58d88b0c5.png)
https://blueteamlabs.online/achievement/share/52929/131
* * *