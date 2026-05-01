# [Blue Team Labs Online - Suspended](https://blueteamlabs.online/home/investigation/suspended-4b2eccb99d)

![163da08451a1b629d23ff5f156b6743b.png](/resources/163da08451a1b629d23ff5f156b6743b.png)

>Security Operations

>**Tags**: Sublime Text 2 Thunderbird Browser OSINT T1566 T1566.001 T1566.002
* * *
**Scenario**
A phishing email was sent to the SOC for analysis. Triage it and collect useful indicators for scoping and defensive activities.
* * *
## Investigation Submission
>Q1) To help us understand which employees have received this email, we can search in our email gateway for the subject line. What is the subject line of the email? (Format: Subject Line)

![63807403f67b9ddd3205f3bdc0ea0961.png](/resources/63807403f67b9ddd3205f3bdc0ea0961.png)

After deployed investigation machine, we can see that we have 3 files inside "Investigation Files" folder and we also have Mozilla Thunderbird to open eml file and CyberChef that will make my life easier since I can use it to read attachment files and use recipe to extract something from them.

![92b3483a721f55236bdef4d94241d635.png](/resources/92b3483a721f55236bdef4d94241d635.png)

We could open eml file with CyberChef but lets open it with Thunderbird first then we will see that this is an typical phishing mail with an attachment temping user to download and open it.

<details>
  <summary>Answer</summary>
<pre><code>Account has been temporary suspended!</code></pre>
</details>

>Q2) Alternatively, we can use the sending address to help scope this incident. What is the From name, and the mailbox used to send the email? (Format: From Name, mailbox@domain.tld)

![18e14d7a5351c10655b9388b6404ee26.png](/resources/18e14d7a5351c10655b9388b6404ee26.png)

Time for CyberChef (or you can use built-in notepad) to open eml file then we can easily copy "From Name" and sender email address to submit. 

<details>
  <summary>Answer</summary>
<pre><code>Prime's Report, kzgxr6fvei99qvheq8kcee6cuibjy5b3@kfndhhejbz.internetartalliance.com</code></pre>
</details>

>Q3) Based on the email file when viewed in a text editor, what is the value of the Date property? (Format: Date Value)

![184bbfbcf15fd383a456444153a1cbc3.png](/resources/184bbfbcf15fd383a456444153a1cbc3.png)
Copy date value from here.
<details>
  <summary>Answer</summary>
<pre><code>Thu, 20 Oct 2022 15:32:11 +0100</code></pre>
</details>

>Q4) What is the filename of the attachment? We can see if any employees have downloaded the attachment by checking our EDR (Format: filename.ext)

![27fe346a69c0772545e71d0f53f02895.png](/resources/27fe346a69c0772545e71d0f53f02895.png)
The name of an attachment, we already have one in "Investigation Files" folder so for the next question, we can just open it on CyberChef.
<details>
  <summary>Answer</summary>
<pre><code>Receiptupdate8761524.pdf</code></pre>
</details>

>Q5) Extract the Base64 from the email file and use CyberChef to decode - this allows us to see the contents of the attached file. Search for http/https. What is the URL contained within the PDF? (Format: http/s://domain/tld/something)

![40c1c4985b1c10a213582b4cc31c317a.png](/resources/40c1c4985b1c10a213582b4cc31c317a.png)

After opened it with CyberChef then we can see that it contains Google Drawing URL with action attribute meaning that after clicking something usually a button, user will be redirect to the URL linked to that button.
<details>
  <summary>Answer</summary>
<pre><code>https://docs.google.com/drawings/d/1Yjoy0g6WvJ0NF2BFH3ythG186xNpIRhNn8PLaw3bUXY/preview</code></pre>
</details>

>Q6) Investigate the attached file (found in the Investigation Files folder on the Desktop). What is the SHA256 hash of this file? (Format: SHA256)

![b8afb701bedf039d1b48b4f9188a9f71.png](/resources/b8afb701bedf039d1b48b4f9188a9f71.png)
CyberChef can't produce SHA256 hash so we have to use `certutil` or PowerShell to calculate file hash.
<details>
  <summary>Answer</summary>
<pre><code>71b6e937013a6a961f3ba8a4fe942dc34a58b9ddebc79c628e1c0ad572b3755b</code></pre>
</details>

>Q7) Open the attached file. What company is this document imitating? (Format: Company Name)

![3aaf2f84732b1de08caf6d635a116ef9.png](/resources/3aaf2f84732b1de08caf6d635a116ef9.png)

Lets open the attachment then you can see that it mimics Amazon to trick user to click URL we found on Q5.

<details>
  <summary>Answer</summary>
<pre><code>Amazon</code></pre>
</details>

>Q8) To identify if any users have clicked the link within the file, we could search for network connections in our EDR or SIEM. Open the web page file associated with the URL destination. What is the full URL of the call-to-action button? (Format: Full URL)

![771642f470e06fcf4e9e59c02483fece.png](/resources/771642f470e06fcf4e9e59c02483fece.png)

The url we found was already saved as HTML page for us to analyze so lets open it and hover your mouse to this button then you can see URL that will be redirected upon clicking this button (Google Redirect URL to malicious URL).

![3f370f6f9a5d671e20cb9197c84bc246.png](/resources/3f370f6f9a5d671e20cb9197c84bc246.png)
Right click at the button and copy link address to submit.
<details>
  <summary>Answer</summary>
<pre><code>https://www.google.com/url?q=http://gaykauaiwedding.com/&sa=D&source=editors&ust=1666280016126192&us</code></pre>
</details>

>Q9) Click the button with the malicious URL and let it (try to) load in the browser (remember, we have no internet in our analysis machine - this is fine). What is the domain name of this site? (Format: domain.tld)

![abb85a4c2d5e962daae804f18afe32c3.png](/resources/abb85a4c2d5e962daae804f18afe32c3.png)

Alternative way to retrieve this url beside copy link address from Q8 is to use CyberChef with extract urls recipe right here.

<details>
  <summary>Answer</summary>
<pre>gaykauaiwedding.com<code></code></pre>
</details>

>Q10) Look at the Phishing technique on MITRE ATT&CK. Which two sub-techniques are used by this actor? (Format: TXXXX.XXX, TXXXX.XXX)

![59fe37b041d1f8392f38936addb7365d.png](/resources/59fe37b041d1f8392f38936addb7365d.png)

We know that this threat actor sent email with an attachment to trick user first so the first technique is [Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)

![846b3d739bd9c207d350eca9cc73a50e.png](/resources/846b3d739bd9c207d350eca9cc73a50e.png)
We also know that the attacker use Google Drawing with button to redirect user to malicious URL so the second technique is [Spearphishing via Service](https://attack.mitre.org/techniques/T1566/003/)

<details>
  <summary>Answer</summary>
<pre><code>T1566.001, T1566.003</code></pre>
</details>

![e188f0541fdb5c8c334b510b65b9c583.png](/resources/e188f0541fdb5c8c334b510b65b9c583.png)
https://blueteamlabs.online/achievement/share/52929/126
* * *