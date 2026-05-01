# [Blue Team Labs Online - Marionette](https://blueteamlabs.online/home/investigation/marionette-636f8aebe3)

![6d60acc64fb87a3b42ed67a368a2915a.png](/resources/6d60acc64fb87a3b42ed67a368a2915a.png)

Look for any possible anti-forensics techniques being used and see if you can discover the files that were downloaded on the machine.

>Digital Forensics

>**Tags**: LibreOffice Text Editor CLI T1070.006
* * *
**Scenario**
There’s been a suspected machine compromise on the network. The SOC identified some strange behavior. One of the analysts saw a couple of strange hashes being flagged by the EDR. They checked with the OffSec team but they said a pentest isn’t scheduled for another 3 days. Contraced David from HR, whose machine the hashes were present on. David mentioned that he received a ‘strange’ email a while ago and downloaded the file like he always does but nothing happened after that.

The analyst cross-checked these hashes with their DB and sources to verify if these are safe. However, they were not matching with any patterns. After some further IR investigations, the analyst couldn't find any suspicious activity. this has flagged the attention of the CIRT team and they have decided to acquire David's machine for forensic investigation.

They have imaged the machine and asked you to look for any possible anti-forensics techniques being used and see if you can discover the files that were downloaded on the machine.
* * *
## Environment Awareness
### Evidence & Tools Discovery
![0c218e705dbea88755a678740ebca231.png](/resources/0c218e705dbea88755a678740ebca231.png)

We only have csv file to be opened with LibreOffice and CyberChef.
***
## Investigation
>Q1) What is the full file path of appdir.dll (including its extension) (Format: /path/to/appdir.dll.extension)

![baf9eba966e57ad474566aceab4fd98b.png](/resources/baf9eba966e57ad474566aceab4fd98b.png)

To make our searching faster, I used `grep` to find this from csv file then we will have full file path ready to submit right here.

<details>
  <summary>Answer</summary>
<pre><code>/Users/david/Desktop/Employees/appdir.dll.exe</code></pre>
</details>

>Q2) Looks like the attacker tried timestomp this file - what is the Modified time of this file? (Format YYYY-MM-DD XX:XX:XX)

![42c2cccff1b1bf818192220998699669.png](/resources/42c2cccff1b1bf818192220998699669.png)

We can use `head -n 1 output.csv` to only print out header of each column but we can also search directly on LibreOffice (it might take a while to load this csv file) but the field that we gonna look to is "Sid info Modification date"

![eead70b2fa347313bc76fa0f5926aca5.png](/resources/eead70b2fa347313bc76fa0f5926aca5.png)

Which is the one right here, you can see that timestamp format is totally looking out of place since it does not have milliseconds.

<details>
  <summary>Answer</summary>
<pre><code>2021-07-22 00:00:00</code></pre>
</details>

>Q3) According to this MFT analysis output, what was the actual $FN time accessed of this file? (Format: YYYY-MM-DD XX:XX:XX)

![7e63c015bea8cd5bbf506d54a2429f40.png](/resources/7e63c015bea8cd5bbf506d54a2429f40.png)
`grep appdir output.csv | cut -d "," -f 13`
We might notice that there is one more timestamp without milliseconds and this is the correct answer of this question but what is this timestamp?

![897cacb2ce3011473caa8702948b87b3.png](/resources/897cacb2ce3011473caa8702948b87b3.png)

Its FN Info Creation data so the attacker resorted double timestoming technique here.

<details>
  <summary>Answer</summary>
<pre><code>2020-03-02 13:00:44</code></pre>
</details>

>Q4) According to the analyst, the SIEM alerted the team about a file accessed at 2023-06-20 11:49:34.785433. What is the name of the tool the attacker was trying to use? (Format: toolname.ext)

![c098d7d959447ff332b01f29eebe4eaa.png](/resources/c098d7d959447ff332b01f29eebe4eaa.png)

Lets grep this timestamp directly which you can see that one of the most popular PowerShell post-exploitation framework was on this system.

<details>
  <summary>Answer</summary>
<pre><code>PowerView.ps1</code></pre>
</details>

>Q5) The attacker was attempting to hide this tool in this directory too. What is the time-stomped Date Accessed for this tool? (Format: YYYY-MM-DD XX:XX:XX)

![80d355e91a4c6629daf102deb11cfb60.png](/resources/80d355e91a4c6629daf102deb11cfb60.png)

Look like the attacker only timestompped SI creation date on this file since there is only 1 timestamp that does not have millisecond.
<details>
  <summary>Answer</summary>
<pre><code>2020-08-17 12:13:56</code></pre>
</details>

>Q6) It looks like the attacker was attempting to download a collection of post-exploitation tools. One of which is notable for dumping LSASS credentials. What's the name of this tool? (Format: toolname)

![dfe24d360867e3a921d5e2d78bb47a9a.png](/resources/dfe24d360867e3a921d5e2d78bb47a9a.png)

The most popular tool used for dumping LSASS credentials is mimikatz so I searched with this name and found it on this system.
<details>
  <summary>Answer</summary>
<pre><code>mimikatz</code></pre>
</details>

>Q7) You discovered another file that was masquerading as a PDF file the Employees directory. What is the name of this file? (Format: filename.extension)

![71385115460c791fc2368ec35bc0b581.png](/resources/71385115460c791fc2368ec35bc0b581.png)

I started with grepping "Employee" then grep "pdf" and we will have only 1 result with these conditions and we can see its a PowerShell script masquerade as pdf file to trick user and was timestomped by the attacker too (Q8).

<details>
  <summary>Answer</summary>
<pre><code>freds-invoice.pdf.ps1</code></pre>
</details>

>Q8) What is the timestomped Date Modified of this file? (Format: YYYY-MM-DD XX:XX:XX)
<details>
  <summary>Answer</summary>
<pre><code>2023-05-12 00:00:00</code></pre>
</details>

![0a91d7c7364455d0030cb2a6a5a9b833.png](/resources/0a91d7c7364455d0030cb2a6a5a9b833.png)
https://blueteamlabs.online/achievement/share/52929/147
* * *