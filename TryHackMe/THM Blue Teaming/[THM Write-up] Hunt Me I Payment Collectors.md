# [TryHackMe - Hunt Me I: Payment Collectors](https://tryhackme.com/room/paymentcollectors)
![43f295e251b3c18687844a3da0316c63.png](/resources/43f295e251b3c18687844a3da0316c63.png)
***
On **Friday, September 15, 2023**, Michael Ascot, a Senior Finance Director from SwiftSpend, was checking his emails in **Outlook** and came across an email appearing to be from Abotech Waste Management regarding a monthly invoice for their services. Michael actioned this email and downloaded the attachment to his workstation without thinking.

![d43611a7769a85a915cc2423d8eb0af5.png](/resources/d43611a7769a85a915cc2423d8eb0af5.png)

The following week, Michael received another email from his contact at Abotech claiming they were recently hacked and to carefully review any attachments sent by their employees. However, the damage has already been done. Use the attached Elastic instance to hunt for malicious activity on Michael's workstation and within the SwiftSpend domain!

>What was the name of the ZIP attachment that Michael downloaded?

![ffe28e27eaee764e2ddace46c8362104.png](/resources/ffe28e27eaee764e2ddace46c8362104.png)

After started the machine, we can access Elastic with provided URL and select the time range to 15 Years to see how many events we have total of 7635 events from this time range.

![95d7b74b851cf64b1536ebf99ea38cca.png](/resources/95d7b74b851cf64b1536ebf99ea38cca.png)

![3822622a0e3b38e4cab0282ff94c6e14.png](/resources/3822622a0e3b38e4cab0282ff94c6e14.png)

Then we can proceed to set specific time range to **Friday, September 15, 2023**, the incident date and we can see that all 7365 events still there but we can see the the last event happened to be at 18:48:08

![33cf9f050ae3b9b178b76431ed7d5ad3.png](/resources/33cf9f050ae3b9b178b76431ed7d5ad3.png)

Its time to look at the event provider, we can see that we have so many event providers including Outlook, Sysmon and PowerShell so we will have to look at the Outlook one first.

![6d90a82fe029c981c6a27b3acfb45ed9.png](/resources/6d90a82fe029c981c6a27b3acfb45ed9.png)

Only 4 events from this provider and all of them does not help much with our investigation so we will have to go for Sysmon.

![f959dd0ae281a19146f70be35c143c91.png](/resources/f959dd0ae281a19146f70be35c143c91.png)

After added Sysmon to the filter, We can see that there are only 125 events from this provider and most of them are Event ID 1

![e26da54174a939d7354b2fff016eac07.png](/resources/e26da54174a939d7354b2fff016eac07.png)

I used `event.code:15` query to get all File Stream created event with would help us get the zone identifier of the downloaded file itself but sadly, there is no stream of zip file but we finally get a clue of something, we can see that user accessed suspicious file with triple extension from the zip file at 2023-09-15 18:41:11.116 

![3fe365dc362d7444b9bccb9daadb8976.png](/resources/3fe365dc362d7444b9bccb9daadb8976.png)

Leveraged what we got, I added `event.code:11` to my filter and search for any zip file creation which leads us to the zip attachment opened by user at 2023-09-15 18:41:00.069 

```
Invoice_AT_2023-227.zip
```

![36e75e1277c0348e2658850f0d6fa251.png](/resources/36e75e1277c0348e2658850f0d6fa251.png)

Another thing I found from this query is `exfilt8me.zip` file creation on `C:\Users\michael.ascot\Downloads\exfiltration` via PowerShell process at 2023-09-15 18:45:34.108, indicates that the attacker conducted data exfiltration during this operation so we will take note of and continue our investigation until we get there.

>What was the contained file that Michael extracted from the attachment?

![e26da54174a939d7354b2fff016eac07.png](/resources/e26da54174a939d7354b2fff016eac07.png)

Remember that there is a shortcut file opened by user so this is the one from the attachment that started the whole thing.

```
Payment_Invoice.pdf.lnk.lnk
```

>What was the name of the command-line process that spawned from the extracted file attachment?

![85ca250cc04ba4611779773362aaf94e.png](/resources/85ca250cc04ba4611779773362aaf94e.png)

Filter for Event ID 1 then we can see that upon opening the shortcut file, at 2023-09-15 18:41:12.923 PowerShell command was executed to execute powercat to make reverse shell connection to host behind ngrok on port 19282 which we can see that it was successful and the attacker executed `systeminfo` as first command after established reverse shell to the system.

![76eb31418b3401ce9185333411118c01.png](/resources/76eb31418b3401ce9185333411118c01.png)

Filter for Event ID 3 for network connection, we can see that the attacker used EC2 instance to receive reverse shell connection from the malicious attachment.

```
powershell.exe
```

>What URL did the attacker use to download a tool to establish a reverse shell connection?
```
https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1
```

>What port did the workstation connect to the attacker on?
```
19282
```

>What was the first native Windows binary the attacker ran for system enumeration after obtaining remote access?
```
systeminfo.exe
```

>What is the URL of the script that the attacker downloads to enumerate the domain?

![d20e48a9e6cb231262ddff3ed40dfabe.png](/resources/d20e48a9e6cb231262ddff3ed40dfabe.png)

After successfully established reverse shell connection, the attacker started enumerating users and groups on the infected system.

![f73d6bf91cb24b13c5bfe28b882410cd.png](/resources/f73d6bf91cb24b13c5bfe28b882410cd.png)

At 2023-09-15 18:42:36.949, the attacker opened another PowerShell process with execution policy bypass which indicates that the attacker will execute script from PowerShell and then we found that after that the attacker then mapped network share to Z drive and use robocopy to copy files from that drive (network share) to exfiltration folder as we found while hunting for zip file.

![b13b467cffb1f1f0d481161a4738a13e.png](/resources/b13b467cffb1f1f0d481161a4738a13e.png)

![b3761749774b8312a932ceda49c96bb6.png](/resources/b3761749774b8312a932ceda49c96bb6.png)

Since sysmon did not catch the script that was executed then we have to use another provider which is PowerShell and just by simply filter for Event ID 4104 for Script Block and we can see that PowerView was executed from user download folder so the file that was downloaded is PowerView and it was used to get the file share that infected system can reach and mapped it for exfiltration. 

![5c3bae65fc5f79eeb3113326d9ced227.png](/resources/5c3bae65fc5f79eeb3113326d9ced227.png)

Going back a little by filter for Event ID 4103 and PowerView string which we can see that at 2023-09-15 18:42:23.787 the attacker downloaded PowerView from Github and saved it as `PowerView.ps1` on the user download folder as we already found from Script Block logging.

```
https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerView/powerview.ps1
```

>What was the name of the file share that the attacker mapped to Michael's workstation?

![f1edae684cfb9d64535ccfa9497fb98e.png](/resources/f1edae684cfb9d64535ccfa9497fb98e.png)

Going back to sysmon again, we can see that the attacker mapped file share related to financial of the victim's organization.

```
SSF-FinancialRecords
```

>What directory did the attacker copy the contents of the file share to?

![0ca3320858b1e5584d893e194b37881d.png](/resources/0ca3320858b1e5584d893e194b37881d.png)
```
C:\Users\michael.ascot\downloads\exfiltration
```

>What was the name of the Excel file the attacker extracted from the file share?

![aed0a98fa9badd535fd9257b6e083949.png](/resources/aed0a98fa9badd535fd9257b6e083949.png)

Utilize Event ID 11 with the name of exfiltration folder, we can see that 2 files were copied to exfiltration folder before compressed into zip file.

```
ClientPortfolioSummary.xlsx
```

>What was the name of the archive file that the attacker created to prepare for exfiltration?
```
exfilt8me.zip
```

>What is the **MITRE ID** of the technique that the attacker used to exfiltrate the data?

![a2f78c013d78dc154fe88c5a70c24e6a.png](/resources/a2f78c013d78dc154fe88c5a70c24e6a.png)

Going back to Sysmon, we can see that after compressed both files into a zip then the attacker using `dig` command to exfiltrate file to "haz4rdw4re.io" domain by appending its subdomain with base64 encoded content of the file.

![dfb22990cd5e37a9f9d8e03a4b1fa253.png](/resources/dfb22990cd5e37a9f9d8e03a4b1fa253.png)

Go to MITRE to find any technique under Exfiltration tactic which we can see that [Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/) is the one that aligns with this action.

```
T1048
```

>What was the domain of the attacker's server that retrieved the exfiltrated data?
```
haz4rdw4re.io
```

>The attacker exfiltrated an additional file from the victim's workstation. What is the flag you receive after reconstructing the file?

![4ccd2d990fcb804222cc77f2b74d173a.png](/resources/4ccd2d990fcb804222cc77f2b74d173a.png)

Notices that last 2 dig events timestamp appears to be late then all the rest by 15 seconds, I made a guess that these 2 events are the flag.

![8391b1d966d567d9c6576f43acb7b735.png](/resources/8391b1d966d567d9c6576f43acb7b735.png)

After decoding it, ye it is indeed a flag!

```
THM{1497321f4f6f059a52dfb124fb16566e}
```

![d6b682a0b7509c34a6183357c5ffcd55.png](/resources/d6b682a0b7509c34a6183357c5ffcd55.png)

And we are done! but one thing I noticed is this room was used in Phishing Unfolding scenario of TryHackMe SOC simulator but in there, you have alerts to triage and you will have to use Splunk.

![3919c3ebdb822f85da6b50919ef33bec.png](/resources/3919c3ebdb822f85da6b50919ef33bec.png)
https://tryhackme.com/chicken0248/badges/threat-hunter

***