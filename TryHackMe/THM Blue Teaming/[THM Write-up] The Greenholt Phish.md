# [TryHackMe - The Greenholt Phish](https://tryhackme.com/room/phishingemails5fgjlzxc)
![a65fee32610a8d6bcb232c4c2ffdd236.png](/resources/a65fee32610a8d6bcb232c4c2ffdd236.png)
***
A Sales Executive at Greenholt PLC received an email that he didn't expect to receive from a customer. He claims that the customer never uses generic greetings such as "Good day" and didn't expect any amount of money to be transferred to his account. The email also contains an attachment that he never requested. He forwarded the email to the SOC (Security Operations Center) department for further investigation. 

Investigate the email sample to determine if it is legitimate. 

>What is the **Transfer Reference Number** listed in the email's **Subject**?

![3432005c3f8b81ec90a15c0e4ea8d055.png](/resources/3432005c3f8b81ec90a15c0e4ea8d055.png)

We can start off by finding other tools on the machine but seem like there are only Wireshark and CyberChef which we will not use it so we can now proceed with email.

![058f6df821d4f88a38be84c2cb8189dd.png](/resources/058f6df821d4f88a38be84c2cb8189dd.png)

Upon opening an email, we can see the subject that contains Reference Number and also in the body of this email as well.

```
09674321
```

>Who is the email from?

![368a239bbe48a296a5a0ef695edd45b5.png](/resources/368a239bbe48a296a5a0ef695edd45b5.png)

We can see that the email was sent from Mr. James Jackson as shown on the "From" and "Reply to" field but noticed that email on "Reply to" is different from email in "From"

```
Mr. James Jackson
```

>What is his email address?
```
info@mutawamarine.com
```

>What email address will receive a reply to this email? 
```
info.mutawamarine@mail.com
```

>What is the Originating IP?

![b5a9b217cde001e76152d9012c179ec6.png](/resources/b5a9b217cde001e76152d9012c179ec6.png)

Its time to inspect the source by typing V or click "More" -> "View Source"

![0cc1cb22595d8233806d0cdb21025f4b.png](/resources/0cc1cb22595d8233806d0cdb21025f4b.png)

Then we can see that the bottom "Received" header is the first hop that was received this email and it also contains domain and IP address of the sender as well.

![d8a8ed2fef4f4ca9854950f2ecd569ed.png](/resources/d8a8ed2fef4f4ca9854950f2ecd569ed.png)

We can copy whole source to [MX Toolbox](https://mxtoolbox.com/Public/Tools/EmailHeaders.aspx?huid=b7a8fc66-4b4f-4831-a63b-421fda233a7b) to automatically analyzed some of important headers, which we can see that the same information from this tool as well.

```
192.119.71.157
```

>Who is the owner of the Originating IP? (Do not include the "." in your answer.)

![006dbddd4b176c3198b93b30fbd92b98.png](/resources/006dbddd4b176c3198b93b30fbd92b98.png)

Utilized [Whois](https://who.is/whois-ip/ip-address/192.119.71.157) then we can see that the Organization that owns this IP is Hostwind LLC.

```
Hostwinds LLC
```

>What is the SPF record for the Return-Path domain?

![5a8af058e08579316789f4c36364298f.png](/resources/5a8af058e08579316789f4c36364298f.png)

MX Toolbox already analyzed SPF and DMARC for us so we can go to the SPF analysis section which we can see that spf.protection.outlook.com is the authorized sender which if the receiver didn't receive an email from this sender then it tells receiver to reject it if not received from authorized sender.

```
v=spf1 include:spf.protection.outlook.com -all
```

>What is the DMARC record for the Return-Path domain?

![c5ee76f51570ea8abd5c4ea8c1d35d8c.png](/resources/c5ee76f51570ea8abd5c4ea8c1d35d8c.png)

This DMARC record telling us that any emails that fail both SPF and DKIM alignment checks will be flagged and sent to the spam/junk folder and generates failure reports for failed SPF/DKIM alignment.

```
v=DMARC1; p=quarantine; fo=1
```

>What is the name of the attachment?

![ba02672c0b0f4663db85c50cf29e14f7.png](/resources/ba02672c0b0f4663db85c50cf29e14f7.png)

We can see that this email also shipped with an attachment and its not common file attachment too.

![335d1be224ed5102fd494425bf32aa07.png](/resources/335d1be224ed5102fd494425bf32aa07.png)

We can also confirm the name of it on from the source as well

```
SWT_#09674321____PDF__.CAB
```

>What is the SHA256 hash of the file attachment?

![edbc6bee8f743bca4d0246f7775632a0.png](/resources/edbc6bee8f743bca4d0246f7775632a0.png)

We can save an attachment from Thunderbird directly with this button.

![a7958ba0e3c3fe2af77016f5792c1e6b.png](/resources/a7958ba0e3c3fe2af77016f5792c1e6b.png)

And now we can generate file hash with `sha256sum` get an answer of this question and we will also use this hash on Threat Intel platform such as VirusTotal as well.

```
2e91c533615a9bb8929ac4bb76707b2444597ce063d84a4b33525e25074fff3f
```

>What is the attachments file size? (Don't forget to add "KB" to your answer, **NUM KB**)

![c1393c8f0c19a4fba4b2805a4292ae85.png](/resources/c1393c8f0c19a4fba4b2805a4292ae85.png)

Since we could not determine that exact file size from Linux by calculation then we will use the intended solution by submit the hash of the attachment to [VirusTotal](https://www.virustotal.com/gui/file/2e91c533615a9bb8929ac4bb76707b2444597ce063d84a4b33525e25074fff3f) which reveals this file attachment is actually RAR file that contains the actual payload which is Lokibot.

```
400.26 KB
```

>What is the actual file extension of the attachment?
```
rar
```

![336c5df16cfaadf4d6a43cb7be6f56f4.png](/resources/336c5df16cfaadf4d6a43cb7be6f56f4.png)

And now we are done!
***