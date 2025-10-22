# LetsDefend - EventID 257 -⭐ SOC282 - Phishing Alert - Deceptive Mail Detected
Created: 11/07/2024 07:06
Last Updated: 11/07/2024 07:10
***
>⭐ This alert is prepared for the ‘How to Investigate a SIEM Alert’ course. If you haven’t taken the course yet, please complete it first. <br>
**EventID** : 257
**Event Time** : May, 13, 2024, 09:22 AM
**Rule** : SOC282 - Phishing Alert - Deceptive Mail Detected
**Level** : Security Analyst
**SMTP Address** : 103.80.134.63
**Source Address** : free@coffeeshooop.com
**Destination Address** : Felix@letsdefend.io
**E-mail Subject** : Free Coffee Voucher
**Device Action** : Allowed
***
## Table of Contents

- [Start Playbook](#start-playbook)
- [Close Alert](#close-alert)

***
## Start Playbook
>Parse Email

![50923c3e949a28f3b82c1d341a236b57.png](/resources/50923c3e949a28f3b82c1d341a236b57.png)

Lets go to Email Security and find this email first then we can see that this is obviously a phishing email from sender email to file attachment 

```
When was it sent? : May, 13, 2024, 09:22 AM
What is the email's SMTP address? : 103.80.134.63
What is the sender address? : free@coffeeshooop.com
What is the recipient address? : Felix@letsdefend.io
Is the mail content suspicious? : Yes
Are there any attachment? : Yes
```

![44951fba7b48aa39062f76a09c69c6de.png](/resources/44951fba7b48aa39062f76a09c69c6de.png)

I also searched for the SMTP address of the sender which was flagged by 12 different security vendors

>Are there attachments or URLs in the email?
```
Yes
```

>Analyze Url/Attachment

![2d2e40035c226a266a0c8424e6505f8d.png](/resources/2d2e40035c226a266a0c8424e6505f8d.png)

After searching filehash on [VirusTotal](https://www.virustotal.com/gui/file/cd903ad2211cf7d166646d75e57fb866000f4a3b870b5ec759929be2fd81d334/detection), we can see that this attachment is an infamous AsyncRAT (Asynchronous Remote Access Trojan) malware so we did not need to think twice and answer this as "Malicious"
```
Malicious
```

>Check If Mail Delivered to User?

Alert details tell us that this mail was allowed so we need to check the endpoint to check if the file was downloaded and executed 

![66142a3f80920de285ef2c146b557071.png](/resources/66142a3f80920de285ef2c146b557071.png)

Upon investigation on the Felix's endpoint when we checked on Browser History, we will see an url to download this malware so now its confirmed that mail was successfully delivered malware to the user

![045e9770c446295d7392d57166be2b4b.png](/resources/045e9770c446295d7392d57166be2b4b.png)

On Log Management, we can see that user downloaded this malware using Google Chrome

![fc6f6a3efb2dc6248984ebb27e6525ae.png](/resources/fc6f6a3efb2dc6248984ebb27e6525ae.png)

After that we can see another log from Felix to C2 server which we can also see the process that responsible for this connection

![5eb02a60d6e1f29694acab7b152c5c3c.png](/resources/5eb02a60d6e1f29694acab7b152c5c3c.png)

After searching for this IP address on VirusTotal, we can see that this IP address also used for multiple RAT, not just AsyncRAT

```
Delivered
```

>Delete Email From Recipient!
<div align=center>

![d76a92fa1f091a9236bf98c7d40d100e.png](/resources/d76a92fa1f091a9236bf98c7d40d100e.png)
</div>


>Check If Someone Opened the Malicious File/URL?

![be085cf1d75a3192cb68a62da3babc22.png](/resources/be085cf1d75a3192cb68a62da3babc22.png)

Look a little bit further into processes on Felix's endpoint, we can see the malicious process is running and its a child process of `explorer.exe` indicating malware was executed by user himself

and after looking other processes, we can see `cmd.exe` is a child process of `Coffee.exe` and there are several processes that spawned after `cmd.exe`

![2b37805de1fd23859614ba6a8f9904df.png](/resources/2b37805de1fd23859614ba6a8f9904df.png)

By taking a look at Terminal History, we can see how many commands were executed and most of them is about recon/gathering information on infected system (Felix's Endpoint)
```
Opened
```

>Containment
<div align=center>

![beaf456c6d9f615a11cb2b36c8c66211.png](/resources/beaf456c6d9f615a11cb2b36c8c66211.png)
</div>


>Add Artifacts
```
free@coffeeshooop.com
coffeeshooop.com
103.80.134.63
37.120.233.226
files-ld.s3.us-east-2.amazonaws.com/59cbd215-76ea-434d-93ca-4d6aec3bac98-free-coffee.zip
961d8e0f1ec3c196499bfcbd0a9d19fa
```

>Analyst Note
```
Phishing mail was detected and was not blocked by firewall or other security measures, which lead to user downloaded AsyncRAT malware and executed it and after that a new connection was established to C2 server and executed command using `cmd.exe` to gather information on the infected system.

Email was deleted and host is contained upon uncovering these facts so the next step would be eradicating malware and recovery process and then after that a lesson learned process need to be conducted to prevent future incidents like this from happening again.
```

***
## Close Alert

<div align=center>

![aff907b3ab37ed9f24df63950a5ea286.png](/resources/aff907b3ab37ed9f24df63950a5ea286.png)
</div>

Editor's Note: [Security Report](https://files-ld.s3.us-east-2.amazonaws.com/Alert-Reports/EventID_257+-+SOC282+-+Phishing+Alert+-+Deceptive+Mail+Detected.pdf)

***