# LetsDefend - EventID 214 - SOC251 - Quishing Detected (QR Code Phishing)
Created: 01/06/2024 12:54
Last Updated: 01/06/2024 12:57
***
>**EventID** : 214
**Event Time** : Jan, 01, 2024, 12:37 PM
**Rule** : SOC251 - Quishing Detected (QR Code Phishing)
**Level** : Security Analyst
**SMTP Address** : 158.69.201.47
**Source Address** : security@microsecmfa.com
**Destination Address** : Claire@letsdefend.io
**E-mail Subject** : New Year's Mandatory Security Update: Implementing Multi-Factor Authentication (MFA)
**Device Action** : Allowed
***
## Table of Contents

- [Start Playbook](#start-playbook)
- [Close Alert](#close-alert)

***
## Start Playbook
>Verify

Lets check out an email to verify this QR code
![Screenshot_20240401_105330.jpg](/resources/Screenshot_20240401_105330.jpg)
Looking at this email, there are couple of red flags here
1. Domain name of the sender 
2. Normally when setup Microsoft's MFA/2FA, QR code will not be sent via an email but on website where user went into setting to setup MFA 

Now lets decode this QR code using CyberChef
![1961a3425b3f788ac41d4b7dbe1f7d4e.png](/resources/1961a3425b3f788ac41d4b7dbe1f7d4e.png)
This is the third red flag, its not look like a link that would come from legit Microsoft at all.
![b876bfd0bf477585acb2c4822035a20f.png](/resources/b876bfd0bf477585acb2c4822035a20f.png)
Result from VirusTotal shows us that this url is a phishing site mimicking Microsoft Login Page, so this alert is true positive.

>Identify potential reconnaissance activity on the network

Lets search SMTP address on Log Management
![25be218718764cd092ccf4b3e079eed6.png](/resources/25be218718764cd092ccf4b3e079eed6.png)
There is only 1 activity from this email, the destination address is Exchange Server so it make sense because this IP responsible for sending a phishing email. 

There is no network recon found on log management.

>Check Alert Details at the Investigation Channel

Now lets check the endpoint since this mail was allowed, user might opened it
![0405bd0fb3b007c911e10b38cb474836.png](/resources/0405bd0fb3b007c911e10b38cb474836.png)
I found that outlook.exe is running so we need to confirm on Browser History that user visited phishing site on this endpoint or not
![00a4a97947847963c5abe3f524d38494.png](/resources/00a4a97947847963c5abe3f524d38494.png)
I found none, but we still couldn't be certained yet that user didn't access this url because its a QR code

User could scan this QR code on a phone too.

>Determine the Type of Reconnaissance
```
Phishing for Information
```

>Attacker IP Analysis
```
External
```

>IP Reputation Check
Is the attacker IP suspicious or not?

Lets check SMTP address on AbuseIPDB
![b5e14493df95ce7bf786bb14cd3b0030.png](/resources/b5e14493df95ce7bf786bb14cd3b0030.png)
This IP address has a bad reputation, its very suspicious or even malicious
```
Yes
```

>Determine the Scope

![3c139d3efbe9b84b8f3aec74f95f0270.png](/resources/3c139d3efbe9b84b8f3aec74f95f0270.png)
We got an IP address that hosting this phishing site from VirusTotal so lets search for this IP address on Log Management
![a547ba04c21abaa557a6445f538e2ec7.png](/resources/a547ba04c21abaa557a6445f538e2ec7.png)
There is no activity related to this IP address found 

This mail is targeted only 1 user 
```
No
```

>Containment

We found no IOC and user didn't access this phishing site on her endpoint, looking at these evidence there is no reason to contain this host but it still should be treated with caution 

Lets just contain it to investigate more futher.if this is a real-life scenario, SOC team should contact Claire to confirm that this phishing site is visited or not. 
```
Yes
```

>Add Artifacts
```
209.94.90.1
158.69.201.47
https://ipfs.io/ipfs/Qmbr8wmr41C35c3K2GfiP2F8YGzLhYpKpb4K66KU6mLmL4#
```

>Analyst Note
```
Quishing attack has been confirmed, an attacker tried to mimicking Microsoft login page to harvest user credential from an employee of this company.

There is not confirmed that this phishing site was visited, SOC team should contacted this employee to investigate if this QR code was scanned on her phone or not.

An employee's endpoint is contained temporary until the investigation process is completed and found no threat.
```

***
## Close Alert
<div align=center>

![6a0e56166f71bdf148581b524d94a250.png](/resources/6a0e56166f71bdf148581b524d94a250.png)
</div>

[Editor's Note](https://files-ld.s3.us-east-2.amazonaws.com/Alert-Reports/EventID_214+-+SOC251+-+Quishing+Detected+(QR+Code+Phishing).pdf)
***