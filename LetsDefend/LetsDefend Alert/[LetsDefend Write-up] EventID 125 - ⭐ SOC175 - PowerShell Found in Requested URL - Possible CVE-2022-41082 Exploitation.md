# LetsDefend - EventID 125 - ⭐ SOC175 - PowerShell Found in Requested URL - Possible CVE-2022-41082 Exploitation
Created: 06/03/2024 10:13
Last Updated: 06/03/2024 10:44
***
⭐ This zero-day vulnerability (CVE-2022-41082) is being actively exploited in the wild.
>**EventID** : 125
**Event Time** : Sep, 30, 2022, 07:19 AM
**Rule** : SOC175 - PowerShell Found in Requested URL - Possible CVE-2022-41082 Exploitation
**Level** : Security Analyst
**Hostname** : Exchange Server 2
**Destination IP Address** : 172.16.20.8
**Log Source** : IIS
**Source IP Address** : 58.237.200.6
**Request URL** : /autodiscover/autodiscover.json?@evil.com/owa/&Email=autodiscover/autodiscover.json%3f@evil.com&Protocol=XYZ&FooProtocol=Powershell
**HTTP Method** : GET
**User-Agent** : Mozilla/5.0 zgrab/0.x
**Action** : Blocked
**Alert Trigger Reason** : Request URL Contains PowerShell
***
[toc]
***
ฺBefore tackle this alert, I did some research on CVE-2022-41082
Here What I learned 

This CVE is called **Microsoft Exchange Server Remote Code Execution Vulnerability** which has CVSS 8.8 and It has been found along with another Server-site Request Forgery CVE which is CVE-2022-41080 (**Microsoft Exchange Server Elevation of Privilege Vulnerability**) these two vulnerability combined is called **ProxyNotShell** 

This vulnerability affected Exchange versions 2013, 2016, and 2019 with an internet-exposed Outlook Web App (OWA) component

To sum up this vulnerability, its a chain vulnerability on Microsoft Exchange that attacker need to be authenticated to exploit CVE-2022-41080 then using *Autodiscover* function on Microsoft Exchange to get access to the Priviledged PowerShell API endpoint then the attacker can use that API to remote code execute on the other endpoints which start by downloading web shell then run arbitary commands to post exploitation activities.

Resources:
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-41082
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-41040
- https://packetstormsecurity.com/files/170066/Microsoft-Exchange-ProxyNotShell-Remote-Code-Execution.html
- https://securelist.com/cve-2022-41040-and-cve-2022-41082-zero-days-in-ms-exchange/108364/

***
## Start Playbook
>Understand Why the Alert Was Triggered
```
PowerShell found on the HTTP request payload sent from an external network to internal Exchange server that likely to be CVE-2022-41082 payload
```

>Collect Data

I started by checking the Log Management to confirmed source, destination, payload and device action
![1e232705209b684d766b68976cdd8c02.png](/resources/1e232705209b684d766b68976cdd8c02.png)
I found that this external IP address only sent 3 requests to the Exchange Server 2 (Internal) on port 443
![6460e43c8fd3b82ceaca41a43e5d0628.png](/resources/6460e43c8fd3b82ceaca41a43e5d0628.png)
![d9baca5e818882168d4d13229ad13ef0.png](/resources/d9baca5e818882168d4d13229ad13ef0.png)
![9d5f574e09bd42d979c4f4c4e3774325.png](/resources/9d5f574e09bd42d979c4f4c4e3774325.png)
All the the request's payloads match the payload that was used to exploit CVE-2022-41082 which fortunately blocked by devices

Then I checked the reputation of the external IP address
![a3fab967a1833634db3549a6415f0619.png](/resources/a3fab967a1833634db3549a6415f0619.png)
The result showed that this IP address belongs to an ISP in Korea and being reported for sevaral malicious activities

``` 
If the traffic is coming from outside (Internet);
Ownership of IP address (Static or Pool Address? Who owns it? Is it web hosting?): 58.237.200.6 (SK Broadband Co Ltd Korea)
Reputation of IP Address (Search in VirusTotal, AbuseIPDB, Cisco Talos) : Bad
```

>Examine HTTP Traffic

Since the payload was logged on Log Management, I copied that payload and let ChatGPT explained everything it could do
![1d29b63a04ed58686bdff387c51c48da.png](/resources/1d29b63a04ed58686bdff387c51c48da.png)
So even ChatGPT knows that this payload attempts to exploit CVE-2022-41082, Then this case is True Positive one

>Is Traffic Malicious?
```
Malicious
```

>What Is The Attack Type?
```
Other
```

>Check If It Is a Planned Test

I searched many keywords on Email Security and found nothing about this CVE or this attack
![08b19bc594158381048fd2a706d4678f.png](/resources/08b19bc594158381048fd2a706d4678f.png)
![5302f578715306b8feea784014b9182d.png](/resources/5302f578715306b8feea784014b9182d.png)
![503591288edda74e4ad0ccd7df006868.png](/resources/503591288edda74e4ad0ccd7df006868.png)
![8581e8d438a687f70c889d30122a7c7a.png](/resources/8581e8d438a687f70c889d30122a7c7a.png)
```
Not Planned
```

>What Is the Direction of Traffic?
```
Internet -> Company Network
```

>Check Whether the Attack Was Successful

Eariler I've investigated the traffice on Log Management and found the attack was blocked by the device
![e2768b484201464767646e4fa1331eb8.png](/resources/e2768b484201464767646e4fa1331eb8.png)
And after investigated the endpoint, I found nothing related to the attack

>Was the Attack Successful?
```
No
```

>Add Artifacts
```
58.237.200.6
```

>Do You Need Tier 2 Escalation?
```
No
```

>Analyst Note
```
The PowerShell found in the requested URL and its possible to be CVE-2022-41082 Exploitation.

Upon the futher investigation, I've confirmed that this HTTP request could be used to exploit CVE-2022-41082, and there are 3 requests that was sent from the source IP address which has poor reputation due to many reports about malicious activities. 

Fortunately all of requests got blocked from the device and no indicator of compromise were found.

Lastly I also found none of the email stated that this attack was a planned test by penetration tester team so this is not a planned test.

This alert is a true positive.
```

***
## Close Alert
<div align=center>

![0e05621ec2f40702ee41272978fcbcfa.png](/resources/0e05621ec2f40702ee41272978fcbcfa.png)
</div>

***