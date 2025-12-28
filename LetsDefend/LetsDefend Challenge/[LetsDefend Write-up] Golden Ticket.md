# [LetsDefend - Golden Ticket](https://app.letsdefend.io/challenge/golden-ticket)
Created: 25/12/2025 19:20
Last Updated: 28/12/2025 11:52
* * *
## Scenario
An alert has been triggered within a network, indicating a possible attack on the Domain Controller (DC). The security team has detected suspicious activity suggesting lateral movement attempts from a compromised workstation to the DC. The attacker, identified as having infiltrated the network, appears to be targeting sensitive systems. An investigator is tasked with analyzing network traffic, reviewing event logs, and identifying how the attacker is navigating through the environment. The goal is to trace the attacker's steps, determine their access point, and prevent further escalation to the Domain Controller.

* * *
![e45bdcf5d04256ce70ed0ff32795d5e4.png](/resources/e45bdcf5d04256ce70ed0ff32795d5e4.png)

We only have a sole security event log on this challenge and I will parse it with EvtxECmd to make it easier to search in Timeline Explorer

![15f61fea34e199b950434473334f416c.png](/resources/15f61fea34e199b950434473334f416c.png)

However, this is the same log used in AS-REP Challenge which I already parsed it 

![ff08897872113e236a9a42920f9df6af.png](/resources/ff08897872113e236a9a42920f9df6af.png)

Which we have total of 8,391 events from this event log and as Golden Ticket attack involving with the service ticket

Command: `evtxecmd -f .\Security.evtx --csv . --csvf golden.csv`

## Start Investigation
> When did the attacker first access the service account within the Domain Controller environment?
<br>**Answer Format**: (YYYY-MM-DD HH:MM:SS UTC)

![71de4acd006f9655d8b062010f0c31b6.png](/resources/71de4acd006f9655d8b062010f0c31b6.png)

After open the result csv file on the Timeline explorer, I will filter for Event ID 4624 for succesful logon and then look for any target account that could indicates their funtionality as service account which I found that "SQLService" account might be the one that was exploited in this case so I will filter for successful logon ID from this account specifically to see if there is any malicious indicators and if its a service account then we should see something like "Logon Type" = 5 or 3 and Authentication Package = "Kerberos"

![1a45f2ec44ceda7b4da942f100657dbe.png](/resources/1a45f2ec44ceda7b4da942f100657dbe.png)

As soon as I applied this filter, I noticed weird thing right away as this account was logged in from "192.168.110.129" over network (probably authentication over SMB) and the authentication was handled over "NTLM" which mean this account was logged on using username and password or Pass-The-Hash attack from "192.168.110.129" and the timestamp of first event is the correct answer of this question so the threat actor compromised this service account first before compromised other account and finally forge golden ticket

```
2024-10-05 16:50:29 UTC
```

> What is the name of the compromised service account?
```
SQLService
```

> Which IP address and port were used by the attacker to log into the compromised account?

![2a0f4869cc399537970f67ea01037df5.png](/resources/2a0f4869cc399537970f67ea01037df5.png)

As there are multiple successful logon event, even all of them logon from the same IP adddress but the port will be different so to get the correct answer of this question we will look for the first event that occured as shown here

```
192.168.110.129:48858
```

> Before that the same attacker tried to perform an AS-REP attack. What user account did the attacker target during this Kerberos attack?

![f65bbce43f5511b3c74381e96058ecad.png](/resources/f65bbce43f5511b3c74381e96058ecad-1.png)

To hunt for AS-REP Roasting attack, we can combine seveal indicator together with Event ID 4678 such as "TicketEncryptionType" = 0x17 (RC4-HMAC) which indicates weak encryption type of Kerberos encryption that is very ideal for AS-REP Roasting attack to crack it and with combination of "PreAuthType" = 0 (PreAuthType: Logon without Pre-Authentication.) indicates user with "do not require Kerberos Pre-authentication" enabled request for TGT 

Then we will have 1 record that very standout which happened at 2024-10-05 14:42:44, as we can see that AS-REP Roasting attack was used to retrieve TGT of Corrado user 

```
Corrado
```

> When did the attacker request that TGT ticket to perform the AS-REP attack?
<br>**Answer Format**: (YYYY-MM-DD HH:MM:SS UTC)
```
2024-10-05 14:42:44 UTC
```

> After gaining access to the Domain Controller, the attacker attempted to generate a Golden Ticket to impersonate a DC user. What was the target account?

A Golden Ticket Attack is an attack where the attacker that already compromised krbtgt account to have it NTLM hash and since this service account is used by the Key Distribution Center (KDC) to encrypt and sign all TGTs, the attacker can forge TGT of any user so normally attacker would like to forge TGT of a member of enterprise or domain admins group so my guess is Administrator and why I have to guess? i'll explain it in the next question

```
Administrator
```

> At what time did the attacker try to log in using the Golden Ticket?
Answer Format: (YYYY-MM-DD HH:MM:SS UTC)

![b5c938c98453decd271b7ea9505a3c8c.png](/resources/b5c938c98453decd271b7ea9505a3c8c.png)

To detect the usage of Golden Ticket, there are 3 events that can be correated together which are 
❌ 4768 (DC did NOT issue the TGT)
✔️ 4769 (service ticket request)
✔️ 4624 (Kerberos)

The authentication happened because of the golden ticket will be handled over Kerberos but the answer that was accepted as the correct answer of this question is the interactive logon event of the administrator user 

In my opinion, the answer of this question is wrong since this is a legitimate logon from the domain controller itself indicates by "Logon Type" = 2 combining with "LogonProcessName" = User32 means Keyboard / console / GUI logon and as Authentication Package is NTLM means that user used username and password to login locally on the machine instead of usage of Golden Ticket. 

```
2024-10-05 17:57:03 UTC
```

* * *
## Summary
We learn about Golden Ticket and AS-REP Roasting and how we should detect them

https://app.letsdefend.io/my-rewards/detail/bad51297fd9944d5b8e389a5a06c6d1a

* * *
