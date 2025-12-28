# [LetsDefend - AS-REP Challenge](https://app.letsdefend.io/challenge/as-rep-challenge)
Created: 25/12/2025 19:13
Last Updated: 26/12/2025 20:41
* * *
## Scenario
A network security team received alerts from a Domain Controller (DC) indicating that a user was making unusual requests for Kerberos tickets, which is not typical for their role. Given that this behavior aligns with potential reconnaissance or lateral movement within the network, the security team escalated the issue to a senior investigator. The investigator has been tasked with analyzing the provided DC and workstation logs to trace the attacker's movements, determine the source of the anomaly, and understand how the attacker gained access and what actions they might have taken inside the network.

* * *
## Start Investigation
![d061ecf79a7b1f0c4b6a12f827bd9f96.png](/resources/d061ecf79a7b1f0c4b6a12f827bd9f96.png)

On this challenge, we have artifacts collected from 2 hosts which are prefetch and Security event log from corrado host and Security event log from DC which I will parse them first since it will be easier for me to use Timeline Explorer to search for anything I need 

![3b854ba98570272448de902d60ed1fbf.png](/resources/3b854ba98570272448de902d60ed1fbf.png)

I'm using my Flare VM and already have Eric Zimmerman's tools installed and baked into the path so I can run them from anywhere, the first artifact I will parse is prefetch which I will parse the whole folder with PECmd and we should have 2 files as the output of this tool like this

Command: `pecmd .\prefetch\ --csv .`

![4dbc78f80892343706687f6505f39db4.png](/resources/4dbc78f80892343706687f6505f39db4.png)

Next, I will use EvtxECmd to parse Security log and I will also give a name to this output file as "corrado_sec.csv" to separate it from DC security log that I will parse after this

Command: `evtxecmd -f .\logs\Security.evtx --csv . --csvf corrado_sec.csv`

![0dc0a5272434a9f142849d33e35ba55c.png](/resources/0dc0a5272434a9f142849d33e35ba55c.png)

Now it is the time for Security log of DC and we can see that there are 8,391 events from this log and majority of them are from Event ID 4624, 4634 and 4672 which associated with Logon and Logoff activity and since this the domain controller, this are pretty common here. 

Beside that since this challenge is call "AS-REP Challenge" which mean we will look into Event ID 4768 (a Kerberos authentication ticket (TGT) was requested) more since AS-REP Roasting attack is an attack that target any domain account that enabled "do not require Kerberos Pre-authentication" and expect TGT (Ticket Granting Ticket) encrypted with password hash of user to crack it offline and then use it to authenticate to the domain normally so with this information, we will start our investigation to find when it was occured in this challenge and how compromised user account was used after successfully the attacker cracked password of domain user with "do not require Kerberos Pre-authentication" enabled.

Command: `evtxecmd -f .\logs\Security.evtx --csv . --csvf DC_sec.csv`

![0e726bfdd50d3bf31397c628f4f1865f.png](/resources/0e726bfdd50d3bf31397c628f4f1865f.png)

Now we should have these files ready to start off our investigation

> While reviewing the logs, Janice identified suspicious Kerberos ticket requests, potentially indicating an AS-REP attack. What is the exact time this attack occurred?

![f65bbce43f5511b3c74381e96058ecad.png](/resources/f65bbce43f5511b3c74381e96058ecad.png)

We can start with security log from the DC first, and to hunt for AS-REP Roasting attack, we can combine seveal indicator together with Event ID 4678 such as "TicketEncryptionType" = 0x17 (RC4-HMAC) which indicates weak encryption type of Kerberos encryption that is very ideal for AS-REP Roasting attack to crack it and with combination of "PreAuthType" = 0 (PreAuthType: Logon without Pre-Authentication.) indicates user with "do not require Kerberos Pre-authentication" enabled request for TGT 

Then we will have 1 record that very standout which happened at 2024-10-05 14:42:44, as we can see that AS-REP Roasting attack was used to retrieve TGT of Corrado user and the timestamp of this event is the correst answer of this question

```
2024-10-05 14:42:44
```

> What user account did the attacker target during this Kerberos attack?
```
Corrado
```

> What is the SID associated with the targeted user account?

![dc7970443c27f4bf59ebfc8d04a6dc05.png](/resources/dc7970443c27f4bf59ebfc8d04a6dc05.png)

We can look at the detailed event to get the TargetSID to get SID associated with the Corrado user here

```
S-1-5-21-3079141193-1468241477-2901848075-1108
```

> What encryption algorithm was used in this Kerberos ticket request?
```
RC4
```

> What is the IP and port number that was used to request the ticket?
<br>**(Answer Format: IP:Port)**

![668d1e8a469f52996e7806892f512f9d.png](/resources/668d1e8a469f52996e7806892f512f9d.png)

From the same page, we can also see that the attacker conducted AS-REP roasting attack from the internal network as seen in the IpAddress detail right here

```
192.168.110.129:49684
```

> The attacker managed to crack the hash and used it to log into the compromised machine. When was their first successful logon?

![6698ab68be6c4352c937c92473191248.png](/resources/6698ab68be6c4352c937c92473191248.png)
![63cb23526cfdb178e2b3a0da2cdb691b.png](/resources/63cb23526cfdb178e2b3a0da2cdb691b.png)

This one tripped me a lot, in normal circumstance. the question was supposed to ask for successful event from the IP address that we identified earier to any machine as "Corrado" user which specified in question "crack the hash and used it to log into the compromised machine" 

But the timestamp that was accepted on this question is the anonymous login event which it’s not proof the cracked credentials were used and you can see that there is failed logon event (Event ID 4625) after this event which indicates that the attacker tried to use credential to login which was successful with anonymous logon but not as "Corrado" user so in my opinion the correct answer should be "2024-10-05 14:50:16"

```
2024-10-05 14:48:58
```

> Once inside, the attacker began exploring the system. What was the first command they executed?

![0fdf6425a84c4cade5f0eefdf030e1dc.png](/resources/0fdf6425a84c4cade5f0eefdf030e1dc.png)

Now it is the time we have to check for prefetch, after opened prefetch timeline output and look at each executable executed during the incident timeframe, the `whoami.exe` is definitely look out of place and just happened after last successful logon attempt from the attacker as well and this is the correct answer of this question

```
whoami
```

> When did the attacker execute this command exactly?
```
2024-10-05 15:01:28
```

* * *
## Summary
On this challenge, we learn how AS-REP Roasting attack can be investigated via Event ID 4768 and correlated it with Event ID 4624 for successful logon to discover lateral movement activity 

https://app.letsdefend.io/my-rewards/detail/22e0151df09d4e71a95208c0d36429e2

* * *
