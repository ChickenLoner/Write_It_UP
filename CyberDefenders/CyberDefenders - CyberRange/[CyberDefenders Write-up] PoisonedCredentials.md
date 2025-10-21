# [CyberDefenders - PoisonedCredentials](https://cyberdefenders.org/blueteam-ctf-challenges/poisonedcredentials/) 
Created: 20/02/2024 12:30
Last Updated: 20/02/2024 12:53
* * *
>**Category**: Network Forensics
>**Tags**: PCAP, Wireshark, Credentials
* * *

**Scenario**:
Your organization's security team has detected a surge in suspicious network activity. There are concerns that LLMNR (Link-Local Multicast Name Resolution) and NBT-NS (NetBIOS Name Service) poisoning attacks may be occurring within your network. These attacks are known for exploiting these protocols to intercept network traffic and potentially compromise user credentials. Your task is to investigate the network logs and examine captured network traffic.

**Tools**: Wireshark
* * *
First I didn't know what is NBT-NS/LLMNR poisoning and even their purposes, So i did some research and found 2 resources that I think will help reader of this write-up understand the basic concept of this kind of attack
- [Red Team Notes - LLMNR/NBT-NS Poisoning and Relay](https://dmcxblue.gitbook.io/red-team-notes/untitled-1/llmnr-nbt-ns-poisoning-and-relay)
- [TCM Security - LLMNR Poisoning and How to Prevent It](https://tcm-sec.com/llmnr-poisoning-and-how-to-prevent-it/)

Then after understands what happening, lets answer all the questions

## Questions
> Q1: In the context of the incident described in the scenario, the attacker initiated their actions by taking advantage of benign network traffic from legitimate machines. Can you identify the specific mistyped query made by the machine with the IP address 192.168.232.162?

![bf27e7c4e79a50ecc2e9ffb5468033b4.png](../../_resources/bf27e7c4e79a50ecc2e9ffb5468033b4.png)
This IP address made a NBNS query for the mistyped of fileshare 
```
fileshaare
```

> Q2: We are investigating a network security incident. For a thorough investigation, we need to determine the IP address of the rogue machine. What is the IP address of the machine acting as the rogue entity?

![ba7fe21e828fb8ce213fbe4aeb7ffd7b.png](../../_resources/ba7fe21e828fb8ce213fbe4aeb7ffd7b.png)
There is one address that sent the previous NBNS response back to 192.168.232.162
![017f0d1da3dade5333613afc1a3666c6.png](../../_resources/017f0d1da3dade5333613afc1a3666c6.png)
This IP was not just responsed with 1 query but 2 of them which are `fileshaare` and `prineter` from the different IP addresses.
```
192.168.232.215
```

> Q3: During our investigation, it's crucial to identify all affected machines. What is the IP address of the second machine that received poisoned responses from the rogue machine?
```
192.168.232.176
```

> Q4: We suspect that user accounts may have been compromised. To assess this, we must determine the username associated with the compromised account. What is the username of the account that the attacker compromised?

![4e8ed2bacf0fc942955f5784ccad2a2e.png](../../_resources/4e8ed2bacf0fc942955f5784ccad2a2e.png)
Since I already knew that 192.168.232.215 is an attacker, I made a query based of it and found the SMB2 session setup request packet with the username
```
janesmith
```

> Q5: As part of our investigation, we aim to understand the extent of the attacker's activities. What is the hostname of the machine that the attacker accessed via SMB?

![81a490da4550e47997f54640b729fbfe.png](../../_resources/81a490da4550e47997f54640b729fbfe.png)
The answer could be found on SMB2 > Session Setup Request (0x01) > Security Blob > GSS-API Generic Security Service Application Program Interface > negTokenTarg > NTLM Secure Service Provider > NTLM Response > NTLMv2 Response
```
ACCOUNTINGPC
```

<div align=center>

![83051b9f1237e24c137fc09ca424156d.png](../../_resources/83051b9f1237e24c137fc09ca424156d.png)
![da235b3b7c870f39c55744c5b07d23e9.png](../../_resources/da235b3b7c870f39c55744c5b07d23e9.png)
</div>

* * *