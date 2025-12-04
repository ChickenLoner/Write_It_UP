# [CyberDefenders - HoneyBOT](https://cyberdefenders.org/blueteam-ctf-challenges/honeybot/)
## Table of Contents

- [Scenario](#scenario)
- [Questions](#questions)

* * *
## Scenario
A PCAP analysis exercise highlighting attacker's interactions with honeypots and how automatic exploitation works.. (Note that the IP address of the victim has been changed to hide the true location.)

As a soc analyst, analyze the artifacts and answer the questions.

**Category**: Network Forensics

**Tools**:
- [BrimSecurity](https://www.brimsecurity.com/)
- [NetworkMiner](https://www.netresec.com/?page=networkminer)
- [Wireshark](https://www.wireshark.org/)
- [Libemu (sctest)](https://github.com/buffer/libemu)
- [scdbg](http://sandsprite.com/blogs/index.php?uid=7&pid=152)
- [IP LookUp](https://www.iplocation.net/ip-lookup)
* * *
## Questions
> Q1: What is the attacker's IP address?

I opened the evidence pcap file on WireShark 

![43ffe3511f0c878d5cca0f21515dce6d.png](/resources/43ffe3511f0c878d5cca0f21515dce6d.png)

As soon as I opened this pcap,I saw the connection between 2 IP addresses right away so I opened the Communication Statistics which I found that there are only 2 IP addresses and I came with the conclusion that
- `98.114.205.102` is the attacker
- `192.150.11.111` is the honeypot

```
98.114.205.102
```

> Q2: What is the target's IP address?
```
192.150.11.111
```

> Q3: Provide the country code for the attacker's IP address (a.k.a geo-location).

You can use any IP lookup service for this question, my first method was to use IPLocation

![e6829a619bebd62cb76db53bf9f64fa8.png](/resources/e6829a619bebd62cb76db53bf9f64fa8.png)

and my second method is using Zui from Brimsecurity

![0b0db7bb112c86c23911ec978c560540.png](/resources/0b0db7bb112c86c23911ec978c560540.png)

```
US
```

> Q4: How many TCP sessions are present in the captured traffic?

I found the answer on Conversation Statistics in Wireshark

![ac6324f79c4414c1df43a4d806d287f6.png](/resources/ac6324f79c4414c1df43a4d806d287f6.png)

Or you can use Zui for this question

![8f1e3e2ff76047b88c91ffc87e08c762.png](/resources/8f1e3e2ff76047b88c91ffc87e08c762.png)

the number of `conn` is the answer
```
5
```

> Q5: How long did it take to perform the attack (in seconds)?

First packet started at 03:28:28

![6fe8c930914ca995add58be94e3b3125.png](/resources/6fe8c930914ca995add58be94e3b3125.png)

And last packet ended at 03:28:44
So it took 44-28 = 16 seconds
```
16
```

> Q7: Provide the CVE number of the exploited vulnerability.

![79c0e6713c695fbb8ec5158d2db582b8.png](/resources/79c0e6713c695fbb8ec5158d2db582b8.png)

After scrolling down I found this `Active Directory Setup, DsRoleUpgradeDownlevelServer` standing out after attacker tried to connect to SMB server

![9fcb10c2e2bb1cc3539812a42b73be93.png](/resources/9fcb10c2e2bb1cc3539812a42b73be93.png)

Here is the description of this function

![0bafecb39dfc528e1d6f13ca99e8e6df.png](/resources/0bafecb39dfc528e1d6f13ca99e8e6df.png)

Then I searched on google to explain this function explaination and how it could be used but I found a CVE, an answer of this question instead so its a win for me

![6d641e3e31ac9c35e0d41927f85500fb.png](/resources/6d641e3e31ac9c35e0d41927f85500fb.png)

```
CVE-2003-0533
```

[here](https://www.broadcom.com/support/security-center/attacksignatures/detail?asid=20615) is the resource about this CVE but if you want the summary, its a buffer overflow attack that lead to remote code execution. thats it

![69081f51bba991d2069d6c16f3ddb64f.png](/resources/69081f51bba991d2069d6c16f3ddb64f.png)

So if you followed the TCP stream of the SMB packages, you can see those suspicious `1` and it is an attempt to make buffer go overflow as it was described

> Q8: Which protocol was used to carry over the exploit?

As I saw on this pcap file it was carries out by SMB
```
SMB
```

> Q9: Which protocol did the attacker use to download additional malicious files to the target system?

Since I already learned that this exploit lead to remote code execution then the connection that was established after the `DsRoleUpgradeDownlevelServer Request` is the code that was executed

![c10f3bfbe937cf11c52d46b7c6453457.png](/resources/c10f3bfbe937cf11c52d46b7c6453457.png)

![047b321bf9c0ec8260fa9e139b67040b.png](/resources/047b321bf9c0ec8260fa9e139b67040b.png)

these chain commands is an attacker made the honeypot connected to his/her ftp server to download `ssms.exe` then executed it, probably a reverse shell or some kind of backdoor.
```
ftp
```

> Q10: What is the name of the downloaded malware?
```
ssms.exe
```

> Q11: The attacker's server was listening on a specific port. Provide the port number.

So after I learned that an attacker used RCE to download and executed an executable file then the next connection is likely to be the established connection between honeypot and attacker directly to download this file

![3df174af457ea28710c4ae01d8981476.png](/resources/3df174af457ea28710c4ae01d8981476.png)

![028f967694757c56d497a3b163edc6b6.png](/resources/028f967694757c56d497a3b163edc6b6.png)

So the port that listening to this is 8884
```
8884
```

> Q12: When was the involved malware first submitted to VirusTotal for analysis? Format: YYYY-MM-DD

Back to Zui, We can get the file hash from `_path:files`

![9d3ae58e69fda30c81c6fabb5f308478.png](/resources/9d3ae58e69fda30c81c6fabb5f308478.png)

![eed5fcf00d44d9eab8301611a4598564.png](/resources/eed5fcf00d44d9eab8301611a4598564.png)

Searched hash on [VirusTotal](https://www.virustotal.com/gui/file/b14ccb3786af7553f7c251623499a7fe67974dde69d3dffd65733871cddf6b6d/detection)

![32dc21aef86e734ff007390c72e9ce0b.png](/resources/32dc21aef86e734ff007390c72e9ce0b.png)

Sure enough, it is a backdoor

![3e9d428f5d566e60e9f762b50a8e4d3c.png](/resources/3e9d428f5d566e60e9f762b50a8e4d3c.png)

Here is the answer
```
2007-06-27
```

> Q13: What is the key used to encode the shellcode?

Back to wireshark at the buffer overflow, we know that this is a stack-based buffer overflow 

![66da7ab093d62a08a90a64ea24b81492.png](/resources/66da7ab093d62a08a90a64ea24b81492.png)

![a541244d3503d79c0c8512262b76bf72.png](/resources/a541244d3503d79c0c8512262b76bf72.png)

Here is the structure of this packet

![39c9ce980fdb5c4016d2abce63e9d373.png](/resources/39c9ce980fdb5c4016d2abce63e9d373.png)

To analyze it, we need to export packet bytes from frame 29 where shell code were sent

![1af51bb53f960e3b994bc39a617ffff3.png](/resources/1af51bb53f960e3b994bc39a617ffff3.png)

You can use sctest (shellcode test) and to run a simulation and plot a graph but I preferred using scdbg (shellcode debugger) since it also decoded some important information for us which you can see that after NOP (0x90) there are several 0x99 appeared before a shellcode start it operation

and you can see that this shellcode is to open a port 1957 which will be spawn cmd after a connection establishment to this port (its a bind shell) so an attacker can use netcat or other tool to establish a bind shell connection to that port

![679a26d9f316e1f38adb55e4e6e4d588.png](/resources/679a26d9f316e1f38adb55e4e6e4d588.png)

We still need to figure it out a key so I started with an offset before operational shellcode then we can see that 0x99 we just found earlier are used to XOR with shellcode to function which mean 0x99 is the key to encode and decode shell code

```
0x99
```

> Q14: What is the port number the shellcode binds to?

![0ddbeafea6b9c7fd6c4a936893ee8181.png](/resources/0ddbeafea6b9c7fd6c4a936893ee8181.png)

First way to answer this question is to debug shellcode from previous question

And another to way is the look at the result on Wireshark

![b583a6d30e964758e483c964c54dedc7.png](/resources/b583a6d30e964758e483c964c54dedc7.png)

Here when an attacker successfully exploited BOF, a connection was established at port 1957
```
1957
```

> Q15: The shellcode used a specific technique to determine its location in memory. What is the OS file being queried during this process?: 

Those functions called were from `kernel32.dll`
```
kernel32.dll
```

https://cyberdefenders.org/blueteam-ctf-challenges/achievements/Chicken_0248/honeybot/

* * *
