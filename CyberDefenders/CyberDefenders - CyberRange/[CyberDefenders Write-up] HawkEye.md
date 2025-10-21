# [CyberDefenders - HawkEye](https://cyberdefenders.org/blueteam-ctf-challenges/hawkeye/)
Created: 15/03/2024 12:59
Last Updated: 26/06/2024 08:24
* * *
>Category: Network Forensics
>Tags: PCAP, Wireshark, NetworkMiner, BRIM, VirusTotal, T1048, T1071, T1056.001, T1016, T1027, T1204, T1566.002
* * *
**Scenario**:
An accountant at your organization received an email regarding an invoice with a download link. Suspicious network traffic was observed shortly after opening the email. As a SOC analyst, investigate the network trace and analyze exfiltration attempts.

**Tools**:
- [Wireshark](https://www.wireshark.org/)
- [BrimSecurity](https://www.brimdata.io/)
- [Apackets](https://apackets.com/)
- [MaxMind Geo IP](https://wiki.wireshark.org/HowToUseGeoIP#:~:text=MaxMind%20produces%20databases%20and%20software,information%20for%20an%20IP%20address.)
- [VirusTotal](https://www.virustotal.com/gui/)
* * *
## Questions
> Q1: How many packets does the capture have?

Open pcap file in wireshark to answer this question
![924a0ce9b43b3360417888ecd503803e.png](../../_resources/924a0ce9b43b3360417888ecd503803e.png)
```
4003
```

> Q2: At what time was the first packet captured?

Inspect first packet to answer this question
![196a02a69b3f8a94a1dbab0e02c30644.png](../../_resources/196a02a69b3f8a94a1dbab0e02c30644.png)
```
2019-04-10 20:37:07 UTC
```

> Q3: What is the duration of the capture?

To answer this question, Go to Statistics > Capture File Properties 
![7d3c908ab76996f9a20d9b9182d03852.png](../../_resources/7d3c908ab76996f9a20d9b9182d03852.png)
```
01:03:41
```

> Q4: What is the most active computer at the link level?

To answer this question, Go to Statistics > Endpoints
![da06fee57c47067912e05176424fc576.png](../../_resources/da06fee57c47067912e05176424fc576.png)
Go to Ethernet then sort out for the highest packets
```
00:08:02:1c:47:ae
```

> Q5: Manufacturer of the NIC of the most active system at the link level?

To answer this question, Go to Tools > MAC Address Blocks then search for MAC address
![51d88bd4f2614ed2799bfbd0adc1435d.png](../../_resources/51d88bd4f2614ed2799bfbd0adc1435d.png)
Alternatively, You can use NetworkMiner
![3ab8abf94483d48139a504997566df06.png](../../_resources/3ab8abf94483d48139a504997566df06.png)
```
Hewlett-Packard
```

> Q6: Where is the headquarter of the company that manufactured the NIC of the most active computer at the link level?

Its OSINT time, just search for "HP HQ location"
![0f8b68f95f4073d09739bec9717bef40.png](../../_resources/0f8b68f95f4073d09739bec9717bef40.png)
```
Palo Alto
```

> Q7: The organization works with private addressing and netmask /24. How many computers in the organization are involved in the capture?

To answer this question, Go to Statistics > Endpoints
![d13bdea7c9f1ec95317c193ba8b2ef26.png](../../_resources/d13bdea7c9f1ec95317c193ba8b2ef26.png)
Go to IPv4, you can see that there are 4 private IP addresses on 10.4.10.0/24 and 10.4.10.255 is the broadcast address so there are 3 computers in the organization are involved in the capture

Alternatively, you can also get the answer from NetworkMiner
![50d8317f7507e5edee2a67cae2d125e6.png](../../_resources/50d8317f7507e5edee2a67cae2d125e6.png)
```
3
```

> Q8: What is the name of the most active computer at the network level?

Still on Endpoints window, then sort for the highest packets then use NetworkMiner to find this host
![af67b211a3328e532c880b558a37cd65.png](../../_resources/af67b211a3328e532c880b558a37cd65.png)
```
BEIJING-5CD1-PC
```

> Q9: What is the IP of the organization's DNS server?

![5ee7c627ceb75367be32e51fe65d7601.png](../../_resources/5ee7c627ceb75367be32e51fe65d7601.png)
Filtered by `dns`, you can see that all DNS queries sent to 10.4.10.4
```
10.4.10.4
```

> Q10: What domain is the victim asking about in packet 204?

You can use filter for a specific frame but this question ask for domain so `dns` filter can still be used
![1e54d108150bc486b02a883954cd8b65.png](../../_resources/1e54d108150bc486b02a883954cd8b65.png)
```
proforma-invoices.com
```

> Q11: What is the IP of the domain in the previous question?

![e350a5d1761b5f3598fdc1750b383fd9.png](../../_resources/e350a5d1761b5f3598fdc1750b383fd9.png)
As you can see that DNS server responded back in packet 206
```
217.182.138.150
```

> Q12: Indicate the country to which the IP in the previous section belongs.

OSINT time again, using [IPLocation](https://www.iplocation.net/ip-lookup), we can easily obtain the answer
![5d9f056dedcdc0aea938914603b7a3b4.png](../../_resources/5d9f056dedcdc0aea938914603b7a3b4.png)
```
France
```

> Q13: What operating system does the victim's computer run?

![90a731052582dbe0f220e3aa60850d4d.png](../../_resources/90a731052582dbe0f220e3aa60850d4d.png)
On NetworkMiner, I found that there is a suspicious exe file downloaded by a private IP address so I assumed this is the victim
![5a127b1de7863e7647533c1b258e1f5b.png](../../_resources/5a127b1de7863e7647533c1b258e1f5b.png)
I went to this host's Browser User-agent to find the answer
```
Windows NT 6.1
```

> Q14: What is the name of the malicious file downloaded by the accountant?

As I found on previous question, I retrieved the hash of that suspicious exe file then searched on [VirusTotal](https://www.virustotal.com/gui/file/62099532750dad1054b127689680c38590033fa0bdfa4fb40c7b4dcb2607fb11)
![14f1aaaeb5c37825ba12a3743e935a85.png](../../_resources/14f1aaaeb5c37825ba12a3743e935a85.png)
Its a hawkeye keylogger, so that's the answer
```
tkraw_Protected99.exe
```

> Q15: What is the md5 hash of the downloaded file?
```
71826ba081e303866ce2a2534491a2f7
```

> Q16: What software runs the webserver that hosts the malware?

![a29fef3a59399df3ac84f5333ca06775.png](../../_resources/a29fef3a59399df3ac84f5333ca06775.png)
On NetworkMiner, It caught web server banner which is LiteSpeed
![62805e189c96bdf20a88ffa5c5152b3d.png](../../_resources/62805e189c96bdf20a88ffa5c5152b3d.png)
You can also used wireshark and followed TCP stream when victim downloaded the malware
```
LiteSpeed
```

> Q17: What is the public IP of the victim's computer?

![0bcbd841b412e206be54256fe88ac6ce.png](../../_resources/0bcbd841b412e206be54256fe88ac6ce.png)
Go to Host Details on NetworkMiner
![3e5b32761914d3f3dbf3a9824ffedcfc.png](../../_resources/3e5b32761914d3f3dbf3a9824ffedcfc.png)
Alternatively, you can also see that there is a website to ask for a public IP address 
![0ed7331f16d1a56124af3a854fba149c.png](../../_resources/0ed7331f16d1a56124af3a854fba149c.png)
Which was contacted by victim machine
![be134e70943e70e5453974d463c3a2a3.png](../../_resources/be134e70943e70e5453974d463c3a2a3.png)
Then you can use wireshark to obtain the answer
```
173.66.146.112
```

> Q18: In which country is the email server to which the stolen information is sent?

![fd3f3fadbfbc96f7c415117203b5e7ac.png](../../_resources/fd3f3fadbfbc96f7c415117203b5e7ac.png)
I filtered for Simple Mail Transfer Protocol on Wireshark then I obtained an IP address of this SMTP server
![b843b3dd0a74816c07ce2a4f2a8e2e13.png](../../_resources/b843b3dd0a74816c07ce2a4f2a8e2e13.png)
With the help of IPLocation, I finally obtained the correct answer
![40930eb68e4de8a7bed2fb9c923ef31a.png](../../_resources/40930eb68e4de8a7bed2fb9c923ef31a.png)
Alternatively, you can also get an IP address with user credential in plaintext from NetworkMiner
```
United States
```

> Q19: Analyzing the first extraction of information. What software runs the email server to which the stolen data is sent?

![9056c81efc57ad5011999d70e9e249ec.png](../../_resources/9056c81efc57ad5011999d70e9e249ec.png)
Followed the tcp stream of SMTP communication, you can see what software is running on the first response of the server
```
Exim 4.91
```

> Q20: To which email account is the stolen information sent?

![5b7d8f2813462c25de65440e3f7aa822.png](../../_resources/5b7d8f2813462c25de65440e3f7aa822.png)
On the SMTP stream, we can see that this email was used to send information
```
sales.del@macwinlogistics.in
```

> Q21: What is the password used by the malware to send the email?

You can copy password from NetworkMiner directly or you can decode base64 password from SMTP stream
![02b5217d55de2e72fe19251c8fbbd9aa.png](../../_resources/02b5217d55de2e72fe19251c8fbbd9aa.png)
```
Sales@23
```

> Q22: Which malware variant exfiltrated the data? 

![e5ade1a67ac8e6c3b7836d15be0700c3.png](../../_resources/e5ade1a67ac8e6c3b7836d15be0700c3.png)
Still on the SMTP stream, I found this base64 encoded text are subjects and content that was sent to the SMTP server so If decoded, I could get some clues
![df941d0619bd536c2af37992ca38c438.png](../../_resources/df941d0619bd536c2af37992ca38c438.png)
After decoded, we can see that this malware stated its name and family along with the infected system information on the subject
```
Reborn v9
```

> Q23: What are the bankofamerica access credentials? (username:password)

![d6905d93bf7e23c173426739349b97a3.png](../../_resources/d6905d93bf7e23c173426739349b97a3.png)
```
roman.mcguire:P@ssw0rd$
```

> Q24: Every how many minutes does the collected data get exfiltrated?

I noticed that malware had to authenticate to SMTP server everytime to send data again so I used `AUTH` command as a filter to obtain the answer
![d18c4ab95f206ac3890d3c13b9cdaf43.png](../../_resources/d18c4ab95f206ac3890d3c13b9cdaf43.png)
As you can see every authentication has 10 minutes time-interval so thats the answer
```
10
```


![15ac476fb2f92dc661c98c46c084d5fc.png](../../_resources/15ac476fb2f92dc661c98c46c084d5fc.png)
* * *
