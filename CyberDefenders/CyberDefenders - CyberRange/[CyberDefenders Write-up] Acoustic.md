# [CyberDefenders - Acoustic](https://cyberdefenders.org/blueteam-ctf-challenges/acoustic/)
Created: 14/03/2024 10:49
Last Updated: 14/03/2024 14:55
* * *
>Category: Network Forensics
>Tags: Network, RTP, SIP, VoIP, T1123, T1046, T1190
* * *
This lab takes you into the world of voice communications on the internet. VoIP is becoming the de-facto standard for voice communication. As this technology becomes more common, malicious parties have more opportunities and stronger motives to control these systems to conduct nefarious activities. This challenge was designed to examine and explore some of the attributes of the SIP and RTP protocols. 

**Lab Files**:
- "*log.txt*" was generated from an unadvertised, passive honeypot located on the internet such that any traffic destined to it must be nefarious. Unknown parties scanned the honeypot with a range of tools, and this activity is represented in the log file.
   - The IP address of the honeypot has been changed to "honey.pot.IP.removed". In terms of geolocation, pick your favorite city.
   - The MD5 hash in the authorization digest is replaced with "MD5_hash_removedXXXXXXXXXXXXXXXX"
   - Some octets of external IP addresses have been replaced with an "X"
   - Several trailing digits of phone numbers have been replaced with an "X"
   - Assume the timestamps in the log files are UTC.
- "*Voip-trace.pcap*" was created by honeynet members for this forensic challenge to allow participants to employ network analysis skills in the VOIP context.

As a soc analyst, analyze the artifacts and answer the questions.

**Tools**:
- [BrimSecurity](http://www.brimsecurity.com/)
- [Wireshark](https://www.wireshark.org/)
* * *
## Questions
> Q1: What is the transport protocol being used?

I started this by opened pcap file on wireshark
![031565a58e9cf33e9c945f7e0665776d.png](../../_resources/031565a58e9cf33e9c945f7e0665776d.png)
And the first package is SIP packet then a lot of HTTP packets came after
![d671749e324dabd025ba1e21ca2d6f7f.png](../../_resources/d671749e324dabd025ba1e21ca2d6f7f.png)
I opened Protocol Statistics and found that there are a lot of UDP packets

And after reading about SIP protocol from https://www.nextiva.com/blog/sip-protocol.html
![c93c966e6eff2d5a3f6f7bff82307cb7.png](../../_resources/c93c966e6eff2d5a3f6f7bff82307cb7.png)
I was sure that udp is the answer of this question
```
udp
```

> Q2: The attacker used a bunch of scanning tools that belong to the same suite. Provide the name of the suite.

I followed UDP stream of the first SIP packet I found
![a47453dad46e8dfd176ea381d2377cd4.png](../../_resources/a47453dad46e8dfd176ea381d2377cd4.png)
There is some string that caught my eyes rightway so I went to google to find out what is it
![2d9db34a37585784c596925a8b2da39c.png](../../_resources/2d9db34a37585784c596925a8b2da39c.png)
Luckily, It is a tool used to VoIP security testing

Here is the github repo I found, https://github.com/EnableSecurity/sipvicious
```
sipvicious
```

> Q3: What is the User-Agent of the victim system? 

Answer still on my first udp stream
![393536fc15a6512d5452d78a5c20c2eb.png](../../_resources/393536fc15a6512d5452d78a5c20c2eb.png)
```
Asterisk PBX 1.6.0.10-FONCORE-r40
```

> Q4: Which tool was only used against the following extensions: 100,101,102,103, and 111?

So I went to sipvicious github 
![c7b40cb16aa97f9aafcbe1ae36f8f4e0.png](../../_resources/c7b40cb16aa97f9aafcbe1ae36f8f4e0.png)
then found that there are 5 python scripts that could be use to test VoIP
![dfa3ae36b004239c5ba47194b95d4c0f.png](../../_resources/dfa3ae36b004239c5ba47194b95d4c0f.png)
Fortunately, I went to `svcrack.py` first cuz on the Register function there is an attempt to make a request to VoIP server
![a0a565b3eee1f31637861644218c2ca2.png](../../_resources/a0a565b3eee1f31637861644218c2ca2.png)
And I also found that this `makeRequest` function was imported from `siphelper.py`
![0e68d9c32a456d8ee933360d82e94c2e.png](../../_resources/0e68d9c32a456d8ee933360d82e94c2e.png)
![aaaf6faf5f978d45b5571f62c4ef9302.png](../../_resources/aaaf6faf5f978d45b5571f62c4ef9302.png)
Then after compare each of different part of the request from this script and on wireshark, there are match so This is the one
```
svcrack.py
```

> Q5: Which extension on the honeypot does NOT require authentication?

I got my answer from `sip` filter
![ed17d1320ad7293f534e9dd132cfc24c.png](../../_resources/ed17d1320ad7293f534e9dd132cfc24c.png)
I found that other extensions got 401 Unauthorized back but the first extension got 200 OK back without using any credentials 

```
100
```

> Q6: How many extensions were scanned in total?

I took some hints on this question and found that the attacker used `svwar.py` then I went to read the description of this script
![176df61cede513116ac7df863cc4031f.png](../../_resources/176df61cede513116ac7df863cc4031f.png)
Its an extension line scanner, so it makes sense that attacker will use this tool to bruteforce and find the existence of extension lines this honeypot has 
![7526840f4a640abdf6b704dc34c0bf8c.png](../../_resources/7526840f4a640abdf6b704dc34c0bf8c.png)
This script also use `makeRequest` function and has similar context
![91e40bf8ebd1fa6ed94da34171281178.png](../../_resources/91e40bf8ebd1fa6ed94da34171281178.png)
I opened `log.txt` to find if I can use some search to find anything and I saw that I could use `Contact: sip:` to find out how many extension lines the attacker tried 
![53a309862c8297d6f2aba7cb5d31d2ff.png](../../_resources/53a309862c8297d6f2aba7cb5d31d2ff.png)
So I used this python script to read `log.txt` then put all starts with `Contact: sip:` to a new file
![45909e1ef9e0ffc1a0a98c1475cf0c69.png](../../_resources/45909e1ef9e0ffc1a0a98c1475cf0c69.png)
After I ran the script, I also found that there are duplicates and the first contact was from `svcrack.py` so I can cut that out
![90b8188ce76fd364254eda820c49123f.png](../../_resources/90b8188ce76fd364254eda820c49123f.png)
And I also saw the pattern that all contacts with `@honey.pot` are the one I was looking for 
![1ae044cf757b86ae1cb57b3666da6fa2.png](../../_resources/1ae044cf757b86ae1cb57b3666da6fa2.png)
So I did just that and got the answer
```
2652
```

> Q7: There is a trace for a real SIP client. What is the corresponding user-agent? (two words, once space in between)

I asked ChatGPT to write me a script to read `log.txt` and put all unique `User-Agent` into a list then print the list out later
![f6bbbd51d68b1918799ab37cc5ac6629.png](../../_resources/f6bbbd51d68b1918799ab37cc5ac6629.png)
There are 2 user-agents, the bottom one is the answer
```
Zoiper rev.6751
```

> Q8: Multiple real-world phone numbers were dialed. What was the most recent 11-digit number dialed from extension 101?

I had no clue about this question so I clicked for a hint and found that I needed to do soem research about how SIP works
![2121f78ac1de4fee4773a928c35330d3.png](../../_resources/2121f78ac1de4fee4773a928c35330d3.png)
![7fa9c820a8efd18fdb25a3f46669ae2c.png](../../_resources/7fa9c820a8efd18fdb25a3f46669ae2c.png)
I read the above diagram along with [Wiki](https://en.wikipedia.org/wiki/Session_Initiation_Protocol) so I finally got that the phone number will be sent with INVITE request
![75198e04d24535c7ab851bda12380a48.png](../../_resources/75198e04d24535c7ab851bda12380a48.png)
I found 4 INVITE requests on `log.txt` and the most recent one is this
```
00112524021
```

> Q9: What are the default credentials used in the attempted basic authentication? (format is username:password)

Now I went back to wireshark
![0526959976eae9e8eed742e88dbe582e.png](../../_resources/0526959976eae9e8eed742e88dbe582e.png)
I saw that on the GET `/mint` request came with Authentication Required so I could find the answer from this kind of request 
![2c60277f03f6538405878d788efa6235.png](../../_resources/2c60277f03f6538405878d788efa6235.png)
Which I finally got the answer, when the Status 301 was there I knew that the authentication was successful.
```
maint:password
```

> Q11: Which codec does the RTP stream use? (3 words, 2 spaces in between)

I searched on google how Codec look like
![a5003fec267769c4f241c4af313eaa11.png](../../_resources/a5003fec267769c4f241c4af313eaa11.png)
And I also found this [website](https://sonary.com/content/what-is-a-codec-and-why-is-it-important-for-voip/) explained about Codec which is very helpful
![5890aa14c20c71b6ee2f7b286b826856.png](../../_resources/5890aa14c20c71b6ee2f7b286b826856.png)
I came back to wireshark using filter `rtp` then Payload Type is the codec i was looking for
```
ITU-T G.711 PCMU
```

> Q12: How long is the sampling time (in milliseconds)?

On the website that I read while finding the answer for previous question, there is also an explaination about sampling rate which directly involved with this question
![f96cf863e3f47d5a122a8fa0cf72a052.png](../../_resources/f96cf863e3f47d5a122a8fa0cf72a052.png)
So from the explaination, 1 second happened 8000 times if sampling rate is 8000Hz
![a692115278f029a7fc3bae6839f961c8.png](../../_resources/a692115278f029a7fc3bae6839f961c8.png)
I also found codec this RTP was used and it got 8000Hz or 8kHz

Next I learned that wireshark has a tool for VoIP which can be access by Telephony > VoIP Calls (First Option) > Play Stream (At the bottom)
![5b59fd5ceee6a4f25ffbba522f21be49.png](../../_resources/5b59fd5ceee6a4f25ffbba522f21be49.png)
On this window, you can see that sampling rate of this call is 8000Hz

So I did some more researched on how to calculate sampling time in milisecond which is
`Sampling time = 1/sample rate in kHz` then `1 / 8 = 0.125`
```
0.125
```

> Q13: What was the password for the account with username 555?

I was too focused on SIP but couldn't find anything and used Find Packet on wireshark
![111910d2c21b138cdcead1570a1d56d1.png](../../_resources/111910d2c21b138cdcead1570a1d56d1.png)
and found that there is a config file for SIP was requested and it contained credentials 
![f416a4bdf4e555d789037271b7fc8ed3.png](../../_resources/f416a4bdf4e555d789037271b7fc8ed3.png)
```
1234
```

> Q14: Which RTP packet header field can be used to reorder out of sync RTP packets in the correct sequence?

I read RTP wiki and found that sequence number and timestamp could be used for that 
![241121e7d0679b6617ba74b2b4707340.png](../../_resources/241121e7d0679b6617ba74b2b4707340.png)
But the answer is timestamp
```
timestamp
```

> Q15: The trace includes a secret hidden message. Can you hear it?

on VoIP Calls, play it 
![70e991346c256aff48bbc88795d22da6.png](../../_resources/70e991346c256aff48bbc88795d22da6.png)
When you reached there, you will hear the secret code
```
mexico
```

![59b3446f0435347c8afee2a10dff5cdf.png](../../_resources/59b3446f0435347c8afee2a10dff5cdf.png)
* * *
