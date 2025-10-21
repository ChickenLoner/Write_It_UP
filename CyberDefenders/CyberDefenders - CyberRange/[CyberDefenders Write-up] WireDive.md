# [CyberDefenders - WireDive](https://cyberdefenders.org/blueteam-ctf-challenges/wiredive/)
Created: 07/03/2024 14:47
Last Updated: 11/03/2024 14:52
* * *
>Category: Network Forensics
>Tags: PCAP, Wireshark, Network, SMB, T1041, T1048, T1005, T1071, T1570, T1059, T1133
* * *
WireDive is a combo traffic analysis exercise that contains various traces to help you understand how different protocols look on the wire where you can evaluate your DFIR skills against an artifact you usually encounter in today's case investigations as a security blue team member.

**Challenge Files**:
- dhcp.pcapng
- dns.pcapng
- https.pcapng 
- network.pcapng 
- secret_sauce.txt 
- shell.pcapng 
- smb.pcapng

**Tools**:
- [BrimSecurity](https://www.brimdata.io/download/)
- [WireShark](https://www.wireshark.org/download.html)
* * *
## Questions
> Q1: File: dhcp.pcapng - What IP address is requested by the client?

Opened dhcp.pcapng with Wireshark and then using `dhcp` as a filter
![23d172e1ee3e561e26153302354a083a.png](../../_resources/23d172e1ee3e561e26153302354a083a.png)
Now we can see that IP 192.168.2.244 got release 
![9f46a1ef28676dcb3eadc7a989c85ccd.png](../../_resources/9f46a1ef28676dcb3eadc7a989c85ccd.png)
Then this client asked for this IP address after it got released then client got that IP address from the DHCP server.

If you don't understand what these DHCP Release to DHCP Ack means [ComputerNetworkingNotes](https://www.computernetworkingnotes.com/ccna-study-guide/how-dhcp-works-explained-with-examples.html) made a note that easy to understand, you can check it out! 
![b43dd72ba99bd44391497c69ab616cdf.png](../../_resources/b43dd72ba99bd44391497c69ab616cdf.png)

```
192.168.2.244
```

> Q2: File: dhcp.pcapng - What is the transaction ID for the DHCP release?

![1ab1f4eafdaf8d93d450c637c6d017f7.png](../../_resources/1ab1f4eafdaf8d93d450c637c6d017f7.png)
![80a287514e103ea7ca72ed3492a5688d.png](../../_resources/80a287514e103ea7ca72ed3492a5688d.png)
```
0x9f8fa557
```

> Q3: File: dhcp.pcapng - What is the MAC address of the client?

![3a3308c96a41be6729dbafd73b663132.png](../../_resources/3a3308c96a41be6729dbafd73b663132.png)
```
00:0c:29:82:f5:94
```

> Q4: File dns.pcapng - What is the response for the lookup for flag.fruitinc.xyz?

First, opened dns.pcapng on Wireshark then filter for `dns` protocol
![525e99ec9c8c908f4bf850846859f4ce.png](../../_resources/525e99ec9c8c908f4bf850846859f4ce.png)
The last package of this filter is the response, We're looking for
```
ACOOLDNSFLAG
```

> Q5: File: dns.pcapng - Which root server responds to the google.com query? Hostname.

Filter out by google.com and response
![e3442d53c821b123c073c01d18c87757.png](../../_resources/e3442d53c821b123c073c01d18c87757.png)
The first response is a response from Root server
![5fdd18ae8c8cc006dd9fc7c6708bb833.png](../../_resources/5fdd18ae8c8cc006dd9fc7c6708bb833.png)
Used IP Address Lookup and got the right answer
```
e.root-servers.net
```

> Q6: File smb.pcapng - What is the path of the file that is opened?

Opened smb.pcapng on Wireshark then filter packages with `smb2` for SMB2 protocol
![ef2fc0a58280185cd461eaeec9fe0afe.png](../../_resources/ef2fc0a58280185cd461eaeec9fe0afe.png)
I scrolled down to the bottom of this filtered packages
![d92cb9cd50dcce4f18754f7d8fc35602.png](../../_resources/d92cb9cd50dcce4f18754f7d8fc35602.png)
I found that this text file inside HelloWorld directory was opened on the Create Response File package
```
HelloWorld\TradeSecrets.txt
```

> Q7: File smb.pcapng - What is the hex status code when the user SAMBA\jtomato logs in?

Still on `smb2` protocol filter
![cca88f67efcf7f25521f2319b2b6551e.png](../../_resources/cca88f67efcf7f25521f2319b2b6551e.png)
![6168f44a63a5f37e249cce519b7aa4f2.png](../../_resources/6168f44a63a5f37e249cce519b7aa4f2.png)
```
0xc000006d
```

> Q8: File smb.pcapng - What is the tree that is being browsed?

Scrolling up before user tried to opened a file, We can see that there is Tree Connect Request and It got responsed back from smb2 server
![509f43b22fb3136bbb47f47d5d785641.png](../../_resources/509f43b22fb3136bbb47f47d5d785641.png)
```
\\192.168.2.10\public
```

> Q9: File smb.pcapng - What is the flag in the file?

I followed TCP stream when a file is opened to read content of this secret text file
![fd3558f3588fdd3525d676abad004dc6.png](../../_resources/fd3558f3588fdd3525d676abad004dc6.png)
Which is too long to find a flag so I copied all readable text to text cleaner/text formatter than find a specific string
![b3fee32dca830e33971a3a095d32fde2.png](../../_resources/b3fee32dca830e33971a3a095d32fde2.png)
That's a flag
```
OneSuperDuperSecret
```

> Q10: File shell.pcapng - What port is the shell listening on?

Open shell.pcapng on Wireshark
![15c68e71314326d66650399aa6840896.png](../../_resources/15c68e71314326d66650399aa6840896.png)
First thing that caught my eyes is the established connection between 192.168.2.5 and 192.168.2.244, Looking at the connection was sent to port 4444 which is a default port of metasploit, its possibly a reverse shell connection.

So I fellow the TCP stream which I proved my hypothesis to be correct
![f6f562d87a1b54b1a22182f2cd1877da.png](../../_resources/f6f562d87a1b54b1a22182f2cd1877da.png)

```
4444
```

> Q11: File shell.pcapng - What is the port for the second shell?

From the reverse shell connection, I've seen that the attacker tried to install netcat 
![4c7fcb553542640906026251c586bb4d.png](../../_resources/4c7fcb553542640906026251c586bb4d.png)
Then use it to send `/etc/passwd` to the attacker machine on port 9999
```
9999
```

> Q12: File shell.pcapng - What version of netcat is installed?
```
1.10-41.1
```

> Q13: File shell.pcapng - What file is added to the second shell
```
/etc/passwd
```

> Q14: File shell.pcapng - What password is used to elevate the shell?

User kept using command `echo` before piping to `sudo` commmand, it could mean that the string that was passed onto `sudo` is the root password that required to execute `sudo` command as root and then use `apt` to install netcat using root priviledge
![c3dc9c6d1378c3e1e2f9b151726478fb.png](../../_resources/c3dc9c6d1378c3e1e2f9b151726478fb.png)
```
*umR@Q%4V&RC
```

> Q15: File shell.pcapng - What is the OS version of the target system?

When `apt` is ran, it checks system OS and distribution so I can find the answer of this question from the same stream.
![00b31c5d1f0268a376b40a3424433da7.png](../../_resources/00b31c5d1f0268a376b40a3424433da7.png)
```
bionic
```

> Q16: File shell.pcapng - How many users are on the target system?

From the previous question, I knew that content of `/etc/passwd` was sent to an attacker using netcat at port 9999
![88720f429307f48049d954e609313828.png](../../_resources/88720f429307f48049d954e609313828.png)
There it is
![c7877958d88cef1a611706b000c62e3a.png](../../_resources/c7877958d88cef1a611706b000c62e3a.png)
```
31
```

> Q17: File network.pcapng - What is the IPv6 NTP server IP?

Opened network.pcapng on WireShark then filter with `ntp`
![10f83a68e5effba3fbe4e54faf27d46c.png](../../_resources/10f83a68e5effba3fbe4e54faf27d46c.png)
We can see that there are only 2 packets using IPv6

First packet send to server to tell that this IPv6 address is client.
Second packet send back to client to confirm that this is a server.
```
2003:51:6012:110::dcf7:123
```

> Q18: File network.pcapng - What is the first IP address that is requested by the DHCP client?

filter by `dhcp`
![8bc3f0c9316070e1a71e0e670958c097.png](../../_resources/8bc3f0c9316070e1a71e0e670958c097.png)
First package request 192.168.20.11 but DHCP server declined then Its discover new IP address then made a request, then it finally obtained an IP address
```
192.168.20.11
```

> Q19: File network.pcapng - What is the first authoritative name server returned for the domain that is being queried?

![2bde83a564a1bfb14cd0ad7f7e4d736a.png](../../_resources/2bde83a564a1bfb14cd0ad7f7e4d736a.png)
```
ns1.hans.hosteurope.de
```

> Q20: File network.pcapng - What is the number of the first VLAN to have a topology change occur?

I didn't know anything about Protocol that VLAN is using on so I did some research and found that ![7fdce62fd35b55626cd9bb0cca6c42fc.png](../../_resources/7fdce62fd35b55626cd9bb0cca6c42fc.png)
There are 3 protocols to look out for
![df231b9b9b052285c8ee1b056e8f2247.png](../../_resources/df231b9b9b052285c8ee1b056e8f2247.png)
It might be STP on this pcapng file so I started with STP

![40cdf0a8449455e1cb930f861030f642.png](../../_resources/40cdf0a8449455e1cb930f861030f642.png)
Then I inspected STP packet and found that there is a flag that could be used here
![730258014537e8e03c358098b768913e.png](../../_resources/730258014537e8e03c358098b768913e.png)
Apply as Filter and then changed from False to True
![c04f1b5a2d28bb912ea78a73a56ccda0.png](../../_resources/c04f1b5a2d28bb912ea78a73a56ccda0.png)
There it is 
```
20
```

> Q21: File network.pcapng - What is the port for CDP for CCNP-LAB-S2?

Read more about [CDP](https://learningnetwork.cisco.com/s/article/cisco-discovery-protocol-cdp-x) (Cisco Discovery Protocol)

I used `cdp` to filter it out rightaway
![ebf7bd12267dda9fe611b5a409d6b1f5.png](../../_resources/ebf7bd12267dda9fe611b5a409d6b1f5.png)
As you can see that there are only 2 port ID which are GigabitEthernet0/1 and GigabitEthernet0/2
```
GigabitEthernet0/2
```

> Q22: File network.pcapng - What is the MAC address for the root bridge for VLAN 60?

I started by filter `vlan` then select one of STP packet
![574fe27bec62672bc5b6f0efc71e37cb.png](../../_resources/574fe27bec62672bc5b6f0efc71e37cb.png)
You can see that we can use Originating VLAN to filter out for VLAN 60
![6f1057eaf6ef573ae4996a090c096c7a.png](../../_resources/6f1057eaf6ef573ae4996a090c096c7a.png)
Got it
```
00:21:1b:ae:31:80
```

Altenatively you can use `vlan.id==60` to filter out vlan 60

> Q23: File network.pcapng - What is the IOS version running on CCNP-LAB-S2?

Back to CDP protocol, there is software information on every packet 
![ca0d28cf17a28dc63d37b12be5dd4545.png](../../_resources/ca0d28cf17a28dc63d37b12be5dd4545.png)
```
12.1(22)EA14
```

> Q24: File network.pcapng - What is the virtual IP address used for hsrp group 121?

First filter with `hsrp` ,[HSRP](https://www.geeksforgeeks.org/hot-standby-router-protocol-hsrp/) (Hot Standby Router Protocol)
![6ce72a42637d2f13453ab6ba18427a13.png](../../_resources/6ce72a42637d2f13453ab6ba18427a13.png)
On hsrp packet, I used group as filter and I could find the answer there
![ddfcf356e62f5ef34cc63a7a8e3d39f0.png](../../_resources/ddfcf356e62f5ef34cc63a7a8e3d39f0.png)
```
192.168.121.1
```

> Q25: File network.pcapng - How many router solicitations were sent?

I didn't know what is router solicitations so I made a query on Google and look like it has something to do with ICMP protocol
![9484ba1cb148c8d23ed898595403855f.png](../../_resources/9484ba1cb148c8d23ed898595403855f.png)
![a5d94447fe900f958060bde970114b4a.png](../../_resources/a5d94447fe900f958060bde970114b4a.png)
Then I found this [post](https://osqa-ask.wireshark.org/questions/19753/ipv6-router-solicitation/) on Wireshark Q&A 
![90d8916faafe6b2d2be1b0f1edd36029.png](../../_resources/90d8916faafe6b2d2be1b0f1edd36029.png)
Now applied that filter on pcapng file
![b1fa423055bc32b404242b699cf828b1.png](../../_resources/b1fa423055bc32b404242b699cf828b1.png)
We got 3
```
3
```

> Q26: File network.pcapng - What is the management address of CCNP-LAB-S2?

back to `cdp`, you can find management address there
![54e54bb25a504aa57f6ea54c6ca4033e.png](../../_resources/54e54bb25a504aa57f6ea54c6ca4033e.png)
```
192.168.121.20
```

> Q27: File network.pcapng - What is the interface being reported on in the first snmp query?

filter by `snmp` then you can see there are get-request and get-response packets
![0fe8df87943084e9993396d336b4d4bf.png](../../_resources/0fe8df87943084e9993396d336b4d4bf.png)
get-request didn't have the answer so It has to be in get-response
![510d701dd58fd1af0d469de989664b8e.png](../../_resources/510d701dd58fd1af0d469de989664b8e.png)
There is it
```
Fa0/1
```

> Q28: File network.pcapng - When was the NVRAM config last updated?

I used Find Packet that looking for NVRAM strgins on packet bytes
![e9a2b20d5b3b28720d599bf0bc74fd10.png](../../_resources/e9a2b20d5b3b28720d599bf0bc74fd10.png)
After found it, I followed UDP stream to find more information
![6476b3a0335325b51e2dc392dbe9e7c2.png](../../_resources/6476b3a0335325b51e2dc392dbe9e7c2.png)
Luckily the NVRAM config last updated were there

```
21:02:36 03/03/2017
```

> Q29: File network.pcapng - What is the ip of the radius server?

I filtered out by `radius` and found nothing so I used Find Packet to find it for me and it shows the same result as previous question
![cb2a1680d3df0f93eb57553273721157.png](../../_resources/cb2a1680d3df0f93eb57553273721157.png)
```
2001:DB8::1812
```

> Q30: File https.pcapng - What has been added to web interaction with web01.fruitinc.xyz?

Searching for web01 strings and found it on TLSv1.2 packet
![af4aad88a3c4ad0cd2a7ec4562201931.png](../../_resources/af4aad88a3c4ad0cd2a7ec4562201931.png)
Which I can't decrypt but I found a [write-up](https://www.petermstewart.net/dfa-ccsc-spring-2020-ctf-wireshark-https-pcapng-write-up/) that can teach us how to decrypt TLS conversation

First go to Preferences
![84d0bd7a2e5d86f429333253fc2f56d5.png](../../_resources/84d0bd7a2e5d86f429333253fc2f56d5.png)
Next find TLS and add (Pre)-Master-Secret log filename and then click OK
![4299f7888a27336d98e5acc1c8b43bcf.png](../../_resources/4299f7888a27336d98e5acc1c8b43bcf.png)
Now after follow TLS, we can read the content inside of it now
![a29e0e071a01c1d8416ec10075c99f50.png](../../_resources/a29e0e071a01c1d8416ec10075c99f50.png)
```
y2*Lg4cHe@Ps
```

> Q31: File https.pcapng - What is the name of the photo that is viewed in slack?

Slack might be opened on the browser and HTTP request might be the one that I was looking for so I used filter `http.host contains "slack"` to find HTTP request that have slack on the host field
![2948b46f090f3b2963e270b2ba4bf349.png](../../_resources/2948b46f090f3b2963e270b2ba4bf349.png)
And look like there is 1 picture that user sent request to view it
```
get_a_new_phone_today_720.jpg 
```

> Q32: File https.pcapng - What is the username and password to login to 192.168.2.1? Format: 'username:password' without quotes.

I filtered out by the IP address and found that HTTP2 has HTML Form URL Encoded field that has all the form that send to the server
![2e1d194bcec7f9a27f765e9d8e100939.png](../../_resources/2e1d194bcec7f9a27f765e9d8e100939.png)
Which we can see in cleartext
![94928a9260d17dd034b34af9baffc086.png](../../_resources/94928a9260d17dd034b34af9baffc086.png)
```
admin:Ac5R4D9iyqD5bSh
```

> Q33: File https.pcapng - What is the certStatus for the certificate with a serial number of 07752cebe5222fcf5c7d2038984c5198?

I used `ocsp` to filter out for OCSP (Online Certificate Status Protocol)
![f16c0e328c6088f25253060342f95ebf.png](../../_resources/f16c0e328c6088f25253060342f95ebf.png)
Luckily the first certificate that i inspected is the certificate that matchs the serialNumber of this question, so I filtered out by using this serialNumber and looking for Response packet
![7eb977e3a6e178ece6e70afa9c6e5dbd.png](../../_resources/7eb977e3a6e178ece6e70afa9c6e5dbd.png)
```
good
```

> Q34: File https.pcapng - What is the email of someone who needs to change their password?

I knew that urlencoded-form has some cleartext data that being sent to the server so I used this filter and finally found the answer
![79d42843077fc0cba3fca81335797352.png](../../_resources/79d42843077fc0cba3fca81335797352.png)
```
Jim.Tomato@fruitinc.xyz
```

> Q35: File https.pcapng - A service is assigned to an interface. What is the interface, and what is the service? Format: interface_name:service_name

I started by searching through `http2` protocol then I found this php file caught my eyes 
![239ca1a8452df963946b7458f7b74e59.png](../../_resources/239ca1a8452df963946b7458f7b74e59.png)
It is a page that used to setting NTP so the service is NTP
![78d913a3cd6d5c9dcd0029bf62ecb949.png](../../_resources/78d913a3cd6d5c9dcd0029bf62ecb949.png)
Followed HTTP2 stream, I found that there is an option to select interface so I might need to find what user had submitted
![c55d28d38fbcb7ea9efa5b788bc570d4.png](../../_resources/c55d28d38fbcb7ea9efa5b788bc570d4.png)
Which is lan
![b704042af3b60861ac6346bed3d1d2c8.png](../../_resources/b704042af3b60861ac6346bed3d1d2c8.png)
```
lan:ntp
```

![51c871a6b93e112c9f0cd909efa5eb62.png](../../_resources/51c871a6b93e112c9f0cd909efa5eb62.png)
* * *
