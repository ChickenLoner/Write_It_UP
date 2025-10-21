# [LetsDefend - Infection with Cobalt Strike](https://app.letsdefend.io/challenge/infection-cobalt-strike)
Created: 28/02/2024 13:40
Last Updated: 28/02/2024 16:36
* * *
<div align=center>

**Infection with Cobalt Strike**
![d74e9aeea572f09d24cbee127c2db27b.png](../../_resources/d74e9aeea572f09d24cbee127c2db27b.png)
</div>

We got network traffic from password stealer. You should do root cause analysis.
PCAP File (pass:321): [~~Download~~](https://files-ld.s3.us-east-2.amazonaws.com/5H42K.zip) C:\Users\LetsDefend\Desktop\Files\5H42K.7z

This challenge prepared by [@Bohan Zhang](https://www.linkedin.com/in/bohan-zhang-078751137/)

PCAP Source: malware-traffic-analysis
* * *
## Start Investigation
I got a pcap file to work with so I opened it with Wireshark
<div align=center>

![cba29166d965569f1efa86611669996b.png](../../_resources/cba29166d965569f1efa86611669996b.png)
First I opened the Protocol Hierarchy Statistics to see what I should filter and focus on, There are SMB2 and HTTP that worth looking for 
</div>
But there are so much noises so I switched from Wireshark to NetworkMiner
<div align=center>

![2c20ffae758273c782f7bf1901d90d4a.png](../../_resources/2c20ffae758273c782f7bf1901d90d4a.png)
After screening the Files section I found that [DocuSign](https://www.docusign.com/) the document signing service provider
</div>

There is several news about DocuSign that was used to deliver malware via phishing attack so I think thats the answer of the first question and initial access of the malware.
![efd2fe0e12f47854c47a003aa6ca2f7a.png](../../_resources/efd2fe0e12f47854c47a003aa6ca2f7a.png)

Now I knew the victim machine (10.7.5.134) so I went back to Wireshark to search anything specific on this IP address
<div align=center>

![3eb13813bc1358e786e62b6bd2acc837.png](../../_resources/3eb13813bc1358e786e62b6bd2acc837.png)
And this HTTP traffic caught my eyes right away, It is a request to `/swellheaded.php` then I followed TCP stream for the content of this conversation
![d67671e24884d4fd3258325dc91cd515.png](../../_resources/d67671e24884d4fd3258325dc91cd515.png)
The request was sent to `ecofiltroform.triciclogo.com` and the response was encoded with gzip
![95b51481312e500cdf3e711ae289094f.png](../../_resources/95b51481312e500cdf3e711ae289094f.png)
The request was sent again and now there are chunks of it then if not an encrypted text then it should be file transfer? file fetching from C2 server?


![37ad434270b39dc7411b31a958d5a3cb.png](../../_resources/37ad434270b39dc7411b31a958d5a3cb.png)
I closed Follow TCP Stream and Follow HTTP Stream instead and found the source code of the webserver front-end


![3c57b3314bde2bcda170bfdc617a8486.png](../../_resources/3c57b3314bde2bcda170bfdc617a8486.png)
Looking at the script it seems like when user enter this page, it sets cookie of the user from the calculated time zone then reloads the page to ensures that cookie is set so that's why we saw 2 requests were sent 
![cc5345489dcd77225040818b5f6c24c5.png](../../_resources/cc5345489dcd77225040818b5f6c24c5.png)
Now after the page has been reloaded the user will face with the other script, maybe because this user got the right cookie? but this new script is used to download a file for sure and the saveAS function takes 2 parameters which is blob and filename ![f98a0c43aa2584fe983de4c82aff1e54.png](../../_resources/f98a0c43aa2584fe983de4c82aff1e54.png)
The second function take no parameter but it should be blob that getting pass for the saveAs function and it use [atob](https://developer.mozilla.org/en-US/docs/Web/API/atob) function which mean the content inside of it must be base64 encoded string
![d4e32842d6a23d2380b2f28fea7ecd31.png](../../_resources/d4e32842d6a23d2380b2f28fea7ecd31.png)
Scrolling to the end of response, and it seems like I was right, the above encoded string are used to create a blob and then pass to saveAs function with `0524_4109399728218.doc` as a file name then it redirects to docusign so It also confirmed that the attacker used docusign to deliver this malware
</div>

I went back to NetworkMiner to find if the malware were captured but sadly there is no doc file were captured so I guessed I need to get this malware and its hash to search on VirusTotal
<div align=center>

![948475a833cb03dfd9629e9db3bdc0e1.png](../../_resources/948475a833cb03dfd9629e9db3bdc0e1.png)
I located to where the NetworkMiner assembled files were created and downloads the malware from the largest html file
![e7b59643815856a3f6838353d0e35ce7.png](../../_resources/e7b59643815856a3f6838353d0e35ce7.png)
The MalDoc file was downloaded and I obtained the hash
![a1fa901a2a4e80e9a15c25c7fcf9de41.png](../../_resources/a1fa901a2a4e80e9a15c25c7fcf9de41.png)
![c3f8269f7f76cb50556412d185418977.png](../../_resources/c3f8269f7f76cb50556412d185418977.png)
I also used oletools to do static analysis and found that its has VBA macros and it will be run once it opened.
![d7b14abe8485ee8299d60fe7f4c5e572.png](../../_resources/d7b14abe8485ee8299d60fe7f4c5e572.png)
After reading some of the macro, look like it tries to run shell code with `rundll32.exe`

![4ebd520d544a68dc661a2f0082e779db.png](../../_resources/4ebd520d544a68dc661a2f0082e779db.png)
Searching the hash on [VirusTotal](https://www.virustotal.com/gui/file/0b22278ddb598d63f07eb983bcf307e0852cd3005c5bc15d4a4f26455562c8ec) and found that this malware where label as Valyria But after I did some research about Valyria I think this malware is not exactly Valyria but Hancitor based on this [Any.run](https://any.run/malware-trends/hancitor) and Relations section on the VirusTotal
![35f11304aad63defcf17885dca3fae55.png](../../_resources/35f11304aad63defcf17885dca3fae55.png)
![9d2107469180ecf4e83ce948deef3ee2.png](../../_resources/9d2107469180ecf4e83ce948deef3ee2.png)
![45d09dec7e16dbd3d827f67ba5318173.png](../../_resources/45d09dec7e16dbd3d827f67ba5318173.png)
Same C2 addresses, Same name

![5866ea1bb02d7247e8ae08d9c0fdeba0.png](../../_resources/5866ea1bb02d7247e8ae08d9c0fdeba0.png)
After opened, it runs `rundll32.exe` with this command as expected
![59883631854a795ce3c4281069202d2d.png](../../_resources/59883631854a795ce3c4281069202d2d.png)
And it also tries to connect to C2 server but sadly from this report its already downed

![7534a958a89ea8cbc1332de7cc4c1e05.png](../../_resources/7534a958a89ea8cbc1332de7cc4c1e05.png)
I went back to Wireshark and found this request was sent and its response with 200 HTTP Status. look at the body part of HTML request, its send information about the infected host to C2 server 
![b7757512b3c726fcfb6def6610828ba1.png](../../_resources/b7757512b3c726fcfb6def6610828ba1.png)
On this report, There I knew for sure that the last 2 were C2 addresses that the maldoc sent collected information to it but there is one address that remain unknown and its reputation is also malicious 
![02e9082097b04526afd43de7b0925a47.png](../../_resources/02e9082097b04526afd43de7b0925a47.png)
Which I found it on NetworkMiner and there 6 packets where captured from this address
![dd66152f07691d7821d7a0d2b479f45a.png](../../_resources/dd66152f07691d7821d7a0d2b479f45a.png)
Sadly nothing useful could be found, look like the connection wasn't establish?
</div>

I tried to do some research about this malware and found [Palo Alto Unit 42 Blog](https://unit42.paloaltonetworks.com/hancitor-infections-cobalt-strike/) that is very informative 
<div align=center>

![5cf6c8ce9985a0c0e53b07d625d4ee65.png](../../_resources/5cf6c8ce9985a0c0e53b07d625d4ee65.png)
After reading this blog, I figured it out what did i miss. including how the user was tricked to download the malware

![83b906928c28c067cad5566fd068b315.png](../../_resources/83b906928c28c067cad5566fd068b315.png)
![deb659bf7b013736f43c6956802c6814.png](../../_resources/deb659bf7b013736f43c6956802c6814.png)
And it turns out, I was blinded by the same filter and should focus on http filter instead also this malware also has a second payload as an executable file

![215098366dd6937c5e96c17043b23033.png](../../_resources/215098366dd6937c5e96c17043b23033.png)
![3e7ca580ddd36f1470a2a721a3c8ea4f.png](../../_resources/3e7ca580ddd36f1470a2a721a3c8ea4f.png)
Here after it contacts first C2 server, it also contacts another one and requested for 2 `.bin` files and 1 executable file so this is the second payload that I was looking for
![f035136b610b4c89c5c8e30d8ec4ec88.png](../../_resources/f035136b610b4c89c5c8e30d8ec4ec88.png)
I searched it on NetworkMiner to grab the hash and search on VirusTotal again

![52f11385a9a27ad3980137b1c778b05f.png](../../_resources/52f11385a9a27ad3980137b1c778b05f.png)
Sure enough, It's ficker stealer
![bd95853825d4493c5b0cfc1ba359c11f.png](../../_resources/bd95853825d4493c5b0cfc1ba359c11f.png)
The contacted URLs are also similiar 
![3a6587ca72791ff5c53525ae0bdeaa90.png](../../_resources/3a6587ca72791ff5c53525ae0bdeaa90.png)
it also confirmed the public IP address of the victim machine 
</div>

Hancitor malware will send Cobalt Strike when it infects a host that joined Active Directory and from the image below (request that was sent to C2)
<div align=center>

![7534a958a89ea8cbc1332de7cc4c1e05.png](../../_resources/7534a958a89ea8cbc1332de7cc4c1e05.png)
The domain is `STORMRUNCREEK`
![25d6047569164bafa9a88743884f5b2b.png](../../_resources/25d6047569164bafa9a88743884f5b2b.png)
These request might related to Cobalt Strike, so now we got the Cobalt Strike C2 server address
![213aa842b53037bcdc4d2b1d4e809394.png](../../_resources/213aa842b53037bcdc4d2b1d4e809394.png)
The connection were established to port 443 of Cobalt Strike C2 Server but since its encrypted, i guessed its enough for now and go back to the question how did this user get tricked to download the malicious maldoc.
![d9662c10fcd5d6d661b57a74be8f7bb6.png](../../_resources/d9662c10fcd5d6d661b57a74be8f7bb6.png)
![b93c32e9d871bbe2fe9f5643101ef65f.png](../../_resources/b93c32e9d871bbe2fe9f5643101ef65f.png)
The answer was already covered from the Unit42 blog post, There are some communications with google docs so I think this is the answer
</div>


* * *
> Investigate the PCAP file, what is one of the popular document signing services used by the attacker to deliver the malware?
```
docusign
```

> Investigate the PCAP file, what is the full URL used by the attacker to create the malicious document?
```
http://ecofiltroform.triciclogo.com/swellheaded.php
```

> On the malicious website from the previous question, what kind of encoding technique used by the attacker to create the malicious document?
```
base64
```

> What is the name of the malicious document opened by the user?
```
0524_4109399728218.doc
```

> What malware family this malicious file belongs to?
```
hancitor
```

> After the user interacts with the malicious file, it runs malicious DLL on the system. What is the DLL run command?
```
rundll32.exe c:\users\[username]\appdata\roaming\microsoft\word\startup\ket.t,EUAYKIYBPAX
```

> What is the C2 URL?
```
http://euvereginumet.ru/8/forum.php
```

> What is the URL that serves the payload?
```
http://gromber6.ru/6hjusfd8.exe
```

> What is the name of the malware this payload links back to?
```
ficker stealer
```

> What is the popular hacking framework being used in this campaign?
```
cobalt strike
```

> What is the popular storage service used by the attacker to deliver the malware?
```
google docs
```

* * *
## Summary
The URL of phishing google docs was sent to user and tricked user to download the Malicious Document (Hancitor malware) that contains malicious VBA macros which will be executed when it opens and user opened it then `rundll32.dll` command was ran, Its send the information about the user machine to C2 server which this machine was also joined the domain then the requests was made to another C2 server to download ficker stealer malware and cobalt strike C2 server connection were established.

<div align=center>

![798ba05652d55f1f80221e88551808a9.png](../../_resources/798ba05652d55f1f80221e88551808a9.png)
</div>

* * *
