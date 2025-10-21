# [CyberDefenders - Phobos](https://cyberdefenders.org/blueteam-ctf-challenges/phobos/)
Created: 25/06/2024 18:05
Last Updated: 30/11/2024 02:44
* * *
>**Category**: Malware Analysis
>**Tags**: IDA, Ghidra, x64dbg, PeStudio, CFF Explorer
* * *
**Scenario:**
You are part of the cybersecurity response team at Global Logistics Solutions, a leading organization in logistics and supply chain management. Recently, an unexpected spike in Remote Desktop Protocol (RDP) traffic has been detected, coinciding with reports of file encryption and ransom demands from various endpoints within the network. Initial investigations suggest that a ransomware attack is underway and you have been provided with the ransomware executable. Your task is to conduct a thorough analysis of the malware to understand its behavior, encryption mechanisms, and any unique characteristics that can aid in mitigation efforts.

**Tools**:
- x32dbg
- HxD Hex Editor
- IDA
- Ghidra
- CFF Explorer
- PEStudio
- PEiD

Link: https://cyberdefenders.org/blueteam-ctf-challenges/phobos/
* * *
## Questions
>Q1: Understanding which hashing algorithm is used by the malware helps understand how the malware functions. What is the hashing algorithm used by the malware?

This lab provides us with a **Phobos** ransomware sample, so knowing the type of malware will help the investigation proceed much faster with online resources.

![e575521908219ed67ed638b942398774.png](/resources/e575521908219ed67ed638b942398774.png)

But we still need to examine the sample ourselves first, and what we will notice from **Detect It Easy** is the high entropy on .cdata section indicates that it could be encrypted data or packed payload inside this section.

Next is the Compiler indicates that we will have to use Ghidra or IDA to disassemble / decompile this sample for static analysis.

Next is to confirm whatever we could extract anything from .cdata section, is it packed or not?

![276c045b510717d796aeea31a3ea07ca.png](/resources/276c045b510717d796aeea31a3ea07ca.png)

I checked it on [unpac.me](https://www.unpac.me/results/12099436-4474-436c-9229-95e79990d28e) which could automate unpacking process for us but the result shows that this sample is not packed.

![48814079ffd68088e00146b3941e4a77.png](/resources/48814079ffd68088e00146b3941e4a77.png)

It has so many capabilities as we can see here.

![c87567f38dc56e83e41d06e1866f271b.png](/resources/c87567f38dc56e83e41d06e1866f271b.png)

Next, I went to [VirusTotal](https://www.virustotal.com/gui/file/43f846c12c24a078ebe33f71e8ea3b4f75107aeb275e2c3cd9dc61617c9757fc/behavior) to understand more behavior of this ransomware which shown file extension that was used to encrypt files on infected system.

![6e55ff1ec4fac66d7a98e4f3f9e7f968.png](/resources/6e55ff1ec4fac66d7a98e4f3f9e7f968.png)

Doing a little bit of research then we could see that this link to 8Base Group then we could see different resources related to this ransomware.

![69a8ed38bbff2cb740dbf753bca4f8e3.png](/resources/69a8ed38bbff2cb740dbf753bca4f8e3.png)

Its time to use online resources as our disposal. The first resource that really helped me complete this lab is a [blog on Cisco Talos](https://blog.talosintelligence.com/deep-dive-into-phobos-ransomware/) highlighting the decrypting Phobos configuration file, which is a very important process that a ransomware will do some certain actions based on these configurations and we can also see that this ransomware will check CRC32 hash of .cdata section before decrypting it.

![f70e32a1d1f488184e96e1a5ef39fb04.png](/resources/f70e32a1d1f488184e96e1a5ef39fb04.png)

To confirm that we have identical functions, I disassembled our sample using IDA Free and verified our hypothesis. The next step will be renaming these functions and variables to match those in Talos's sample.

```
CRC32
```

>Q2: Following up on the previous question. Could you provide the hard-coded value of the .cdata checksum?

![2f498ea342b1ce8bb65ac39af0fca101.png](/resources/2f498ea342b1ce8bb65ac39af0fca101.png)

We know that `payload_hash` variable store checksum of .cdata section so we could follow it to retrieve the answer of this question right here.
```
0D55F8833
```

>Q3: Different malware versions may be linked to specific cybercriminal groups or campaigns, thus providing valuable leads for your threat intel analysts. What is the malware's version?

![4b7d96bda89656dcf50e9fa63f72ea45.png](/resources/4b7d96bda89656dcf50e9fa63f72ea45.png)

From the blog, we also know that Phobos has a debug file feature that prints out its version if a debug file exists. In the 8Base campaign, this file is named suppo. The intended way to solve this question might have been to create the debug file and execute the ransomware to generate the log files. However, I took a guess and submitted Talos's sample version as the answer, and it turned out to be correct. So, I guess I don't need to execute the ransomware anymore. 😅

![7f48bc6f840dc3d561e95b192f49da15.png](/resources/7f48bc6f840dc3d561e95b192f49da15.png)

Talos also made a malware configuration index of this ransomware which we can see the malware version ID entry index right here.

![8d3c0fb3c7a186453cc07132c17ee7ee.png](/resources/8d3c0fb3c7a186453cc07132c17ee7ee.png)

This time I used Ghidra to decompiled and search for `mal_GetDecryptedConfigVar(0x33` (named after Talos's sample) which we can see the function responsible for debugging right here.

```
2.9.1
```

>Q4: Malware sometimes masquerades as legitimate DLL files to bypass standard security measures and evade detection. Identifying which legitimate DLL a malware is impersonating allows for more accurate and effective detection mechanisms. Could you provide the name of the legitimate DLL that the malware is masquerading as?

![c5fef63982a87ff4f5bc3fb9d806c707.png](/resources/c5fef63982a87ff4f5bc3fb9d806c707.png)

I imported the sample into pestudio and examined the imported libraries. I noticed that `ole32.dll` didn't fit the context of this ransomware at all (you can find other dlls on many pe samples), and it turned out to be the right call!

```
ole32.dll
```

>Q5: It is important to understand what this malicious DLL is used for and how it works. Could you analyze it and provide the first API function it calls?

For this one, I unfortunately don't have a detailed analysis to offer, since I merely guessed it.😅

Many malicious DLLs call `CreateProcessW` to spawn another malicious executable or script. This is why `CreateProcessW` is often the first function invoked, as it allows the malware to continue its execution by creating new processes.

![02eb72afc6d272f11859ef202bbd0d1c.png](/resources/02eb72afc6d272f11859ef202bbd0d1c.png)

So I traced back to the function responsible for this which I found out that it will execute command / shell 

![287ee4c50ed3461dfca7b24d3144ea6d.png](/resources/287ee4c50ed3461dfca7b24d3144ea6d.png)

Which we can see them on VirusTotal.
```
CreateProcessW
```

>Q6: In ransomware attacks, the malware often terminates any processes that might disrupt its encryption before starting. Could you provide the address at which the process list decryption function is called?

Second online resource I utilized on this lab is a [blog on Threatdown](https://www.threatdown.com/blog/a-deep-dive-into-phobos-ransomware/) which also conducted malware analysis on Phobos ransomware that resembles our sample just like Talos's sample. This resource highlighted various functionalities of this ransomware which really helped me understand how this ransomware worked and completed this lab.

![576a869729e4e0b9bda68ecda623421b.png](/resources/576a869729e4e0b9bda68ecda623421b.png)

So we know that this ransomware has a configuration data that will be decrypted which also contains list of processes that will be terminated during execution time of this ransomware.

![14ad027ecc8d091bda62acf1180ac77e.png](/resources/14ad027ecc8d091bda62acf1180ac77e.png)

First, I opened Ghidra and located a reference to the `TerminateProcess` API, which led me to the function responsible for killing processes. However, since the question asks for the process list decryption function, we need to identify which function calls this one.

![0df9449cc7e852499a28bae85d78c2cf.png](/resources/0df9449cc7e852499a28bae85d78c2cf.png)

Then we will find that there is only function that calls this function so we will have to take a look at that function next.

![8d132bd7ba27705d8ddd063483339c08.png](/resources/8d132bd7ba27705d8ddd063483339c08.png)

To confirm if the function is the one we’re looking for, we can check the malware configuration index to identify which entry is linked to the process kill list. 

We can see that the value `0x0A` is associated with this list. This value will be passed to the `mal_GetDecryptedConfigVar` function, and we need to find the address of that function call to submit as the answer.

![fedb65df76a433d3bb347d3a51ab6a5b.png](/resources/fedb65df76a433d3bb347d3a51ab6a5b.png)

Then we will find that this function is really called for process list decryption function right here .

```
004022fb
```

>Q7: Malware often disables and turns off the security settings part of the victim's machine to avoid detection and stay under the radar. What's the first command the malware uses to turn off a critical security measure?

![809a09a039e4b2c5f6cb28d8f405796f.png](/resources/809a09a039e4b2c5f6cb28d8f405796f.png)

We can find it from threatdown blog or VirusTotal behavior tab right here.

```
netsh advfirewall set currentprofile state off
```

>Q8: Malware that successfully establishes a foothold and persistence can cause long-term damage by maintaining a presence on the infected system, allowing for continuous data theft, further infections, or other malicious activities. Could you provide the address of the function used by the malware for this purpose?

![b15ccfe215752e2a970cc360cac2bebe.png](/resources/b15ccfe215752e2a970cc360cac2bebe.png)

We know that Phobos have several persistence mechanism but the one that we can utilize API to pin point a function responsible for these persistence are API related registry such as `RegSetValueExW`

![49f857d61960c5f27a12885ce5cebe18.png](/resources/49f857d61960c5f27a12885ce5cebe18.png)

We will have to search this API on IDA since the answer format are made to match IDA function which we can see that a function that responsible for persistence is this function.

```
sub_401236
```

>Q9: Knowing how the malware communicates with its command and control (C2) server for data transmission is vital for understanding the threat's capabilities and potential reach. What protocol is used by the malware for C2 communication to transmit the data?

![397f69e70d12838e0d324759deeff2bf.png](/resources/397f69e70d12838e0d324759deeff2bf.png)

There are a lot of HTTP related API are utilized by this sample and 

![62f68eac569f64df5645da8c52f98468.png](/resources/62f68eac569f64df5645da8c52f98468.png)

After searching for these API to find out which function utilized them which we can see that there is a function responsible for HTTP communication (by sending POST request to specific address)

![8e280b08595a689f2d02188dc255261f.png](/resources/8e280b08595a689f2d02188dc255261f.png)

We can also find this information from Talos's blog as well.

```
http
```

>Q10: We need to understand further how the malware interacts with system hardware, how it monitors the system environment, and how it extends its reach. Could you provide the address of the thread used to check continuously for new disk connections?

![e03de5fabf54927187f2159be431b3ec.png](/resources/e03de5fabf54927187f2159be431b3ec.png)

Threatdown highlighted which function that responsible for network shares enumeration so I used this to find how a threat will be created for this activity.

![96339b461df3ed70b44568e1fdea03b8.png](/resources/96339b461df3ed70b44568e1fdea03b8.png)

We can see that it will create a thread with an address of each function but which function is responsible for network share enumeration? 

*I also found the function showed by threatdown but that not the right answer so I had to find the other function.*

![fca2ecbedd33b4eda8a4311c2d838912.png](/resources/fca2ecbedd33b4eda8a4311c2d838912.png)

I did a little bit more search on this ransomware which I finally found [fortinet blog](https://www.fortinet.com/blog/threat-research/deep-analysis-the-eking-variant-of-phobos-ransomware) highlighting a function used to monitor and scan future logical drive.

![8a1810e9d8a120cef3ad238af63d09c4.png](/resources/8a1810e9d8a120cef3ad238af63d09c4.png)

This function is really resembled a function from fortinet blog and the address of this function is the correct answer of this question.

```
00401cc5
```

- [Here](https://cybergeeks.tech/a-technical-analysis-of-the-backmydata-ransomware-used-to-attack-hospitals-in-romania/) is another resource I recommended to read which heavily rely on debugger to conduct malware analysis on BackMyData ransomware which is a variant of Phobos ransomware 

>Q11: The malware appears to be using different functions to encrypt small and large files. A check is performed before each encryption. The file size is compared to a specific value. Could you provide this value?

![1cf52de675f4c65c16c8aa9fbda2d8c7.png](/resources/1cf52de675f4c65c16c8aa9fbda2d8c7.png)

We could find this answer on threatdown blog right here, take a note at the value that used to compare then go back to our sample to find this value and identical instructions.

![176c63ea12464ca8e87602a0a411e322.png](/resources/176c63ea12464ca8e87602a0a411e322.png)

There you go.

```
180000
```

![6c0ef3efefc038c833cd8a8798eba49a.png](/resources/6c0ef3efefc038c833cd8a8798eba49a.png)

https://cyberdefenders.org/blueteam-ctf-challenges/progress/Chicken_0248/176/
Somehow I managed to complete this lab without using debugger but heavily relied on online resources but all good I guess?.
* * *


