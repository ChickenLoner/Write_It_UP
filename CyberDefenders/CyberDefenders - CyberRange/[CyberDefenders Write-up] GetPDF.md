# [CyberDefenders - GetPDF](https://cyberdefenders.org/blueteam-ctf-challenges/getpdf/)
Created: 22/06/2024 19:13
Last Updated: 23/06/2024 00:47
* * *
>Category: Malware Analysis
>Tags: PDF, Macro, CVEs, Exploit, Wireshark, NetworkMiner, de4js, JavaScript, scdbg, T1203, T1071, T1189
* * *
**Scenario**:
PDF format is the de-facto standard in exchanging documents online. Such popularity, however, has also attracted cyber criminals in spreading malware to unsuspecting users. The ability to generate malicious pdf files to distribute malware is a functionality that has been built into many exploit kits. As users are less cautious about opening PDF files, the malicious PDF file has become quite a successful attack vector.
The network traffic is captured in lala.pcap contains network traffic related to a typical malicious PDF file attack, in which an unsuspecting user opens a compromised web page, which redirects the user’s web browser to a URL of a malicious PDF file. As the PDF plug-in of the browser opens the PDF, the unpatched version of Adobe Acrobat Reader is exploited and, as a result, downloads and silently installs malware on the user’s machine.

As a soc analyst, analyze the PDF and answer the questions.

**Supportive resources**:
- [PDF format structure](https://resources.infosecinstitute.com/topic/pdf-file-format-basic-structure/)
- [Portable document format](https://web.archive.org/web/20220113130243/https://www.adobe.com/content/dam/acom/en/devnet/pdf/pdfs/PDF32000_2008.pdf)

**Helpful Tools**:
- [de4js](https://lelinhtinh.github.io/de4js/)
- [pdfid](https://github.com/Rafiot/pdfid)
- [pdfparser](https://github.com/smalot/pdfparser)
- [peepdf](https://github.com/jesparza/peepdf)
- [PDFStreamDumper](https://github.com/dzzie/pdfstreamdumper)
- [WireShark](https://www.wireshark.org/download.html)
- [tshark](https://www.wireshark.org/docs/man-pages/tshark.html)
- [scdbg](http://sandsprite.com/blogs/index.php?uid=7&pid=152)
- [NetworkMiner](https://www.netresec.com/?page=NetworkMiner)
* * *
## Questions
> Q1: How many URL path(s) are involved in this incident?

![34b490a97bfd4d08bc3d38ce93a707bc.png](../../_resources/34b490a97bfd4d08bc3d38ce93a707bc.png)

To make it easy, lets do this inside NetworkMiner and go to DNS tab then we can see DNS query to 1 url that should be the one, we're looking for

![9ccb41430e865c96c6efced3913cf8f4.png](../../_resources/9ccb41430e865c96c6efced3913cf8f4.png)

There are not much communications were captured so it would be easier to move to wireshark 

![3789c1aabcd3d8a4bd5db01003626496.png](../../_resources/3789c1aabcd3d8a4bd5db01003626496.png)

It we filtered for HTTP protocol then we can see there are 6 different url involved in this incident

```
6
```

> Q2: What is the URL which contains the JS code?

![3789c1aabcd3d8a4bd5db01003626496.png](../../_resources/3789c1aabcd3d8a4bd5db01003626496.png)

Open pcap file with Wireshark then inspect each conversation to find which URL has JS code inside

![ef540c119b150a2f860aff091c6b6154.png](../../_resources/ef540c119b150a2f860aff091c6b6154.png)

Which you can see that this URL has very suspicious obfuscated JavaScript inside script tag 

```
http://blog.honeynet.org.my/forensic_challenge/
```

> Q3: What is the URL hidden in the JS code?

![eaa0d7d9a1b66893a063e45853fc798d.png](../../_resources/eaa0d7d9a1b66893a063e45853fc798d.png)

We can make this script look a little more readable by using https://beautifier.io/

![3ba6de161ddd5b9fda54584399f7deb3.png](../../_resources/3ba6de161ddd5b9fda54584399f7deb3.png)

Then we will use https://playcode.io/empty_javascript to play with this JS and we can see that one the line 24 is the one that execute payload so lets confirm it with `console.log(GaDemee)` , now it confirmed that `GaDemee` is `eval()` function then the argument inside should be the command that will be executed 

![f5cc8c7d63c17e01136010a482ab2ea0.png](../../_resources/f5cc8c7d63c17e01136010a482ab2ea0.png)

We can see that it inserts an iframe into the document, which loads content from the specified URL.

```
http://blog.honeynet.org.my/forensic_challenge/getpdf.php
```

![e2e0af616c72f3b530f5acac8696655f.png](../../_resources/e2e0af616c72f3b530f5acac8696655f.png)

Which you can see that after this page was requested, URL that we found was requested and then it will redirect to download another pdf file

> Q4: What is the MD5 hash of the PDF file contained in the packet?

![e89b69bb24412818a2ef4df6b02d9b7d.png](../../_resources/e89b69bb24412818a2ef4df6b02d9b7d.png)

Go to NetworkMiner to get the hash of pdf file we found earlier

```
659cf4c6baa87b082227540047538c2a
```

> Q5: How many object(s) are contained inside the PDF file?

![dde76f305907416169bd94fef77839c8.png](../../_resources/dde76f305907416169bd94fef77839c8.png)

We can see on wireshark that this pdf file contains JS so we will go to NetworkMiner to find this file that was assembled automatically when we opened pcap file on NetworkMiner

![0824195fb08f6a37a240273b3272b407.png](../../_resources/0824195fb08f6a37a240273b3272b407.png)

Then open pdf file with PDFStreamDumper, we will see how many objects contains within this pdf file

```
19
```

> Q6: How many filtering schemes are used for the object streams?

![5f7d93f150c2e528830aac774b3e27e2.png](../../_resources/5f7d93f150c2e528830aac774b3e27e2.png)

It will be easier to find them on Wireshark so after reviewing this conversation, we can see that there are 4 filters that were applied to these object streams

```
4
```

> Q7: What is the number of the 'object stream' that might contain malicious JS code?

![4d054d40db112e7789c8013da073d0d8.png](../../_resources/4d054d40db112e7789c8013da073d0d8.png)

We can easily obtain an answer here, its an object 5

```
5
```

![b908fc8cc7594bc9f53650010453f209.png](../../_resources/b908fc8cc7594bc9f53650010453f209.png)

So lets examine this JS on PDFStreamDumper

![bca48fafecad4348cc5597f350c5ae59.png](../../_resources/bca48fafecad4348cc5597f350c5ae59.png)
![6805eafeab3bf5edf7a50e71ce84d6e2.png](../../_resources/6805eafeab3bf5edf7a50e71ce84d6e2.png)

According to ChatGPT, this JS code will scan for annotations and look for strings which will eventually decoded and execute as shellcode

> Q8: Analyzing the PDF file. What 'object-streams' contain the JS code responsible for executing the shellcodes? The JS code is divided into two streams. Format: two numbers separated with ','. Put the numbers in ascending order

![639726657d25a040e8587f1ed2c613a1.png](../../_resources/639726657d25a040e8587f1ed2c613a1.png)

First we will need to find all annotations which will be scanned by JS code and we will find it on object 3

We can see that it reference to object 6 and object 8 

![888a7bcddd5f062511f743f4b7ec3dd7.png](../../_resources/888a7bcddd5f062511f743f4b7ec3dd7.png)

Which object 6 leads us to object 7 

![58f13e7307d6fa46f6f9e647cc76b645.png](../../_resources/58f13e7307d6fa46f6f9e647cc76b645.png)

And object 7 contains very long hex string and another thing that we could see right away is a lot of same pattern that repeating itself so this might need a little bit of cleansing before it could be useful

![8dbcb8e41e35984688d7021b4587d305.png](../../_resources/8dbcb8e41e35984688d7021b4587d305.png)

Now back to object 8 which will lead us to object 9

![f112a57ad1b2db2207cb033eaaddc80e.png](../../_resources/f112a57ad1b2db2207cb033eaaddc80e.png)

And it contains long strings that needed to be process 

![918dd43fc43c1ab8140e88618efb91ef.png](../../_resources/918dd43fc43c1ab8140e88618efb91ef.png)

But from both object, we didn't see any pattern relatively closed to ` var arr = $S.split(/U_155bf62c9aU_7917ab39/);` which will be splited yet so after searching other object, object 10 contains long string which this pattern

![7531e62101a079161126dddb07870d4f.png](../../_resources/7531e62101a079161126dddb07870d4f.png)

So now to sum up what we have found, look like JS code will gets the content of the object 10 and removes the `U_155bf62c9aU_7917ab39` string from it, so we will have to remove this string first and try to make some senses of it

![869ab3c99b619a2cb1a1af51acc2a171.png](../../_resources/869ab3c99b619a2cb1a1af51acc2a171.png)

Then we will use `sed 's/U_155bf62c9aU_7917ab39//g' obj10.txt | xxd -r -p` to remove unwanted string from object 10 and output it as human-readable text

![aa7e0a4a8d3c054a1fc4cbee8e950de0.png](../../_resources/aa7e0a4a8d3c054a1fc4cbee8e950de0.png)

Put it in https://beautifier.io/, then we will see it get content of object 9 and replace specific strings with `%` and then concatenate with object 7 that will be replaced by specific strings with `%` too and then lastly it will be executed by `eval()` 

Now it is confirmed that object 7 and 9 are the shellcodes that was divided

```
7,9
```

> Q9: The JS code responsible for executing the exploit contains shellcodes that drop malicious executable files. What is the full path of malicious executable files after being dropped by the malware on the victim machine?

![c7302a0be821371bbad3af051d93ec50.png](../../_resources/c7302a0be821371bbad3af051d93ec50.png)

To get full JS script that will launch shellcode we will use `sed 's/X_17844743X_170987743/%/g' obj9.txt | xxd -r -p > shellcode.js && sed 's/89af50d/%/g' obj7.txt | xxd -r -p >> shellcode.js` then we will have `shellcode.js` which have combined 2 shellcode from both object back to one 

![f8b4decc8c373c5f4d469ac6c0717729.png](../../_resources/f8b4decc8c373c5f4d469ac6c0717729.png)

Which you can see that look like there are several types of payload for each executable that could be used here which are
- `calc.exe`
- `freecell.exe`
- `notepad.exe`
- `cmd.exe`

![29707f5cc3f09eabf7709af626b03ff8.png](../../_resources/29707f5cc3f09eabf7709af626b03ff8.png)

To find out, we need to pick one of them to try out with shellcode debugger and the result should not be different since the only different is which executable that will be launched

![2133958eb44ce7cf074257c0212ae62c.png](../../_resources/2133958eb44ce7cf074257c0212ae62c.png)

Then after emulate how this shellcode work with shellcode debugger, we can see that it will download file from specific url and execute it

![8261a0249f91f8fc8b31c236e30b1844.png](../../_resources/8261a0249f91f8fc8b31c236e30b1844.png)

Here is the result from `notepad.exe` payload, look like there is a little bit different between both payload which is URL to download an executable file but in the end, it will be downloaded to the same path and execute it

```
c:\WINDOWS\system32\a.exe
```

> Q10: The PDF file contains another exploit related to CVE-2010-0188. What is the URL of the malicious executable that the shellcode associated with this exploit drop?

![a70081af97f2068f5f49a026f0848904.png](../../_resources/a70081af97f2068f5f49a026f0848904.png)

Now we're back to wireshark and we can see that another executable file which is not matched what we found from 4 payloads from above

![4643ccf881c758ad940e363d1b9d538e.png](../../_resources/4643ccf881c758ad940e363d1b9d538e.png)

We still have object 11 that we didnot pay any attention to it until now

![f61eb785f8a750aaf7aaa5e9c6afd51e.png](../../_resources/f61eb785f8a750aaf7aaa5e9c6afd51e.png)

This look quite messy so we will dump it first (Right click -> Save As)

![32d78caaae1b257a05077a5a738368ac.png](../../_resources/32d78caaae1b257a05077a5a738368ac.png)

It is zlib compressed data, now it makes sense why it looks so messy

![2256097e6fd2dc88f84fa724f7f5d4d2.png](../../_resources/2256097e6fd2dc88f84fa724f7f5d4d2.png)

Now go back to PDFStreamDumper then go to "Tools -> Zlib Decompress_File" and select the file that we dumped earlier


![6986d3fa3ba62e1df532ffc0057c1bc1.png](../../_resources/6986d3fa3ba62e1df532ffc0057c1bc1.png)
![7fa1a13e95c872c0010867665c77a6cd.png](../../_resources/7fa1a13e95c872c0010867665c77a6cd.png)

Now we have XML document

![b60ebd76bb190b2d8b474f687a2080f4.png](../../_resources/b60ebd76bb190b2d8b474f687a2080f4.png)

This look like a payload encoded with base64 so I did some research on this vulnerability and find out that we are in the right track

- [Adobe Reader PDF - LibTiff Integer Overflow Code Execution](https://www.exploit-db.com/exploits/11787)

![0d14220696b4171bea54884f56a154b2.png](../../_resources/0d14220696b4171bea54884f56a154b2.png)

Now put these base64 inside CyberChef and to make a shellcode, we need to use "From Base64 -> To Hex -> Remove whitespace" 

![a2ba12c8a634157924c9e1172da947ff.png](../../_resources/a2ba12c8a634157924c9e1172da947ff.png)

Save it as a file then use shellcode debugger to get the answer

```
http://blog.honeynet.org.my/forensic_challenge/the_real_malware.exe
```

> Q11: How many CVEs are included in the PDF file?

Turn out each payloads are designed for each vulnerability so lets find each one of them by searching on your search engine and we have to pick a line that might indicates that vulnerability

![2ccf48819cf6211859a9240c5b1db97b.png](../../_resources/2ccf48819cf6211859a9240c5b1db97b.png)

Lets start with `calc.exe` payload, we will use this line to search 

![54fef308635422dbfee14abf4b3f02fd.png](../../_resources/54fef308635422dbfee14abf4b3f02fd.png)

So this payload was here to exploit [CVE-2009-4324 Adobe Doc.media.newPlayer Use After Free Vulnerability](https://www.exploit-db.com/exploits/16623)

![cdf66b522196aafad3ef67acec3aa880.png](../../_resources/cdf66b522196aafad3ef67acec3aa880.png)

Next is `freecell.exe` payload, this variable seem unique enough to be searched

![a575fd68d655100f848e9a9c3cb1100a.png](../../_resources/a575fd68d655100f848e9a9c3cb1100a.png)

and it landed us with [CVE-2008-2992 Adobe Reader Javascript Printf Buffer Overflow Exploit](https://www.exploit-db.com/exploits/7006)

![a98b103d7648261165e52396312d3ed5.png](../../_resources/a98b103d7648261165e52396312d3ed5.png)

Third one is `notepad.exe` payload

![30a1756236379d2d6de35785576ba513.png](../../_resources/30a1756236379d2d6de35785576ba513.png)

That leads us to [CVE-2007-5659 Adobe Collab.collectEmailInfo() Buffer Overflow](https://www.exploit-db.com/exploits/16674)

![4c69c6f7e285f1bef8d8934072bacc72.png](../../_resources/4c69c6f7e285f1bef8d8934072bacc72.png)

And lastly, `cmd.exe` payload

![521890c3e1ce22ac0a111e93da51a972.png](../../_resources/521890c3e1ce22ac0a111e93da51a972.png)

Which leads us to [CVE-2009-0927 Adobe Collab.getIcon() Buffer Overflow](https://www.exploit-db.com/exploits/16681)

Now if we count the fifth vulnerability we found on previous task, it will be 5 vulnerabilities in total!

```
5
```

![df55e8d265ac373f94b791f788fb23ad.png](../../_resources/df55e8d265ac373f94b791f788fb23ad.png)

It could be 6 since Exploits_Scan from PDFStreamDumper found this one on object 5 too but we're good now

![9cc22601691e614200d16652f81020db.png](../../_resources/9cc22601691e614200d16652f81020db.png)
* * *