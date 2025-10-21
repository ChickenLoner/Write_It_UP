# [CyberDefenders - XLM Macros](https://cyberdefenders.org/blueteam-ctf-challenges/xlm-macros/)
Created: 21/06/2024 00:22
Last Updated: 22/06/2024 02:03
* * *
>Category: Malware Analysis
>Tags: Excel 4 (XLM) Macros, Macro, OLEDUMP, XLMDeobfuscator, Office IDE, REMnux, T1485, T1136.001, T1071, T1083, T1033, T1140, T1059.003
* * *
Recently, we have seen a resurgence of Excel-based malicous office documents. Howerver, instead of using VBA-style macros, they are using older style Excel 4 macros. This changes our approach to analyzing these documents, requiring a slightly different set of tools. In this challenge, you, as a security blue team analyst will get hands-on with two documents that use Excel 4.0 macros to perform anti-analysis and download the next stage of the attack.

**Samples**:
- Sample1: MD5: fb5ed444ddc37d748639f624397cff2a
- Sample2: MD5: b5d469a07709b5ca6fee934b1e5e8e38

**Helpful Tools**:
- REMnux VM
- XLMDeobfuscator
- OLEDUMP with PLUGIN_BIFF
- Office IDE

**Suggested Resources**:
- [Example Excel 4 macro analysis from Hack-in-the-Box 2020 workshop](https://youtu.be/_rlEpPwSIoc?t=6421)
- [Excel 4 macro reference for Get.Workspace](https://0xevilc0de.com/excel-4-macros-get-workspace-reference/)
* * *
## Questions
> Q1: Sample1: What is the document decryption password?

![8a08b8d8e54a6acd4b445a31b2a335aa.png](../../_resources/8a08b8d8e54a6acd4b445a31b2a335aa.png)

We got 2 microsoft excel sample to investigate and we will have to investigate sample 1 first and step up to sample 2 

![fe65e2858be639ae0516bd206fd2c46b.png](../../_resources/fe65e2858be639ae0516bd206fd2c46b.png)

First, we will determine if this file is encrypted or not with `msoffcrypto-tool -t -v sample1-fb5ed444ddc37d748639f624397cff2a.bin`, we use `-t` which we can see it is encrypted so we will use `msoffcrypto-crack.py sample1-fb5ed444ddc37d748639f624397cff2a.bin` to find for the password hence the answer of this question

```
VelvetSweatshop
```

> Q2: Sample1: This document contains six hidden sheets. What are their names? Provide the value of the one starting with S.

![0c42ce263d814c87b3f5cfcb3cb28707.png](../../_resources/0c42ce263d814c87b3f5cfcb3cb28707.png)

We can easily obtain this answer by using `olevba` but to expand our knowledge and toolset, lets do it as this challenge was intended to be solved

![1c4131e353660f05da2e38d23c7e1381.png](../../_resources/1c4131e353660f05da2e38d23c7e1381.png)

First, using password we got from the last time to decrypt it then we will have a new file that all contents are decrypted 

![3e2608382f859e6d90056375408a46b1.png](../../_resources/3e2608382f859e6d90056375408a46b1.png)

Next lets use `oledump.py sample1_decrypt -p /opt/oledump-files/plugin_biff.py --pluginoptions '-x'` to dump all relevant information for us then at the top we can see all sheet information including hidden sheets

```
SOCWNEScLLxkLhtJp
```

> Q3: Sample1: What URL is the malware using to download the next stage? Only include the second-level and top-level domain. For example, xyz.com.

![3d93f066f84880aaf2d49d7d6d786151.png](../../_resources/3d93f066f84880aaf2d49d7d6d786151.png)

Back to `olevba`, just take a look that IOC this tool caught for us

```
http://rilaer.com
```

> Q4: Sample1: What malware family was this document attempting to drop?

![f6ac8715d4ac7514a31065706c902862.png](../../_resources/f6ac8715d4ac7514a31065706c902862.png)

Searching this domain on [urlhaus](https://urlhaus.abuse.ch/browse.php?search=rilaer.com) and you will see which malware family was dropped from this domain

```
Dridex
```

> Q5: Sample2: This document has a very hidden sheet. What is the name of this sheet?

![80b167adf3e964b5af52b9764f2d430e.png](../../_resources/80b167adf3e964b5af52b9764f2d430e.png)

First we need to check if this file is encrypted or not which is not

![df4fac18e454318f36b9c4e97fa1a89a.png](../../_resources/df4fac18e454318f36b9c4e97fa1a89a.png)

So we can proceed with `oledump.py sample2-b5d469a07709b5ca6fee934b1e5e8e38.bin -p /opt/oledump-files/plugin_biff.py --pluginoptions '-x'` which we can see that there is only 1 sheet that is very hidden

```
CSHykdYHvi
```

> Q6: Sample2: This document uses reg.exe. What registry key is it checking?

![572f47771a103183b918eee23fe2919a.png](../../_resources/572f47771a103183b918eee23fe2919a.png)

Using `olevba` and go to XLM Macro that was extracted for us, we can see that this macro is using registry key to check microsoft excel specific security option of a system

![ad7c99e854ec6215424d89988d0678b9.png](../../_resources/ad7c99e854ec6215424d89988d0678b9.png)

To find which key is really check, we need to use `strings` then you will found this registry key that related to VBA warning when open macro embbed microsoft excel file

![2ac61413960be0ab7a510dcb2177b031.png](../../_resources/2ac61413960be0ab7a510dcb2177b031.png)

Here is the describe for each value it could represent

```
VBAWarnings
```

> Q7: Sample2: From the use of reg.exe, what value of the assessed key indicates a sandbox environment?

![872e011cefafee2fb5d48397c41d2fb2.png](../../_resources/872e011cefafee2fb5d48397c41d2fb2.png)

We can see that after it retrieve `VBAWarnings` key value, it will be check with "0001" to check if this sheet will be closed or not

As we can see that "1" mean its potentially mean a sandbox which it need least restrictive to execute malware

```
0x1
```

> Q8: Sample2: This document performs several additional anti-analysis checks. What Excel 4 macro function does it use?

![f0dc0755d31849f3c44a8db1f38864f8.png](../../_resources/f0dc0755d31849f3c44a8db1f38864f8.png)

We can see these chains of formula so lets ChatGPT analyze them for us

![5035d676e3817a6f2064ca7f6dc1dc2a.png](../../_resources/5035d676e3817a6f2064ca7f6dc1dc2a.png)

So it use `GET.WORKSPACE` to retrieve environment information to determine if it should exit or not 

```
GET.WORKSPACE
```

> Q9: Sample2: This document checks for the name of the environment in which Excel is running. What value is it using to compare?
```
Windows
```

> Q10: Sample2: What type of payload is downloaded?

![edd15caf1f52a4eb4f8f4f1699008b17.png](../../_resources/edd15caf1f52a4eb4f8f4f1699008b17.png)

After It passed all tests, this macro will download a file from specific url and run it with `rundll32.exe` which is an executable file designed to run dll file hence the file that will be downloaded is dll 

```
dll
```

> Q11: Sample2: What URL does the malware download the payload from?

![428ae43e5155ac717f61399756400b65.png](../../_resources/428ae43e5155ac717f61399756400b65.png)
```
https://ethelenecrace.xyz/fbb3
```

> Q12: Sample2: What is the filename that the payload is saved as?

![150868672a430cc8ebb0254e48e82a81.png](../../_resources/150868672a430cc8ebb0254e48e82a81.png)
```
bmjn5ef.html
```

> Q13: Sample2: How is the payload executed? For example, mshta.exe
```
rundll32.exe
```

> Q14: Sample2: What was the malware family?

![7a03b7ff4c0f00d3c5578e40264f9e32.png](../../_resources/7a03b7ff4c0f00d3c5578e40264f9e32.png)

I couldn't find this domain on URLHaus so I searched it on google and found someone posted about this on T**X**ITTER

![827091ae449c5e9ffd30500d69d9c278.png](../../_resources/827091ae449c5e9ffd30500d69d9c278.png)
```
zloader
```

![d999e856aee989f74d85b8552156fea2.png](../../_resources/d999e856aee989f74d85b8552156fea2.png)
* * *
