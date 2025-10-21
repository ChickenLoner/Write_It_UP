# [CyberDefenders - MalDoc101](https://cyberdefenders.org/blueteam-ctf-challenges/maldoc101/)
Created: 21/06/2024 20:48
Last Updated: 21/06/2024 21:39
* * *
>Category: Malware Analysis
>Tags: Malicious Document, Macro, OLEDUMP, CyberChef, Strings, VirusTotal, T1105, T1059
* * *
It is common for threat actors to utilize living off the land (LOTL) techniques, such as the execution of PowerShell to further their attacks and transition from macro code. This challenge is intended to show how you can often times perform quick analysis to extract important IOCs. The focus of this exercise is on static techniques for analysis.

As a security blue team analyst, analyze the artifacts and answer the questions.

**Suggested Tools**:
- REMnux Virtual Machine (remnux.org)
- Terminal/Command prompt w/ Python installed
- [Oledump](https://blog.didierstevens.com/programs/oledump-py/)
- Text editor
* * *
## Questions
> Q1: Multiple streams contain macros in this document. Provide the number of highest one.

![66aa4d8eb04afd4704f031510902ab2c.png](../../_resources/66aa4d8eb04afd4704f031510902ab2c.png)

We can a sample which whish is Microsoft Document Macro even though it was named `sample.bin`

![a79337ba56e921da54d04eed94e6c147.png](../../_resources/a79337ba56e921da54d04eed94e6c147.png)

I always make sure to use `oleid` first to identify VBA Macros within any document files which there is so we can proceed with `olevba` to dump all macros embbed on this file

![365309a3c0ba807ce3db20f8cd4a7362.png](../../_resources/365309a3c0ba807ce3db20f8cd4a7362.png)

But to answer this question, we need to use `oledump.py` which you can see that there are 3 objects that contain macros and the highest one is stream 16

```
16
```

> Q2: What event is used to begin the execution of the macros?

![196167a78d0fda58c8520f30289d4182.png](../../_resources/196167a78d0fda58c8520f30289d4182.png)

Using `olevba` then we can see that this tool already detect which event reponsisble for execution of macros

```
Document_Open
```

> Q3: What malware family was this maldoc attempting to drop?

![f6640c9d2ca256ae6262e577dd0ad456.png](../../_resources/f6640c9d2ca256ae6262e577dd0ad456.png)

Using `md5sum` or other hash generator then search it on VirusTotal

```
emotet
```

> Q4: What stream is responsible for the storage of the base64-encoded string?

![6c6734e18ee32f9652992b3437d4e35c.png](../../_resources/6c6734e18ee32f9652992b3437d4e35c.png)

After dumping all macros with `olevba`, we can see that there is an object that contains there large and weird base64 encoding strings

![558fbebbb834013b4fa5516899871be3.png](../../_resources/558fbebbb834013b4fa5516899871be3.png)

Go back to `oledump.py` and identify stream of this object

```
34
```

> Q5: This document contains a user-form. Provide the name?

![47d2a7f31ccd9725e35a932881be4286.png](../../_resources/47d2a7f31ccd9725e35a932881be4286.png)

lets open this maldoc on LibreOffice which macro is turn off by default so we donot have to worry about it

![a7889ab1337d9496214d243b555af9cc.png](../../_resources/a7889ab1337d9496214d243b555af9cc.png)

Then go to "Tools" > "Macros" > "Edit Macros..." to edit/view all macros on this document file

![7916e21a7ef5891409d24c4b4d0508d0.png](../../_resources/7916e21a7ef5891409d24c4b4d0508d0.png)

Which we will see the name of user-form inside this document

```
roubhaol
```

> Q6: This document contains an obfuscated base64 encoded string; what value is used to pad (or obfuscate) this string?

![c7ce7ecc819afbd3e64e5e313fbcf1b2.png](../../_resources/c7ce7ecc819afbd3e64e5e313fbcf1b2.png)

there are these weird string that keep repeating so we need to remove them to get an actual base64 encoded string that was intended to be executed

![25d95dc03f10b56ebfc11ebfcf46d2f5.png](../../_resources/25d95dc03f10b56ebfc11ebfcf46d2f5.png)

Go back to `olevba` result, we can see which object responsible for removing these padding and executing malicious code

![44234ebe1abdd3f68bc72a53c39d3748.png](../../_resources/44234ebe1abdd3f68bc72a53c39d3748.png)

Use `oledump.py` again to find which stream match this object name

![0af55ba4100e039eb4015f879741b631.png](../../_resources/0af55ba4100e039eb4015f879741b631.png)

Then we will use `oledump.py -s 15 --vbadecompresscorrupt sample.bin > macro.vba` to dump this object into a file with VBA decompression to analyze which you can see from an above that this string is a pattern to be removed

```
2342772g3&*gs7712ffvs626fq
```

> Q7: What is the program executed by the base64 encoded string?

Lets dump object that store base64 encoded string to a file with `oledump.py -s 34 -d sample.bin > sample.b64`

![073f2b593edd18b8892912dfa6fcd6ff.png](../../_resources/073f2b593edd18b8892912dfa6fcd6ff.png)
![3c318deab4e3968f4b7f8085c1eef16d.png](../../_resources/3c318deab4e3968f4b7f8085c1eef16d.png)

Then use find and replace function to remove all strings that match the pattern we found earlier

![d449c5993ffcc75659c3c9b65290da4e.png](../../_resources/d449c5993ffcc75659c3c9b65290da4e.png)

Now after removing padding strings, we come down to this and as you can see we need to do a little bit of manual work to remove unrelated data

![0f9a21c921d1a279ac852afc25cdf7e2.png](../../_resources/0f9a21c921d1a279ac852afc25cdf7e2.png)

Now we can see that it is a powershell command to execute this base64 encoded string

```
powershell
```

> Q8: What WMI class is used to create the process to launch the trojan?

![2721ae24462e7e35c28016b5564498bd.png](../../_resources/2721ae24462e7e35c28016b5564498bd.png)

Decode base64 string then we will see that `win32_Process` is used here

```
win32_Process
```

> Q9: Multiple domains were contacted to download a trojan. Provide first FQDN as per the provided hint.

![f100f9f5185167eb83bbf2fe5eaea0fa.png](../../_resources/f100f9f5185167eb83bbf2fe5eaea0fa.png)
```
haoqunkong.com
```

![93186614fc76af03c012822366527d6f.png](../../_resources/93186614fc76af03c012822366527d6f.png)
* * *
