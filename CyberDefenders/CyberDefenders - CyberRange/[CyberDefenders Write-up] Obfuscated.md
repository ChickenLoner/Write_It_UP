# [CyberDefenders - Obfuscated](https://cyberdefenders.org/blueteam-ctf-challenges/obfuscated/)
Created: 23/06/2024 01:41
Last Updated: 23/06/2024 20:22
* * *
>Category: Malware Analysis
>Tags: Malicious Document, Backdoor, OLEDUMP, CMDWatcher, JavaScript, T1140, T1059.007, T1204, T1566.001
* * *
**Scenario**
During your shift as a SOC analyst, the enterprise EDR alerted a suspicious behavior from an end-user machine. The user indicated that he received a recent email with a DOC file from an unknown sender and passed the document for you to analyze.

**Tools**
1. [CmdWatcher](https://www.kahusecurity.com/posts/cmd_watcher_updated.html)
2. [oledump](https://blog.didierstevens.com/programs/oledump-py/)
3. [sha256sum](https://linux.die.net/man/1/sha256sum)
* * *
## Questions
> Q1: What is the sha256 hash of the doc file?

![a16c0c8c14c4acf1135616cddf268833.png](../../_resources/a16c0c8c14c4acf1135616cddf268833.png)

After confirmed that we got the right file then we can proceed with your hash generation tool to obtain the answer

![9c46e3baf96c7fa50b308ccc4cedfccd.png](../../_resources/9c46e3baf96c7fa50b308ccc4cedfccd.png)

```
ff2c8cadaa0fd8da6138cce6fce37e001f53a5d9ceccd67945b15ae273f4d751
```

> Q2: Multiple streams contain macros in this document. Provide the number of lowest one.

![feacd1e9b70b38f8765a7c1f3f425ff9.png](../../_resources/feacd1e9b70b38f8765a7c1f3f425ff9.png)

By using `oledump.py` then you can see that there are macros in object 8 and 9 and also have OLE stream within object 17 too

```
8
```

> Q3: What is the decryption key of the obfuscated code?

![6f6630c18643ab6f0be79a8fe11bfd98.png](../../_resources/6f6630c18643ab6f0be79a8fe11bfd98.png)

I tried to dump macros with `olevba --deob 49b367ac261a722a7c2bbbc328c32545`, you can see that I used `--deob` because it was obfuscated then we can see this weird string will be pass down to `maintools.js` via `wscript`

![8e7141a7545339a155b52d20d9f8125e.png](../../_resources/8e7141a7545339a155b52d20d9f8125e.png)

Lets search file hash of this document file on any.run then we will see that it was actually passed to `maintools.js` as expected

```
EzZETcSXyKAdF_e5I2i1
```

> Q4: What is the name of the dropped file?
```
maintools.js
```

> Q5: This script uses what language?
```
JScript
```

> Q6: What is the name of the variable that is assigned the command-line arguments?

![e506e9760927e320aa221c408dafc4b6.png](../../_resources/e506e9760927e320aa221c408dafc4b6.png)

First, we will need to get `maintools.js` to analyze locally so we will go to VirusTotal of this malicious document file and go to Relation tab under Dropped Files section

![1392cc1628d52b41d6b8fa312f399749.png](../../_resources/1392cc1628d52b41d6b8fa312f399749.png)

Grab file hash from this [page](https://www.virustotal.com/gui/file/3a065547adb0afc63e318c2fa1f682108664e602934490a898c3de1b23975628/details) then search it on any.run

![94bbb858ce1a9bc0f9cad36c9a91f819.png](../../_resources/94bbb858ce1a9bc0f9cad36c9a91f819.png)

After we found this script on any.run, click "Get sample" to download a file in zip

![19cfca4656b437ed8dd9963542e09fd3.png](../../_resources/19cfca4656b437ed8dd9963542e09fd3.png)

after extracted file, then we can see that `wvy1` variable will be assigned a value from wscript argument that we found earlier

![6b79ab55ca0f527b83004931d9647813.png](../../_resources/6b79ab55ca0f527b83004931d9647813.png)

We can use https://beautifier.io/ to beautify JS code from this file and make our analysis a little bit easier

```
wvy1
```

> Q7: How many command-line arguments does this script expect?
```
1
```

> Q8: What instruction is executed if this script encounters an error?

![10affacbee15e98552915929d66eea14.png](../../_resources/10affacbee15e98552915929d66eea14.png)

This script using `try` and `catch(e)` to execute a script which mean any errors that occurs will be handled by `catch(e)` and it will quit wscript that was running this script

```
WScript.Quit()
```

> Q9: What function returns the next stage of code (i.e. the first round of obfuscated code)?

![d9e01fabd93694a8cbac7fdd5ae1ddd7.png](../../_resources/d9e01fabd93694a8cbac7fdd5ae1ddd7.png)

There is a very long base64 string declaration inside this function and it will return this value when this function was called  

![ec26428528d472a7a6c8a233da48ae10.png](../../_resources/ec26428528d472a7a6c8a233da48ae10.png)

Which will be called here and assigned to `ES3c` variable which will be passed to other 2 functions before execute with `eval`

```
y3zb
```

> Q10: The function LXv5 is an important function, what variable is assigned a key string value in determining what this function does?

![c8f293a5f3d3b922129559b4e0414042.png](../../_resources/c8f293a5f3d3b922129559b4e0414042.png)

We can see that `LXv5` and `MTvK` function are used to decode base64 to binary then it will be handles by `CpPT` function later

![a54d6a91fea991ab9629727fd897c514.png](../../_resources/a54d6a91fea991ab9629727fd897c514.png)

Here is an indicator that telling us it decoding base64 string

```
LUK7
```

> Q11: What encoding scheme is this function responsible for decoding?
```
base64
```

> Q12: In the function CpPT, the first two for loops are responsible for what important part of this function?

![de2c59fe91ef323bf518333459c53125.png](../../_resources/de2c59fe91ef323bf518333459c53125.png)

We know that `LXv5` and `MTvK` function are used to decode base64 to binary but what about `CpPT` that will handle this binary to executable command? ChatGPT got our back and it telling us how this can be possible by using RC4 cipher to convert it back to respective script

```
Key-Scheduling Algorithm
```

> Q13: The function CpPT requires two arguments, where does the value of the first argument come from?

![9ab851ee69ec43ce29a264dd941f92cf.png](../../_resources/9ab851ee69ec43ce29a264dd941f92cf.png)

First argument that this function required is a key for RC4 and we already know where it comes from

```
command-line argument
```

> Q14: For the function CpPT, what does the first argument represent?
```
key
```

> Q15: What encryption algorithm does the function CpPT implement in this script?
```
rc4
```

> Q16: What function is responsible for executing the deobfuscated code?

![0e285df43d2a023f6cccef2afccc8023.png](../../_resources/0e285df43d2a023f6cccef2afccc8023.png)
```
eval
```

> Q17: What Windows Script Host program can be used to execute this script in command-line mode?

![353167ec980989812a16b6802eab603d.png](../../_resources/353167ec980989812a16b6802eab603d.png)
```
cscript.exe
```

> Q18: What is the name of the first function defined in the deobfuscated code?

![5b4c5942388d6c721fa2c0db5fa43273.png](../../_resources/5b4c5942388d6c721fa2c0db5fa43273.png)

Using CyberChef to decode base64 and then decrypt those messy binary to respective script with RC4 with a key we got which we can see the first function is called `UspD` and it responsible for create an ADODB.Stream object and read a file

```
UspD
```

![a4895eb54c1eb43e7c926b9b8457c99a.png](../../_resources/a4895eb54c1eb43e7c926b9b8457c99a.png)
* * *
