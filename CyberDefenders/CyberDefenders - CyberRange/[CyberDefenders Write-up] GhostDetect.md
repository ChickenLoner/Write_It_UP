# [CyberDefenders - GhostDetect](https://cyberdefenders.org/blueteam-ctf-challenges/ghostdetect/)
## Table of Contents

- [Scenario](#scenario)
- [Questions](#questions)

* * *
## Scenario
One of the employees reported receiving an email with a suspicious-looking attachment. Suspecting that a known Threat Actor may be attempting to use phishing to gain a foothold in the organization, you need to analyze the provided file and identify the threat.

**Category**: Malware Analysis

**Tools**:
CyberChef
Wireshark
Strings
VS Code
LECmd
ProcMon

* * *
![c96b364a10c45f3b4376a6a7504eb725.png](/resources/c96b364a10c45f3b4376a6a7504eb725.png)

On this lab, we will have a malware sample which is shortcut file (`.lnk`) and we have limited tool to use which indicates that we will need to “run” this malware while letting procmon monitoring system activity.

## Questions
>Q1: In analyzing the malware's behavior after the initial intrusion, it's crucial to understand where it attempts to establish persistence or further infection. Where were the files dropped by the malware located within the system's file structure?

![6672bfe0facee5460e441fdb98714222.png](/resources/6672bfe0facee5460e441fdb98714222.png)

Since this is a shortcut (`.lnk`) file, we can use `LECmd` from Eric Zimmerman’s toolkit to parse it and extract useful metadata. The output shows suspicious behavior: the shortcut is configured to launch itself through `mshta`, which strongly suggests that an HTA file with embedded VBScript is being executed indirectly through the shortcut.

Command: `LECmd.exe -f "C:\Users\Administrator\Desktop\Start here\Artifacts\Xuzhou_Shenyang2024.lnk"`

![b8a8c1239cf7cd032656f2a8c7e9a025.png](/resources/b8a8c1239cf7cd032656f2a8c7e9a025.png)

We can use `strings` to extract the HTA file that was embedded within this shortcut file.

![465690bdb72839efaf3d33c898ba849a.png](/resources/465690bdb72839efaf3d33c898ba849a.png)

The end of the script reveals that upon executing this file with `mshta`, 2 files will be generated in the `%TEMP%` folder of the user who executed it. the first file is the js file and the second one is pdf file.

Command: `strings "C:\Users\Administrator\Desktop\Start here\Artifacts\Xuzhou_Shenyang2024.lnk" > stage0.hta`

![d26051e908557e03157a932abcc2707c.png](/resources/d26051e908557e03157a932abcc2707c.png)

I open procmon and wireshark to capture network and system activity, then execute the shortcut file which will pop up the lure pdf file. 

![e6bfc611a29e244566c798683694a2f9.png](/resources/e6bfc611a29e244566c798683694a2f9.png)

On the procmon, I open the process tree which we can see that after shortcut file is executed, `mshta` is followed and open lure pdf file (on this machine Chrome act as the pdf reader so it opens on chrome)

![9a2197b79404d932a0816d884174b32b.png](/resources/9a2197b79404d932a0816d884174b32b.png)

![7152b2051f8f2a14c15e4b30e4b4f438.png](/resources/7152b2051f8f2a14c15e4b30e4b4f438.png)

I filtered the whole branch of the shortcut file process tree and focus on “CreateFile” operation which reveals that 2 files were dropped to Temp folder (also inside “2” folder in this case) as expected.

```
C:\Users\Administrator\AppData\Local\Temp
```

>Q2: The malware's communication with external servers is key to its operation. What is the URL that was used by the malware to download a secondary payload?

![f51c6085471f8c3735f30b08f08617c9.png](/resources/f51c6085471f8c3735f30b08f08617c9.png)

![57f4164849fdfee2ee63d1f4b2e7e884.png](/resources/57f4164849fdfee2ee63d1f4b2e7e884.png)

As we already know that the pdf file might be the lure to make it look legitimate so we will focus on js file which we can see that the content is the same as the one we found on the VBScript embedded inside shortcut file.

![00e18bcb93b25e0dcb7b702491aa5734.png](/resources/00e18bcb93b25e0dcb7b702491aa5734.png)

![079636ed64d9f918166d52eb50dcb9c3.png](/resources/079636ed64d9f918166d52eb50dcb9c3.png)

By using the online deobfuscator such as [Obfuscator.io Deobfuscator](https://obf-io.deobfuscate.io/) with the help of LLM, we can see that this script will download encrypted payload from `windacarmelita.pw` , decrypt it with Rabbit cipher and save it to the same temp folder under the name of  `mokpp9342jsOUth.dll` and execute it with `rundll32` by invoking specific function “NormalizeF”. 

```
https://windacarmelita.pw/picdir/big/113-1131910-clipart.svg
```

>Q3: Understanding the malware's defense evasion techniques is essential for developing effective detection strategies. What encryption technique is employed by the malware to conceal its activities or payloads?

![242778690435314753c1d37a3fa02f1b.png](/resources/242778690435314753c1d37a3fa02f1b.png)

```
Rabbit
```

>Q4: Decrypting payloads is a common technique used by malware to evade initial analysis. What is the decryption key used to unlock the second stage of the malware?
```
dfshji349jg843059utli
```

>Q5: Malware analysis often involves tracking how it interacts with the filesystem. What is the name of the file created by the malware to store decrypted data?
```
mokpp9342jsOUth.dll
```

>Q6: Analyzing the malware's execution flow is crucial for understanding its impact and behavior. What function does the malware execute within the DLL to perform its malicious activities?

![8cf3f29f73f49d1a30e8128a4fc1a1a4.png](/resources/8cf3f29f73f49d1a30e8128a4fc1a1a4.png)

```
NormalizeF
```

>Q7: Investigating related artifacts can provide insights into the broader campaign. What is the name of another JavaScript file that utilizes the domain identified during the investigation?

![93d7e9a9550c03d011a6bcefc52f8756.png](/resources/93d7e9a9550c03d011a6bcefc52f8756.png)

First, I generate file hash from the original js file and search it on [VirusTotal - File - 290eb8511ac21a20b718152b09075acf2fd6b615d3ad22fb682ce9322c661a22](https://www.virustotal.com/gui/file/290eb8511ac21a20b718152b09075acf2fd6b615d3ad22fb682ce9322c661a22), which we will pivot from the contacted domain here.

![eb479f4e70d9c7cdc310ea3d2290c6b7.png](/resources/eb479f4e70d9c7cdc310ea3d2290c6b7.png)

One more thing to notice here if you searched this domain while logging in on VirusTotal, then Crowdsourced context will also display and reveal that this domain was related to GHOSTWRITER activity.

![4aea925b16ee4954ca490f9d88de846d.png](/resources/4aea925b16ee4954ca490f9d88de846d.png)

On the “Relation” tab, under the “Communicating Files”. we can see that there are 3 js files but there is only one file that match the answer format.

```
sdfhui2kjd.js
```

>Q8: Attribution is a critical aspect of threat intelligence. Can you identify which Advanced Persistent Threat (APT) group is likely behind this attack?

![e8197df99442345c5338c45e3784f6ec.png](/resources/e8197df99442345c5338c45e3784f6ec.png)

I search this domain on Google to find any resource that mention it since VirusTotal already revealed that it is related to GHOSTWRITER group which have many aliases and on my top search, there is the [github raw file](https://www.notion.so/CyberDefenders-GhostDetect-2be23193757080f89fbdc706615b62af?pvs=21) that contains the IOC of this group

![8926d69d7ad565790501340cc155bada.png](/resources/8926d69d7ad565790501340cc155bada.png)

There are 5 different references that mentioned this domain

![2e1e235f08346fa623f9e38783487cdb.png](/resources/2e1e235f08346fa623f9e38783487cdb.png)

On the CERT-UA article, they mentioned this group as `UAC-0057` which is the correct answer of this question.

```
UAC-0057
```

>Q9: What is the country of origin associated with the APT group identified in this investigation?

![7e29209f86555cf065f932c802983a6c.png](/resources/7e29209f86555cf065f932c802983a6c.png)

Quick google search about this threat actor group reveals that they allegedly originating from “Belarus” and that’s all we need for this question.

```
Belarus
```

https://cyberdefenders.org/blueteam-ctf-challenges/achievements/Chicken_0248/ghostdetect/
* * *
