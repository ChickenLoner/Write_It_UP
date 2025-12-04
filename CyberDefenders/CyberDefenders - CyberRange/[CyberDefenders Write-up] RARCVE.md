# [CyberDefenders - RARCVE](https://cyberdefenders.org/blueteam-ctf-challenges/rarcve/)
## Table of Contents

- [Scenario](#scenario)
- [What is CVE-2023-38831?](#what-is-cve-2023-38831)
- [Questions](#questions)

* * *
## Scenario
Around April 2023, threat actors leveraged a zero-day vulnerability (CVE-2023-38831) in the WinRAR compression tool. These weaponized ZIP files, carriers of various malware families such as DarkMe, GuLoader, and Remcos RAT, were strategically distributed on trading forums. Disguised as enticing content like "Personal Strategies to trade with Bitcoin," the archives, once executed, gave threat actors the capability to control the victim machine. You have a copy of the malicious ZIP file to dissect and understand its functionality.

**Category**: Malware Analysis

**Tools**:
CyberChef
VsCode
scdbg

* * *
## What is CVE-2023-38831?
![022e54bcc268794eb9ae2ce1313d0812.png](/resources/022e54bcc268794eb9ae2ce1313d0812.png)

Since the threat actor leveraged this CVE on this lab then we should understand what make this CVE dangerous and how it could be exploited which I used the POC from this [GitHub](https://github.com/HDCE-inc/CVE-2023-38831) to understand how it works.

To put it simply, this CVE allows could make user execute a file inside a folder with the same name as "benign" file that will be opened by a user so inside the zip file, we should expect 1 "benign" file, a folder with the same name and the file inside that folder.

## Questions
>Q1: Malware often uses encryption to conceal its malicious code from detection mechanisms. After extracting the malicious code from the archive, what key is used to decrypt the 2nd stage of the malware?

![89037e9896fc229559e7e3fde893da63.png](/resources/89037e9896fc229559e7e3fde893da63.png)

And there we have the zip file that contains "benign" pdf file and a folder with the same name as it.

![13acca23fe9579de14d1adcc6df4aa34.png](/resources/13acca23fe9579de14d1adcc6df4aa34.png)

Inside the folder, there is a bat file that will be executed upon opening "benign pdf" file if user use vulnerable version of Winrar. 

![118bd9e33e7df8851094cb7b01f74732.png](/resources/118bd9e33e7df8851094cb7b01f74732.png)

After extracted the file out from zip file, we can see that PowerShell command with this weird long hex payload.

![7f2dfc3c2a01dfd41f9825dab47fb7b3.png](/resources/7f2dfc3c2a01dfd41f9825dab47fb7b3.png)

Which will be decoded and XOR with 0x23 (the answer to this question) before putting it to `C:\Users\Public\akvzmVI.cmd` file and then execute it stealthy as minimized windows.

![80fe58aae51568433337b454cb75d49f.png](/resources/80fe58aae51568433337b454cb75d49f.png)

Then we can see can CyberChef to confirm that the XOR key is really 0x23 and it is! the decrypted content is another powershell base64 command that need more decode.

```
0x23
```

>Q2: Knowing where the malware drops its payload on a system can help trace its footprints and subsequent actions. Where is the malware dropped after execution?
```
C:\Users\Public\akvzmVI.cmd
```

>Q3: Based on the libraries the malware is attempting to import, it appears there is a third stage to its operation. Can you identify the library name from which the malware is trying to import functions?

![16c486cf7c84537203ac4085b23a3148.png](/resources/16c486cf7c84537203ac4085b23a3148.png)

Now we can decode base64 command which we can see that it will import `VirtualAlloc` function from `kernel32.dll` to allocate virtual memory and also import `CreateThread` function from the same dll to create a thread to execute shellcode that will be allocated in virtual memory.

```
kernel32.dll
```

>Q4: How many functions is the malware trying to import from the library you discovered in the previous question?	
```
2
```

>Q5: From the imported functions, the malware seems to be trying to inject a shell code into the memory. To evade detection, threat actors attempt to encrypt the shellcode. Can you identify the specific algorithm for encrypting the shellcode during this stage?

![8313cb50e5c8b990322dca5fbce33b45.png](/resources/8313cb50e5c8b990322dca5fbce33b45.png)
![030fea04c5cb7b0c58da38e0afe4a3a5.png](/resources/030fea04c5cb7b0c58da38e0afe4a3a5.png)

The shellcode is encrypted and there is a function that responsible for the decryption right here and it will take 2 variables (ciphertext and a key) decrypt it

![f5f0c8f60369bb02eedd899e8dfbc67d.png](/resources/f5f0c8f60369bb02eedd899e8dfbc67d.png)

this function is resembled RC4 algorithm and it is indeed RC4 algorithm.

```
RC4
```

>Q6: Malware often uses a specific user agent to blend in or for specific functionality when communicating over the internet. Identifying this user agent can help detect this malware's network activity. What is the user agent used by the malware?

![6b0aa9c1b9e21a07da2723920527163d.png](/resources/6b0aa9c1b9e21a07da2723920527163d.png)

We can copy this stage of the script into ps1 file, keep only RC4 decryption function, shellcode and a key then we can use `[System.IO.File]::WriteAllBytes("C:\Users\Administrator\shellcode.raw", $Yzoic)` to create a file that contain decrypted shellcode for debugging.

![cf11dadaf19fa653b1a287f048b85802.png](/resources/cf11dadaf19fa653b1a287f048b85802.png)

We can use scdbg (Shellcode Debugger) to debug this shell code (with Unlimited steps and Findsc checked), we can see that the first 2 bytes is FC E8 that typical shellcode targeted Windows.

![a0ac634afaa0d78782bdf84b35193c26.png](/resources/a0ac634afaa0d78782bdf84b35193c26.png)

Launch the debugger and start from the index 0, we can see that it will load `wininet` library which is API used to interact with FTP and HTTP protocols to access Internet. then it will connect to `linode.bratbg.eu` on port 8080 with pre-defined user-agent and the path that was used is quite so it could mean that it will try to get another stage into the compromised machine, looking at another `VirttualAlloc` after `HTTPSendRequestA` was called.

```
Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15
```

>Q7: This shellcode is a stageless payload waiting for the attacker server to download the final payload. What is the domain and port that the malware downloads the final stage from?
```
linode.bratbg.eu:8080
```

https://cyberdefenders.org/blueteam-ctf-challenges/achievements/Chicken_0248/rarcve/ 
* * *
