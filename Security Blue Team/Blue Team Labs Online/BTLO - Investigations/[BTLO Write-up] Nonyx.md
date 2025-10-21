# [Blue Team Labs Online - Nonyx](https://blueteamlabs.online/home/investigation/nonyx-63b4769449)
<div align=center>

![81155214d4921ba1c8014f030140fa8d.png](/resources/81155214d4921ba1c8014f030140fa8d.png)
</div>
Purify Black Energy 2 from Shadowbrook’s digital infrastructure by reverse-engineering the malware’s code.

>Reverse Engineering

>**Tags**: Volatility 2, Malfind, Strings, File, T1014
* * *
**Scenario**
Exorcise Black Energy 2 from Shadowbrook’s digital infrastructure by reverse-engineering the malware’s code. You must dismantle its hooks, identify its payload, and stop its command-and-control mechanisms to restore peace to the town’s network before the Haunted Festival reaches its darkest hour.
* * *
## Investigation Submission
>Q1) Which process most likely contains injected code, providing its name, PID, and memory address? (Format: Name, PID, Address)

![2766a7a20c7347663ec4b84ac701bd2c.png](/resources/2766a7a20c7347663ec4b84ac701bd2c.png)

After deployed investigation machine, we will see that we have memory image on the desktop and a note telling how to run volatility on this machine and a profile to use and if i have to guess, we will analyze [BlackEnergy](https://daniel25097.medium.com/blackenergy-v-2-full-driver-reverse-engineering-c9fd6d071946) malware.

![e4de6ee75494746d9e8f77d87cd8529b.png](/resources/e4de6ee75494746d9e8f77d87cd8529b.png)

So after executed `python vol.py -f ../BlackEnergy.vnem --profile=WinXPSP2x86 malfind` then we can see a process that was injected right here.

<details>
  <summary>Answer</summary>
<pre><code>svchost.exe, 856, 0xc30000</code></pre>
</details>

>Q2) What dump file in the malfind output directory corresponds to the memory address identified for code injection? (Format: Output File Name)

![d90bb00052d1089b44331003db023cd2.png](/resources/d90bb00052d1089b44331003db023cd2.png)

We can add `--dump --pid ../ 856` to our previous command to dump this memory address from memory dump then the name of dump file will be the answer of this question.
<details>
  <summary>Answer</summary>
<pre><code>process.0x80ff88d8.0xc30000.dmp</code></pre>
</details>

>Q3) Which full filename path is referenced in the strings output of the memory section identified by malfind as containing a portable executable (PE32/MZ header)? (Format: Filename Path)

![ba41af5940d1886562825e8420cfe1c1.png](/resources/ba41af5940d1886562825e8420cfe1c1.png)
Use `strings` the output file from previous question then we will see this suspicious driver found which is an answer of this question and since we could guess that we're investigating BlackEnergy malware that make this driver stood out even more since BlackEnergy being known for root kit which loading drivers as part of its toolkit.
<details>
  <summary>Answer</summary>
<pre>C:\WINDOWS\system32\drivers\str.sys<code></code></pre>
</details>

>Q4) How many functions were hooked and by which module after running the ssdt plugin and filtering out legitimate SSDT entries using egrep -v '(ntoskrnl|win32k)'? (Format: XX, Module)

![908463673e86d065566731ddc0e20be4.png](/resources/908463673e86d065566731ddc0e20be4.png)

Lets use `python vol.py -f ../BlackEnergy.vnem --profile=WinXPSP2x86 ssdt | egrep -v '(ntoskrnl|win32k)'` to list System Service Descriptor Table (SSDT) and also filtering out legitimate SSDT then we will have these 14 functioned hooked by 00004D2A module and why we have to find SSDT ? Because the SSDT holds pointers to core OS functions, it has often been targeted by rootkits and malware just like this BlackEnergy malware.
<details>
  <summary>Answer</summary>
<pre><code>14, 00004D2A</code></pre>
</details>

>Q5) Using the modules (or modscan) plugin to identify the hooking driver from the ssdt output, what is the base address for the module found in Q4? (Format: Base Address)

![969d4cb9448993592c9ce452f01834f8.png](/resources/969d4cb9448993592c9ce452f01834f8.png)

Since we already got the name of the module then we can use `python vol.py -f ../BlackEnergy.vnem --profile=WinXPSP2x86 modscan | grep "00004A2A"` to find out base address of this module.
<details>
  <summary>Answer</summary>
<pre><code>0xff0d1000</code></pre>
</details>

>Q6) What is the hash for the malicious driver from the virtual memory image? (Format: SHA256)

![61884b9ee32890be42b178ab415e0015.png](/resources/61884b9ee32890be42b178ab415e0015.png)
Now we can use moddump plugin to dump this module / driver file like this `python vol.py -f ../BlackEnergy.vnem --profile=WinXPSP2x86 moddump -b 0xff0d1000 -D ../` then after that we can use `sha256sum` to generate hash of this file.

<details>
  <summary>Answer</summary>
<pre><code>12b0407d9298e1a7154f5196db4a716052ca3acc70becf2d5489efd35f6c6ec8</code></pre>
</details>

![c2b3365e70d15c4054724038a15cc3e5.png](/resources/c2b3365e70d15c4054724038a15cc3e5.png)

If you searched this file on VirusTotal then it is indeed Black Energy module.

![e9bf4aafb65af080f09e8f3e65f9f552.png](/resources/e9bf4aafb65af080f09e8f3e65f9f552.png)
https://blueteamlabs.online/achievement/share/52929/243
* * *