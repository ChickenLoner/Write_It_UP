# [HackTheBox Sherlocks - OpSalwarKameez24-1: Super-Star](https://app.hackthebox.com/sherlocks/OpSalwarKameez24-1:%20Super-Star)
Created: 03/11/2024 11:50
Last Updated: 04/11/2024 14:59
* * *
![ad182b363cab89cb70400686be2d2526.png](/resources/ad182b363cab89cb70400686be2d2526.png)

**Scenario:**
StoreD Technologies' customer support team operates tirelessly around the clock in 24/7 shifts to meet customer needs. During the Diwali season, employees have been receiving genuine discount coupons as part of the celebrations. However, this also presented an opportunity for a threat actor to distribute fake discount coupons via email to infiltrate the organization's network. One of the employees received a suspicious email, triggering alerts for enumeration activities following a potential compromise. The malicious activity was traced back to an unusual process. The Incident Response Team has extracted the malicious binaries and forwarded them to the reverse engineering team for further analysis. This is a warning that this Sherlock includes software that is going to interact with your computer and files. This software has been intentionally included for educational purposes and is NOT intended to be executed or used otherwise. Always handle such files in isolated, controlled, and secure environments. One the Sherlock zip has been unzipped, you will find a DANGER.txt file. Please read this to proceed.

* * *
>Task 1: What is the process name of malicious NodeJS application?

![38245d3bbf10803ffe40be25894b623e.png](/resources/38245d3bbf10803ffe40be25894b623e.png)

We got 2 files, The first file is Nullsoft Scriptable Installer (NSIS file) and other one is pcap file so lets dig into this NSIS installer first.

![f7220a030aa1ffdcf80167360b281972.png](/resources/f7220a030aa1ffdcf80167360b281972.png)

Generate file hash then search it on [VirusTotal](https://www.virustotal.com/gui/file/bb46f86d668b5a9928f2f8353e9618ef42cf837b53f9ee277d76acdc03d19945/behavior) and go to Behavior tab then we would be able to see malicious nodejs process is a child process of NSIS process.

```
Coupon.exe
```

>Task 2: Which option has the attacker enabled in the script to run the malicious Node.js application?

NSIS file can be extracted with 7zip so lets extract it

![8912d24ec0e648b8ef459b19539a2885.png](/resources/8912d24ec0e648b8ef459b19539a2885.png)

 then we should have `$PLUGINSDIR` and `[NSIS].nsi` but we are not done yet.

![4c28eca13ceefca381862db32f2b5aaa.png](/resources/4c28eca13ceefca381862db32f2b5aaa.png)

Go inside `$PLUGINSDIR` folder and extract `app-64.7z`.

![ae2553339caaa3f800751448b6486be4.png](/resources/ae2553339caaa3f800751448b6486be4.png)

Now we have a folder of [Electron](https://www.electronjs.org/), now we can see malicious nodejs process from Q1 in this folder but we want an answer of Q2 so we need to dig a little bit deeper until we find the application's source code. 

![30990e888eb9a5d62a731def9391966c.png](/resources/30990e888eb9a5d62a731def9391966c.png)

Go to `resources` folder which will have `app.asar` inside of it and it is a crucial file that contains the packaged application code (HTML, CSS, JavaScript) so if we need to extract this file but how?. 

![99e96e211c1cb9dad35ff1f0ec7e4062.png](/resources/99e96e211c1cb9dad35ff1f0ec7e4062.png)

First lets install asar package with `npm install -g --engine-strict asar` then use `asar l app.asar` to list files inside this asar archive which you can see that there are so many files within this asar archive but mostly in `node_modules` that contain libraries and dependencies rather than the application's source code.

![403272a14bc56557f81cbccdbcda5de8.png](/resources/403272a14bc56557f81cbccdbcda5de8.png)

But if we used `asar l .\app.asar | Select-String -NotMatch "^\\node_modules"` then we should be able to see application source code that really relevant to our needs and the one the totally standout from the rest is `keylogger.js`.

![fff6c21adb2cf09e4e62a5ff82d3d6b3.png](/resources/fff6c21adb2cf09e4e62a5ff82d3d6b3.png)

Since we already got what we should dig into then lets extract it with `asar e .\app.asar .\asar_extract\`

![84d610fefc3285c916d739a6ca0a203c.png](/resources/84d610fefc3285c916d739a6ca0a203c.png)

The one that we need to answer is lying on `index.js` file then you can see on line 13 that this application will enable nodejs integration with `nodeIntegration` option which allow the script to run the malicious Node.js application.

Notice that it also loads `/../extraResources/preload.js` and `/public/testPage.html` which we will take a look at them on Q3 and Q4.

![bc688847b2a8529e0e5628c07c00373a.png](/resources/bc688847b2a8529e0e5628c07c00373a.png)

Here is the explaination from [Quasar Framework documentation](https://v1.quasar.dev/quasar-cli/developing-electron-apps/node-integration)

```
nodeIntegration
```

>Task 3: What protocol and port number is the attacker using to transmit the victim's keystrokes?

![62b0c77fce4089328d5ba49515683137.png](/resources/62b0c77fce4089328d5ba49515683137.png)

Now lets take a look what's inside `testPage.html` which we can see that it will trigger `keylogger.js` script.

![d62cbe5d3a7816fcb718068657f21e9f.png](/resources/d62cbe5d3a7816fcb718068657f21e9f.png)

Upon reviewing this script, we can see that it will capture keystroke and send it to C2 IP address (0.0.0.0 is likely be to a placeholder for us investigator to run this safely) on port 44500 using WebSocket.

```
WebSocket, 44500
```

>Task 4: What XOR key is the attacker using to decode the encoded shellcode?

![c0b5d48ed0918932f9fdeedf1077a3b0.png](/resources/c0b5d48ed0918932f9fdeedf1077a3b0.png)

Its time to take a look at `preload.js` file.

![f2921aba1a211b79d6498935cb4fccbd.png](/resources/f2921aba1a211b79d6498935cb4fccbd.png)

Then we can see that it will send a request to C2 address on port 80 which will response with a key to XOR with base64 decoded payload.

![066badb06218748541a38bedfc0eb3dc.png](/resources/066badb06218748541a38bedfc0eb3dc.png)

So if we opened provided pcap file and use `http` or `tcp.port==80` filter then we would see this TCP stream 9 that sent XOR key back to infected system.

```
ec1ee034ec1ee034
```

>Task 5: What is the IP address, port number and process name encoded in the attacker payload ?

We got both base64 strings and key so lets decode and XOR it to find an actual payload.

![c78e6708afaf3ebd8244c2ad051e9dcb.png](/resources/c78e6708afaf3ebd8244c2ad051e9dcb.png)

Which we can see that this is a function that will spawn `cmd.exe` and connect back to C2 on port 4444 (Reverse shell).

```
15.206.13.31, 4444, cmd.exe
```

>Task 6: What are the two commands the attacker executed after gaining the reverse shell?

![f5d264ded9f20529cd950395eefcfdb9.png](/resources/f5d264ded9f20529cd950395eefcfdb9.png)

Lets go back to Wireshark then filter for `tcp.port==4444` for reverse shell connection which we only have 1 stream and after taking a look at this, we can also see that this reverse shell session was not that long so maybe the attacker terminated it after executed 2 commands asked on this question.

![2b521b4d659970767321ceb39798fdf5.png](/resources/2b521b4d659970767321ceb39798fdf5.png)

Follow TCP Stream then we can see that the attacker executed `whoami` and `ipconfig` before terminated this session.

```
whoami, ipconfig
```

>Task 7: Which Node.js module and its associated function is the attacker using to execute the shellcode within V8 Virtual Machine contexts?

![768552680e95b0db40758119701d0d66.png](/resources/768552680e95b0db40758119701d0d66.png)

Go back to `preload.js` then we can see that it uses [vm](https://nodejs.org/api/vm.html#class-vmmodule) module that provides a way to execute JS within Virtual Machine context. 

![cb815b264147822a6aa770ba86dcdcfb.png](/resources/cb815b264147822a6aa770ba86dcdcfb.png)

Then the function that uses to execute the shellcode is [runInNewContext](https://nodejs.org/api/vm.html#scriptruninnewcontextcontextobject-options) function.

```
vm, runInNewContext
```

>Task 8: Decompile the bytecode file included in the package and identify the Win32 API used to execute the shellcode.

![981afdac124d4b6910a505b569937e73.png](/resources/981afdac124d4b6910a505b569937e73.png)

The bytecode file is `script.jsc` that located in the same folder as `preload.js` and its compiled script file for JS which we need to decompiled it with ByteCode decompiler tool. 

![b149dcdeb353ecbdf5f11b56e9ddcee7.png](/resources/b149dcdeb353ecbdf5f11b56e9ddcee7.png)

I searched for several tools for this including Ghidra plugin but the one that really worked out for me is [View8](https://github.com/suleram/View8) 

Kudo to my friend, [warlocksmurf](https://github.com/warlocksmurf) that recommended me this awesome v8 decompiler tool 

![25b861d41f0cd850deda1f0ac66e51c6.png](/resources/25b861d41f0cd850deda1f0ac66e51c6.png)

To use this tool, we have to clone git repository and download 3 disassembler binaries for 3 different V8 version and put in `Bin` folder.

![8c2fd9d1be7558627cbc615978a26d6f.png](/resources/8c2fd9d1be7558627cbc615978a26d6f.png)

After we got everything ready, run it with `python view8.py script.jsc outputfile.js -p .\Bin\9.4.146.24.exe` 

Why `9.4.146.24.exe`? I tried to run it without disassembly binary and this python script will tell me which binary should I use and it recommended this binary for Node V16.

![cf7cebd8a9ff05db600e49c247a177ab.png](/resources/cf7cebd8a9ff05db600e49c247a177ab.png)

Open an output file which stores disassembly of the bytecode file then we can see that the Win32 API that will be used to execute shellcode is [CreateThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread).

```
CreateThread
```

>Task 9: Submit the fake discount coupon that the attacker intended to present to the victim.

![a423c5217f43808b9550ef2f940df407.png](/resources/a423c5217f43808b9550ef2f940df407.png)

There is one array on the output file that stores shellcode so I wrote a simply python script to convert it to hex.

![c6d177383b5d3b41f55c24443faff826.png](/resources/c6d177383b5d3b41f55c24443faff826.png)

Use CyberChef to convert it then we might notice 2 weird strings ("COUPON1337" and "PWNED") with `user32.dll` and the take discount coupon is the first string we found from this output. 

```
COUPON1337
```

![b499ad77e9ae85148c29770ae48dbe9c.png](/resources/b499ad77e9ae85148c29770ae48dbe9c.png)
https://labs.hackthebox.com/achievement/sherlock/1438364/790
* * *