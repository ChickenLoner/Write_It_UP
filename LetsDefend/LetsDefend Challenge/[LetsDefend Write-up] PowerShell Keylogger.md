# [LetsDefend - PowerShell Keylogger](https://app.letsdefend.io/challenge/powershell-keylogger)
Created: 28/12/2025 18:13
Last Updated: 29/12/2025 10:56
* * *
## Scenario
You are a malware analyst investigating a suspected PowerShell malware sample. The malware is designed to establish a connection with a remote server, execute various commands, and potentially exfiltrate data. Your goal is to analyze the malware’s functionality and determine its capabilities.

* * *
## Start Investigation
![8bf089b93e98b249ee4cbc8f30d00fd3.png](/resources/8bf089b93e98b249ee4cbc8f30d00fd3.png)
![d42ff808faa40f4e183e28b5cfcfa914.png](/resources/d42ff808faa40f4e183e28b5cfcfa914.png)

We have a single PowerShell file in this challenge. As the challenge name implies, we're dealing with a keylogger written in PowerShell. After opening it with VS Code, I can see parameter declarations at the top of the script along with C# code that will be executed via `Add-Type`.

Let's explore what each function does before answering the challenge questions.

This malware contains 9 main functions and a custom C# class. Let's understand each component:
- `Establish-Connection` : This function is the core of this script, which is constantly run inside while loop and keep calling every 60 seconds after fails. it responsible for other function calling and establish connection back to the threat actor via SOCKS5 proxy to Tor hidden service and it handles command sending from the threat actor to each function defined in this script like a C2 including upload and download files from victim host as well
![79093236239386cfde776299196dbe3b.png](/resources/79093236239386cfde776299196dbe3b.png)
![0a6601fc5390f251c7417f28ef419b91.png](/resources/0a6601fc5390f251c7417f28ef419b91.png)

- `Cap-Sc` : This function responsible for capturing the screenshot of the victim's entire screen and save it to temp directory with random name which invokes by "screenshot" command from `Establish-Connection` function and the image will be removed once encoded to base64 and send back to the threat actor
![590b550c8b68ff16ab3cc9082fc09783.png](/resources/590b550c8b68ff16ab3cc9082fc09783.png)

- `Encode-Data` : Encode strings to Base64-encoded Unicode strings, mainly use for sending response back to the threat actor

- `Decode-Data` : Decode Base64-encoded Unicode strings back to plaintext, mainly used to decode command sending from C2 by the threat actor

- `Execute-CommandInMemory` : Executes arbitrary PowerShell commands in the memory with Invoke-Expression which is called when decoded command does not match the rest of string defined in `Establish-Connection` function
![7038a093c70d73177bf229d0bdfa47c9.png](/resources/7038a093c70d73177bf229d0bdfa47c9.png)
![817aa6742a7c88a94b90f75fdf62b199.png](/resources/817aa6742a7c88a94b90f75fdf62b199.png)

- `Get-SystemInfo` : Get OS version, Machine name, Username and Internal IP address (filters out localhost and APIPA addresses) then convert to JSON and display to the threat actor C2, this function is invoked by default in `Establish-Connection` function
![544dd70c49f15a49bc587081c44ecdcd.png](/resources/544dd70c49f15a49bc587081c44ecdcd.png)

- `Start-Keylogger` : Main functionaility of the keylogger which can be started if threat actor send "keylog_start" command, which will save keystroke into `keylog.txt` file located in temp directory of the victim user
![8def3a0b05d6428fbf4b378ac9d10288.png](/resources/8def3a0b05d6428fbf4b378ac9d10288.png)

- `Stop-Keylogger` : Stop keylogging function

- `Get-KeylogData` : Get content of `keylog.txt` file and display to the threat actor which also remove `keylog.txt` as well, it can be invoked with "keylog_dump" command
![a5ff14f587954b8aa0f401222cd771a1.png](/resources/a5ff14f587954b8aa0f401222cd771a1.png)

Now lets start answering the question and finish this challenge before wrap it up in summary 

> What is the proxy port used by the script?

![38039a77099d131035d38f69c6aa4784.png](/resources/38039a77099d131035d38f69c6aa4784.png)

As this keylogger also have C2 capability and it will connect back to the threat actor TOR service, and the proxy port that was used is 9050 with the IP address of "37.143.129.165"

```
9050
```

> What function-method is used for starting keylogging?
```
Start-Keylogger
```

> What is the name of the file used by the script to store the keylog data?
```
keylog.txt
```

> What command is used by the script to achieve persistence?

![47e91fe411bfe98ef848c642ec15e685.png](/resources/47e91fe411bfe98ef848c642ec15e685.png)

The script does not yet implement any persistence mechanism yet but as we can see that it is intended to have one from the `Establish-Connection` function

```
persist
```

> What is the command used by the script to upload data?
```
upload:
```

> What is the regex used by the script to filter IP addresses?
```
^(127\.|169\.254\.)
```

> What is the DLL imported by the script to call keylogging APIs?

![9995d98a4ec81b7ba8ad083e6e0eb840.png](/resources/9995d98a4ec81b7ba8ad083e6e0eb840.png)

In `Start-Keylogger` function, 4 functions used for keylogging are imported from `user32.dll`

```
user32.dll
```

> How many seconds does the script wait before re-establishing a connection?
```
60
```

* * *
## Summary
In this challenge, we conducted script-based analysis on the PowerShell-based RAT demonstrates sophisticated attacker techniques including Tor-based anonymization, fileless execution, and keylogger functionality.

https://app.letsdefend.io/my-rewards/detail/af38186a2b204a378fd572aa8405185c
* * *
