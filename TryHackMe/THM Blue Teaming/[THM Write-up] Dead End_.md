# [TryHackMe - Dead End?](https://tryhackme.com/room/deadend)
![75158528f017d3840c84ca61a3c248ed.png](/resources/75158528f017d3840c84ca61a3c248ed.png)
***
## Table of Contents

- [Memory](#memory)
- [Disk](#disk)

***
## Memory
An in-depth analysis of specific endpoints is reserved for those you're certain to have been compromised. It is usually done to understand how specific adversary tools or malwares work on the endpoint level; the lessons learned here are applied to the rest of the incident.

You're presented with two main artefacts: a memory dump and a disk image. Can you follow the artefact trail and find the flag?

>What binary gives the most apparent sign of suspicious activity in the given memory image? <br>
Use the full path of the artefact.

![f47c7834ae5b2e82a01161b89698c729.png](/resources/f47c7834ae5b2e82a01161b89698c729.png)

After started the machine, we have the Linux environment with 2 memory dump (memdump.mem and pagefile) and volatility 3 to work with it.

![41d064887bb9c4d10dc59b2673da1b36.png](/resources/41d064887bb9c4d10dc59b2673da1b36.png)

Firstly we can start with `python3 vol.py -f ../RobertMemdump/memdump.mem windows.info` to create the symbol for the memory dump (it gonna take a while) and also get basic information from the memory dump which the results shown that this memory dump was captured from 64-bit Windows 10 at 2024-05-14 22:07:36 according to System time.

![6c61b2948d936f419d1cf84f9671bc76.png](/resources/6c61b2948d936f419d1cf84f9671bc76.png)

Now we can proceed with `python3 vol.py -f ../RobertMemdump/memdump.mem windows.pstree` to display process trees which we can see that from the image above, we got the `svchost.exe` that is not from `C:\\Windows\\System32` folder and the command line of this process indicates that this process is actually a netcat which used to create reverse shell connection to 10.14.74.53 on port 6996

```
C:\Tools\svchost.exe
```

>The answer above shares the same parent process with another binary that references a .txt file - what is the full path of this .txt file?

![f153d616055f1e54637290df3ff9b878.png](/resources/f153d616055f1e54637290df3ff9b878.png)

From the same process tree, we can see that `notepad.exe` was used to open `part2.txt` file and after tracing back the process tree, we can see that both netcat process and notepad are the child processes of PowerShell process and the PowerShell is the child process of `explorer.exe` which make it look like user itself opened the PowerShell. 

```
C:\Users\Bobby\Documents\tmp\part2.txt
```

We are done with this machine, Lets go to the second machine

***
## Disk
>What binary gives the most apparent sign of suspicious activity in the given disk image?<br>Use the full path of the artefact.

![dccd4ba621a11394a035b71b5e89e52d.png](/resources/dccd4ba621a11394a035b71b5e89e52d.png)

On this machine, we have disk image on D drive and EZ tools ready to be used on the desktop and beside that we also have FTK Imager to load the disk image as well.

![dbba23301b3bdf7c07ff5803f6468fde.png](/resources/dbba23301b3bdf7c07ff5803f6468fde.png)

After loaded an image with FTK Imager, we cab see that there is only 1 user on this system that is not default user and we can also see the netcat binary from the Tools folder as well.

![e3554ba9b974ac90126da8c61928cffd.png](/resources/e3554ba9b974ac90126da8c61928cffd.png)

After navigating to the folder that stores text file we found from the memory dump, we found another file which is the PowerShell script that will execute netcat binary to create reverse shell upon execution.

![314eacf7c1b28ae8db16b1cd6811beff.png](/resources/314eacf7c1b28ae8db16b1cd6811beff.png)

Next, I exported the `C:\\Windows\\System32\\config` folder that contains registry hives out.

![a6db8379647c0ef9374d9892eea0d33d.png](/resources/a6db8379647c0ef9374d9892eea0d33d.png)

Then I checked the Zone.Identifier of the netcat binary which we can see that it was downloaded from the same IP address found from the script.

![7e25b9a57ecf3c26c2ffa3f85e125fb3.png](/resources/7e25b9a57ecf3c26c2ffa3f85e125fb3.png)

I could not find where the culprit binary that going to download this file and PowerShell script is located so I also exported NTUSER.DAT hive of Booby user as well.

![8924b45e3dc1d024eb6d9eeb29e2faf8.png](/resources/8924b45e3dc1d024eb6d9eeb29e2faf8.png)

Then I used registry explorer to inspect UserAssist key of this user which I found that before notepad and PowerShell were executed, there is one more binary that was executed before them from the Tools folder.

![0ad846b1eef1a7a51a2c740042416f3a.png](/resources/0ad846b1eef1a7a51a2c740042416f3a.png)

Lets export this binary.

![a32d36ec706a5b8ef6f44839ffaf8088.png](/resources/a32d36ec706a5b8ef6f44839ffaf8088.png)

To confirm its maliciousness, I enabled Audit Process Creation (event ID 4688) and PowerShell Script Block Logging via audit policy which you can follow these step to archive the same

1. Press Win + R, type gpedit.msc, and hit Enter. (Open Local Group Policy Editor)
2. Go To Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> Detailed Tracking
3. Double click at "Audit Process Creation" and enable Success event logging.

![59279f7aaee35c3380d37c0e69c590ca.png](/resources/59279f7aaee35c3380d37c0e69c590ca.png)

For PowerShell Script Block Logging, Go to Computer Configuration -> Administrative Templates -> Windows Components -> Windows PowerShell and enable "Turn on PowerShell Script Block Logging"

![776c67006b0cc864fb81469f0504ba20.png](/resources/776c67006b0cc864fb81469f0504ba20.png)

Now we execute the binary and open Event Viewer to find the process creation trail which we can see that `cmd.exe` spawned after binary was executed.

![0f205adbc9003c67c7b6d7adabbf0058.png](/resources/0f205adbc9003c67c7b6d7adabbf0058.png)

The PowerShell was spawned under `cmd.exe`.

![650cb10b69f17c5129e80e742b32da92.png](/resources/650cb10b69f17c5129e80e742b32da92.png)

Since I could forget to enable command line logging so I went to PowerShell log to find the command that was executed by PowerShell which we can see that `AddReg.ps1` was executed.

![ebe6cf5920fb493521c9c6fde49b8968.png](/resources/ebe6cf5920fb493521c9c6fde49b8968.png)

By inspecting the content of this file on Script Block, we can see that this script will edit open\shell\command registry of text file to execute `connector.ps1` when a text file was opened and also added the first path of the flag to the registry as well.

```
C:\Users\windows-networking-tools-master\windows-networking-tools-master\LatestBuilds\x64\Autoconnector.exe
```

Useful resource to follow to enable process ID 4688 with full capabilities (Command line included)
- https://docs.nxlog.co/integrate/windows-command-line-auditing.html

>What is the full registry path where the existence of the binary above is confirmed?

![d6f2221381f498f1652972f82f5d5145.png](/resources/d6f2221381f498f1652972f82f5d5145.png)

There are several ways to proof the binary were executed but the intended way and the answer of this question is using bam registry as shown in the image above 

```
HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\bam\State\UserSettings\S-1-5-21-1966530601-3185510712-10604624-1008
```

>What is the content of "Part2"?

![6b50edb44a7c78dae814ddf65dd26384.png](/resources/6b50edb44a7c78dae814ddf65dd26384.png)

```
faDB3XzJfcDF2T1R9 
```

>What is the flag?

![5cfe93f6372477bf7b5b684dd61344cc.png](/resources/5cfe93f6372477bf7b5b684dd61344cc.png)

We know the first part of the flag was added to the registry key so you can confirm it if you want to or we can just copy the value from PowerShell log directly.

![0d96ded96ddb6f2e893d20e2f31ec2da.png](/resources/0d96ded96ddb6f2e893d20e2f31ec2da.png)

Decode base64 string then we should be able to get a flag.

```
THM{6l4D_y0u_kNOw_h0w_2_p1vOT}
```

![5e6c5a409ca4bc8994a680bc9012b16f.png](/resources/5e6c5a409ca4bc8994a680bc9012b16f.png)

And we are done!
***