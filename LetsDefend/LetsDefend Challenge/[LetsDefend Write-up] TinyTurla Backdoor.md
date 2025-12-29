# [LetsDefend - TinyTurla Backdoor](https://app.letsdefend.io/challenge/tinyturla-backdoor)
Created: 29/12/2025 11:32
Last Updated: 29/12/2025 14:52
* * *
## Scenario
You are a malware analyst assigned to investigate a suspected backdoor malware sample. The malware is designed to communicate with a remote server, execute various commands, and potentially exfiltrate data. Your task is to analyze the malware, understand its functionality, and determine its capabilities.

* * *
## Start Investigation

![dd1f89ac7633937639152561ee41cce6.png](/resources/dd1f89ac7633937639152561ee41cce6.png)
![99c878faa9db94188b614f99116930fb.png](/resources/99c878faa9db94188b614f99116930fb.png)

On this challenge, we have an .NET malware sample which as the name of the challenge imply, we are dealing with the TinyTuria Backdoor so to make our analysis easier then we will need to understand what it is first

![1667ca46086e5722ac58fc35c52b5f3f.png](/resources/1667ca46086e5722ac58fc35c52b5f3f.png)

According to [MITRE ATT&CK](https://attack.mitre.org/software/S0668/), TinyTurla is a backdoor that has been used by Turla against targets in the US, Germany, and Afghanistan since at least 2020 and according to an article published by [Cyble](https://cyble.com/blog/tiny-backdoor-goes-undetected-suspected-turla-leveraging-msbuild-to-evade-detection/), we have the similar malware sample as analyzed in this article so we can use this article as a guide to solve this challenge!

> What is the name of the process used to run the shell command in the "RunShell" method?

![1454eaf3de4fd21943abb9b85fbb00f4.png](/resources/1454eaf3de4fd21943abb9b85fbb00f4.png)

In `RunShell` method, it will pass 1 argument from the function calls and execute it as an argument of `cmd.exe /c` command

```
cmd.exe
```

> Which command in the "runCommand" method sets the sleep time for the program?

![44af2d1bece6c1e43dbd623666bf3fd5.png](/resources/44af2d1bece6c1e43dbd623666bf3fd5.png)
![5f5bd066e1709d32a58543f90ca49b56.png](/resources/5f5bd066e1709d32a58543f90ca49b56.png)

`runCommand` method that is responsible for handles command polling from C2 server and the command that will be used to set sleep time of this backdoor is `[<sleep>]`

```
[<sleep>]
```

> Which command in the "runCommand" method is used to execute a shell command?

![22a488698a2998c4cfc55dfd316c9b9a.png](/resources/22a488698a2998c4cfc55dfd316c9b9a.png)

When the `[<shell>]` is specified from C2 and pass the argument to `RunShell` method which will execute command via `cmd.exe`

```
[<shell>]
```

> Which command in the "runCommand" method downloads a file to the server?

![2d161860f0cfc4cf6509322852d296ea.png](/resources/2d161860f0cfc4cf6509322852d296ea.png)

When `[<download>]` is specified, it will get the name of the file then send it to C2 server with HTTP POST request via `HttpsPost` method

```
[<download>]
```

> Which process's main window title is specifically checked and hidden in the "Execute" method?

![dc64c3b3e12e411df95bfbe49aa88db1.png](/resources/dc64c3b3e12e411df95bfbe49aa88db1.png)

The main functionality of this backdoor is this `Execute` method where it executes the decrypted MSBuild project file using `MSBuild.exe`, which subsequently runs the inline task present within the project file directly in memory when the project is built and one of its thread will monitor for main window title contains `MSBuild.exe` and hide it, this will hide itself from MSBuild inline task running 

```
MSBuild.exe
```

> Which DLL is imported to use the GetConsoleWindow function in the code?

![6167781063214926d8fb19878f69e816.png](/resources/6167781063214926d8fb19878f69e816.png)

The backdoor imported `GetConsoleWindows` API from `kernel32.dll`

```
Kernel32.dll
```

> What method is used to perform HTTP GET requests in the provided code?

![7519417200669047daa68308359cd26e.png](/resources/7519417200669047daa68308359cd26e.png)
![5fe1c1291f0dd7f07685e250e6c46c8a.png](/resources/5fe1c1291f0dd7f07685e250e6c46c8a.png)

`HttpsGet` method will be invoked after specifiy with `[<upload>]` command to download a file from C2 server to the target which as its name imply, will use HTTP GET Method to fetch file from C2 and save it to victim host

```
HttpsGet
```

> Which IP address does the "HttpsPost" method use when making POST requests?

![61e2222ed2f6e79c35cd60dbd8188850.png](/resources/61e2222ed2f6e79c35cd60dbd8188850.png)

The IP address and the url scheme was declared in the `ClassExample` class directly and as we can see that it use private IP which could indicates that this is a custom malware made to mimick TinyTurla backdoor and test it locally

```
192.168.31.10
```

* * *
## Summary
In this challenge, we analyzed .NET binary that resemble the TinyTuria backdoor used by Turla APT to execute command via MSBuild inline task and have C2-like functionality such as download, upload, shell execution and set sleep time for the agent

https://app.letsdefend.io/my-rewards/detail/962203eb33b3444da44adb00784ec76d

* * *
