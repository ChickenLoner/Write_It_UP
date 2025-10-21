# [MemLabs Lab 2 - A New World](https://github.com/stuxnet999/MemLabs/tree/master/Lab%202)
Created: 14/07/2024 16:01
Last Updated: 
***
## Challenge Description
One of the clients of our company, lost the access to his system due to an unknown error. He is supposedly a very popular "environmental" activist. As a part of the investigation, he told us that his go to applications are browsers, his password managers etc. We hope that you can dig into this memory dump and find his important stuff and give it back to us.

**Note**: This challenge is composed of 3 flags.

**Challenge file**: [MemLabs_Lab2](https://mega.nz/#!ChoDHaja!1XvuQd49c7-7kgJvPXIEAst-NXi8L3ggwienE1uoZTk)
***
![70e93d802c06eecca5e8050fc3691e29.png](../../_resources/70e93d802c06eecca5e8050fc3691e29.png)
Lets start with `vol.py -f MemoryDump_Lab2.raw imageinfo` to find the suitable profile for this memory dump then after we have one, we will continue to follow the challenge description to get all flags.

## Get first flag
![42112ca22d254a9e6eaf41fca46cc5e7.png](../../_resources/42112ca22d254a9e6eaf41fca46cc5e7.png)

First one that describes client who owns a machine that was taken memory dump of is "environmental" so this is our first hint toward our first flag and volatility 2 just happened to have a plugin that print all environment variables of provided memory dump so lets proceed with `vol.py -f MemoryDump_Lab2.raw --profile=Win7SP1x64 envars` and then after carefully review an output, we could see that `NEW_TMP` variable in `conhost.exe` store some strange path.

![2359d826fb789b9fada1fa309ccc1d9e.png](../../_resources/2359d826fb789b9fada1fa309ccc1d9e.png)

So I tried to decode this path with base64 and look like it worked, we got our first flag!

```
flag{w3lc0m3_T0_$T4g3_!_Of_L4B_2}
```

## Get second flag
![c2da9489c47a111acbb4a230b22d4e1e.png](../../_resources/c2da9489c47a111acbb4a230b22d4e1e.png)

Now lets see how many processes were running when this memory was captured with `vol.py -f MemoryDump_Lab2.raw --profile=Win7SP1x64 pstree` then we could see that `cmd.exe` and `chrome.exe` are running so we might use `consoles` for command history and `chromehistory` plugin for Chrome browsing history.

![2caad62185f8ef78703b69a84abf8c11.png](../../_resources/2caad62185f8ef78703b69a84abf8c11.png)
![f276ac12dedfc78aa9271a6a02f182ee.png](../../_resources/f276ac12dedfc78aa9271a6a02f182ee.png)

We can also noticed that `notepad.exe` and `KeePass.exe` were also running as well which mean we might have to dump keepass database to get a flag from this password manager.

![0862e4b1e1afcb501c61c09272057377.png](../../_resources/0862e4b1e1afcb501c61c09272057377.png)

To determine which file `notepad.exe` and `KeePass.exe` were opened we can use `vol.py -f MemoryDump_Lab2.raw --profile=Win7SP1x64 cmdline` which display all command-line arguments of all running processes (when it was captured) then we could see that these 2 processes were opened the same file.

![8f540a2e010efb3eb685572d86af7da3.png](../../_resources/8f540a2e010efb3eb685572d86af7da3.png)

Before going to dump it, I tried to use view command history via `consoles` plugin but there is nothing here

![c0e935351f6130088b5cf40668efedcc.png](../../_resources/c0e935351f6130088b5cf40668efedcc.png)

Next I also tried `notepad` plugin which is not working neither because of this profile.

![c6ef1ba447cb9510a43be5bb79827c3c.png](../../_resources/c6ef1ba447cb9510a43be5bb79827c3c.png)

So lets get physical address of the all files using `vol.py -f MemoryDump_Lab2.raw --profile=Win7SP1x64 filescan > mem2_filescan.txt` then using grep to get physical address of that keepass database we found which we will use `vol.py -f MemoryDump_Lab2.raw --profile=Win7SP1x64 dumpfiles -Q 0x000000003fb112a0 -D .` to dump it and rename to its original name.

![4464a6425ba5ea3c5ac5d4639fdfee82.png](../../_resources/4464a6425ba5ea3c5ac5d4639fdfee82.png)

I tried to bruteforce for master password with `keepass2john` and `john` but it did not work so I came back to `mem_filescan.txt` to find for anything we could use which we can see that `Password.png` might be the one we're looking for

![d1cea484bf3c106eb65699156e20ef86.png](../../_resources/d1cea484bf3c106eb65699156e20ef86.png)

Lets dump it with `vol.py -f MemoryDump_Lab2.raw --profile=Win7SP1x64 dumpfiles -Q 0x000000003fce1c70 -D .` and do not forget to rename it so we could open this file with image viewer.

![Password.png](../../_resources/Password.png)

This is an image we just dumped, there is no flag but a password was there.

![8f4bbc822d357fd17be712b0583b3c33.png](../../_resources/8f4bbc822d357fd17be712b0583b3c33.png)

We can this password to open keepass database file and obtain a flag from "Recycle Bin"

```
flag{w0w_th1s_1s_Th3_SeC0nD_ST4g3_!!}
```

## Get third flag
![2c82f504ecd8d9549cf86f342d981a5f.png](../../_resources/2c82f504ecd8d9549cf86f342d981a5f.png)

The only thing we still did not tackle in is Chrome Browser History so lets use `vol.py -f MemoryDump_Lab2.raw --profile=Win7SP1x64 chromehistory` then we can see one MEGA url that is so outstanding here

![a8afc97d9d8c60ee196f28df4c118d01.png](../../_resources/a8afc97d9d8c60ee196f28df4c118d01.png)

Upon visiting this, we can see a zip file on this url so lets download it

![90820b5a57d0b5f52df7ea1a71ea1225.png](../../_resources/90820b5a57d0b5f52df7ea1a71ea1225.png)

We got the right file! we just need SHA1 of Lab 1 - stage-3 flag to read an image file inside.

![97dfbf312a1dd6f4a832dc6a6009ce5a.png](../../_resources/97dfbf312a1dd6f4a832dc6a6009ce5a.png)

Before tackle this lab, we should already done with Lab 1 so we just need to calculate SHA1 hash of this text then use it as a password for this zip file.

![Important.png](../../_resources/Important.png)

We're done with Lab 2! see you in Lab 3!

```
flag{oK_So_Now_St4g3_3_is_DoNE!!}
```

## Lab 2 : Flags
```
flag{w3lc0m3_T0_$T4g3_!_Of_L4B_2}
flag{w0w_th1s_1s_Th3_SeC0nD_ST4g3_!!}
flag{oK_So_Now_St4g3_3_is_DoNE!!}
```
***