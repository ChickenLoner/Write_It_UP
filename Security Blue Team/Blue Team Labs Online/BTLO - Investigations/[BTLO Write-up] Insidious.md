# [Blue Team Labs Online - Insidious](https://blueteamlabs.online/home/investigation/insidious-b9b71928f4)

![099dc0935841855a4a3a1c2acec3d1a2.png](/resources/099dc0935841855a4a3a1c2acec3d1a2.png)

The malicious file went undetected, allowing it to execute without raising immediate suspicion.

>**Incident Response**

>**Tags**: Volatility3 Volatility2 Chromehistory.py T1036 T1555.003 T1140 T1567.004
* * *
**Scenario**
One of our employees has fallen victim to a data leak, resulting in the theft of sensitive information about our organization. During our preliminary investigation, we discovered unauthorized login attempts from an IP address that is not associated with any of our employees.
* * *
## Environment Awareness
### Evidence Discovery
![e703afa7c67e8e78df02cd81de937562.png](/resources/e703afa7c67e8e78df02cd81de937562.png)

We will have to read `README` file on the desktop which telling us that WSL is ready on this investigation and there are a bunch of tools we could use.

![87142945345c2e73dece92b788c51db9.png](/resources/87142945345c2e73dece92b788c51db9.png)

On the `Investigation` folder, we could see another `README` file along with memory dump that we have to use

`README` file provides another useful information on this investigation which is profile to use on Volatility 2, symbol already installed for Volatility 3 and lastly, we have to use de-obfuscate Javascript on this investigation

***
### Tool Discovery and Preparation
![2ce72f127539f778c60160261dfe7a60.png](/resources/2ce72f127539f778c60160261dfe7a60.png)

On the `Quick Tools (Basic Triage)`, we have EZ Tools folder that I will use on this investigation.

![c822525fb057f843f82c046d70b96649.png](/resources/c822525fb057f843f82c046d70b96649.png)

On `Deep Tools (Complete Triage)`, there are 2 folder inside this folder which are `Forensic Programs` and `Forensic Programs 2`

Here are all the tools on `Forensic Programs` folders

![c19131a98a95e3065b851099f346aa4a.png](/resources/c19131a98a95e3065b851099f346aa4a.png)

Here are all the tools on `Forensic Programs 2` folders

![9b181f55df9163362f1aa827cab0ba55.png](/resources/9b181f55df9163362f1aa827cab0ba55.png)

WSL is already pinned to the taskbar so we can access it directly and once we accessed to WSL then we can see `tools` folder inside this that contains both Volatility 2 and Volatility 3.

Lets start our investigation

***
## Investigation
>Q1) What is the complete URL for the malicious package? (Format: URL)

![53b77265cc0e03695090163675a1b40b.png](/resources/53b77265cc0e03695090163675a1b40b.png)

I started with `python2 ~/tools/volatility/vol.py -f memdump.mem --profile=Win10x64 pstree` to list process tree from this memory dump and we can see that there are several google chrome processes when this memory was captured and there is no suspicious process name from this process tree.

![73a0fab0adecf061445990609600e4ed.png](/resources/73a0fab0adecf061445990609600e4ed.png)

The reason why I went with pstree on volatility 2 is because [windows.pstree](https://volatility3.readthedocs.io/en/latest/_modules/volatility3/plugins/windows/pstree.html#PsTree) plugin on volatility will print out image path and cmdline of processes which will overwhelmed the terminal like this

![138b98ed3628398b1280b49f85bce8e2.png](/resources/138b98ed3628398b1280b49f85bce8e2.png)

One thing we might notice when running volatility 2 is an error that we could not use chromehistory plugin so we have to get creative on this one.

![7e9f96b2364856e1f217c67579de042e.png](/resources/7e9f96b2364856e1f217c67579de042e.png)

Since I did not see any standout process so I used `python3 ~/tools/volatility3/vol.py -f memdump.mem windows.psxview` to list hidden process which I found that there are 4 processes running at the same time as `powershell.exe` and the OneDrive process that has different process ID from pstree result.

![ad203298d21856b5925886d5996ffc62.png](/resources/ad203298d21856b5925886d5996ffc62.png)

Then I used `python3 ~/tools/volatility3/vol.py -f memdump.mem windows.filescan > file.txt` to list all files that still cached in the memory dump to a text file so I can use grep to search for specific file I want.

![340564c0195e874a7ed99b22a20f288e.png](/resources/340564c0195e874a7ed99b22a20f288e.png)

Since chromehistory plugin is not available by default then I used `python3 ~/tools/volatility3/vol.py -f memdump.mem windows.dumpfiles --virtaddr 0xe001b0006f20` to dump Chrome History file from memory dump

![c79f86786d44b2ffb3c0a9a9fea3b571.png](/resources/c79f86786d44b2ffb3c0a9a9fea3b571.png)

Then I renamed DataSectionObject file to `History` then used [SQLECmd](https://github.com/EricZimmerman/SQLECmd) with `SQLECmd.exe -f C:\Users\BTLOTest\Desktop\Investigation\History --csv C:\Users\BTLOTest\Desktop\Investigation` command to parse all records possible from this history file and we can see that we have output 3 files after running this commands which separate download history, visit history and keyword search 

![1aaa1da50d01b9f4ed64d1c7d6b7a9e4.png](/resources/1aaa1da50d01b9f4ed64d1c7d6b7a9e4.png)

I did not see any download history that stand out so I went with Visit history which I found peritter npm package which might be typosquatting version of prettier package

![afe96f71191876d585eeb06fa7a86939.png](/resources/afe96f71191876d585eeb06fa7a86939.png)

When we visit this package url then we can see that there are 3 files on the code section.

![2e13f6069071a345eeb0325449976112.png](/resources/2e13f6069071a345eeb0325449976112.png)

After reading `package.json`, we can confirm that this this package is indeed typosquatting of prettier package and will execute `index.js` upon installation

![cfdd5e992a92348d9781e661c162ceaf.png](/resources/cfdd5e992a92348d9781e661c162ceaf.png)

`index.js` seem to have one-liner obfuscation code, this raises another red flag so we will have to de-obfuscate this script to uncover what happened 

![bafb8d99308f2cc7ae351d39a1e96573.png](/resources/bafb8d99308f2cc7ae351d39a1e96573.png)

By using https://obf-io.deobfuscate.io/ to beautify and de-obfuscate then we will see that this script will decode content of `dataset.db`,create a file on start up folder and executed it so without a doubt we can submit the package url on npm marketplace as Q1 answer. 

<details>
  <summary>Answer</summary>
<pre><code>https://www.npmjs.com/package/peritter</code></pre>
</details>

>Q2) Provide the full path for the main file of the malicious package. (Format: PATH) 

![82ee693c90eb39e0297ea3d819e3e51a.png](/resources/82ee693c90eb39e0297ea3d819e3e51a.png)

At first, I thought this one is `index.js` since its the actual main file of this malicious package specify in `package.json` file (I also consulted with the creator of this lab, and he also agreed to this)

![55971a491f87cf50785c434c585175fd.png](/resources/55971a491f87cf50785c434c585175fd.png)

But BTLO changed the answer to `package.json` as shows in the above image which the only explanation I could think of is when we installed package with npm, it will read `package.json` file first which mean its also served as an entry point of this package.

<details>
  <summary>Answer</summary>
<pre><code>C:\Users\User\node_modules\peritter\package.json</code></pre>
</details>

>Q3) What is the name of the threat actor responsible for publishing the malicious package? (Format: Name) 

![0a38a93a2cdb432997fca733caef9eb5.png](/resources/0a38a93a2cdb432997fca733caef9eb5.png)

We can get the publisher/author of this package (he is also the author of this lab), by reading `package.json` file right here. 

![20889fb8c281838277f868925b9ab779.png](/resources/20889fb8c281838277f868925b9ab779.png)

We could also look at the Collaborators name right here

![5966d33f6a790576681bd2a66c1b36dd.png](/resources/5966d33f6a790576681bd2a66c1b36dd.png)

Which will lead to the publisher profile and as we can see that he only have 1 package on this marketplace.

<details>
  <summary>Answer</summary>
<pre><code>s1rx-dev</code></pre>
</details>

>Q4) When was the malicious package downloaded? (Format: YYYY-MM-DD HH:MM:SS UTC)

![1aaa1da50d01b9f4ed64d1c7d6b7a9e4.png](/resources/1aaa1da50d01b9f4ed64d1c7d6b7a9e4.png)

We know that victim accessed malicious package on 2025-01-19 13:16:28 so we could filter out any events before that and since we know that to install this package, user have to use npm so it won't log on any browser history.

![3cc55b2d23e09f1bfd74294d384de994.png](/resources/3cc55b2d23e09f1bfd74294d384de994.png)

But we can use MFT to file the creation time of `package.json` or `peritter` folder to find out which time it was created on the system and it also mean the installation time so I used `python3 ~/tools/volatility3/vol.py -f memdump.mem windows.mftscan.MFTScan > mft.txt` to parse MFT record from memory dump to a text file.

![2a65ed2e427bf19e9b3ac250bd75278f.png](/resources/2a65ed2e427bf19e9b3ac250bd75278f.png)

After filtering for the package name, I noticed that the result from `windows.mftscan.MFTScan` plugin did not contain full path of the file but at least we can see that `peritter` folder was in used at  2025-01-19 13:17:34.

![1f0375e71d212a18d1880f27fdbb76bd.png](/resources/1f0375e71d212a18d1880f27fdbb76bd.png)

So I used `python2 ~/tools/volatility/vol.py -f memdump.mem --profile=Win10x64 mftparser > mftpar.txt` to use different plugins to compare result. 

![9c70bfa3de4d827db5a5e4dda81e5ecc.png](/resources/9c70bfa3de4d827db5a5e4dda81e5ecc.png)

Then we can see that the creation timestamp of this folder is indeed matches the result from `windows.mftscan.MFTScan` plugin so we can conclude that this is the installation time of this package.

<details>
  <summary>Answer</summary>
<pre><code>2025-01-19 13:17:34 UTC</code></pre>
</details>

>Q5) What will the full path be for the malicious executable after copying it? (Format: PATH)

![667ab9dce5937373fb59991688c3477f.png](/resources/667ab9dce5937373fb59991688c3477f.png)

Lets go back to the script again, we know that the malicious file is `OneDrive.exe` and it will be created on the start up folder of infected user.

![5959a2ea93dba35051a4fce4c910d43f.png](/resources/5959a2ea93dba35051a4fce4c910d43f.png)

Which we could confirm this again by searching for this file on the output of `filescan` plugin.

<details>
  <summary>Answer</summary>
<pre><code>C:\Users\User\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\OneDrive.exe</code></pre>
</details>

>Q6) Provide the username and password for the corporate login credentials that the malware has stolen. (Format: username:password)

![ecedc4be2e26ae2dc7f93db39f7be436.png](/resources/ecedc4be2e26ae2dc7f93db39f7be436.png)

When I filtered for the `peritter` package folder from `filescan` output then I noticed weird text file on the package folder.

![bd9c0a15db585097ffa56189870839a3.png](/resources/bd9c0a15db585097ffa56189870839a3.png)

So I dumped it with `python3 ~/tools/volatility3/vol.py -f memdump.mem windows.dumpfiles --virtaddr 0xe001af6958d0`

![a531d60f0e1cc763f9cb421b150a4c6f.png](/resources/a531d60f0e1cc763f9cb421b150a4c6f.png)

And then we could see that this text file stores user credential for linkedln and victim's corporate website.

<details>
  <summary>Answer</summary>
<pre><code>3bd0o:PssW0rD-1</code></pre>
</details>

>Q7) When was the malicious executable executed? (Format: YYYY-MM-DD HH:MM:SS UTC)

![7e9f96b2364856e1f217c67579de042e.png](/resources/7e9f96b2364856e1f217c67579de042e.png)

We already know that malicious file is `OneDrive.exe` so we can come back to `psxview` plugin result and confirm that the timestamp of these 4 executables align with the incident timeframe and this is indeed the correct answer of this question. 

<details>
  <summary>Answer</summary>
<pre><code>2025-01-19 13:18:13 UTC</code></pre>
</details>

![88175aa376178e1e3e728245d62c3047.png](/resources/88175aa376178e1e3e728245d62c3047.png)
https://blueteamlabs.online/achievement/share/52929/255
* * *