# [LetsDefend - Suspicious Python Package](https://app.letsdefend.io/challenge/suspicious-python-package)
Created: 01/10/2024 08:56
Last Updated: 01/10/2024 10:46
* * *
One of our employees attempted to install a Python package, and shortly afterward, someone logged into his work account. He doesn't know how it happened and needs your help as a forensics investigator to determine what occurred.

**File Location**: C:\Users\LetsDefend\Desktop\ChallengeFile\MalPy.zip
* * *
## Start Investigation
>The attacker downloaded a malicious package. What is the full URL?

![292049caac051b817918e3d9c89d342c.png](../../_resources/292049caac051b817918e3d9c89d342c.png)

After extracted content of zip file, I got relevant artefacts to analyze but the question ask for "downloaded" a malicious package so It might reside on one of user's download folder and the only user of this machine (not include Guest and Public) is Administrator and this is suspicious python package that might be extracted from archive file.

![f4ca20788ee8ee068fa27f642a6d55bc.png](../../_resources/f4ca20788ee8ee068fa27f642a6d55bc.png)

I also found chrome browser artefacts so I opened History file with DB Browser then we can see that there is suspicious zip file downloaded from Github.

```
https://github.com/0xMM0X/peloton
```

>What is the name and version of the downloaded package?
**Answer Format**: package-name111:0.0.01

![28e0aca0e6d477b0dd4ecdf3e489e045.png](../../_resources/28e0aca0e6d477b0dd4ecdf3e489e045.png)

We will find this information in `PKG-INFO` (package information) file 

```
peloton-client123:0.8.10
```

>What is the exact time that this package was downloaded?
**Answer Format**: YYYY-MM-DD HH:MM:SS

I tried to get download end time chrome browser history but thats not accept as the answer of this question so it seems like we need to parse Master File Table to get Created0x10 timestamp.

![b15315a0321732b0a547cc7ed309cace.png](../../_resources/b15315a0321732b0a547cc7ed309cace.png)

Go back to chrome history database again to get name of malicious archive package.

![20122aca6613588031772887f448a3e0.png](../../_resources/20122aca6613588031772887f448a3e0.png)

Use `MFTECmd.exe` from EZ tools to parse `$MFT` file.

![33e96867c8b2956bdc69d9ff7584dcb1.png](../../_resources/33e96867c8b2956bdc69d9ff7584dcb1.png)

Now search for malicious package archive to get create timestamp which also the exact time this file was downloaded successful.

```
2024-01-22 20:00:11
```

>What file in the package contains malicious code?

![3d2cdf87851fb4b1a9fcd142137f94a3.png](../../_resources/3d2cdf87851fb4b1a9fcd142137f94a3.png)

Another interesting artefacts that I found is PowerShell History that indicate this user executed `setup.py` via PowerShell

![84ba326d738487aa5266f6fdbd2d677e.png](../../_resources/84ba326d738487aa5266f6fdbd2d677e.png)

So lets take a look at `setup.py`, we can see a lot of red flag here since it got base64 encode strings that need to be reversed and decompressed so lets do that in CyberChef and find out what this file really does

![d8e7ddda76db4117194d92586196fa96.png](../../_resources/d8e7ddda76db4117194d92586196fa96.png)

Now we can see that it exfiltrate chrome's login data database file -> `temp_file.zip` -> send to C2 server -> delete `temp_file.zip` (clean up)

```
setup.py
```

>What was the name of the archive file created for exfiltration and then deleted?
```
temp_file.zip
```

>When did the zip file get deleted?
**Answer Format**: YYYY-MM-DD HH:MM:SS

![d8a751213ca1d79e5865a851394a620a.png](../../_resources/d8a751213ca1d79e5865a851394a620a.png)

We will need to parse UsnJournal (`$J`) for this one, we could still use `MFTECmd.exe` for this

![f646f32a55edff978db9559253f0abe5.png](../../_resources/f646f32a55edff978db9559253f0abe5.png)

After search for this file from output, we can see that it got 5 records from Create to Delete so we have to get the last record timestamp

![9428f13ea61e009b905988f3c7d64c95.png](../../_resources/9428f13ea61e009b905988f3c7d64c95.png)

Turn out... there is no need since this file was created and deleted in such short amount of time so it appeared with the same timestamp.

```
2024-01-22 20:00:42
```

>What exactly did the attacker steal from the victim's machine? (Name of the file)
```
Login Data
```

>The stolen file contains some sensitive data. What is the full URL of the website and the victim’s username?
**Answer Format**: URL_username

![645d52cb1a119b5ea1ac77a147ca3757.png](../../_resources/645d52cb1a119b5ea1ac77a147ca3757.png)

Lets see whats important in `Login Data` database file which we could see that attacker could get saved login credential of app.letsdefend.io (self-promo)

```
https://app.letsdefend.io/_all4m
```

>What is the IP and PORT number of the attacker C2?
**Answer Format**: IP:Port
```
172.31.78.151:8000
```
* * *
## Summary
On this challenge, we analyzed 
- Browser artefacts to find download url of malicious python package and also user that was affected by this exfiltration.
- Master File Table to find the download timestamp of malicious package archive file.
- Malicious payload that got executed.
- UsnJournal to find deleted timestamp of temporary file that sent to C2 server

<div align=center>

![d284a338d007982c893b2ab970391f7a.png](../../_resources/d284a338d007982c893b2ab970391f7a.png)
</div>

* * *
