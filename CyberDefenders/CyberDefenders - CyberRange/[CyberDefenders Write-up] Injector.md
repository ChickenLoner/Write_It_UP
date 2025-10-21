# [CyberDefenders - Injector](https://cyberdefenders.org/blueteam-ctf-challenges/injector/)
Created: 18/06/2024 18:56
Last Updated: 19/06/2024 21:44
* * *
>Category: Endpoint Forensics
>Tags: Memory Forensic, Disk Forensic, Volatility, FTK Imager, Autopsy, Registry Explorer, RegRipper, R-Studio, T1059.003, T1136.001, T1548, T1222, T1083, T1016, T1100, T1190
* * *
A company’s web server has been breached through their website. Our team arrived just in time to take a forensic image of the running system and its memory for further analysis.

As a soc analyst, you are tasked with mounting the image to determine how the system was compromised and the actions/commands the attacker executed.

Tools:
- [R-Studio](https://www.r-studio.com/)
- [FTK Imager](https://accessdata.com/products-services/forensic-toolkit-ftk/ftkimager)
- [Autopsy](https://www.sleuthkit.org/autopsy/)
- [Volatility](https://github.com/volatilityfoundation/volatility)
- [Registry Explorer](https://f001.backblazeb2.com/file/EricZimmermanTools/RegistryExplorer_RECmd.zip)
- [RegRipper](https://github.com/keydet89/RegRipper3.0)
* * *
## Questions
> Q1: What is the computer's name?

![987b458c0c1ba8ef223a87c0da8dcd54.png](../../_resources/987b458c0c1ba8ef223a87c0da8dcd54.png)

An easiest way to obtain computer name in my opinion is to use RegRipper on Software registry hive which can be found at `C:\Windows\System32\config`  

![82310384fdab355b7ec153d143920802.png](../../_resources/82310384fdab355b7ec153d143920802.png)

Open an output file from RegRipper and search for "ComputerName"

```
WIN-L0ZZQ76PMUF
```

> Q2: What is the Timezone of the compromised machine? Format: UTC+0 (no-space)

![212fc6c861c57bb1087e6df816fc104b.png](../../_resources/212fc6c861c57bb1087e6df816fc104b.png)

Still on result from software hive, this time search for TimeZone which you will see that this machine is using PST which can be either UTC-7 or UTC-8 but "ActiveTimeBias" telling us that it uses UTC-7 

```
UTC-7
```

> Q3: What was the first vulnerability the attacker was able to exploit?

![2e711827a3a4ab6de82ce2581ccdc441.png](../../_resources/2e711827a3a4ab6de82ce2581ccdc441.png)

I found xampp folder which mean web server was hosting by xampp then we can go to `\apache\logs` for `access.log` 

![300108487f3caec32934a41d45c5a1b4.png](../../_resources/300108487f3caec32934a41d45c5a1b4.png)

We can see that this web server was hosting dvwa (damn vulnerable web application) which is an application designed to be exploited and learn about multiple vulnerabilities and then you can see that first vulnerability that was exploited is XSS (cross-site scripting)

```
xss
```

> Q4: What is the OS build number?

![dfc2e88378e77bf3fd2a2e2cd4f16e40.png](../../_resources/dfc2e88378e77bf3fd2a2e2cd4f16e40.png)

Go back to an output file from Software hive and search for "winver", you will eventually see this build version of this Windows server 

```
6001
```

> Q5: How many users are on the compromised machine?

![c1c5e5d0de67f1f18e7722433e6d556f.png](../../_resources/c1c5e5d0de67f1f18e7722433e6d556f.png)

This time we're going to use RegRipper on SAM registry hive for user information which you can see that Administrator (Normal user account) and Guest (Which is disabled) account are built-in account are still there

![285726ffd32729c80af635af90deb7a6.png](../../_resources/285726ffd32729c80af635af90deb7a6.png)

But the other 2 users were created around the same time which mean it could be created by threat actor

But thats 4 users in total

```
4
```

> Q6: What is the webserver package installed on the machine?

![4c5f76ff9104cb56fe95f2f1d80f2bef.png](../../_resources/4c5f76ff9104cb56fe95f2f1d80f2bef.png)
```
xampp
```

> Q7: What is the name of the vulnerable web app installed on the webserver?
```
dvwa
```

> Q8: What is the user agent used in the HTTP requests sent by the SQL injection attack tool?

![9c95446b728d629aaeea3d79078369ce.png](../../_resources/9c95446b728d629aaeea3d79078369ce.png)

Go back to `access.log` then search for `/vulnerabilities/sqli/` which we will eventually see an sqlmap was used to exploit sqli vulnerability on this website

```
sqlmap/1.0-dev-nongit-20150902
```

> Q9: The attacker read multiple files through LFI vulnerability. One of them is related to network configuration. What is the filename?

![05243eafb26df10ab965ba1e5e2430c7.png](../../_resources/05243eafb26df10ab965ba1e5e2430c7.png)

Search for `/vulnerabilities/fi` then we will see that `hosts` file was read by exploiting local file inclusion vulnerability

```
hosts
```

> Q10: The attacker tried to update some firewall rules using netsh command. Provide the value of the type parameter in the executed command?

![a70941c3752908953fb2e40495811dca.png](../../_resources/a70941c3752908953fb2e40495811dca.png)

After determine which profile to use for a given memory dump then we can proceed with `vol.py -f memdump.mem --profile=Win2008SP1x86 pstree` to list process tree and you can see that there are 2 cmd process that looking out of place here

![1a6ce0e6204433f08a2c98149d261b3b.png](../../_resources/1a6ce0e6204433f08a2c98149d261b3b.png)

So we can use `vol.py -f memdump.mem --profile=Win2008SP1x86 consoles` to display console log when cmd commands were executed which we can see that `netsh` was used to make remotedesktop available 

```
remotedesktop
```

> Q11: How many users were added by the attacker?

![accd6681b6d718b92e1189c0da02983f.png](../../_resources/accd6681b6d718b92e1189c0da02983f.png)

Remember 2 users that we suspected to be added by threat actor? seem like that is the case here even through we didn't find second one here but timeline tells us it was 2 users

```
2
```

> Q12: When did the attacker create the first user?
```
2015-09-02 09:05:06 UTC
```

> Q13: What is the NThash of the user's password set by the attacker?

![fc923784733fa5bb42f4c10493a3aab5.png](../../_resources/fc923784733fa5bb42f4c10493a3aab5.png)

We can get this easiliy by using `vol.py -f memdump.mem --profile=Win2008SP1x86 hashdump` 

```
817875ce4794a9262159186413772644
```

> Q14: What is The MITRE ID corresponding to the technique used to keep persistence?

![755ca00b667a0f246d6ba07171e766cd.png](../../_resources/755ca00b667a0f246d6ba07171e766cd.png)

There is no doubt that it is T1136.001

```
T1136.001
```

> Q15: The attacker uploaded a simple command shell through file upload vulnerability. Provide the name of the URL parameter used to execute commands?

![a009dea32e1cfa0fff44460b9a8a3948.png](../../_resources/a009dea32e1cfa0fff44460b9a8a3948.png)

File upload vulnerability on web server often exploited by uploading webshell in php script so we just have to find for any php script that take an argument into a parameter which eventuallly lead us to `phpshell.php` which take argument to `cmd` paremeter to execute

```
cmd
```

> Q16: One of the uploaded files by the attacker has an md5 that starts with "559411". Provide the full hash.

![3f01fc0192307b7bcc88930973d5a0d3.png](../../_resources/3f01fc0192307b7bcc88930973d5a0d3.png)

uploaded file should be at `\xampp\htdocs\DVWA\` which we can see there are 2 files inside `webshells.zip`

![11639e0fc9a763aaa5ab0b95f62bb6f9.png](../../_resources/11639e0fc9a763aaa5ab0b95f62bb6f9.png)

`webshell.php` md5 hash start with "559441" so we can copy the rest to answer this question

```
5594112b531660654429f8639322218b
```

> Q17: The attacker used Command Injection to add user "hacker" to the "Remote Desktop Users" Group. Provide the IP address that was part of the executed command?

![596047a902a35d0180e62f345024d683.png](../../_resources/596047a902a35d0180e62f345024d683.png)

Lets assume that this command injection spawned cmd process so we have to dump memory of this process with `vol.py -f memdump.mem --profile=Win2008SP1x86 memdump -p 1972 -D .` then use `strings 1972.dmp | grep -i "hacker"` to find for anything related to this user and we got lucky that this cmd process is the one that responsible for this activity

```
192.168.56.102
```

> Q18: The attacker dropped a shellcode through SQLi vulnerability. The shellcode was checking for a specific version of PHP. Provide the PHP version number?

![804a70e69b69fe7273f5e9b684326f47.png](../../_resources/804a70e69b69fe7273f5e9b684326f47.png)

Go back to `access.log` and tried to find a packet that might indicate shellcode and look like we got one here

![5e6df9c5d384aa4b09833d4bbb75ac11.png](../../_resources/5e6df9c5d384aa4b09833d4bbb75ac11.png)

By inspecting this payload, we can see that it was started by `0x` which mean its hex encoded 

![f74a72de3c8bd790d64c76bee961dc09.png](../../_resources/f74a72de3c8bd790d64c76bee961dc09.png)

Convert back to ASCII then we can see its check for php version lower than 4.1.0

![c92f6f4b2f3d00d12a110b2bb61352b7.png](../../_resources/c92f6f4b2f3d00d12a110b2bb61352b7.png)

We can put this in PHP beautifier and learn how this shell code works

```
4.1.0
```

![7da822263c57fe3378a29a9546ff7897.png](../../_resources/7da822263c57fe3378a29a9546ff7897.png)
* * *
