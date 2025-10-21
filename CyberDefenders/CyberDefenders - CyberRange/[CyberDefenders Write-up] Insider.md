# [CyberDefenders - Insider](https://cyberdefenders.org/blueteam-ctf-challenges/insider/) 
Created: 05/03/2024 13:30
Last Updated: 02/04/2024 08:30
* * *
>Category: Endpoint Forensics
>Tags: Disk, Linux, FTK, Kali, T1496, T1059, T1005, T1003
* * *
**Scenario**:
After Karen started working for 'TAAUSAI,' she began to do some illegal activities inside the company. 'TAAUSAI' hired you as a soc analyst to kick off an investigation on this case.

You acquired a disk image and found that Karen uses Linux OS on her machine. Analyze the disk image of Karen's computer and answer the provided questions.

**Tools**:
- [FTK Imager](https://accessdata.com/product-download/ftk-imager-version-4-5)
* * *
## Questions
> Q1: What distribution of Linux is being used on this machine?

I opened the evidence file using FTK Imager
![1307e44f65a166bedc8356de9e9d3705.png](../../_resources/1307e44f65a166bedc8356de9e9d3705-1.png)
And look like only root user, boot and var directories are presented here
![1ce648ca23acc77e3c62193af589275c.png](../../_resources/1ce648ca23acc77e3c62193af589275c-1.png)
Under boot directory, We can see that this evidence file was captured from kali linux system
```
kali
```

> Q2: What is the MD5 hash of the apache access.log?

Go to `/var/log/apache2` then we can see there is access.log file which has 0 size there
![381e2accf063014258ae8218b59c3193.png](../../_resources/381e2accf063014258ae8218b59c3193-1.png)
Export File Hash List to csv file then open it to see the MD5 of this log file
![feedd5ab1004c11366dc7330381d5099.png](../../_resources/feedd5ab1004c11366dc7330381d5099-1.png)
```
d41d8cd98f00b204e9800998ecf8427e
```

> Q3: It is believed that a credential dumping tool was downloaded? What is the file name of the download?

When user download files, The destination could be custom but the default directory is `~/Download` so go to `/root/Downloads` then the downloaded file is still there
```
mimikatz_trunk.zip
```

> Q4: There was a super-secret file created. What is the absolute path?

When file was created then user might be the one who did it and the lastest 1000 commands of that user will be logged on `~/.bash_history` so I checked out `/root/.bash_history`, we can see that user created a supersecret file on Desktop directory
![654858634c4a5c8d087cac7b0889e3a9.png](../../_resources/654858634c4a5c8d087cac7b0889e3a9-1.png)
```
/root/Desktop/SuperSecretFile.txt
```

> Q5: What program used didyouthinkwedmakeiteasy.jpg during execution?

Still on `.bash_history`, after scrolling there is a command used with this jpg file which is [binwalk](https://github.com/ReFirmLabs/binwalk) probably to find secret message or secret file inside of this image
![e072732cb0363c2d55988ae7da6bcafe.png](../../_resources/e072732cb0363c2d55988ae7da6bcafe-1.png)
```
binwalk
```

> Q6: What is the third goal from the checklist Karen created?

On Desktop, there is a file named Checklist and all the goal of this machine's user could be found here
![9ed267bde7bfbc9cd3f9100723c91df6.png](../../_resources/9ed267bde7bfbc9cd3f9100723c91df6-1.png)
```
profit
```

> Q7: How many times was apache run?

We can check the log files at `/var/log/apache2`, Now since all the log files have 0 size that mean user didn't run apache at all
![9310bd87918d11f39982eacb27b847cd.png](../../_resources/9310bd87918d11f39982eacb27b847cd-1.png)
```
0
```

> Q8: It is believed this machine was used to attack another. What file proves this?

On `/root` directory, there is an image file which is a screenshot of windows system and flag is presented in this image, maybe user used this machine to play CTF and tried to root the flag 
![c02864f7896af2eddf8372ea387456b0.png](../../_resources/c02864f7896af2eddf8372ea387456b0-1.png)

```
irZLAohL.jpeg
```

> Q9: Within the Documents file path, it is believed that Karen was taunting a fellow computer expert through a bash script. Who was Karen taunting?

![d9c7b8077a75977136f7f62ab235a79a.png](../../_resources/d9c7b8077a75977136f7f62ab235a79a-1.png)
You can get an answer from `firstscript_fixed`  
```
Young
```

> Q10: A user su'd to root at 11:26 multiple times. Who was it?

When user tried to authenticate, it will be logged at `\var\log\auth.log` so I went there and found that Karen used switch user command (`su`) from root to postgres multiple times at 11:26
![66e94b2763c39b8a1859d87316f868e7.png](../../_resources/66e94b2763c39b8a1859d87316f868e7-1.png)

```
postgres
```

> Q11: Based on the bash history, what is the current working directory?

The lastest change directory command (`cd`) destination is `../Documents/myfirsthack` and the above of it tells us that its in user root's directory
![69f4103b15b270a865693534aa950756.png](../../_resources/69f4103b15b270a865693534aa950756-1.png)
```
/root/Documents/myfirsthack
```

![e6b523d3b29f40c5dd1b300ec01b5c9c.png](../../_resources/e6b523d3b29f40c5dd1b300ec01b5c9c.png)
* * *