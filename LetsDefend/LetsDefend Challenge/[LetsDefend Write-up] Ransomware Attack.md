# [LetsDefend - Ransomware Attack](https://app.letsdefend.io/challenge/ransomware-attack)
Created: 02/06/2024 22:00
Last Updated: 02/06/2024 22:47
* * *
<div align=center>

**Ransomware Attack**
![f164fd88b9c57fe18290f50d3fc8fc92.png](../../_resources/f164fd88b9c57fe18290f50d3fc8fc92.png)
</div>
We have extracted the memory dump from the compromised machine. Find the evidence of the ransomware attack.

Memory Dump (pass: infected): C:\Users\LetsDefend\Desktop\Files\AnalysisSession1.7z

This challenge prepared by [@RussianPanda](https://www.linkedin.com/in/an-fam-868921105/)

* * *
You can also download memory dump file from [Download](https://files-ld.s3.us-east-2.amazonaws.com/AnalysisSession.zip) (pass: 321), This is a legitimate file that LetsDefend provided before they implemented built-in investigation lab on this challenge

And if you're not familiar with RedLine, [here](https://www.youtube.com/watch?v=tCIEYCWTdk4) is a video posted by 13Cubed which he taught about this software and demonstrate it.

## Start Investigation
> Please you find the dropped dll, include the whole path including the dll file

![cd345e01f1553a4d5bc9a0aa0eeabc6b.png](../../_resources/cd345e01f1553a4d5bc9a0aa0eeabc6b.png)
First we will need to open .mans file, after open Redline then click "Open Previous Analysis" then select file and click "Next"

![ff356cb0a1ecd6fbc773c94edd520b5f.png](../../_resources/ff356cb0a1ecd6fbc773c94edd520b5f.png)
.. wait for a sec then we're good to go

![9a3ef81bb07a803c148866736cf64147.png](../../_resources/9a3ef81bb07a803c148866736cf64147.png)
First thing I always want to check is File Download History and right there, its the hugh red flag since lsass should not be downloaded because its a core windows process

![509a30e7628fcceaa846755e73c36152.png](../../_resources/509a30e7628fcceaa846755e73c36152.png)
Go to File System and search for this file, then we can copy it hash to search on VirusTotal

![c3dbb97411bc830c859d700aef80bf4f.png](../../_resources/c3dbb97411bc830c859d700aef80bf4f.png)
There it is, look like its a trojan or even a ransomware

![68ca802026629eff6be8656bbdd7a7aa.png](../../_resources/68ca802026629eff6be8656bbdd7a7aa.png)
Next, I checked for process which I found this "MsMpEng.exe" (Microsoft Malware Protection Engine) was executed from user temp directory which is not the right place for it

![e710ff097c6a78c05c052d90c4b3132c.png](../../_resources/e710ff097c6a78c05c052d90c4b3132c.png)
Check out for ports and look like this process was used to established a connection to external IP address

![49d960e775b007205a9c0296378a68df.png](../../_resources/49d960e775b007205a9c0296378a68df.png)
This IP address is owned by Amazon AWS, it still didn't make sense why Microsoft Malware Protection contacted this IP address

![22acad080a03f69d5ea0bebf2a9fa356.png](../../_resources/22acad080a03f69d5ea0bebf2a9fa356.png)
An executable file is legitimate so the problem should come from dll sideloading

![7afbc97d873dbe30944cc321c7f7c483.png](../../_resources/7afbc97d873dbe30944cc321c7f7c483.png)
Go to File System > Imports then serach for this process then we will have "mpsvc.dll" and "KERNEL32.dll" was imported with this process, later is the legitimate one so we only need to check for the first one

![37a48f162564477211a6a5ddf329aa52.png](../../_resources/37a48f162564477211a6a5ddf329aa52.png)
Go to File System to grab it hash

![d64b6448e5126e2410bd65a0e79e93b8.png](../../_resources/d64b6448e5126e2410bd65a0e79e93b8.png)
This dll is a ransomware so its the one we're looking for
```
C:\Users\charles\AppData\Local\Temp\MpsVc.dll
```

> What is the MD5 hash for the dll?
```
040818b1b3c9b1bf8245f5bcb4eebbbc
```

> What is the name of ransomware note that got dropped?

![08606a153abe4f8373ee119267776e07.png](../../_resources/08606a153abe4f8373ee119267776e07.png)
On File System, I searched with ".txt" that we have this ransomnotes on sevaral locations
```
2s6lc-readme
```

> What is the URL that the initial payload was downloaded from? (Include the whole URL with the payload)

![9a3ef81bb07a803c148866736cf64147.png](../../_resources/9a3ef81bb07a803c148866736cf64147.png)
```
http://192.168.75.129:8111/Documents/lsass
```

> The ransomware drops the copy of the legitimate application into the Temp folder. Please provide the filename including the extension

![7401ef78f0f55d640db485d7de0306ed.png](../../_resources/7401ef78f0f55d640db485d7de0306ed.png)
We already know that "MsMpEng.exe" is legitimate file but was executed from user temp directory that is not where its belong
```
MsMpEng.exe
```

> What is name of the ransomware?

![d80adf3133f3993d49786c9f03dda47a.png](../../_resources/d80adf3133f3993d49786c9f03dda47a.png)
Sodinokibi or it also known as REvil ransomware
```
Sodinokibi
```

* * *
## Summary

On this challenge, we learn how to use Redline for memory analysis looking for an initial attack of Sodinokibi ransomware which will be known later as REvil

<div align=center>

![a02edaebf8cab0f3921bd9afce1b55df.png](../../_resources/a02edaebf8cab0f3921bd9afce1b55df.png)
</div>

* * *
