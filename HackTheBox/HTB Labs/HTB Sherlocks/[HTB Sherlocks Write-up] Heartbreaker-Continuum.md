# [HackTheBox Sherlocks - Heartbreaker-Continuum](https://app.hackthebox.com/sherlocks/Heartbreaker-Continuum)
Created: 12/07/2024 17:30
Last Updated: 12/07/2024 22:38
* * *

![4d357b7ab63cde19a96bbfa8cd223a77.png](..//resources/4d357b7ab63cde19a96bbfa8cd223a77-1.png)
**Scenario:**
Following a recent report of a data breach at their company, the client submitted a potentially malicious executable file. The file originated from a link within a phishing email received by a victim user. Your objective is to analyze the binary to determine its functionality and possible consequences it may have on their network. By analyzing the functionality and potential consequences of this binary, you can gain valuable insights into the scope of the data breach and identify if it facilitated data exfiltration. Understanding the binary's capabilities will enable you to provide the client with a comprehensive report detailing the attack methodology, potential data at risk, and recommended mitigation steps.

* * *
>Task 1: To accurately reference and identify the suspicious binary, please provide its SHA256 hash.

![f6d1cb94e7c16c50b9cbb45ca0a44d3b.png](..//resources/f6d1cb94e7c16c50b9cbb45ca0a44d3b-1.png)

This can easily be obtained by several ways, I preferred HashMyFiles since it was already built-in within FlareVM

```
12daa34111bb54b3dcbad42305663e44e7e6c3842f015cccbbe6564d9dfd3ea3
```

>Task 2: When was the binary file originally created, according to its metadata (UTC)?

![d050da75809b0ddaa6fad9c814ac7484.png](..//resources/d050da75809b0ddaa6fad9c814ac7484-1.png)

We can check metadata of this file to obtain an answer or we can just search filehash on VirusTotal and grab this "Creation Time" in "Details" tab

![f4826949f8f6e60b25bd0baab5d6f070.png](..//resources/f4826949f8f6e60b25bd0baab5d6f070-1.png)

And from VirusTotal, we can see that its an executable file that was converted from PowerShell to PE32 executable

```
2024-03-13 10:38:06
```

>Task 3: Examining the code size in a binary file can give indications about its functionality. Could you specify the byte size of the code in this binary?

![04b5402a77683f9200c0d631f0f73cbf.png](..//resources/04b5402a77683f9200c0d631f0f73cbf-1.png)

We can use pestudio for this one and after opened a file in pestudio, go to "optional header" then we can see "size of code" there

```
38400
```

>Task 4: It appears that the binary may have undergone a file conversion process. Could you determine its original filename?

![56aa2ca8d5260cf6b812d459c1f5299e.png](..//resources/56aa2ca8d5260cf6b812d459c1f5299e-1.png)

In pestudio, go to resources then we can see the name of an original powershell script that was converted to this PE32 executable file

```
newILY.ps1
```

>Task 5: Specify the hexadecimal offset where the obfuscated code of the identified original file begins in the binary.

![baa846270bd41f991ae8efe8f5c5d1b2.png](..//resources/baa846270bd41f991ae8efe8f5c5d1b2-1.png)

We can use "strings" (built-in tool in FlareVM) to find where the obfuscated code is located in this PE32 executable file

![29e10f875ae1e196d0b58dae7ef5c57b.png](..//resources/29e10f875ae1e196d0b58dae7ef5c57b-1.png)

Alternatively, you can use any hex editor to locate this obfuscated code directly

```
2C74
```

>Task 6: The threat actor concealed the plaintext script within the binary. Can you provide the encoding method used for this obfuscation?

Obfuscated code started with "==" which is likely to be base64 string in reverse and to confirm this we need to scroll down a little bit more to find method that eventually execute this code

![72c7f145912ccc6c579297b2f68a6593.png](..//resources/72c7f145912ccc6c579297b2f68a6593-1.png)

![6f7308d8b2888eb7adbada1be6b95367.png](..//resources/6f7308d8b2888eb7adbada1be6b95367-1.png)

Then we can see that it is reverse base64 as expected

```
Base64
```

>Task 7: What is the specific cmdlet utilized that was used to initiate file downloads?

![def09b55566b353f8b06564f89b3f877.png](..//resources/def09b55566b353f8b06564f89b3f877-1.png)

Go to Cyberchef to make it a little bit easier to decode then we can see that it will use `Invoke-WebRequest` to download "itself" from C2 server to current user's Downloads location before execute it

```
Invoke-WebRequest
```

>Task 8: Could you identify any possible network-related Indicators of Compromise (IoCs) after examining the code? Separate IPs by comma and in ascending order.

![b41d8e099dc746e35cb29969d071b6ba.png](..//resources/b41d8e099dc746e35cb29969d071b6ba-1.png)

We can use "Regular expression" operation in Cyberchef with "IPv4 address" regex built-in to get all IPv4 addresses then we will see that there are only 2 uniques IPv4 addresses from this code

```
35.169.66.138,44.206.187.144
```

>Task 9: The binary created a staging directory. Can you specify the location of this directory where the harvested files are stored?

![d563a3a25726e6ca2b3320bd03c24ed3.png](..//resources/d563a3a25726e6ca2b3320bd03c24ed3-1.png)

We can see that `targetDir` varible was assigned to this path to store all output files generated by this code

```
C:\Users\Public\Public Files
```

>Task 10: What MITRE ID corresponds to the technique used by the malicious binary to autonomously gather data?

![2fbdf508eeff8c2dfac4d75483bd2bf6.png](..//resources/2fbdf508eeff8c2dfac4d75483bd2bf6-1.png)

This is the technique that this task referring to

```
T1119
```

>Task 11: What is the password utilized to exfiltrate the collected files through the file transfer program within the binary?

![595bb75a109d7bcb7ad7f00efe6caff5.png](..//resources/595bb75a109d7bcb7ad7f00efe6caff5-1.png)

before exit program, it uses "sftp" to send all harvested files to another C2 server that we found on task 8 which including user credentials for this service too

```
M8&C!i6KkmGL1-#
```

![ac75390cfee51202e13999bc5400027a.png](..//resources/ac75390cfee51202e13999bc5400027a-1.png)

https://labs.hackthebox.com/achievement/sherlock/1438364/699
* * *
