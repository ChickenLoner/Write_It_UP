# [HackTheBox Sherlocks - Takedown](https://app.hackthebox.com/sherlocks/Takedown)
![14e66ef239ea48fe7c93da4a2ae8f40e.png](/resources/14e66ef239ea48fe7c93da4a2ae8f40e.png)
**Scenario:**
We've identified an unusual pattern in our network activity, indicating a possible security breach. Our team suspects an unauthorized intrusion into our systems, potentially compromising sensitive data. Your task is to investigate this incident.
* * *
>Task 1: From what domain is the VBS script downloaded?

![adc8d1b64739344e445bb2f16ef4521f.png](/resources/adc8d1b64739344e445bb2f16ef4521f.png)

We have a single pcap file as a evidence on this sherlock so I'll use Wireshark to investigate it.

![754c91e3a84cfbd7e540f80f3a7819e5.png](/resources/754c91e3a84cfbd7e540f80f3a7819e5.png)

After opening the network capture file in Wireshark, I immediately noticed a DNS request to resolve the domain escuelademarina[.]com, as it appeared in the very first packet. Shortly afterward, there was an SMB request to access the cloud share on the previously resolved IP address (165.22.16.55) as the "admin" user, attempting to retrieve the file `AZURE_DOC_OPEN.vbs`. However, it appears that the initial attempt was unsuccessful to retrieve a whole file.

![510862b1721a2e47ae39a3be4c417ce1.png](/resources/510862b1721a2e47ae39a3be4c417ce1.png)

Using Wireshark’s Export Objects feature to inspect SMB file transfers, we can see that the admin user successfully retrieved the full content of this file in packet number 60. We also observe a request from 10.3.19.101—the same IP address that previously downloaded the VBS script from escuelademarina[.]com—making another HTTP request to 103.124.105.78. With this confirmed, we can proceed to answer the first three tasks and review the VBS script for further analysis.

```
escuelademarina.com
```

>Task 2: What was the IP address associated with the domain in question #1 used for this attack?
```
165.22.16.55
```

>Task 3: What is the filename of the VBS script used for initial access?
```
AZURE_DOC_OPEN.vbs
```

>Task 4: What was the URL used to get a PowerShell script?

![14bedec8f39390ce13c2140ec92882b8.png](/resources/14bedec8f39390ce13c2140ec92882b8.png)

The VBS script appeared harmless until the last four lines, where it created an object to execute a PowerShell command. This command retrieved content from badbutperfect[.]com/nrwncpwo and executed it.

![428f8d93767cc15a29734c4126c76062.png](/resources/428f8d93767cc15a29734c4126c76062.png)

After reviewing the content of `nrwncpwo`, we found that it is a PowerShell script designed to create the folder `C:\rimz`, then download three additional files—`AutoHotkey.exe`, `script.ahk`, and `test.txt`—from the same domain. This indicates that the AutoHotkey script will be executed afterward. The script also hides the `C:\rimz` directory. However, the purpose of `test.txt` remains unclear until we examine either `script.ahk` or `test.txt` itself.

```
badbutperfect.com/nrwncpwo
```

>Task 5: What likely legit binary was downloaded to the victim machine?
```
AutoHotkey.exe
```

>Task 6: From what URL was the malware used with the binary from question #5 downloaded?
```
http://badbutperfect.com/jvtobaqj
```

>Task 7: What filename was the malware from question #6 given on disk?
```
script.ahk
```

>Task 8: What is the TLSH of the malware?

![5ee0555f54aadc2eab2eb3f7d2267ea6.png](/resources/5ee0555f54aadc2eab2eb3f7d2267ea6.png)

Now we can export the AutoHotKey script to generate filehash and search it on VirusTotal.

![6787dbc061c4edc469d643114ac0758a.png](/resources/6787dbc061c4edc469d643114ac0758a.png)

The [VirusTotal](https://www.virustotal.com/gui/file/5aac7d31149048763e688878c3910ae4881826db80e078754f5d08f2c1f39572) reveal that this script will infect the victim with DarkGate malware.

![8b52aef3b69946995741f50b3919a1c5.png](/resources/8b52aef3b69946995741f50b3919a1c5.png)

We can get TLSH hash of this script right here.

```
T15E430A36DBC5202AD8E3074270096562FE7DC0215B4B32659C9EF16835CF6FF9B6A1B8
```

>Task 9: What is the name given to this malware? Use the name used by McAfee, Ikarus, and alejandro.sanchez.

![8e2137dc9049b52ed276258dd0af9a67.png](/resources/8e2137dc9049b52ed276258dd0af9a67.png)

As we already know that this script will infect victim with DarkGate but we can dig a little bit more deeper right? I have take the first screenshot on the day this sherlock was released and we can see that this sample have been contained in various collection related to DarkGate.

![5f502044c7947933d0b31b71b6affcdf.png](/resources/5f502044c7947933d0b31b71b6affcdf.png)

Here is the screenshot I took on 10th August 2025 while writing this write-up, all those collection gone but it is still contained in alejandro.sanchez's DarkGate collection here.

```
DarkGate
```

>Task 10: What is the user-agent string of the infected machine?

![c9c6378abf6949198cd7f19f217ccd51.png](/resources/c9c6378abf6949198cd7f19f217ccd51.png)

After infection, we observed numerous POST requests sent from the compromised machine to the C2 server, indicating beaconing activity. We were also able to identify the User-Agent used in this activity right here and now we should be able to finish this sherlock!

```
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36
```

>Task 11: To what IP does the RAT from the previous question connect?
```
103.124.105.78
```

![f492d709726f6898973c6de3350f9ac1.png](/resources/f492d709726f6898973c6de3350f9ac1.png)
https://labs.hackthebox.com/achievement/sherlock/1438364/761
* * *
## Appendix & Beyond Solved
![107f24870beecb889b92601bd2ed70fe.png](/resources/107f24870beecb889b92601bd2ed70fe.png)

I was curious about this DarkGate malware so I took a peek at the content of ahk script, we can see that the actual code might be hidden among these comments.

![bf8ff712985f6156f6604ec74606cfc4.png](/resources/bf8ff712985f6156f6604ec74606cfc4.png)

Then I discovered a [threat research report](https://unit42.paloaltonetworks.com/darkgate-malware-uses-excel-files/) released by Unit42 of Palo Alto Network which has already analyzed variant of this ahk script and DarkGate malware, we can see that they got their various only have different folder name and domain but everything look almost the same. 

![ad1c6d9ed2c1b42333e5fc6f3f2d2b6d.png](/resources/ad1c6d9ed2c1b42333e5fc6f3f2d2b6d.png)

On this report, we also learned that `test.txt` contains shellcode for DarkGate and `script.ahk` is used to deobfuscates it and load the shellcode in to the memory.

![ba1a57bc2a80a81a2217c1d49e060457.png](/resources/ba1a57bc2a80a81a2217c1d49e060457.png)

I went back to TCP stream again and discovered the first line of this script that was supposed to executed so I let ChatGPT write a simple script to remove all comments from ahk script for me to get the actual payload and here is the script I got
```python
import re

def remove_multiline_comments(file_path):
    # Read original file
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # Regex pattern to match /* ... */ (including across multiple lines)
    pattern = re.compile(r'/\*.*?\*/', re.DOTALL)

    # Keep removing until no more matches
    while pattern.search(content):
        content = pattern.sub('', content)

    # Save cleaned file
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(content)

    print(f"Removed all /* */ comment blocks from {file_path}")

if __name__ == "__main__":
    remove_multiline_comments("script.ahk")
```

![efe34a2dc4f4a39985499c7fed599561.png](/resources/efe34a2dc4f4a39985499c7fed599561.png)
![3859cf1a43ea8812a7b912f6937d8235.png](/resources/3859cf1a43ea8812a7b912f6937d8235.png)

Run the script and now we should have ahk script that look like Unit42's and that's it for this blog, thank you everyone for reading this far!

* * *