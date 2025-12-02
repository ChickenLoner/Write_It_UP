# [Blue Team Labs Online - Zeta End](https://blueteamlabs.online/home/investigation/zeta-end-2a5b4e8c18)
<div align=center>

![fed2cf400076028b38af448fc011abe1.png](/resources/fed2cf400076028b38af448fc011abe1.png)

</div>

The situation has Escalated! Continue your investigation as part of Zeta-9’s Cyber Response & Incident Security Investigation Services (CRISIS) . A full triage image has been taken from a machine within Zeta-9's Secret LAN Perform a full DFIR analysis To uncover the Threat Actors Final Objectives...

>Digital Forensics

>**Tags**: EZ-TOOLS, IDA, HxD, TimeLineExplorer
* * *

## Scenario
The situation has escalated to its breaking point: the cure — humanity’s last safeguard against the outbreak — has been fully erased from Zeta-9’s systems and simultaneously leaked onto the dark web; Dr. Frankenstein Code, head of the division, confirms there is no trace left across any researcher’s machine, raising fears of deliberate sabotage rather than simple theft. Investigators have already uncovered the attackers’ entry point: after compromising a trusted cloud-hosted web server, they defaced a site frequently visited by the Secret Division’s researchers. That single foothold allowed them to infect the Secret Division LAN, granting the access they needed to strike at the heart of Zeta-9. You have been contracted as part of Zeta-9’s Cyber Response & Incident Security Investigation Services (CRISIS) . Your mission: trace the breach, uncover what the attackers stole, and determine whether the company’s darkest secret — and humanity’s last hope — has already slipped beyond its grasp. The most urgent question remains: is the cure already slipped beyond recovery, or can you act quickly enough to reclaim it and pull Zeta-9 back from the edge of total collapse? WARNING: this lab has a number of artifacts you will need to access on your internet connected machine
* * *
## Background
- On [Patient Z-ero](https://blueteamlabs.online/home/investigation/patient-z-ero-b358d0acb9) investigation, the threat actor successfully compromised FortiGate firewall which grant them access to the internal network via VPN
- On [The Walking Packets](https://blueteamlabs.online/home/investigation/the-walking-packets-f8cf5573cf), the threat actor compromised surveillance platform and obtained credential of the JUMPHOST user from the surveillance video record.
- On [The Headless Dead](https://blueteamlabs.online/home/investigation/the-headless-dead-f8e2c3f90b), the threat actor leveraged local administrator credential obtained from surveillance platform and with the access to the internal network with VPN to conduct WMI-based lateral movement to JUMPHOST and exfiltrated the AWS secret.
- On [Rotten Cloud](https://blueteamlabs.online/home/investigation/rotten-cloud-dcf4ab87e0), the threat actor used AWS secret to access multiple sensitive S3 objects and secret and then use secret web portal of the organization website to requested OAuth token and access multiple sensitive objects in Azure blob and lastly, defaced website with malcious filefox hosting page.

***
## Environment Awareness
### Evidence & Tool Discovery
![4cba1fa884a8f97e787dc6c879b4d0fc.png](/resources/4cba1fa884a8f97e787dc6c879b4d0fc.png)

On this investigation, we will have the triaged evidence of the workstation belong to Dr. Frankenstein Code, the researcher of Zeta-9.  

![366853180ab265a502319cbf1bf130b3.png](/resources/366853180ab265a502319cbf1bf130b3.png)

Interestingly, this workstation also have Wing FTP Server installed which suddenly made me think of CVE-2025-47812 that is the RCE vulnerability of Wing FTP Server but as we already know that Dr. Frankenstein Code might fall for the ClickFix attack as discovered from Rotten Cloud investigation so this might be a rabbit hole.

![8d964d368eafae15892a945adca23305.png](/resources/8d964d368eafae15892a945adca23305.png)

We also have Dr. Helena on this workstation as well but our main focus would be on the Dr. Frankenstein Code

Now I will parse Windows event log folder with EvtxECmd, Usn journal and MFT with MFTECmd and lastly, prefetch with PECmd to be ready for this investigation.

Command: `EvtxECmd.exe -d "C:\Users\BTLOTest\Desktop\Artefacts\C\Windows\System32\winevt\logs" --csv . --csvf log_timeline.csv`

![75975bc4e6a8773ef87365e7debaa0fc.png](/resources/75975bc4e6a8773ef87365e7debaa0fc.png)

Command: `MFTECmd.exe -f C:\Users\BTLOTest\Desktop\Artefacts\C\$Extend\$J -m C:\Users\BTLOTest\Desktop\Artefact\C\$MFT --csv C:\Users\BTLOTest\Desktop`

![3c38a50842ccabb881bd145b8d2878a7.png](/resources/3c38a50842ccabb881bd145b8d2878a7.png)

Command: `PECmd.exe -d C:\Users\BTLOTest\Desktop\Artefacts\C\Windows\prefetch --csv c:\Users\BTLOTest\Desktop`

* * *
## Investigation
>Q1) Investigators found that Dr. Frankenstein visited a compromised Zeta-9 web page that served the initial access to the Secret Division network. When did he access that page?

As we already know from the Rotten Cloud investigation that the threat actor defaced the organization's website (`https://zeta9-research-portal.azurewebsites.net/`) to host malicious filefix command. we will need to look for browser history of Dr. Frankenstein that visit this site 

![4160423e761927143f9a5cd769eca003.png](/resources/4160423e761927143f9a5cd769eca003.png)

And as we can see that Dr. Frankenstein visited the defaced website at 2025-09-27 11:17:33, this should set the starter time of our incident timeline and focus on any suspicious event that come after this.

<details>
  <summary>Answer</summary>
<pre><code>2025-09-27 11:17:33</code></pre>
</details>

>Q2) While viewing a shared Zeta-9 document, Frankenstein unknowingly ran a payload delivered via the site. What is the name of the Powershell script he was tricked into executing?

![e2ae77af51e6da28c3a0cd98d45a4fc7.png](/resources/e2ae77af51e6da28c3a0cd98d45a4fc7.png)

Now we shall go back to [web archive](https://web.archive.org/web/20250925080847/https://zeta9-research-portal.azurewebsites.net/) of the organization website and now we shall copy the command to reveal what being executed on the compromised workstation.

![6d1e9d4d69b3e94ca4df244188a2b87d.png](/resources/6d1e9d4d69b3e94ca4df244188a2b87d.png)

We can see that when this command is entered into the File Explorer address bar, the PowerShell script hosted on the provided [Gist URL](https://gist.githubusercontent.com/a1l4m/6061b2f64b6ba3044ad6126d7b80a89e/raw/11ce5924a3c35d28bed2572db2bac7e2ac733af5/Microsoft.PowerShell.DataV4Adapter.ps1) is executed. This execution results in the threat actor gaining initial access to the workstation.

<details>
  <summary>Answer</summary>
<pre><code>Microsoft.PowerShell.DataV4Adapter.ps1</code></pre>
</details>

>Q3) Based on the way the victim was duped into running the payload, identify the exact technique name the attacker used.

![e2ae77af51e6da28c3a0cd98d45a4fc7.png](/resources/e2ae77af51e6da28c3a0cd98d45a4fc7.png)

As we already discovered that the technique that was used here is "filefix" so this is the easy answer. I've also seen many people misinterpret the question as MITRE ATT&CK Technique but it's just simple as this.

<details>
  <summary>Answer</summary>
<pre><code>filefix</code></pre>
</details>

>Q4) As Frankenstein was tricked into running a malicious command on their system, that has led to the execution of shellcode that granted the attacker full access to his machine. What is the MD5 hash of this shellcode?

![ebe8de21a2008c295ce8acc2779dfaab.png](/resources/ebe8de21a2008c295ce8acc2779dfaab.png)

Now we shall making sense of the script here, we can see that it has `$compressedBase64` variable store base64 blob which will be decoded and decompress (gunzip) to get another PowerShell script and execute it with `Invoke-Expression` 

![be4b0921cc9941dd447495f5cdd2c752.png](/resources/be4b0921cc9941dd447495f5cdd2c752.png)

We can use CyberChef to decode and gunzip the base64 blob which reveal another PowerShell script that also contain another base64 blob in `$ETPvFICDa` variable and to get the decrypted script, this time we will need to reverse it first before base64 decoding.

![19f0a4382063ceb70885f79a52d402ea.png](/resources/19f0a4382063ceb70885f79a52d402ea.png)

Now this should be the final script, which will fetch the shellcode from another [Gist URL](https://gist.githubusercontent.com/a1l4m/2e771fb306028fabfc8e098427181f78/raw/37f3db6b29d64f1045fb60967d6297f525ddf443/IamTheDanger.txt) which will be convert from Hex to raw bytes, decompress it (gunzip) and lastly, XOR with 0xFF to get the final shellcode ready to be injected and executed.

![402ed67fb5fea2ce810fc350beb4e3bc.png](/resources/402ed67fb5fea2ce810fc350beb4e3bc.png)

To get MD5 of this shellcode, we shall replicate the step from the script but here is the catch, A1l4m, the creator have this lab required us to convert raw shellcode back to hex and remove whitespace before calculating MD5 hash. I don't really know the reason so let's just go with that.

<details>
  <summary>Answer</summary>
<pre><code>d3cf756ebbdf7b015a2ee4e154b638ee</code></pre>
</details>

>Q5) As a result of the shellcode running, Frankenstein’s machine reached back to a command-and-control host. Provide the external IP and port used.

![3965ed69e033df76f9c48b69e9b1e44e.png](/resources/3965ed69e033df76f9c48b69e9b1e44e.png)

There are multiple way to find out the question. First is to run the shellcode while let Process Monitor running to detect any connection to any IP from powershell process and the second way is to fall for the filefix attack in the sandbox as seen in this [any.run report](https://app.any.run/tasks/012f6aa4-d26d-4fa9-b88d-992bcb8459f4) here, the IP and port that was reach out from `powershell.exe` is 35.158.153.237:34651

<details>
  <summary>Answer</summary>
<pre><code>35.158.153.237:34651</code></pre>
</details>

>Q6) After the C2 connection succeeded, the attacker ran a simple command to confirm identity and environment. Which command did they run to enumerate the machine?

![3f4e220ecfc4b4aabedb8a628a192c3a.png](/resources/3f4e220ecfc4b4aabedb8a628a192c3a.png)

We can take a look at prefetch timeline to see what's going on after Dr. Frankenstein accessed the defaced website which we can see that `whoami.exe` was executed afterward and follow by multiple `rclone.exe` execution to `runtimebroker.exe` on public user's home folder which is not standard location for this executable at all and now it is confirmed that after gaining access to this workstation. the threat actor executed `whoami` to confirm its identity on this host first before transfering tool from cloud with rclone.

<details>
  <summary>Answer</summary>
<pre><code>whoami</code></pre>
</details>

>Q7) Shortly after gaining access, the intruder changed PowerShell’s execution policy. When exactly was that modification made?

![4dfb25ef024a80969eebc3a9cf1cb0c1.png](/resources/4dfb25ef024a80969eebc3a9cf1cb0c1.png)

We can use Registry Explorer to look at the ExecutionPolicy registry key under `NTUSER.dat` hive of Dr. Frankenstein which reveals that at 2025-09-27 11:19:49, the threat actor changed the execution policy of this user to Unrestricted which will allow any script to run on this workstation under this user.

<details>
  <summary>Answer</summary>
<pre><code>2025-09-27 11:19:49</code></pre>
</details>

>Q8) To survive reboots, the attacker dropped a secondary executable. What is the full filesystem path to the executable used for persistence?

![435743b75d9b77ad37690d9569b76532.png](/resources/435743b75d9b77ad37690d9569b76532.png)

As we already discovered that the `RunTimeBroker.exe` was executed after rclone and Powershell and we also have this file to calculate file hash as well so lets get its hash and submit to VirusTotal.

![3b387168e2637bb4070b1c6ae26ddbaf.png](/resources/3b387168e2637bb4070b1c6ae26ddbaf.png)

The [VirusTotal](https://www.virustotal.com/gui/file/2c327fdbaf65f8626f76858206a18a81790c5233917396e96f12d4cdea06fc7b/detection) reveals that this executable is the sliver implant so it make sense that the threat actor will drop binary to stay persistence because of the initial access was acquired via clickfix (well technically, the threat actor could set up persistence to execute the filefix payload again)

<details>
  <summary>Answer</summary>
<pre><code>C:\Users\Public\RunTimeBroker.exe</code></pre>
</details>

>Q9) Which tool did the attacker use to retrieve that persistence binary?

![19d318d88df56f342c04413795b0532d.png](/resources/19d318d88df56f342c04413795b0532d.png)

Now lets find the origin of this file though Usn Journal, as we already discovered that it might come from `rclone` and the Usn Journal confirmed it as it was first created under the name of rclone temporary file which was later renamed to its orginal name (`sapi.cpl`) which then renamed to `RunTimeBroker.exe` and moved to `C:\Users\Public\` at the end.

<details>
  <summary>Answer</summary>
<pre><code>rclone</code></pre>
</details>

>Q10) When was the persistence mechanism actually put in place (i.e., when was the content that trigger the executable written)?

![0a1d2a2c2db8cd76fc67e27033ae8995.png](/resources/0a1d2a2c2db8cd76fc67e27033ae8995.png)

This one is quite tricky, from the prefetch file we can see that the sliver implant were executed after the PowerShell every time which make me believe that it must be the persistence related to PowerShell.

![ec8c2fb21bee4540c5c38b47c7859b74.png](/resources/ec8c2fb21bee4540c5c38b47c7859b74.png)

And after looking though the Usn Journal, we can see that at 2025-09-27 11:35:08 during the incident timeframe, the PowerShell profile was edited and it is also confirmed that the threat actor edited PowerShell profile to make sliver implant execute every time the PowerShell profile is loaded (normally when PowerShell started)

<details>
  <summary>Answer</summary>
<pre><code>2025-09-27 11:35:08</code></pre>
</details>

>Q11) Which C2 server (IP:Port) did the persistence binary contact?

![3ccffec1def079dfa115842e57276f24.png](/resources/3ccffec1def079dfa115842e57276f24.png)

There are 2 ways to find out about this, first is to run this bad boy while letting Process Monitoring captures it network connection which is send to 63.178.44.21:8838

![fb945bbdaa52b511a773a396d5cb35b4.png](/resources/fb945bbdaa52b511a773a396d5cb35b4.png)

Another way is to go back to VirusTotal and we can see that it contact the same IP address and Port and this port is not standard at all which make it standout as the reverse shell connection port.

<details>
  <summary>Answer</summary>
<pre><code>63.178.44.21:8838</code></pre>
</details>

>Q12) Identify the framework used by the malicious file for command and control communication.

![0a328b5968b85a651fdbe4ef816646f5.png](/resources/0a328b5968b85a651fdbe4ef816646f5.png)

Sliver it is.

<details>
  <summary>Answer</summary>
<pre><code>Sliver</code></pre>
</details>

>Q13) Once the intruder confirmed continued access, they casually explored the network of the secret division without fear of being cut off. They downloaded a ZIP file containing their exfiltration toolkit. Provide the MD5 hash of that ZIP.

![a09eafc6d993723de1d451670286bac4.png](/resources/a09eafc6d993723de1d451670286bac4.png)

First, we will have to identify what is the zip file and how it was downloaded to this workstation, and using Usn Journal. we can see that `CUREKiller.zip` was downloaded via certutil lolbin and it has 5 files inside of it.

![5b4c13b1abe16c9da0646cdfdcefc94b.png](/resources/5b4c13b1abe16c9da0646cdfdcefc94b.png)

Sadly, there is no relevant cerutil artifact for us so we will have to use webcache located at `C:\Users\Dr.FrankensteinCode\AppData\Local\Microsoft\Windows\WebCache` and we can see that it cached HTTP request that requested to download `CUREKiller.zip` file but how could we obtain the hash of this file?

![244e69ed22a3f523c75f23f08db445e5.png](/resources/244e69ed22a3f523c75f23f08db445e5.png)

We can take the value of `x-ms-blob-content-md5` which was used to verify the integrity of the blob during transport.

![f8f90d21c93ed00f97af7c7318f97829.png](/resources/f8f90d21c93ed00f97af7c7318f97829.png)

We will need to convert it back from base64 and convert it to hex to finally obtain MD5 of this file.

<details>
  <summary>Answer</summary>
<pre><code>b289a7f5fd8bcb22e5452d4fe3e57174</code></pre>
</details>

>Q14) Eventually, the adversary moved from reconnaissance to data theft. When exactly was the executable used for exfiltration run?

![0c33d73614856c10c82322493fe27dde.png](/resources/0c33d73614856c10c82322493fe27dde.png)

From the prefetch timeline, we can see that `KillTheCure.exe` which was believed to be the executable used for exfiltration executed at 2025-09-27 15:49:58 follow my `sdelete` to securely delete 6 different files from this workstation.

![7ce04e3b91dc371b1e9e6f5faf2f7060.png](/resources/7ce04e3b91dc371b1e9e6f5faf2f7060.png)

At the same time, we can see that `Exfiltrated_data.zip` was created during the execution of `KillTheCure.exe`

![8d827a50b3da81a764d42a97fded03d3.png](/resources/8d827a50b3da81a764d42a97fded03d3.png)

`SDelete.exe` execution was observed executing immediately after the execution of `KillTheCURE.exe` which deleted 6 files on the desktop which are.

- `C:\Users\Dr.FrankensteinCode\Desktop\confidential.png`
- `C:\Users\Dr.FrankensteinCode\Desktop\CURE.txt`
- `C:\Users\Dr.FrankensteinCode\Desktop\gunman.png`
- `C:\Users\Dr.FrankensteinCode\Desktop\Helena.txt`
- `C:\Users\Dr.FrankensteinCode\Desktop\test.txt`
- `C:\Users\Dr.FrankensteinCode\Desktop\outbreak.png`

and all of these files are located on the desktop that make us believe that the exfiltration executable only target desktop of the user that execute it.

<details>
  <summary>Answer</summary>
<pre><code>2025-09-27 15:49:58</code></pre>
</details>

>Q15) What is the IP address of the remote host used for exfiltration?

![764096811f2cd9a5bff66978c809ed4d.png](/resources/764096811f2cd9a5bff66978c809ed4d.png)

We will need to get the `CUREKiller.zip` file and reverse `KillTheCure.exe` binary but how? there is an interesting article made by SBT that could help us [here](https://www.securityblue.team/blog/posts/github-discord-secret-file-locker-hackers-playground) which is talking about the alternative way to host file on GitHub in issue, pull request or even comment and even provide us with URL scheme to play around with it.

![dd02cf649e0f42db03a907031b27a8ba.png](/resources/dd02cf649e0f42db03a907031b27a8ba.png)

So assuming the threat actor used the same trick to host this zip file, how could we obtain the "unique_id"? well it is easier than expected. its in the end of url before parameter was added after `?`

![1451db772571f63fd08102b98cb90aee.png](/resources/1451db772571f63fd08102b98cb90aee.png)

Which mean now we should be able to download ZIP file from `https://github.com/user-attachments/files/22441452/CUREKiller.zip` and here are the 5 files as already discovered from Usn Journal.

![8bd1338373bca091632e64faf3470ca6.png](/resources/8bd1338373bca091632e64faf3470ca6.png)

![d1aaf24b356b7916b12acbafd0c466d8.png](/resources/d1aaf24b356b7916b12acbafd0c466d8.png)

We can now decompile the executable with any tool we like, and we can see that the upon execution, it will search for `.png` and `.jpg` file in Downloads and Desktop folder of the user who executed it and move to temp folder to zip it as `Exfiltrated_data.zip` before embededed it inside `BetterCallSaul.png` file (which we have it in the investigation machine on the Downloads folder) and then use `sdelete` to remove original file, then it also delete all temp files (without sdelete)

![24a0ca5d77a167198cf873797d2e32b3.png](/resources/24a0ca5d77a167198cf873797d2e32b3.png)

Lastly it will send `BetterCallSaul.png` to 36.157.123.216 using HTTP POST request to `/upload` path. 

<details>
  <summary>Answer</summary>
<pre><code>36.157.123.216</code></pre>
</details>

>Q16) The attacker stole and erased the critical files from the Secret Division network. Name the stolen files and sort them alphabetically.

As already that there are 6 files with have `.png` or `.txt` on the Desktop folder during the execution of exfiltrate executable which are `confidential.png`, `cure.txt`, `gunman.png`, `Helena.txt`, `outbreak.png` and `test.txt`

<details>
  <summary>Answer</summary>
<pre><code>confidential.png, cure.txt, gunman.png, Helena.txt, outbreak.png, test.txt</code></pre>
</details>

>Q17) When the attacker’s primary C2 endpoints used for exfil failed, they turned to a different tool to keep exfiltration going. What tool was used as the fallback?

![7aa984de33e6dcaa8bd4c392428b0bdc.png](/resources/7aa984de33e6dcaa8bd4c392428b0bdc.png)

We already know that the threat actor used rclone to drop sliver C2 so it can also be used as a fallback to sync/upload exfilrated file and the browser history of chrome in the investigation machine also reveals that we downloaded `BetterCallSaul.png` from MEGA.

![b3307b5f3cb892ffb448d3f0632b8a57.png](/resources/b3307b5f3cb892ffb448d3f0632b8a57.png)

Now we just have to confirm it, by getting the MEGA credential from rclone configuration file but the password is encrypted right now. we will need to decrypt it

![4edb4eaf206c82ee3fe2cde0d9183168.png](/resources/4edb4eaf206c82ee3fe2cde0d9183168.png)

Since Rclone is open source then there are multiple tool that can decrypt rclone ciphertext including [this one](https://github.com/maaaaz/rclonedeobscure) and now I have password of both user in cleartext.

![f21e4eb53c123956eb49a3a831a2cc85.png](/resources/f21e4eb53c123956eb49a3a831a2cc85.png)

I login into each MEGA account, the first account is not really interesting but the second one confirmed that the image file also cloned here using rclone!

![6e8e6ea67fa66638eb7d929749cfa2fb.png](/resources/6e8e6ea67fa66638eb7d929749cfa2fb.png)

Beside that, we can also see the sliver implant here with netcat binary and exploitation script of Wing FTP Server RCE as already suspected

<details>
  <summary>Answer</summary>
<pre><code>rclone</code></pre>
</details>

>Q18) To use that alternate tool, the attacker needed cloud access. They stored credentials on the system. Provide the email and password for that account that they used. [No need for brute force anywhere.]
<details>
  <summary>Answer</summary>
<pre><code>00darksideofme00+2@gmail.com:Necrobyte001123!</code></pre>
</details>

>Q19) The critical file 'cure.txt' was among the wiped data! Recovery is considered possible — if you can restore it, submit the file’s MD5 hash. Fellow Investigators have logged into the attacker’s cloud using the credentials from the previous question and stored a copy of the exfiltrated content locally here: C:\users\BTLOtest\Downloads

Since we have the exfiltration binary and the image file, I will use the following script generated by ChatGPT to extract zip file from the image.

```python
# extractor.py
# Requires: Pillow (PIL)
# Usage: python extractor.py hidden.png recovered.bin

import sys
from PIL import Image
import zlib
import struct

def read_rgba_bytes(png_path):
    img = Image.open(png_path)
    img = img.convert("RGBA")
    data = img.tobytes()  # row-major RGBA
    return data

def extract(png_path, out_path):
    data = read_rgba_bytes(png_path)
    # The C code stored the header+payload directly into the RGBA bytes.
    # So the first 16 bytes of 'data' are the header.
    if len(data) < 16:
        raise ValueError("PNG too small or not containing embedded data.")
    header = data[:16]
    crc32_field, key_field_lo, orig_size = struct.unpack("<I Q I", header)
    # key_field_lo contains the 4-byte key in its low 4 bytes.
    key = struct.pack("<Q", key_field_lo)[:4]  # first 4 bytes little-endian
    original_size = orig_size
    encrypted = data[16:16+original_size]
    if len(encrypted) < original_size:
        raise ValueError("PNG does not contain full payload (truncated).")
    # verify CRC32: the C function used crc32(0,..) then crc32(prev, &v71, 12)
    # Which effectively is CRC32 over the 12-byte block starting at v71 (key + size)
    # Recreate the 12-byte block:
    key_u32 = key  # 4 bytes little-endian
    block12 = key_u32 + struct.pack("<I", original_size) + b'\x00\x00\x00\x00'[:0]  # ensure 12 bytes layout matches
    # The C code wrote: 4-byte CRC, 8-byte key-field, 4-byte size -> so the 12 bytes crc used are (low 12 bytes of that area)
    # Build what the code likely CRC'd: 4 bytes key + 4 bytes zero? + 4 bytes size might differ per compile.
    # To be compatible with the producer, reconstruct as the C code did:
    # In practice we'll compute crc32 over the 12 byte region that starts at the 8-byte key_field (little-endian)
    # Build the 12-bytes as: low 4 bytes = key, next 4 bytes = 0 (upper of Q), next 4 bytes = size
    block12 = key + b'\x00\x00\x00\x00' + struct.pack("<I", original_size)
    check_crc = zlib.crc32(block12) & 0xFFFFFFFF
    if check_crc != crc32_field:
        print("Warning: CRC mismatch (payload integrity check failed).")
        # still attempt extraction, maybe the producer's exact CRC ordering differs.
    # XOR decrypt with 4-byte key repeating
    key_bytes = key
    out = bytearray()
    for i, b in enumerate(encrypted):
        out.append(b ^ key_bytes[i % 4])
    with open(out_path, "wb") as f:
        f.write(out)
    print(f"Wrote {len(out)} bytes to {out_path}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python extractor.py hidden.png recovered.bin")
        sys.exit(1)
    extract(sys.argv[1], sys.argv[2])
```

![0793646fac2eda076faae5100bb7c5a1.png](/resources/0793646fac2eda076faae5100bb7c5a1.png)

And now we should be able to unzip it.

![1e29b0de5589c85f284dc39eab11b684.png](/resources/1e29b0de5589c85f284dc39eab11b684.png)

and finally obtained the hash of `CURE.txt` file.

<details>
  <summary>Answer</summary>
<pre><code>d81c7ad96edfb8e183613f579f105578</code></pre>
</details>

>Q20) After completing the earlier steps, the attacker turned to covering his tracks. the adversary deleted various artifacts (tools, event logs, registry keys). When were the registry keys that contained the initial-access command wiped?

![17186022a661fef49f26f0d6799623b9.png](/resources/17186022a661fef49f26f0d6799623b9.png)

Since we know that the threat actor lured Dr. Frankenstein with filefix attack then the registry that might record the command is the `TypedPaths` registry key but since its all cleared then the threat actor cleared it and the timestamp of the last write key reveals when it was happened.

<details>
  <summary>Answer</summary>
<pre><code>2025-09-28 02:20:47</code></pre>
</details>

>Q21) Finally, the attacker cleared Windows event logs to cover their tracks. How many log files were cleared?

![8b9abd05921ddd7f9f1ce69cb5a89e14.png](/resources/8b9abd05921ddd7f9f1ce69cb5a89e14.png)

Lastly, we can see that the threat actor executed `wevutil` to clear 5 different logs and now all the questions were answered. thanks for reading!

<details>
  <summary>Answer</summary>
<pre><code>5</code></pre>
</details>

https://blueteamlabs.online/achievement/share/52929/280
* * *