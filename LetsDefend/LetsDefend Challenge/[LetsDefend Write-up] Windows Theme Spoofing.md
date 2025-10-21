# [LetsDefend - Windows Theme Spoofing](https://app.letsdefend.io/challenge/windows-theme-spoofing)
Created: 07/01/2025 22:12
Last Updated: 12/01/2025 01:04
* * *
SOC team got an alert on their SIEM about the possible exploitation of CVE-2024-21320. The analyst on site captured the triage and relevant network capture as well to assist in this crucial investigation.
* * *
## Understand the vulnerability
![9069d946f4bb7e70ad44d2b2758af8a6.png](/resources/9069d946f4bb7e70ad44d2b2758af8a6.png)
https://youtu.be/06jmo8IIFtg

CVE-2024-21320 is a vulnerability involving Microsoft Themes that the threat actor can craft a theme file that will fetch resource from the threat actor SMB server then trick a victim to open it which will trigger automatic thumbnail creation by Explorer process which also sending SMB handshake packets to the threat actor machine including NTLM hash of the victim who opened the theme file which then the threat actor can crack it and login to the victim machine later.

**Resource**: 
- https://www.rbtsec.com/blog/cve-2024-21320-windows-themes-spoofing-vulnerability-walkthrough/
- https://www.akamai.com/blog/security-research/leaking-ntlm-credentials-through-windows-themes

Now we can start our investigation
***
## Start Investigation
>Can you identify the Attacker's file share path utilized to exploit the CVE?

![7781263b0f08878d4e347f4e8f84b9f4.png](/resources/7781263b0f08878d4e347f4e8f84b9f4.png)

Lets check out what we have first, there are 2 folders on the desktop which are `ChallengeFile` that contains evidence files collected by KAPE and `ntlm.pcapng` file.

![4c721605f38963743e8cf10869d06c52.png](/resources/4c721605f38963743e8cf10869d06c52.png)

We have bunch of tools as our disposal so lets just start with pcapng file first and come back to this when we really them.
 
![d43a4ef762d6ce391199361eaf8b3777.png](/resources/d43a4ef762d6ce391199361eaf8b3777.png)

After opened `ntlm.pcapng` with Wireshark and filtered with `smb2` for SMB 2 protocol then we can see that there are several attempts to fetch resource from `\\DESKTOP-887GK2L\smb12` and this is the file share path that we are looking for.

```
\\DESKTOP-887GK2L\smb12
```

>Victim's NTLM hash was relayed to the attacker's server allowing them to capture the hash and either use it in NTLM relay attacks or crack the hash. What is the Full Username of the compromised account? <br>
**Answer Format**: DOMAIN\Username

![e5b8f6d91423881aa6f98b4de74984ea.png](/resources/e5b8f6d91423881aa6f98b4de74984ea.png)

We can filter `ntlmssp` for NTLMSSP which is a protocol for Authentication using NTLM protocol which we can see that there are 3 Session Setup Requests using NTLMSSP_AUTH by "DESKTOP-ND6FH5D\LetsDefend" user and by sending these request then the attacker will be able to capture NTLM hash of this user.

```
DESKTOP-ND6FH5D\LetsDefend
```

>The victim's credentials were relayed to attackers 3 times. Considering only the packets related to the first relay, what is the NTLM Server challenge used in the NTLM negotiation?

![7e328b82a76552a4917c415f89213c32.png](/resources/7e328b82a76552a4917c415f89213c32.png)

Lets select packet number 122 which is the first Session Setup Response Error packet then by inspecting 

SMB2 (Server Block Message Protocol version 2) -> Session Setup Request (0x01) -> Security Blob: ... -> GSS-API ... -> Simple Protected Negotiation -> negTokenTarg -> NTLM Secure Service Provider -> **NTLM Server Challenge**

Then we will be able to get the NTLM Server Challenge used for this NTLM negotiation right here.

```
7b28fde95a265713
```

>What is the NTProofStr value in the NTLM negotiation?

![1ea6184b57181a95fb987d22f603e664.png](/resources/1ea6184b57181a95fb987d22f603e664.png)

Now lets move to packet number 123 and inspecting

SMB2 (Server Block Message Protocol version 2) -> Session Setup Request (0x01) -> Security Blob: ... -> GSS-API ... -> Simple Protected Negotiation -> negTokenTarg -> NTLM Secure Service Provider -> NTLM Response: ... -> NTLMv2 Response: ... -> **NTProofStr**

Then we should be able to retrieve NTProofStr value of this NTLM negotiation right here.

```
2731f9c2ac40d2f1aa3c1797ff0f026e
```

>Security team saw an RDP connection from the Attacker's internal machine to the compromised victim's machine, a day after the CVE was exploited. When did the attacker log on successfully? <br>
**Answer Format**: (YYYY-MM-DD HH:MM:SS)

![323d8b7006b15437f3e979781fffdfca.png](/resources/323d8b7006b15437f3e979781fffdfca.png)

To find out about this, we have to inspect this Windows Event log which focuses on remote connections to a machine, particularly for Remote Desktop Protocol (RDP) sessions.

![2ff7ad5b30e03cd175efeffde4f85e8d.png](/resources/2ff7ad5b30e03cd175efeffde4f85e8d.png)

By filtering Event ID 1149 (A successful Remote Desktop connection attempt is made.) on Terminal Services Remote Connection Manager (Operational) log then we should only have this 1 event right here which happened at "2024-03-15 03:03:44"

![731ac3585ff051d64fe11ad597ee9353.png](/resources/731ac3585ff051d64fe11ad597ee9353.png)

Then we can also see that "172.17.79.132" was the source IP of the attacker which successfully cracked "letsdefend" user password and connected to the victim machine via RDP

```
2024-03-15 03:03:44
```

>Tracing back to the start of the exploitation, what was the name of the file used to exploit the victim and exploit the cve. Please detail the full path of the file.

![187d78a7407557b8753ac65651b1b2f7.png](/resources/187d78a7407557b8753ac65651b1b2f7.png)

We know that this CVE can be exploited tricking user to open crafted theme file so we can use `MFTECmd.exe` (EZ tool) on `$MFT` to parse Master File Table then we will be able to search for the theme file from the output of this tool.

![d340917a5617bbc34a47526afd8728a5.png](/resources/d340917a5617bbc34a47526afd8728a5.png)

Open the output from `MFTECmd.exe` with "Timeline Explorer" and just simply search for `.theme` extension and now we can see that there is a suspicious theme file that we are looking for located at the LetsDefend user's Downloads folder.

```
C:\Users\LetsDefend\Downloads\theme.theme
```

>Attacker downloaded a Powershell script on the system, to further their objectives. What is the name of the script?

![4dbd09bb62fc5cfcb5c6b9238f16c4cf.png](/resources/4dbd09bb62fc5cfcb5c6b9238f16c4cf.png)

Now we will change our search term to `.ps1` extensino then we can see that `PowerView.ps1` is the one we are looking for and this script can gather detailed information about an Active Directory environment for reconnaissance and lateral movement.

```
PowerView.ps1
```

>Attacker Added a backdoor account for persistence mechanisms. What is the username and password of the newly created account? <br>
**Answer Format**: Username:Password

![a19047a5450eea51d87702a79a6846ac.png](/resources/a19047a5450eea51d87702a79a6846ac.png)

This time, we will have to check PowerShell commands then focus on Event ID 4104 for ScriptBlockLogging and we will see that the new user was created via PowerShell with `net user SupportAgent AgentPassword! /all`.

![68ae29df718063cc2b747f751238a8d9.png](/resources/68ae29df718063cc2b747f751238a8d9.png)

We can also see that this user was also added to "administrators" group after successfully created.

```
SupportAgent:AgentPassword!
```

* * *
## Summary
On this challenge, we got to know how CVE-2024-21320 works along with the way to detect it (such as capturing network traffic) then we also used Windows event log and Master File Table record to find out what happened after the attacker successfully exploited this vulnerability.

<div align=center>

![12bed00d9b33ee8cdfafb41434c52e0d.png](/resources/12bed00d9b33ee8cdfafb41434c52e0d.png)
https://app.letsdefend.io/my-rewards/detail/08d735067dde442c8c4e1e3d8e66a171
</div>

* * *
