# [CyberDefenders - Kerberoasted](https://cyberdefenders.org/blueteam-ctf-challenges/kerberoasted/)
[toc]
* * *
## Scenario
As a diligent cyber threat hunter, your investigation begins with a hypothesis: 'Recent trends suggest an upsurge in Kerberoasting attacks within the industry. Could your organization be a potential target for this attack technique?' This hypothesis lays the foundation for your comprehensive investigation, starting with an in-depth analysis of the domain controller logs to detect and mitigate any potential threats to the security landscape.

Note: Your Domain Controller is configured to audit Kerberos Service Ticket Operations, which is necessary to investigate kerberoasting attacks. Additionally, Sysmon is installed for enhanced monitoring.

**Category**: Threat Hunting

**Tools**:
Splunk
ELK
* * *
## Questions
>Q1: To mitigate Kerberoasting attacks effectively, we need to strengthen the encryption Kerberos protocol uses. What encryption type is currently in use within the network?

![0094068f34049ae793dd12ab5c29d1ba.png](/_resources/0094068f34049ae793dd12ab5c29d1ba.png)

After deploying the Splunk instance, I ran the query `index="kerberoasted" | stats count by event.provider, host` to list all event providers and see the number of events in each. There were a total of 4,781 events ingested, but I am only interested in the Security and Sysmon logs, which together account for 3,835 events—the majority of all ingested events.

A Kerberoast attack occurs when an attacker uses a valid domain account to request a TGS (Ticket Granting Service) ticket for another account—typically a service account—that has a ServicePrincipalName (SPN) set. The domain controller returns a TGS ticket encrypted with the service account’s password hash. If the attacker can influence the ticket encryption type (the default is 0x12 for AES) to use 0x17 (RC4-HMAC), they can attempt to crack the ticket offline using tools like Hashcat or John the Ripper, especially if the account’s password is weak.

![f9b3e5c7a398c1dae9c2b1dfe8895733.png](/_resources/f9b3e5c7a398c1dae9c2b1dfe8895733.png)

Knowing what to look for, I queried Event ID 4769 and found that the ticket encryption type on this domain controller is RC4-HMAC. Suspicious activity was detected from the user johndoe, who requested tickets for SQLService and FileShareService. This observation addresses both Q2 and we still need to confirm Q3 with successful logon event after this.

Query : `index="kerberoasted" event.code=4769 |  sort @timestamp | table @timestamp,winlog.event_data.ServiceName,winlog.event_data.TargetUserName,winlog.computer_name,winlog.event_data.TicketEncryptionType`

```
RC4-HMAC
```

>Q2: What is the username of the account that sequentially requested Ticket Granting Service (TGS) for two distinct application services within a short timeframe?
```
johndoe
```

>Q3: We must delve deeper into the logs to pinpoint any compromised service accounts for a comprehensive investigation into potential successful kerberoasting attack attempts. Can you provide the account name of the compromised service account?

![764793671896e3e63a8fabfd24cffe10.png](/_resources/764793671896e3e63a8fabfd24cffe10.png)

To confirm which account was used after successfully cracking the password, we filtered for Event ID 4624 with NTLM authentication. This revealed that the attacker used a Kali Linux machine to authenticate to the domain controller as SQLService. Therefore, this is the compromised account.

Query : `index="kerberoasted" "event.code"=4624 winlog.event_data.AuthenticationPackageName=NTLM | sort @timestamp | table @timestamp,winlog,winlog.event_data.TargetUserName,winlog.event_data.IpAddress,winlog.computer_name,winlog.event_data.WorkstationName`

```
SQLService
```

>Q4: To track the attacker's entry point, we need to identify the machine initially compromised by the attacker. What is the machine's IP address?
```
10.0.0.154
```

>Q5: To understand the attacker's actions following the login with the compromised service account, can you specify the service name installed on the Domain Controller (DC)?

![d6835a0c2f618e9a2f2c902ab41aeabe.png](/_resources/d6835a0c2f618e9a2f2c902ab41aeabe.png)

To detect any service installation, we need to look at Event ID 7045 in the Application log. The query returned only two events. The first event shows the installation of the service `iOOEDsXjWeGRAyGl`, which is configured to execute an obfuscated PowerShell script as SYSTEM on demand.

Query : `index="kerberoasted" "event.code"=7045 | sort @timestamp`

![5617a0aeefe47fc029383986a5dfa8c3.png](/_resources/5617a0aeefe47fc029383986a5dfa8c3.png)

The second event also shows another service installation with different name, but the content appears to be the same as the first one.

```
iOOEDsXjWeGRAyGl
```

>Q6: To grasp the extent of the attacker's intentions, What's the complete registry key path where the attacker modified the value to enable Remote Desktop Protocol (RDP)?

![5e88fd1b5ea95973fa435d1221e676e7.png](/_resources/5e88fd1b5ea95973fa435d1221e676e7.png)
Now it’s time to examine the Sysmon logs. After the PowerShell command execution from SYSTEM (likely because SQLService has Domain Admin or local admin privileges, allowing the attacker to gain SYSTEM access on the domain controller via service installation, similar to PsExec), we can see that the attacker executed `hostname` and `whoami`. Following that, they enabled RDP by modifying the registry and configuring a Windows Firewall rule.

Query : 
```
index="kerberoasted" "event.provider"="Microsoft-Windows-Sysmon" "event.code"=1
| sort winlog.event_data.UtcTime
| table winlog.event_data.UtcTime, winlog.event_data.CommandLine, winlog.event_data.ProcessId, winlog.event_data.ParentCommandLine, winlog.event_data.ParentProcessId, winlog.event_data.User, winlog.computer_name
| rename winlog.event_data.UtcTime as Time,
         winlog.event_data.CommandLine as CommandLine,
         winlog.event_data.ProcessId as PID,
         winlog.event_data.ParentCommandLine as ParentCmd,
         winlog.event_data.ParentProcessId as ParentPID,
         winlog.event_data.User as User,
         winlog.computer_name as Computer
```

```
HKLM\system\currentcontrolset\control\terminal server\fDenyTSConnections
```

>Q7: To create a comprehensive timeline of the attack, what is the UTC timestamp of the first recorded Remote Desktop Protocol (RDP) login event?

![36d8b6f009eb68376b09913c920f67ba.png](/_resources/36d8b6f009eb68376b09913c920f67ba.png)

After enabling RDP, the attacker logged on to the domain controller via RDP using the SQLService account from IP address 10.0.0.154 at 2023-10-16 07:50:29.

Query : `index="kerberoasted" "winlog.channel"=Security "event.code"=4624 "winlog.event_data.LogonType"=10 | sort @timestamp | table  @timestamp,winlog.event_data.TargetUserName,winlog.computer_name,winlog.event_data.WorkstationName,winlog.event_data.IpAddress`

```
2023-10-16 07:50
```

>Q8: To unravel the persistence mechanism employed by the attacker, what is the name of the WMI event consumer responsible for maintaining persistence?

![ce0da649c7f2675909e64ac96843b0fb.png](/_resources/ce0da649c7f2675909e64ac96843b0fb.png)


Leveraging Sysmon Event ID 20 to detect WMI event consumer registrations, we can see that at 2023-10-16 07:58:06, the "Updater" WMI Event Consumer was created to execute a PowerShell command. To identify the condition that triggers this consumer, we need to examine Sysmon Event ID 19, which logs the registration of the corresponding WMI event filter.

Query : `index="kerberoasted" event.code=20 "event.provider"="Microsoft-Windows-Sysmon"`

```
Updater
```

>Q9: Which class does the WMI event subscription filter target in the WMI Event Subscription you've identified?

![3c22216d85f1f1d77c82b128a9026361.png](/_resources/3c22216d85f1f1d77c82b128a9026361.png)

We can see that the WMI trigger for "Updater" is configured to execute when there is a failed logon attempt for the "johndoe" user. The `Win32_NTLogEvent` event subscription monitors logon events to fulfill this trigger. and now we are done with this lab but I am not done yet

Query : `index="kerberoasted" event.code=19 "event.provider"="Microsoft-Windows-Sysmon"`

```
Win32_NTLogEvent
```

* * *

## Rabbit Hole Digging (WMI Persistence Commands)

![9bd6591644854dea072c0020ae99775e.png](/_resources/9bd6591644854dea072c0020ae99775e.png)
![c86f0f462cd3052868f0deedb81ac367.png](/_resources/c86f0f462cd3052868f0deedb81ac367.png)

I wanted to decode the Base64 command executed by this WMI event consumer. After decoding it once, it revealed another obfuscated payload. To properly decode it, I first replaced all `''+''` concatenations with blanks and substituted `{0}` with `e`. After that, I could decode it again with Base64 and decompress it using Gzip to obtain the final payload.

![722cd31c8a18a800736c27e39137e7b9.png](/_resources/722cd31c8a18a800736c27e39137e7b9.png)


We can see that upon execution of the WMI Event Consumer, shellcode is loaded into memory. I stopped the analysis at this point without using a shellcode debugger to further inspect it.

![946f0767277baa33b4e42b4b2f98b08d.png](/_resources/946f0767277baa33b4e42b4b2f98b08d.png)
![50b934961dcbe43f38a067ae067d7a6b.png](/_resources/50b934961dcbe43f38a067ae067d7a6b.png)

We can see that this event consumer was triggered once based on Sysmon Event ID 1 but thats it on my part, thank you for your reading.
* * *

