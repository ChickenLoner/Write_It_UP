# [HackTheBox Sherlocks - OPTinselTrace24-3: Blizzard Breakdown](https://app.hackthebox.com/sherlocks/OPTinselTrace24-3:%20Blizzard%20Breakdown)
Created: 15/12/2024 23:05
Last Updated: 21/12/2024 00:14
* * *
![3743d95094069cce184afbe11fcb3bf7.png](..//resources/3743d95094069cce184afbe11fcb3bf7.png)
Furious after discovering he's been left off the Nice List this holiday season, one particular elf - heavily influenced by Krampus - goes rogue, determined to take revenge. Consumed by anger, he hatches a sinister plan to sabotage Christmas by targeting Santa Claus' most critical asset - its S3 data archive! This repository holds sensitive information, including blueprints for new toys, holiday logistics, toy production schedules, and most importantly, the coveted gift list! With Christmas preparations in full swing, any disruption to this storage could cause chaos across the entire operation, threatening to derail everyone's holiday season. Will the holiday magic prevail, or will Christmas fall into dismay?

* * *
>Task 1: The Victim Elf shared credentials that allowed the Rogue Elf to access the workstation. What was the Client ID that was shared?

![d9caaa58482f49f0d8dc5e46c5ae88a4.png](..//resources/d9caaa58482f49f0d8dc5e46c5ae88a4.png)

This sherlock provides us with AWS Cloudtrail logs and Windows Artifacts but lets save AWS for task 6 and enumerate what we have on Windows.  

![f54448a18e141f20e0f7c51722512aee.png](..//resources/f54448a18e141f20e0f7c51722512aee.png)

There we can see that we got Amcache and Prefetch which we can use them to find out the binary (PE32 exe) executed on this system, SHA1 and also the execution time 

![b81960563f50610bb3509251ef9d0706.png](..//resources/b81960563f50610bb3509251ef9d0706.png)

There are also `Ammyy` and `Microsoft` folders inside `ProgramData` folder and after a quick search on Google, we can see that it is a folder that `Ammy Admin`, a remote admin tool created and this folder contains `settings` of this software including it logs so we might come across to this log later after confirming its use on this machine

(Read more about Ammy Admin case with Trend Micro [here](https://www.trendmicro.com/en_th/research/18/g/malicious-macro-hijacks-desktop-shortcuts-to-deliver-backdoor.html))

We can also see that "lannyl" might be the only user on this system so lets dig into this user directory first.

![a899861750812022973e4f5f7830e7e3.png](..//resources/a899861750812022973e4f5f7830e7e3.png)

Deep dive into lannyl's `Appdata` folder, we can see that there is an IceChat Networks log folder so lets find out what it is.

![d0fde31d432d5c7c8fc5c6572b022043.png](..//resources/d0fde31d432d5c7c8fc5c6572b022043.png)

[IceChat IRC Client](https://icechat.net/site/) is a quick, user friendly chatting program so this might be the initial access of the Rogue Elf that contacted the owner of this system and doing some kind of social engineering tactic to install Ammyy Admin and gain initial access on this system and lead to AWS S3 bucket compromised. 

![bcb5b5c3b4fb1e4857fe9a9d345c95df.png](..//resources/bcb5b5c3b4fb1e4857fe9a9d345c95df.png)

Take a look at these logs, we will have to review each one of them.

![bf763cd58aa9e62e290edbf0c25badec.png](..//resources/bf763cd58aa9e62e290edbf0c25badec.png)

Then after reviewing all of them, a message from "W4yne" is the most suspicious one which will can see that this user asked "Lanny" to use Ammy Admin instead of team viewer and we can even get ID and password that the Rogue Elf used to connect to this system right here.

```
95192516
```

>Task 2: What is the IP address of the Rogue Elf used during the attack?

![8c38c2f38a15487d3806dd8f84256929.png](..//resources/8c38c2f38a15487d3806dd8f84256929.png)

We can get an IP address of the Rogue Elf right here.

```
146.70.202.35
```

>Task 3: What is the name of the executable the victim ran to enable remote access to their system?

![3881b17bc5b0145142a518f8527a719e.png](..//resources/3881b17bc5b0145142a518f8527a719e.png)

Now lets use Amcache (you can also use prefetch) to find out Ammy Admin executable which I used [AmcacheParser](https://www.sans.org/tools/amcacheparser/) from Eric Zimmerman's Tools to parse Amcache.
- `-f` to specify Amcache registry hive to be parsed
- `--csv` to specify the output format to be csv with the following argument as the folder that stores output files

![b70f7ed06f311762ff0f7159987f0d1d.png](..//resources/b70f7ed06f311762ff0f7159987f0d1d.png)

Then use Timeline Explorer to open    can see that there is one file with `AA_v3.exe` as a filename that likely be a shortform of "Ammyy Admin Version 3" but lets just confirm it by copy its SHA1 hash to search on VirusTotal

![3dd8774b38797c8523da7be73071c107.png](..//resources/3dd8774b38797c8523da7be73071c107.png)

There it is!

```
AA_v3.exe
```

>Task 4: What time (UTC) did the Rogue Elf connect to the victim's workstation?

![46e95a2eec9ec09e7014993b4eb1efdc.png](..//resources/46e95a2eec9ec09e7014993b4eb1efdc.png)

Its time to explore what in `access.log` in `Ammyy` folder under `ProgramData`!

![57f5025d2a4a2e944197f07a06c81c67.png](..//resources/57f5025d2a4a2e944197f07a06c81c67.png)

There we have 2 line of logs, first is the started of session and second is the ended of that session which we can not use the timestamp of the first line directly since Ammy Admin logged timestamp as system timestamp so we have to figure it out the timezone of this system first then we can convert this timestamp to UTC

![952cc3b28689f57731d14b88f0072881.png](..//resources/952cc3b28689f57731d14b88f0072881.png)

We can use tool like [Registry Explorer](https://www.sans.org/tools/registry-explorer/) or [RegRipper](https://github.com/keydet89/RegRipper3.0) to parse system hive that holds Timezone information of system at `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\TimeZoneInformation` then we will see the timezone of this system that it was using PST (Pacific Standard Time/UTC -8).

So we will have to add 8 hour to the timestamp which will convert it to UTC

```
2024-11-13 12:23:34
```

>Task 5: The Rogue Elf compromised an AWS Access Key. What is the AWS Access Key ID obtained from the victim's workstation?

![504fd13c472dc51666a3a3a8d5c63202.png](..//resources/504fd13c472dc51666a3a3a8d5c63202.png)

So we know that Rogue Elf accessed to this system using Ammy Admin while Lanny was away (according to IceChat) and there is another artifact that might stores sensitive data on this system which is Microsoft Sticky Notes so we can parse `plum.sqlite` file within `AppData\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\` to read current notes store in Microsoft Sticky Notes.

![263b4bd789bba563e6c08a54e90cc39d.png](..//resources/263b4bd789bba563e6c08a54e90cc39d.png)

But for Linux user, we can just read `plum.sqlite-wal` or `plum.sqlite-shm` which store transaction log and event which we can also see that Lanny stores password list and AWS access key ID and secret key on Sticky Notes which can also be obtained by Rogue Elf after remoted access to this system!

```
AKIA52GPOBQCBFYGAYHI
```

>Task 6: Which S3 bucket did the Rogue Elf target during the incident?

Now lets analyze CloudTrail logs but since I am not an expert on `jq` then I will use Splunk (docker) to analyze them.

![9739f40dcb5efcf6ca1346da7c420855.png](..//resources/9739f40dcb5efcf6ca1346da7c420855.png)

(For those who want to analyze using `jq`, you will need to `gunzip` all files inside `AWS-CloudTrail` folder first)

Since I'll import these logs into Splunk then I'll have to make these logs are readable in Splunk so I'll use [aws-cloudtrail2sof-elk.py](https://raw.githubusercontent.com/philhagen/sof-elk/main/supporting-scripts/aws-cloudtrail2sof-elk.py) that will read AWS Cloudtrails logs (gzip supported) then create a single json file that SOF-ELK VM can read (Splunk can read it too), here is a command I used -> `python3 aws-cloudtrail2sof-elk.py -r ./BlizzardBreakdown/AWS-CloudTrail/ -w output.json -f`

- `-r` to specify folder/directory to read (which will automatically included it sub-directories)
- `-w` to specify an output filename
- `-f` to force a script to create file other than default SOF-ELK ingest location (this flag is also a must)

![b371d588037062bbbf0eafc8a99f51d1.png](..//resources/b371d588037062bbbf0eafc8a99f51d1.png)

Now after uploaded our log file into Splunk then we can start with the query like `source="output.json" host="blizzard" sourcetype="_json" 146.70.202.35 | sort eventTime` to list all events with an IP address of the Rouge Elf and sort them by `eventTime` field which we can see that there are 158 events associated with this IP address and the first event start with [GetCallerIdentity](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html) event which similar to `whoami` on Windows and the timestamp of this event log is 2024-11-13 15:23:22.

![cf147dfe248e5c7ca0e11041b842e0c2.png](..//resources/cf147dfe248e5c7ca0e11041b842e0c2.png)

After that Rouge Elf tried to list attached user policy with [ListAttachUserPolicies](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListAttachedRolePolicies.html) but failed with "AccessDenied" error

![b581596a627aca79631f0198a739c9c5.png](..//resources/b581596a627aca79631f0198a739c9c5.png)

Rouge Elf also failed to list user policy with the same error code.

![68a3380398233a5396d6afc6dd556938.png](..//resources/68a3380398233a5396d6afc6dd556938.png)

Then Rouge Elf went to enumerate S3 storage at 2024-11-13 15:25:48 with [ListObjects](https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjects.html) event to return objects in `arctic-archive-freezer` bucket which is the answer of this question

```
arctic-archive-freezer
```

![57a288afa0083903bd7b7f771bdbc815.png](..//resources/57a288afa0083903bd7b7f771bdbc815.png)

We can also see that there are 154 events related to S3 from this IP address 

>Task 7: Within the targeted S3 bucket, what is the name of the main directory where the files were stored?

![fbac25bd322db123068af76c8ab4e992.png](..//resources/fbac25bd322db123068af76c8ab4e992.png)

After that Rouge Elf started to dig deeper into this bucket with each queries from `Claus_Operation_Data` to
- `Claus_Operation_Data/blueprints/`
- `Claus_Operation_Data/gift_lists/`
- `Claus_Operation_Data/operational_files/`
- `Claus_Operation_Data/security_protocols/`

```
Claus_Operation_Data
```

>Task 8: What time (UTC) did the Rogue Elf disable versioning for the S3 bucket?

![8fb181986f1751f2502c61a8d8de8ba8.png](..//resources/8fb181986f1751f2502c61a8d8de8ba8.png)

Then Rouge Elf obtained versioning state of a bucket with [GetBucketVersioning](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketVersioning.html) at 2024-11-13 15:29:20

![4817a198cfc2a6ec6b9d217f8ed30e9c.png](..//resources/4817a198cfc2a6ec6b9d217f8ed30e9c.png)

Then at 2024-11-13 15:31:15, Rouge Elf used [PutBucketVersioning](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketVersioning.html) to disable bucket versioning which effectively disable an ability to restore file from previous version. 

```
2024-11-13 15:31:15
```

![7bbfa44b0ef94929a9f856569bd92c5b.png](..//resources/7bbfa44b0ef94929a9f856569bd92c5b.png)

*For Query, we can use `source="output.json" host="blizzard" sourcetype="_json" 146.70.202.35 eventSource="s3.amazonaws.com"  eventName=PutBucketVersioning | sort eventTime` to list only this single event on Splunk

>Task 9: What is the MITRE ATT&CK Technique ID associated with the method used in Question 8?

![be56bd4861c5309ce4d788d24eb991bc.png](..//resources/be56bd4861c5309ce4d788d24eb991bc.png)

The action from question 8 could be linked to [T1490: Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/) technique on MITRE ATT&CK

```
T1490
```

>Task 10: What time (UTC) was the first restore operation successfully initiated for the S3 objects?

![125fd118ab0aebabb645c0f7d04e2256.png](..//resources/125fd118ab0aebabb645c0f7d04e2256.png)

Then at 2024-11-13 15:36:52, Rouge Elf attempted to restore several S3 objects with [RestoreObject](https://docs.aws.amazon.com/AmazonS3/latest/API/API_RestoreObject.html) but could not do that due to "KeyTooLongError" 

![8c30dc513b8ab811f342d0d4acc6d5e1.png](..//resources/8c30dc513b8ab811f342d0d4acc6d5e1.png)

Then Rouge Elf successfully restored first S3 object at 2024-11-13 15:43:49

```
2024-11-13 15:43:49
```

![cce2170a507df175f630489a7d781770.png](..//resources/cce2170a507df175f630489a7d781770.png)

To query for RestoreObject events, we can use this filter to specific only these 22 events

>Task 11: Which retrieval option did the Rogue Elf use to restore the S3 objects?

![905fa183c69d458dd9bf7526f110b6b1.png](..//resources/905fa183c69d458dd9bf7526f110b6b1.png)

Rouge Elf used Expedited tier to recover S3 objects which is the most fastest one to restore but also cost the most among 3 tiers! (you can read more about these tiers from [RestoreObject](https://docs.aws.amazon.com/AmazonS3/latest/API/API_RestoreObject.html) documentation)

```
Expedited
```

>Task 12: What is the filename of the S3 object that the Rogue Elf attempted to delete?

![48501b5e87a1e7ae94d391ce4bb84fa6.png](..//resources/48501b5e87a1e7ae94d391ce4bb84fa6.png)

After retrieves so many objects, Rouge Elf deleted s3 object with [DeleteObject](https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteObject.html) and we can use `source="output.json" host="blizzard" sourcetype="_json" 146.70.202.35 eventSource="s3.amazonaws.com" eventName=DeleteObject | sort eventTime` to query for this specific event.

![0c60cc7aae200f5983bdefd92d1af6f0.png](..//resources/0c60cc7aae200f5983bdefd92d1af6f0.png)

Which we can see that at 2024-11-13 16:04:09, Rouge Elf successfully deleted `GiftList_Worldwide.csv` from S3 bucket.

```
GiftList_Worldwide.csv
```

>Task 13: What is the size (MB) of the S3 object that the Rogue Elf targeted in Question 12?

This time, we will have to query for a file from question 12 with [GetObject](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html) event, and here is the query I used -> `source="output.json" host="blizzard" sourcetype="_json" 146.70.202.35   eventSource="s3.amazonaws.com"  | spath "requestParameters.key" | search "requestParameters.key"="Claus_Operation_Data/gift_lists/GiftList_Worldwide.csv" eventName=GetObject | sort eventTime`

![2128cdc904b3633670a8d56e1eebc132.png](..//resources/2128cdc904b3633670a8d56e1eebc132.png)

Which we can see that at 2024-11-13 15:56:58, Rouge Elf retrieved this file from S3 bucket and we can also see that there is "bytesTransferredOut" field that log how many bytes were transfer out from S3 bucket but 8MB is not the right answer so we will have to sum up all bytes in previous query. 

![907610ed1a609385fbd095999f49c1b2.png](..//resources/907610ed1a609385fbd095999f49c1b2.png)

Then we can see that there are total of 19 events with this bytes transfer so lets sum them up by 8 MB x 19 which is 152 MB in total.

```
152
```

>Task 14: The Rogue Elf uploaded corrupted files to the S3 bucket. What time (UTC) was the first object replaced during the attack?

![ebfa0b634b7bb4ee3612e3b7a23d7be8.png](..//resources/ebfa0b634b7bb4ee3612e3b7a23d7be8.png)

This time we have to query for [PutObject](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html) which is an event that can put an object to S3 bucket (think of it like an upload event), here is the query I used -> `source="output.json" host="blizzard" sourcetype="_json" 146.70.202.35 eventSource="s3.amazonaws.com" eventName=PutObject | sort eventTime`

![f9f6bf74d5208050f060bcd1ae3db330.png](..//resources/f9f6bf74d5208050f060bcd1ae3db330.png)

Then we can see that at 2024-11-13 16:10:03, Rouge Elf putted the first object to S3 bucket (effectively replaced a file with same name in S3 bucket).

```
2024-11-13 16:10:03
```

>Task 15: What storage class was used for the S3 objects to mimic the original settings and avoid suspicion?

![5ee564bbe41378da72366df99f5c40b1.png](..//resources/5ee564bbe41378da72366df99f5c40b1.png)

Take a look at "[x-amz-storage-class](https://docs.aws.amazon.com/AmazonS3/latest/userguide/storage-class-intro.html)" then we can see that Rouge Elf used GLACIER (S3 Glacier Deep Archive) class to when putted objects to S3 bucket.

![2f30158d2f8b3b784603916e18d92c56.png](..//resources/2f30158d2f8b3b784603916e18d92c56.png)

We can also see that all 20 PutObject events were used with this setting. 

```
GLACIER
```

![0820fae8daf0bba938274b0127b2e272.png](..//resources/0820fae8daf0bba938274b0127b2e272.png)
https://labs.hackthebox.com/achievement/sherlock/1438364/831
***
## Summary
An incident started when Rouge Elf joined IceChat messaging room to chat with Lanny and deployed social engineering technique to remotely accessed to Lanny's computer with Ammy Admin software which lead to AWS access key ID, secret key and password list of Lanny compromised.

Next, Rouge Elf used obtained access key to access AWS which he retrieved several files from "arctic-archive-freezer" bucket, he also removed and replaced objects on this bucket after disabled bucket versioning which make it unlikely for those files to be recovered from his actions.

### Timeline
- 2024-11-13 11:37:28 : Rouge Elf messaged Lanny with username "W4yne" on IceChat
- 2024-11-13 12:07:37 : Ammy Admin executable (`AA_V3.exe`) was executed
- 2024-11-13 12:23:34 : Rouge Elf accessed to Lanny's workstation
- 2024-11-13 15:23:22 : Rouge Elf accessed to AWS service (based on GetCallerIdentity event)
- 2024-11-13 15:25:48 : Rouge Elf started enumerate S3 objects
- 2024-11-13 15:31:15 : Rouge Elf disabled bucket versioning of "arctic-archive-freezer" bucket
- 2024-11-13 15:36:52 : Rouge Elf attempted to restore objects on "arctic-archive-freezer"
- 2024-11-13 15:43:49 : Rouge Elf successfully restored first object on "arctic-archive-freezer"
- 2024-11-13 15:56:58 : Rouge Elf retrieved `GiftList_Worldwide.csv` from "arctic-archive-freezer"
- 2024-11-13 16:04:09 : Rouge Elf deleted `GiftList_Worldwide.csv` from "arctic-archive-freezer"
- 2024-11-13 16:10:03 : Rouge Elf started replacing files on "arctic-archive-freezer"

### IOCs
- `146[.]70[.]202[.]35` (Rouge Elf's IP Address)
- `050b7eba825412b24e3f02d76d7da5ae97e10502` (SHA1 of `AA_V3.exe`)
* * *
