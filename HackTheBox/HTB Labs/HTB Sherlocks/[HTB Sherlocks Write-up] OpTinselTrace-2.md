# [HackTheBox Sherlocks - OpTinselTrace-2](https://app.hackthebox.com/sherlocks/OpTinselTrace-2)

![d062c1824ee9d55632681aa4bc1390d7.png](/resources/d062c1824ee9d55632681aa4bc1390d7.png)

## Scenario
It seems our precious technology has been leaked to the threat actor. Our head Elf, PixelPepermint, seems to think that there were some hard-coded sensitive URLs within the technology sent. Please audit our Sparky Cloud logs and confirm if anything was stolen! PS - Santa likes his answers in UTC... Please note - these Sherlocks are built to be completed sequentially and in order!

* * *
## Investigation

![2a075ca481580ad3e82d9cbd85596be2.png](/resources/2a075ca481580ad3e82d9cbd85596be2.png)

On this sherlock, we have exported cloudtrail log from 2 regions here and there are several approches to investigate AWS cloudtrail log such as
- Using [aws-cloudtrail2sof-elk.py](https://github.com/philhagen/sof-elk/blob/main/supporting-scripts/aws-cloudtrail2sof-elk.py) to make a single JSON file then upload it to Splunk
- Using jq

But in this write-up, I want to show case a new tool I vibed to investigate AWS Cloudtrail log, [TrailInspector](https://github.com/ChickenLoner/TrailInspector), with this tool, you can just select a folder that contain cloudtrail logs and it will automatically parse them even if there are compressed in tar.gz.

![8c540c50f39ac0a0689d467738bf410b.png](/resources/8c540c50f39ac0a0689d467738bf410b.png)

And then after it finished the parsing, it will populated it into this Splunk-like interface and automatically detected source IP, user-agent, user, event name, service, region, error code, identity type and S3 bucket so we can filter only existing events with just a click.

![e7055eaffd98ba9e3c902597229509e9.png](/resources/e7055eaffd98ba9e3c902597229509e9.png)

And we can see that there are 22,440 events detected from AWS Cloudtrail log of this sherlock and we can also see that almost 5k events came from "terraform-gumdrop" which should be a user that was used to set up an environment. our interested would be the "elfadmin" user as its hardcoded credenial was leaked from santa binary exfiltrated to the threat actor from previous sherlock (OpTinselTrace-1).

>Task 1: What is the MD5 sum of the binary the Threat Actor found the S3 bucket location in?

![cadad8ff88274b7cd2ddc36feab36df2.png](/resources/cadad8ff88274b7cd2ddc36feab36df2.png)

![9163eed8ecb96fd3eefcbb4947a44e49.png](/resources/9163eed8ecb96fd3eefcbb4947a44e49.png)

To obtain the answer of this question, we need to go back to the artifacts collected from previous sherlock and calculate MD5 of the the `santa_deliveries` file which leaked the existence of public S3 bucket (`https://papa-noel.s3.eu-west-3.amazonaws.com/santa-list.csv`)

```
62d5c1f1f9020c98f97d8085b9456b05
```

>Task 2: What time did the Threat Actor begin their automated retrieval of the contents of our exposed S3 bucket?

![efc901736445bcf41481549045c32249.png](/resources/efc901736445bcf41481549045c32249.png)

I noticed 43 events from python user-agent which likely to indicate the automation script so I filtered for it

![df8974b940dbcb33ecd68a028889b7f1.png](/resources/df8974b940dbcb33ecd68a028889b7f1.png)

Upon the filtering for this user-agent, we can see that all of them originated from the same IP address - 191.101.31.57, this reveals the automatic file retrival from "papa-noel" bucket.

```
2023-11-29 08:24:07
```

>Task 3: What time did the Threat Actor complete their automated retrieval of the contents of our exposed S3 bucket?

![7ee06a861bfb05c03512ea875ea671e7.png](/resources/7ee06a861bfb05c03512ea875ea671e7.png)

The automated retreival ended at 2023-11-29 08:24:16, 9 seconds to retrieve files from the exposed S3 bucket.

```
2023-11-29 08:24:16
```

>Task 4: Based on the Threat Actor's user agent - what scripting language did the TA likely utilise to retrieve the files?
```
python
```

>Task 5: Which file did the Threat Actor locate some hard coded credentials within?

![d8f6e646c150770b3bdfa003853919ee.png](/resources/d8f6e646c150770b3bdfa003853919ee.png)

This sherlock was intended to be played at the time the event was live (Chrismas 2023) so players could get the same files as the threat actor to analyze what leaked, but I played this in 2026 so the S3 bucket was already gone.

![6de1bcbdb8b51e03ca6c2e381bafd6a2.png](/resources/6de1bcbdb8b51e03ca6c2e381bafd6a2.png)

So the only way to make up for this is to read Official write-up but i can not blame Seb for this. AWS is costly.

As we can see that `claus.py` exposed the existence of `north-pole-private`, a private S3 bucket along with AWS Access and Secret key to access it. 

```
claus.py
```

>Task 6: Please detail all confirmed malicious IP addresses. (Ascending Order)

![b671eeced948e2080f51906518ba5314.png](/resources/b671eeced948e2080f51906518ba5314.png)

We know that 191.101.31.57 is one of them but we need to find the second IP address which likely used to access `north-pole-private` bucket

![6ddd9a984c3f03e31492ea9f9260f6ae.png](/resources/6ddd9a984c3f03e31492ea9f9260f6ae.png)

We can filter by this bucket with the time range after the retrieval of first S3 bucket, which we can see that the threat actor used different IP address to access private S3 bucket after successfully ListBucket using leaked access key which belongs to "elfadmin" 

```
45.133.193.41, 191.101.31.57
```

>Task 7: We are extremely concerned the TA managed to compromise our private S3 bucket, which contains an important VPN file. Please confirm the name of this VPN file and the time it was retrieved by the TA.

![d930f409373a518d1f0f9c167a353891.png](/resources/d930f409373a518d1f0f9c167a353891.png)

After successfully utilized access key to access private S3 bucket, the threat actor retrieved 2 files from this bucket which are
- `santa_journey_log.csv`
- `bytesparkle.ovpn`

The openvpn configuration file can be used to connect and conduct operation inside the internal network later.

```
bytesparkle.ovpn, 2023-11-29 10:16:53
```

>Task 8: Please confirm the username of the compromised AWS account?
```
elfadmin
```

>Task 9: Based on the analysis completed Santa Claus has asked for some advice. What is the ARN of the S3 Bucket that requires locking down?

![55b53d99450f5edaa973c80b212d40b9.png](/resources/55b53d99450f5edaa973c80b212d40b9.png)

The root cause of this breach came from public S3 bucket exposed AWS access key and private S3 bucket so lock down `papa-noel` is obviously the right choice here.

```
arn:aws:s3:::papa-noel
```

![a28db93ad85bf47f6af67bb712d9cb7c.png](/resources/a28db93ad85bf47f6af67bb712d9cb7c.png)

https://labs.hackthebox.com/achievement/sherlock/1438364/578
* * *
