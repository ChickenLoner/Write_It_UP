# [HackTheBox Sherlocks - Heartbreaker-Denouement](https://app.hackthebox.com/sherlocks/Heartbreaker-Denouement)
Created: 26/07/2024 19:48
Last Updated: 13/08/2024 11:30
* * *

![8b46614690e89248a1bd47c0a0a0f3ef.png](..//resources/8b46614690e89248a1bd47c0a0a0f3ef.png)
**Scenario:**
Your digital forensics expertise is critical to determine whether data exfiltration has occurred from the customer’s environment. Initial findings include a compromised AWS credential, indicating a potential unauthorized access. This investigation follows from a customer report of leaked data allegedly for sale on the darknet market. By examining the compromised server and analyzing the provided AWS logs, it will not only validate the customer's breach report but also provide valuable insights into the attacker's tactics, enabling a more comprehensive response.
* * *
>Task 1: What type of scanning technique was used to discover the web path of the victim's web server? Specify the name of the corresponding MITRE sub-technique.

![6d727a8ba095a6b3506658d041b2629b.png](..//resources/6d727a8ba095a6b3506658d041b2629b.png)

We got AWS Cloudtrail logs from several regions and artifacts gathered with UAC (Unix Artifact Collector), task mentioning web server so we could find `access.log` or `error.log` and start investigating from here

![7da068b3916f67a37e0bc9a33aebe343.png](..//resources/7da068b3916f67a37e0bc9a33aebe343.png)

You can find both logs here after extracted them from `tar.gz` file

![8f3b0769423819c437144dfac2028ee0.png](..//resources/8f3b0769423819c437144dfac2028ee0.png)

Then after examined  `access.log`, we can see that there are several requests from `35.169.66.138` and we can clearly see that it is directory fuzzing or directory bruteforcing

![5f907b215c0894a6c06e6e4d9c40660a.png](..//resources/5f907b215c0894a6c06e6e4d9c40660a.png)

And according to MITRE ATT&CK, this action is called [Wordlist Scanning](https://attack.mitre.org/techniques/T1595/003/)

```
Wordlist Scanning
```

>Task 2: It seems a web request possibly could have been rerouted, potentially revealing the web server's web path to the Threat Actor. What specific HTML status code might have provided this information?

There are 2 HTTP Status code that we might want to take a look which are
- 301 Moved Permanently: Permanent redirection.
- 302 Found: Temporary redirection.

![0f34a173a34339c5eb568ce1350bd427.png](..//resources/0f34a173a34339c5eb568ce1350bd427.png)

I didnot find 302 but I found one 301 so it has to be this one

```
301
```

>Task 3: What was the initial payload submitted by the threat actor to exploit weakness of the web server?

![f21f3df07d8c5b8f147418423a1d777b.png](..//resources/f21f3df07d8c5b8f147418423a1d777b.png)

We have to investigate `error.log` and we can see that the threat actor tried to exploit LFI with `file:///etc/passwd` payload

```
file:///etc/passwd
```

>Task 4: What is the name of the vulnerability exploited by the Threat Actor?

The Threat Actor send POST requests and get what he want from a server, it is SSRF

```
Server Side Request Forgery
```

>Task 5: At what time (UTC) did the Threat Actor first realize they could access the cloud metadata of the web server instance?

![afd41d0376dee7846750fb91814f0a5d.png](..//resources/afd41d0376dee7846750fb91814f0a5d.png)

We can see that from here, The Threat actor gained access to cloud metadata of the web server instance.

![60242281cfea196951762059ffb25ac6.png](..//resources/60242281cfea196951762059ffb25ac6.png)

We can confirm `/etc/timezone` to check the timezone before submit the timestamp and fortunately, this machine is using UTC so we do not need to convert anything.

```
2024-03-13 14:06:21
```

>Task 6: For a clearer insight into the Database content that could have been exposed, could you provide the name of at least one of its possible tables?

![d65176e6dfabd86b8ac87d8df43692df.png](..//resources/d65176e6dfabd86b8ac87d8df43692df.png)

There is `.mysql_history` file on `ubuntu` user home directory which stores all sql queries used in `mysql` on that system

![56b3205d38a26ed211d4e8da725d2f55.png](..//resources/56b3205d38a26ed211d4e8da725d2f55.png)

We can see that there is a table name `CustomerInfo` in `CUSTOMER_DATA` database so this table is the one that could have been exposed to the threat actor.

```
CustomerInfo
```

>Task 7: Which AWS API call functions similarly to the 'whoami' command in Windows or Linux?

![f729668dc1444eef230e61caa7daadc2.png](..//resources/f729668dc1444eef230e61caa7daadc2.png)

an API call function similarly to `whoami` command is [GetCallerIdentity](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html)

```
GetCallerIdentity
```

![0095ad6e8cc7bad679029048aa4cfc99.png](..//resources/0095ad6e8cc7bad679029048aa4cfc99.png)

Its time to aggregrate CloudTrail logs to our Splunk instance so we can continue with the rest of this investigation, as you can see that all log files are compressed with gzip 

![fe8cc942cca7fdc9a814227ae2dad06a.png](..//resources/fe8cc942cca7fdc9a814227ae2dad06a.png)

We do not need to use gunzip to decompress them since [aws-cloudtrail2sof-elf.py](https://github.com/philhagen/sof-elk/blob/main/supporting-scripts/aws-cloudtrail2sof-elk.py) can parse gzip files so lets do it with `python3 aws-cloudtrail2sof-elk.py -r ./AWS/ -w hbk-d.json -f` and now we should have a single file to import on our Splunk instance. 

>Task 8: It seems that the reported compromised AWS IAM credential has been exploited by the Threat Actor. Can you identify the regions where these credentials were used successfully? Separate regions by comma and in ascending order.

![1bbdab9b4b00129c187be7c29c87afd9.png](..//resources/1bbdab9b4b00129c187be7c29c87afd9.png)

We know that the threat actor had accessed to cloud metadata of web server instance and from this log file, we can see that 2 credentials were compromised

![7cda1c578d50afce3a6b932b8891b9c0.png](..//resources/7cda1c578d50afce3a6b932b8891b9c0.png)

We could not use `EC2DatabaseConnection` to solve this task since this identity could access all 17 regions but luckily for us that `ec2-instance` were not widely used and only used on these 2 regions which are correct answers on this task.

```
us-east-1,us-east-2
```

>Task 9: Discovering that the compromised IAM account was used prior to the web server attack, this suggests the threat actor might have obtained the public IP addresses of running instances. Could you specify the API call the could have exposed this information?

![cac13afd54e2c9e7212cf6d4cee561e2.png](..//resources/cac13afd54e2c9e7212cf6d4cee561e2.png)

We can suspect that the threat actor used `GetCallerIdentity` From task 7 and we already know which regions we need to search so lets get `userName`, `arn` that the threat actor could get a hand on and `sourceIPAddress` of the threat actor.

![34b8b9c4ee7b55dac3fa266bf9823629.png](..//resources/34b8b9c4ee7b55dac3fa266bf9823629.png)

Then we can find any API calls that could expose an information about running instance which there is one particular API call that could do this job which is [DescribeInstances](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstances.html)

```
DescribeInstances
```

>Task 10: Looks like the Threat Actor didn’t only use a single IP address. What is the total number of unsuccessful requests made by the Threat Actor?

![bf3ec891146355af10f844ee9fd7b458.png](..//resources/bf3ec891146355af10f844ee9fd7b458.png)

We already know the first IP address of the Threat Actor which is `35.169.66.138` but we need to find another one and one way to find out is to use `errorCode="*"` and find top 2 `sourceIPAddress` that appeared with this query, now we have both IP address of the threat actor so we can combine them and answer this task.

```
742
```

>Task 11: Can you identify the Amazon Resource Names (ARNs) associated with successful API calls that might have revealed details about the victim's cloud infrastructure? Separate ARNs by comma and in ascending order.

There are so many events that could have done this job so I asked ChatGPT to combine all of them to a single search query for me and here is the result that prompt
`(eventName="DescribeInstances" OR eventName="DescribeSecurityGroups" OR eventName="DescribeSubnets" OR eventName="DescribeVpcs" OR eventName="DescribeVolumes" OR eventName="DescribeAddresses" OR eventName="GetAccountSummary" OR eventName="ListUsers" OR eventName="ListRoles" OR eventName="ListGroups" OR eventName="GetRole" OR eventName="ListBuckets" OR eventName="GetBucketPolicy" OR eventName="GetBucketAcl" OR eventName="DescribeDBInstances" OR eventName="DescribeDBClusters" OR eventName="DescribeTrails" OR eventName="GetTrailStatus" OR eventName="DescribeStacks" OR eventName="ListFunctions" OR eventName="GetFunction")`

![1b188d9caf4c6c79805b36a4d3795b43.png](..//resources/1b188d9caf4c6c79805b36a4d3795b43.png)

Then go to `userIdentity.arn` field to separate each `arn` associated with both threat actor IP addresses

And as we already know that `arn:aws:iam::949622803460:user/devops-ash` was used by `35.169.66.138` and `EC2DatabaseConnection` is one of an identity the threat actor got his hand on using SSRF vulnerability

Then after digging a little bit more, we can also confirm that  `arn:aws:sts::949622803460:assumed-role/EC2DatabaseConnection/i-0bdf91168b50e943e` was used by `34.202.84.37` which is another IP address of the threat actor

```
arn:aws:iam::949622803460:user/devops-ash,arn:aws:sts::949622803460:assumed-role/EC2DatabaseConnection/i-0bdf91168b50e943e
```

>Task 12: Evidence suggests another database was targeted. Identify all snapshot names created. Separate names by comma and in ascending order.

![e8f971473157d9f9195d24bc9367df5f.png](..//resources/e8f971473157d9f9195d24bc9367df5f.png)

We will have to search for [CreateDBSnapshot](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_CreateDBSnapshot.html) api call and get `dBSnapshotIdentifier` of all snapshots created by the threat actor, this is the first one

![1442174535eab0306dd30745fc444807.png](..//resources/1442174535eab0306dd30745fc444807.png)

And this is the second one, the threat actor only created 2 DB snapshots so we can submit both as an answer of this task rightaway.

```
transactiondb-prod-2024-03-13-06-53,wb-customerdb-prod-2024-03-13-07-59
```

>Task 13: The Threat Actor successfully exfiltrated the data to their account. Could you specify the account ID that was used?

![97efb8114dcc8888b47a7e02368f7558.png](..//resources/97efb8114dcc8888b47a7e02368f7558.png)

We can search for one of `dBSnapshotIdentifier`, we found earlier and obtain the value of `valuesToAdd` field

When I gave a hint to my new friend on discord, he gave me this [link](https://docs.datadoghq.com/security/default_rules/cloudtrail-aws-rds-snapshot-exfiltration/) which is related to this technique directly (RDS snapshot exfiltration) so if possible, you should give it a try! 

```
143637014344
```

>Task 14: Which MITRE Technique ID corresponds to the activity described in Question 13?

![570fd809cecf91d91ce873678a85c564.png](..//resources/570fd809cecf91d91ce873678a85c564.png)

This technique is called [Transfer Data to Cloud Account](https://attack.mitre.org/techniques/T1537/) according to MITRE ATT&CK framework.

```
T1537
```

![4fbd2add930d702e2f0beb900af3e471.png](..//resources/4fbd2add930d702e2f0beb900af3e471.png)
https://labs.hackthebox.com/achievement/sherlock/1438364/700
* * *
