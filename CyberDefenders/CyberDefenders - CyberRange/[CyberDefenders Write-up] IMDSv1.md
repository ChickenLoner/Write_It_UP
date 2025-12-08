# [CyberDefenders - IMDSv1](https://cyberdefenders.org/blueteam-ctf-challenges/imdsv1/)
## Table of Contents

- [Scenario](#scenario)
- [Questions](#questions)

* * *
## Scenario
On October 15, 2024, a security breach occurred involving a web application named "`Visa Checker`," which was hosted on an `AWS EC2 instance`. The attacker exploited a `Server-Side Request Forgery (SSRF)` vulnerability within the application, enabling them to steal `IAM` role credentials. With these compromised credentials, the attacker gained unauthorized access to sensitive information stored in `Amazon S3 bucket`. This S3 bucket contained data on approximately 20 million tourists.

The attacker leveraged the stolen credentials to perform various unauthorized actions within the AWS environment, including data exfiltration. To evade detection, the attacker routed their traffic through multiple `Tor` exit nodes, using anonymized IP addresses to obscure their true location, making it difficult to trace the source of the attack.

You have been given a `PCAP file` and `CloudWatch Logs` from the incident for analysis. The goal is to identify the attacker's actions, determine the compromised resources, and assess the overall scope and impact of the breach.

**Category**: Cloud Forensics

**Tools**:
jq
Wireshark

* * *
## Questions
>Q1: The attacker tested the SSRF vulnerability by accessing an external website. What URL was used to conduct this test?

![00544c70063cc71eb81f4422fd81047b.png](/resources/00544c70063cc71eb81f4422fd81047b.png)

We have 4 CloudTrail log files and 1 pcap file to investigate what happened so I'm gonna use WireShark on pcap and `grep` on CloudTrail logs (yes I refused to use `jq`)

![34745f55fe6f0be78451d0daa29b8d13.png](/resources/34745f55fe6f0be78451d0daa29b8d13.png)

After I opened the pcap file, I noticed that URL that might vulnerable to SSRF right away as we can see that the "check_url" variable was used to handle URL of visa checker URL. 

![af66c07928dea4dcbed38f7bd9bd4a02.png](/resources/af66c07928dea4dcbed38f7bd9bd4a02.png)

By filtering for this variable, we can see that the attacker leveraged this vulnerable endpoint to access google first and then retrieved AWS secret of EC2-S3-Visa but one more thing to notice is the threat actor used different IP addresses to exploit SSRF to hide the actual IP address. 

**Filter** : `http.request.full_uri contains "check_url"`

```
http://www.google.com
```

>Q2: The attacker exploited the vulnerable website to send requests, ultimately obtaining the IAM role credentials. What is the exact URI used in the request made by the webserver to acquire these credentials?

![62309aeffcb0013faa25e06114481974.png](/resources/62309aeffcb0013faa25e06114481974.png)

Here is the url that was the answer of this question but lets take a look at the inside, shall we?

![0afccaba3885398a523f4972258c393c.png](/resources/0afccaba3885398a523f4972258c393c.png)

Then we can see that the secret of EC2-S3-Visa was really leaked with this URL.

```
http://169.254.169.254/latest/meta-data/iam/security-credentials/EC2-S3-Visa
```

>Q3: The attacker executed an AWS CLI command, similar to `whoami` in traditional systems, to retrieve information about the IAM user or role associated with the operation. When exactly did he execute that command?

![261051d4a6defdd5b1232962c6815f82.png](/resources/261051d4a6defdd5b1232962c6815f82.png)

The similar event to `whoami` command on AWS is `GetCallerIdentity` so we can simply grep it and since we already know that UserName EC2-S3-Visa was compromised, you can add it in the grep filter as well but just the eventName, the only 1 event return from 4 logs.

**Command** : `cat 124355653975_CloudTrail_eu-central-1*  | grep 'aws-cli/2.18.5' | grep GetCaller` 

![8b5f833664cc1167d160b196eaeee16c.png](/resources/8b5f833664cc1167d160b196eaeee16c.png)

To make it a little bit (?) easier to read then we can use CyberChef and get the eventTime to answer this question.

```
2024-10-15 10:20
```

>Q4: During the investigation of the network traffic, we observed that the attacker attempted to retrieve the instance ID and subsequently tried to terminate or shut down the instance. What was the error code returned?

![1d57a9b69a9d1dfcccafa9576fc58095.png](/resources/1d57a9b69a9d1dfcccafa9576fc58095.png)
![415af1d73d92b4f8237585edbd5dc337.png](/resources/415af1d73d92b4f8237585edbd5dc337.png)

To terminate an instance, the attacker had to use `TerminateInstance` event which we can see that it was errored out because the compromised user does not have authorization to do so.

**Command** : `cat 124355653975_CloudTrail_eu-central-1*  | grep 'aws-cli/2.18.5' | grep Terminate` 

```
Client.UnauthorizedOperation
```

>Q5: The attacker made an attempt to create a new user but lacked the necessary permissions. What was the username the attacker tried to create?

![ca6a9db25f3b055dad08d39fa779d9ee.png](/resources/ca6a9db25f3b055dad08d39fa779d9ee.png)
![ebc4357ec5b3e58e616a716021094168.png](/resources/ebc4357ec5b3e58e616a716021094168.png)

To create a new user, the attacker have to use `CreateUser` event and it also errored out as well since it does not have necessary permission and we can also see the name/arn of the new user that the attacker intended to create it right here.

**Command** : `cat 124355653975_CloudTrail_eu-central-1*  | grep 'aws-cli/2.18.5' | grep CreateUser` 

```
H3ll
```

>Q6: Which version of the AWS CLI did the attacker use?

![0b031112df051b8313260df8d1b4a8c5.png](/resources/0b031112df051b8313260df8d1b4a8c5.png)

We can look into the user-Agent of each request made by threat actor which all will have the same version of AWS CLI version as shown in the image above.

```
aws-cli/2.18.5
```

>Q7: After listing the available S3 buckets, the attacker proceeded to list the contents of one of them, Which bucket did the attacker list its contents?

![5fd6a9b4f446cd28ca3d35d046f4317d.png](/resources/5fd6a9b4f446cd28ca3d35d046f4317d.png)
![d96d24e93a2e69d5c0aff40aae7a301c.png](/resources/d96d24e93a2e69d5c0aff40aae7a301c.png)

We can take a look at which object was listed by filter for `ListObjects` event which we can see that the attacker listed files from the `tourists-visa-info` for several occasion.

**Command** : `cat 124355653975_CloudTrail_eu-central-1*  | grep 'aws-cli/2.18.5' | grep ListObjects`

```
tourists-visa-info
```

>Q8: The attacker subsequently began downloading data from the bucket. What was the total amount of data stolen, measured in bytes?
<br>Note: Don't forget to use the right filters to get the right answer.

![5a4413d04da893643ae684301735d499.png](/resources/5a4413d04da893643ae684301735d499.png)

To get how many bytes that was transferred out then we can filter for `GetObject` event which we can see that there is "ByteTransferredOut" field that contain the total bytes was sending out for each event but each event will cap with this amount of number so we need to form a query / command to filter for this value and sum them up.

![aa1444d42e6c6f39fd9099645b2e9f94.png](/resources/aa1444d42e6c6f39fd9099645b2e9f94.png)

Which I made it with this, I grep `visa` because there was other `GetObject` event that not related to the `tourists-visa-info` bucket mixed up as well and now we have to number to answer this question.

`Command` : `cat 124355653975_CloudTrail_eu-central-1*  | grep 'aws-cli/2.18.5' | grep GetObject | grep visa | awk '{print $13}' | cut -d ":" -f 13 | cut -d '}' -f 1 | awk '{sum += $1} END {print sum}'`

```
5449252456
```

>Q9: After stealing the data, the attacker began deleting the contents of the bucket. What IP address was used during these deletion activities?

![6e4756e7469e3bc625625e216e61e448.png](/resources/6e4756e7469e3bc625625e216e61e448.png)
![459c9d5a947c14a9ca8ab2b44f8654a8.png](/resources/459c9d5a947c14a9ca8ab2b44f8654a8.png)

When deleting the content inside the bucket then `DeleteObject` will be called and we can see the IP address that associated with this event right here.

**Command** : `cat 124355653975_CloudTrail_eu-central-1*  | grep 'aws-cli/2.18.5' | grep DeleteObject`

```
193.189.100.204
```

>Q10: The attacker executed a deletion operation on the bucket, removing all of its contents. Every request in AWS is linked to a unique identifier for tracking purposes. What was the request ID associated with the `bucket's deletion event`?

![798576e04ea3e440ef6806cf548001aa.png](/resources/798576e04ea3e440ef6806cf548001aa.png)
![b013cf9c1b77ed594cada72b5458a92f.png](/resources/b013cf9c1b77ed594cada72b5458a92f.png)

`DeleteBucket` is the event/api that was used to delete bucket as its name imply and there is only 1 event from this AWS-CLI version and it was used to delete `tourists-visa-info` bucket and look like it successful as well.

**Command** : `cat 124355653975_CloudTrail_eu-central-1*  | grep 'aws-cli/2.18.5' | grep DeleteBucket`

```
XT27FP62J3ACKDNW
```

To sum it up, the attacker exploited SSRF to get the secret of "EC2-S3-Visa" then tried to create backdoor user but failed then exfiltrated files from `tourists-visa-info` before deleting them and delete the bucket as a whole.

https://cyberdefenders.org/blueteam-ctf-challenges/achievements/Chicken_0248/imdsv1/ 
* * *
