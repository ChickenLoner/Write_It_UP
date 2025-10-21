# [Blue Team Labs Online - Deep Freeze](https://blueteamlabs.online/home/investigation/deep-freeze-fc58456bb2)
<div align=center>

![42dee1a3ad5fe8795d5055b9c89ceae5.png](..//resources/42dee1a3ad5fe8795d5055b9c89ceae5.png)
</div>
FrostGuard is freezing us out with its hacks...

>**Incident Response**

>**Tags**: Linux CLI Splunk JQ CloudTrail Logs S3 Access Logs
* * *
**Scenario**
Our IT Team have an urgent need for the analysis of a set of S3 Access logs and some corresponding CloudTrail data. We think some data may have leaked after a mistake in a configuration change. FrostGuard needs you...
* * *
## Environment Awareness
### Evidence Discovery
![cf9bad8615b5e56422466f6f30974b96.png](..//resources/cf9bad8615b5e56422466f6f30974b96.png)

This investigation machine provides with 2 AWS related logs which are [AWS CloudTrail](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html#:~:text=AWS%20CloudTrail%20is%20an%20AWS,recorded%20as%20events%20in%20CloudTrail.) and S3 Access log (treat it like webserver access log but for S3 storage).

![da76ea63cd472d9aefccf36bf8592502.png](..//resources/da76ea63cd472d9aefccf36bf8592502.png)

After taking a look at file size of both files, we would not need tool like Splunk to query efficiently but if you still want to use Splunk then you could the next section for Splunk preparation. 

***
### Tool Discovery and Preparation
![b1beb52aa624a4a66d6f10963e4cf50d.png](..//resources/b1beb52aa624a4a66d6f10963e4cf50d.png)

This investigation room tagged with "Linux CLI", "Splunk" and "JQ" beside CyberChef we found on Desktop, lets find them to confirm its presence 

![d2b828a726f83c90094225806f8b924b.png](..//resources/d2b828a726f83c90094225806f8b924b.png)

First, we can easily find the existence of `jq` by simply using `which jq` command that will print out where the binary of `jq` located on this machine and it is indeed installed on this machine

![e58cd30eea400ef72e14b2f962b038e9.png](..//resources/e58cd30eea400ef72e14b2f962b038e9.png)

At the bottom of the screen, we can see that Sublime Text was also installed on this machine

![28913f622f632cd9489c1ac042273c5f.png](..//resources/28913f622f632cd9489c1ac042273c5f.png)

Then after open Mozilla Firefox browser, we can see that there is a quick tab to Splunk running on port 8000

![d14d28fa45fa46e329aedb090b505392.png](..//resources/d14d28fa45fa46e329aedb090b505392.png)

But we are unable to connect so we will have to manually start Splunk via its binary on this system

![efcf1dd648ce01a20e84a97aa8f4a508.png](..//resources/efcf1dd648ce01a20e84a97aa8f4a508.png)

Splunk is located at `/opt/splunk`, we will have to execute `splunk` binary inside `/opt/splunk/bin` directory.

![28c81c08ad819fda6ec98b6821f0360f.png](..//resources/28c81c08ad819fda6ec98b6821f0360f.png)

Execute the command : `/opt/splunk/bin/splunk start` and wait for a sec until Splunk web interface is ready.

![31e3ee54b88dc8d1a8352bec20fd17f1.png](..//resources/31e3ee54b88dc8d1a8352bec20fd17f1.png)

Splunk will tell user that its web interface is ready like this so we can go back to refresh Splunk web interface on Firefox or just accessed it with this new URL. 

![441a7deada1835b324c4652d42337ad1.png](..//resources/441a7deada1835b324c4652d42337ad1.png)

Change license group page will appear as soon as it finished loading but do not worry, just click "Save" button as we can use Free license to query our log.

![c6452122ddfb0a94ee58bee696d5d1b8.png](..//resources/c6452122ddfb0a94ee58bee696d5d1b8.png)

Splunk restart will be required so we can just click "Restart Now" and wait for a sec before browse to index page.

![df92ade741d5d26eba8b9c783370fe99.png](..//resources/df92ade741d5d26eba8b9c783370fe99.png)

Now what we need to do is to import our log into Splunk.

![7268660e3aa504d9970dc625acc22423.png](..//resources/7268660e3aa504d9970dc625acc22423.png)

Go to `http://127.0.0.1:8000/en-US/manager/search/adddata` to upload files.

![de6b26c5fccd22e73da1e1702f56bf18.png](..//resources/de6b26c5fccd22e73da1e1702f56bf18.png)

Now you are ready for the investigation using Splunk. (which I didn't use btw)

***
## Investigation
>Q1) The IT team accidentally applied an overly permissive policy to the subject’s AWS user account, instead of a specific policy. What policy was applied, and what is the username of the subject? (Format: Username, PolicyName)

![cc97531ff6bf31590d846809776282b5.png](..//resources/cc97531ff6bf31590d846809776282b5.png)

Lets start with AWS CloudTrail and The first even we will see is [**PutUserPolicy**](https://docs.aws.amazon.com/IAM/latest/APIReference/API_PutUserPolicy.html) event and as it names imply, its an event that will add or update a policy to IAM user and this record showed that username "CodyShaddock" was added with [**GrantS3FullAccess**](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AmazonS3FullAccess.html) policy which will provides full access to all S3 buckets via AWS Management Console so this is ***overly permissive policy*** that we are looking for.

<details>
  <summary>Answer</summary>
<pre><code>CodyShaddock, GrantS3FullAccess</code></pre>
</details>

>Q2) What is the username of the account that made this change? (Format: Username)

![d053aeb9255e5390591c64887e1f8ca7.png](..//resources/d053aeb9255e5390591c64887e1f8ca7.png)

The user responsible for this action is "TimSmithADMIN"
<details>
  <summary>Answer</summary>
<pre><code>TimSmithADMIN</code></pre>
</details>

>Q3) What S3 buckets were made available to the subject? (Format: Bucket1, Bucket2)

![9b44d755c1a5336fc34a484d84d76f01.png](..//resources/9b44d755c1a5336fc34a484d84d76f01.png)

Under "Statement" section, we can see these 2 S3 buckets were made available due to new policy added to "CodyShaddock"

![7039125121243b242207a4b32dc73823.png](..//resources/7039125121243b242207a4b32dc73823.png)

We can also confirm this with record below that which is [**ListBuckets**](https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListBuckets.html) event that will return all available S3 buckets to authenticated request sender.

<details>
  <summary>Answer</summary>
<pre><code>lab-bucket-sensitive, lab-bucket-general</code></pre>
</details>

>Q4) What is the Insider Threat Matrix preparation section ID most relevant to this activity? (Format: PRXXX)

![8a3ce96dfcf3019bfd44bffb5fc23593.png](..//resources/8a3ce96dfcf3019bfd44bffb5fc23593.png)

GrantS3FullAccess is a policy that will increase privilege for specific user which match [PR024: Increase Privileges](https://insiderthreatmatrix.org/articles/AR3/sections/PR024) on Insider Threat Matrix.

<details>
  <summary>Answer</summary>
<pre><code>PR024</code></pre>
</details>

>Q5) What IP address did the subject use when enumerating the S3 buckets, and what event name is present? (Format: X.X.X.X, EventName)

![c3d4eb98e795a42a64168fd2eda4c79b.png](..//resources/c3d4eb98e795a42a64168fd2eda4c79b.png)

We know which event can be used to retrieve available S3 buckets so we will just have to grab source IP Address of this request right here.
<details>
  <summary>Answer</summary>
<pre><code>203.0.113.46, ListBuckets</code></pre>
</details>

>Q6) What type of retrieval was used, and what is the event name? (Format: xxxx, EventName)

![e4bdd6ddeb0bf1f02267735d10768b33.png](..//resources/e4bdd6ddeb0bf1f02267735d10768b33.png)

After listing S3 storages, next event we will see is [**RestoreObject**](https://docs.aws.amazon.com/AmazonS3/latest/API/API_RestoreObject.html) which is an event to create a temporary of the object from [S3 Glacier archive storage](https://aws.amazon.com/s3/storage-classes/glacier/) which can be downloaded or accessed and the retrieval tier is "When restoring an object, you can choose how quickly you need the data" which will range from

Tier	| Time to Retrieve	| Cost	| Use Case
-|-|-|-
Expedited|1–5 minutes|Highest cost|Urgent small data retrieval.
Standard|3–5 hours|Moderate cost|Regular access with reasonable speed.
Bulk|5–12 hours (Glacier), 48 hours (Deep Archive)|Lowest cost|Large-scale, non-urgent data recovery.

Then we can see that retrieval tier on this event is "Bulk"

![b3dc63f18dc680af92022dd90a45bf7c.png](..//resources/b3dc63f18dc680af92022dd90a45bf7c.png)

We can also found this request on S3 access log right here.
<details>
  <summary>Answer</summary>
<pre><code>bulk, RestoreObject</code></pre>
</details>

>Q7) What bucket was targeted in the retrieval request? (Format: BucketName)

![683a31e17f5d2348b1cc51f8b74a0e26.png](..//resources/683a31e17f5d2348b1cc51f8b74a0e26.png)

After RestoreObject event, 2 [**GetObject**](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html) were made to download zip files from S3 buckets and those files reside in this sensitive bucket.

![8265d5626f98a1e1422baa170de366e9.png](..//resources/8265d5626f98a1e1422baa170de366e9.png)

From S3 Access Log, we can see that all 3 requests were made to specifically for this bucket. 

<details>
  <summary>Answer</summary>
<pre><code>lab-bucket-sensitive</code></pre>
</details>

>Q8) What is the timestamp of the retrieval request? (Format: YYYY-MM-DDTHH:MM:SS)

![6746b8f1895e19b5a76655d9b8410eb9.png](..//resources/6746b8f1895e19b5a76655d9b8410eb9.png)

There are 2 GetObject events, the timestamp I submitted is the first GetObject event right here.

![a3483b18f3175e5210f0697fc6cd41f5.png](..//resources/a3483b18f3175e5210f0697fc6cd41f5.png)

Which can also be retrieve from S3 Access Log right here.
<details>
  <summary>Answer</summary>
<pre><code>2024-11-29T12:45:00</code></pre>
</details>

>Q9) What are the names of the files downloaded by the subject? (Format: file1.ext, file2.ext)

![ca846c01210649386465da344a4f86a1.png](..//resources/ca846c01210649386465da344a4f86a1.png)

We can obtain the names of both files from CloudTrail or S3 Access Log right here.
<details>
  <summary>Answer</summary>
<pre><code>project-orion-CONFIDENTIAL.zip, project-chimera-CONFIDENTIAL.zip</code></pre>
</details>

>Q10) What is the Insider Threat Matrix preparation section ID most relevant to this activity? (Format: PRXXX)

![928d450d2cd727fcb0410cfc91cf3ad1.png](..//resources/928d450d2cd727fcb0410cfc91cf3ad1.png)

We know that GetObject request were made to download sensitive files which match [PR-025: File Download](https://insiderthreatmatrix.org/articles/AR3/sections/PR025) from Insider Threat Matrix 
<details>
  <summary>Answer</summary>
<pre><code>PR025</code></pre>
</details>

>Q11) What policy was removed from the subject’s user account, and what is the event name? (Format: PolicyName, EventName)

![00ad9e5dc017055f72aeaa8a2d4eeee6.png](..//resources/00ad9e5dc017055f72aeaa8a2d4eeee6.png)

We can see on the last record on CloudTrail that GrantS3FullAccess Policy was deleted from "CodyShaddock" by [**DeleteUserPolicy**](https://docs.aws.amazon.com/IAM/latest/APIReference/API_DeleteUserPolicy.html) event.

<details>
  <summary>Answer</summary>
<pre><code>GrantS3FullAccess, DeleteUserPolicy</code></pre>
</details>

>Q12) What is the Insider Threat Matrix anti-forensics section ID most relevant to this activity? (Format: AFXXX)

![7beae21578d92c40df317f04bc13fec4.png](..//resources/7beae21578d92c40df317f04bc13fec4.png)

Which will [decrease privilege](https://insiderthreatmatrix.org/articles/AR5/sections/AF019) of that user back before it was granted with full S3 access.

<details>
  <summary>Answer</summary>
<pre><code>AF019</code></pre>
</details>

![8a202713bd08aadf816228b0fd52809e.png](..//resources/8a202713bd08aadf816228b0fd52809e.png)
https://blueteamlabs.online/achievement/share/52929/249

***
## Summary
After "TimSmithADMIN" (IT team) applied "GrantS3FullAccess" policy to "CodyShaddock" user which made then started to restore object within "lab-bucket-sensitive" bucket from S3 Glacier Deep Archive and exfiltrated 2 confidential files from the bucket then remove "GrantS3FullAccess" from "CodyShaddock" user.

### Timeline
- 2024-11-29T12:00:00Z : "TimSmithADMIN" user applied "GrantS3FullAccess" policy to "CodyShaddock" user
- 2024-11-29T12:15:00Z : "CodyShaddock" first activity seen with "ListBuckets" event
- 2024-11-29T12:30:00Z : "CodyShaddock" restored `project-orion-CONFIDENTIAL.zip` object from "lab-bucket-sensitive" bucket
- 2024-11-29T12:45:00Z : "CodyShaddock" exfiltrated first confidential file from "lab-bucket-sensitive" bucket
- 2024-11-29T12:47:00Z : "CodyShaddock" exfiltrated second confidential file from "lab-bucket-sensitive" bucket
- 2024-11-29T13:00:00Z : "CodyShaddock" remove "GrantS3FullAccess" policy from itself

### IOCs
- `203[.]0[.]113[.]46` 

* * *