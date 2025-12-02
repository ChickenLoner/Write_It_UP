# [Blue Team Labs Online - Rottencloud](https://blueteamlabs.online/home/investigation/rotten-cloud-dcf4ab87e0)

![e3efe79da6e0bffc8111276c46d3fed1.png](/resources/e3efe79da6e0bffc8111276c46d3fed1.png)

As part of the C.R.I.S.I.S. response team, you’ve been assigned to investigate Zeta-9’s hybrid cloud environment supporting its quantum research division. Using Splunk, you must analyze cloud-based logs to determine whether the threat actor has pivoted into Zeta-9’s cloud infrastructure — and act quickly to prevent them from moving deeper into the network.

>Incident Response

>**Tags**: Splunk, Cloud
* * *

## Scenario
Zeta-9 Corporation operates a hybrid cloud infrastructure supporting its Quantum Research Division, where highly sensitive data is stored across secure cloud environments. Authorized personnel access this data through a web-based research portal that serves as the primary interface for ongoing projects. Following the breach, C.R.I.S.I.S must extend their investigation into Zeta-9’s cloud environment — analyzing activity, identifying signs of lateral movement, and determining whether the threat actor has already pivoted into the cloud infrastructure. Time is critical; stopping them before they move deeper into the network may be the only way to contain the damage.
* * *
## Background
- On [Patient Z-ero](https://blueteamlabs.online/home/investigation/patient-z-ero-b358d0acb9) investigation, the threat actor successfully compromised FortiGate firewall which grant them access to the internal network via VPN
- On [The Walking Packets](https://blueteamlabs.online/home/investigation/the-walking-packets-f8cf5573cf), the threat actor compromised surveillance platform and obtained credential of the JUMPHOST user from the surveillance video record.
- On [The Headless Dead](https://blueteamlabs.online/home/investigation/the-headless-dead-f8e2c3f90b), the threat actor leveraged local administrator credential obtained from surveillance platform and with the access to the internal network with VPN to conduct WMI-based lateral movement to JUMPHOST and exfiltrated the AWS secret.
* * *
## Environment Awareness
### Evidence & Tool Discovery

![637ba727b79622ada02695f8b69e55f6.png](/resources/637ba727b79622ada02695f8b69e55f6.png)

We only have Splunk on this investigation machine which already bookmarked for us.

![346a10a26dc396e33c381ef52c59a78f.png](/resources/346a10a26dc396e33c381ef52c59a78f.png)

We only have 4,028 events here from all index so this should be a piece of cake and very fast to query.

![6de3c5e5aa8833c41d831cc3b2e45c95.png](/resources/6de3c5e5aa8833c41d831cc3b2e45c95.png)

`host` and `source` field reveal that we are dealing with multi cloud environment involving AWS and Azure and from the previous investigation. we already know that the threat actor obtained AWS secret from JUMPHOST so our starter point should be the AWS.

![1c38facb45c4ab991a8e05702176d617.png](/resources/1c38facb45c4ab991a8e05702176d617.png)

`sourcetype` field reveals that we have CloudTrail from AWS, on the other hand, we have StorageBlobLogs and AppServiceHTTPLogs from Azure so we will be dealing with both Storage Blob and web application log from Azure as well.

* * *
## Investigation
>Q1) Analyze the AWS CloudTrail logs and identify the attacker's IP address. Note that legitimate users were working remotely from India

![4c5f28cdd497dfc0d62db53448057920.png](/resources/4c5f28cdd497dfc0d62db53448057920.png)

I start with the simple query to reveal every event from CloudTrail and we can see that beside `cloudtrail.amazonaws.com` that was normal, there are 8 events originated from `172.235.129.221` which we will need to dig into.

Query: `index=* sourcetype=CloudTrail | sort _time`

![8fe0ea84fdcc3a57f35911ca0cdb8b67.png](/resources/8fe0ea84fdcc3a57f35911ca0cdb8b67.png)

We can see that this IP address is not from India but from US, notably owned by Akamia so it must be VM (probably Linode?)

![d40527840563e6f9bfce9b3026357850.png](/resources/d40527840563e6f9bfce9b3026357850.png)

After I added the source IP address to my query, I can see 3 different events made by this individual. 

Query: `index=* sourcetype=CloudTrail sourceIPAddress="172.235.129.221" | sort _time`

![ef5500108a654878ad522984dc91428f.png](/resources/ef5500108a654878ad522984dc91428f.png)

We can see the same access key exfiltrated from previous investigation used here and it is confirmed that 172.235.129.221 is indeed the threat actor. and this access key is belong to “VictorVenom”

<details>
  <summary>Answer</summary>
<pre><code>172.235.129.221</code></pre>
</details>

>Q2) The attacker performed reconnaissance on EC2 instances. What specific API call/EventName was generated during this reconnaissance activity?

![7e0836995aedbbd4e083cf7c732291d4.png](/resources/7e0836995aedbbd4e083cf7c732291d4.png)

The first event made by the threat actor is [DescribeInstances](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstances.html) which can be used to retrieve information about your Amazon Elastic Compute Cloud (EC2) instances, such as their state, IP addresses, and other metadata.

<details>
  <summary>Answer</summary>
<pre><code>DescribeInstances</code></pre>
</details>

>Q3) After gathering information about EC2 instances, the attacker attempted to find instance passwords to establish connections. Identify the secretID that contained the Windows instance password

![204dc13363cdbcac153379af15704b1c.png](/resources/204dc13363cdbcac153379af15704b1c.png)

The second event from this threat actor is to use [GetSecretValue](https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html) to retrieve the secret of `zeta9/windows/admin-password`

<details>
  <summary>Answer</summary>
<pre><code>zeta9/windows/admin-password</code></pre>
</details>

>Q4) The attacker discovered and targeted S3 buckets to download sensitive data. Find how many unique S3 buckets were targeted as well as total files were downloaded from all buckets.

![608e6abc879c745b66964c53d22accaa.png](/resources/608e6abc879c745b66964c53d22accaa.png)

After that, the threat actor downloaded 5 objects/files from 3 different Amazon S3 buckets including database backup, secret API key, threat analysis report, and Zombie 15 experiment.

Query: `index=* sourcetype=CloudTrail sourceIPAddress="172.235.129.221" eventName=GetObject | sort _time |  table  eventTime,requestParameters.bucketName,requestParameters.key`

<details>
  <summary>Answer</summary>
<pre><code>3, 5</code></pre>
</details>

>Q5) Through analysis of the compromised EC2 instance's browsing history, the attacker found traces leading to a secret web portal used by restricted individuals. Using cross-correlation with other log sources, identify the URL of this secret portal. 

*Note that the timestamp of the HTTP event might be off as I already asked the author, all of this event should happened after AWS event and before Storage Blog event.

![f94ce6dbc5adea20871ab3306d79c0ee.png](/resources/f94ce6dbc5adea20871ab3306d79c0ee.png)

After retrieval of S3 objects, the threat actor discovered secret web portal which can execute system command to request OAuth access token from Azure Managed Identity using a secret that was possibly obtained from an AWS S3 object.

Query: `index=* "172.235.129.221" sourcetype=AppServiceHTTPLogs | sort _time`

![a1669d12b737396624e141fa0880089f.png](/resources/a1669d12b737396624e141fa0880089f.png)

BTW, the organization site is `zeta9-research-portal.azurewebsites.net`

<details>
  <summary>Answer</summary>
<pre><code>zeta9-research-portal.azurewebsites.net</code></pre>
</details>

>Q6) The attacker pivoted to another cloud environment by exploiting a vulnerability. Provide the complete command used for this cross-cloud activity

![e44577af4a79994d403865c310f947f7.png](/resources/e44577af4a79994d403865c310f947f7.png)

As already discovered from previous question, the threat actor exploited an exposed Azure Instance Metadata Service (IMDS) endpoint to obtain a Managed Identity access token from the local metadata IP 169.254.130.3, which is used by Azure VMs to provide credentials to applications running inside the VM.

By sending this request, the threat actor can trick the VM into issuing an OAuth token for the Azure Management API (https://management.azure.com/).
With that token, they could access or modify Azure resources depending on the VM’s identity permissions.

<details>
  <summary>Answer</summary>
<pre><code>curl -H secret:4ebc6d54-f421-4321-81c4-fd9e29d28a0f 'http://169.254.130.3:8081/msi/token?api-version=2017-09-01&resource=https://management.azure.com/' </code></pre>
</details>

>Q7) After gaining access to the Azure environment, the attacker was able to list and access data from cloud storage services. Identify the name of the specific storage blob container that was targeted.

![5b8622ea4fae593c920ccfe32be2e30f.png](/resources/5b8622ea4fae593c920ccfe32be2e30f.png)

After obtained OAuth token, the threat actor can now access Azure Storage Blob from cloud storage service of Zeta 9 research. the first event is to ListContainers which will return a list of the containers under the specified storage account.

Query: `index=* "172.235.129.221" sourcetype=StorageBlobLogs | sort _time`

![66827211d34e63fb40faaeee2a05a8b2.png](/resources/66827211d34e63fb40faaeee2a05a8b2.png)

The threat actor then list blobs storage with ListBlobs under "quantum-research-secrets" blob container.

<details>
  <summary>Answer</summary>
<pre><code>quantum-research-secrets</code></pre>
</details>

>Q8) Determine how many files the attacker successfully downloaded from the Azure blob storage during the attack. 

![97781fb6dd18137ecb269324833009e7.png](/resources/97781fb6dd18137ecb269324833009e7.png)

The threat actor then proceed to downloaded 6 different files from "quantum-research-secrets" blob container.

Query: `index=* "172.235.129.221" sourcetype=StorageBlobLogs OperationName=GetBlob | sort _time | table TimeGenerated [UTC]",ObjectKey`

<details>
  <summary>Answer</summary>
<pre><code>6</code></pre>
</details>

>Q9) To gain access to the secret division systems, the attacker defaced the organization's website by deploying malicious content. Provide the URL that hosted the defaced website code.

![54043d49f7b9262ab367ab75133ce4e5.png](/resources/54043d49f7b9262ab367ab75133ce4e5.png)

Now we can come back to web service log again to list all commands and we can see that the threat actor replaced `index.html` file with the content from `https://pastebin.com/raw/sBEs83q3`

Query: `index=* "172.235.129.221" sourcetype=AppServiceHTTPLogs | sort _time | table "TimeGenerated [UTC]", CsUriQuery`

![9f90366f92743e0dd0bcc59a97785169.png](/resources/9f90366f92743e0dd0bcc59a97785169.png)

Although the pastebin is already gone but we still have archive of the defaced website as seen here, the defaced website is now used to lure victim to execute malicious command with "filefix" technique invented my Mr.d0x.

<details>
  <summary>Answer</summary>
<pre><code>https://pastebin.com/raw/sBEs83q3</code></pre>
</details>

![fde57ca8c556cc999490224278cb0a17.png](/resources/fde57ca8c556cc999490224278cb0a17.png)
https://blueteamlabs.online/achievement/share/52929/283
* * *