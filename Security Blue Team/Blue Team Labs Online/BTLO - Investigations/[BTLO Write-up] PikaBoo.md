# [Blue Team Labs Online - PikaBoo](https://blueteamlabs.online/home/investigation/pikaboo-6bcb02f1a9)
<div align=center>

![8d5062ade7bce839a279168f4f46eead.png](/_resources/8d5062ade7bce839a279168f4f46eead.png)
</div>
Will's in hot water for sharing his credentials—never share yours! Can you uncover how the environment got AWSaultAD?

>Incident Response

>**Tags**: Splunk, Git, T1566, T1059, T1567, T1529
* * *
**Scenario**
ToT, a company, was developing a top-secret cloud project. Their lead developer, Will (who always uses GitHub), went on Halloween vacation but received feedback on his website, where he’d added his email for feedback. Needing someone to check his inbox, he sent his credentials to a colleague, Michelle. A few hours later, the entire cloud environment vanished. Will's in hot water for sharing his credentials—never share yours! Can you uncover how the environment got AWSaultAD?
* * *
## Investigation Submission
>Q1) What email address did Will add to his website? (Accessible on port 80) (Format: Email Address)

![84d1879c9e51784ebf080b79f294db57.png](/_resources/84d1879c9e51784ebf080b79f294db57.png)

We were provided with `gitdumper.sh` so I guess we have to dump git to find something related to AWS.

![a5ba38814480f9c23987473fcd056c5c.png](/_resources/a5ba38814480f9c23987473fcd056c5c.png)

After accessed localhost port 80, we will see this strange image which I could not click anything.

![66f260da532620c8af485ad73e716e2d.png](/_resources/66f260da532620c8af485ad73e716e2d.png)

So I used my ultimate move "view page source" to see what happened and found the answer of Q1 as a comment of this page right here.

<details>
  <summary>Answer</summary>
<pre><code>will.befired@tot.com</code></pre>
</details>

>Q2) The attacker targeted the cloud. Check Will’s website—was anything leaked or somehow left behind? Provide the access key. (Format: Access Key)

![b3f75553726e9ea819b0810b2353e807.png](/_resources/b3f75553726e9ea819b0810b2353e807.png)

Since we have `gitdumper.sh` so I tried to access `/.git` which I found git directory of this website. 

![22dd894c3964ffdd743c54d2fe9476d0.png](/_resources/22dd894c3964ffdd743c54d2fe9476d0.png)

So lets execute `./gitdumper.sh http://localhost/.git/ .` to dump those files on our machine so we can use git command and cli to analyze this.

![8e3ea3ea1bf393d1fc8721d5bd487871.png](/_resources/8e3ea3ea1bf393d1fc8721d5bd487871.png)

First thing I did after dumping git is using `git log` which show me 2 commits of this website.

![4badec2008e47ebc3b650c6e7b54d03d.png](/_resources/4badec2008e47ebc3b650c6e7b54d03d.png)

Then I found AWS access key and secret key from "Initial Commit - Website v2" commit so this is how the threat actor obtained leaked AWS key.

<details>
  <summary>Answer</summary>
<pre><code>AKIA3EBEV4OQLWYJIHGN</code></pre>
</details>

>Q3) Using Splunk, find the user to whom this access key belongs.(Format: Username)

![e867c24fe4337f6a359359cac97b8af2.png](/_resources/e867c24fe4337f6a359359cac97b8af2.png)

Go back to browser then we can see splunk was bookmarked right here.

![ca97fa2e3c1a8a226915578231713bb8.png](/_resources/ca97fa2e3c1a8a226915578231713bb8.png)

Then upon checking each field, I realized that there is only one username on this log which is thirdPartyVendor so this guy is a problem all along.

<details>
  <summary>Answer</summary>
<pre><code>thirdPartyVendor </code></pre>
</details>

>Q4) Michelle used Internet Explorer to download an attachment from Will’s email. Identify the file that led to initial access. (Format: Filename.extension)

![b9f66b89a57805c7451c6ebcfe66f824.png](/_resources/b9f66b89a57805c7451c6ebcfe66f824.png)

Since splunk is so easy to search, I just searched for "Michelle" which revealed event log related to Michelle user including SID that we could use for our next query.

![352ef88f605bf26bff0b2eb4853abbce.png](/_resources/352ef88f605bf26bff0b2eb4853abbce.png)

Using SID to query then we can see the actual username that we can use to query next.

![1925d6545f59f76a899b5e71c1f2930e.png](/_resources/1925d6545f59f76a899b5e71c1f2930e.png)

I realized that there is a sysmon log so its time to use it.

![34f55da42392ebfa39924892a0e60c3e.png](/_resources/34f55da42392ebfa39924892a0e60c3e.png)

I queried with `mgibson SourceName="Microsoft-Windows-Sysmon" iexplore.exe  | sort UtcTime` which will listed all sysmon log related to IE process and we only have 7 events to look for.

![29d2e961b5150c1208bdb3d667d2e261.png](/_resources/29d2e961b5150c1208bdb3d667d2e261.png)

Which we will see `Feedback.exe` from this query result and without a doubt that it is the file that lead to initial access.  
<details>
  <summary>Answer</summary>
<pre><code>Feedback.exe</code></pre>
</details>

>Q5) Which host was compromised first? (Format: Host)

![a41694fa4495e8b1e4ec9b0e2bcba198.png](/_resources/a41694fa4495e8b1e4ec9b0e2bcba198.png)

We know that "mgibson" was the one who executed the payload.

![cd016610f0567285c7bba16fcbfca079.png](/_resources/cd016610f0567285c7bba16fcbfca079.png)

And this user is only presented on Machine-2 host .

<details>
  <summary>Answer</summary>
<pre><code>Machine-2</code></pre>
</details>

>Q6) An ASREPRoast attack occurred. What was the targeted account? (Format: username)

![8befec8786fabff2e676cc8a0c07536d.png](/_resources/8befec8786fabff2e676cc8a0c07536d.png)

After analyzing sysmon log for a while, I found PowerShell was executed from `cmd.exe`.

![47defae234e513e12159614bcfa78956.png](/_resources/47defae234e513e12159614bcfa78956.png)

So I took a look at each command executed by "mgibson" and found command used to get all file with "password" in its name and also base64 powershell command.

![f007d25f3aedd7f307fea233912cfa47.png](/_resources/f007d25f3aedd7f307fea233912cfa47.png)

At this time, I realized since we already know PowerShell was created by cmd then we could query for PowerShell log which reveal ASREPRoasting script right here.

ASREP Roasting attack will generate `Ticket_Encryption_Type 0x17` which asking for a hash from domain controller so the threat actor could crack it 

![a84f0def45ec44c5311580cce122365e.png](/_resources/a84f0def45ec44c5311580cce122365e.png)

Then I used `source = *   host=DC  EventCode=4768  Ticket_Encryption_Type=0x17 | sort UtcTime` to find out which user was the target of this ASREP Roasting attack and we could also see the IP address of the threat actor right from this event too.

<details>
  <summary>Answer</summary>
<pre><code>pika.boo</code></pre>
</details>

>Q7) On the first compromised system, an obfuscated command was executed. Provide the de-obfuscated part of the first command found. (If multiple, use the first one, as per time, with obfuscation) (Format: De-obfuscated String_

![47defae234e513e12159614bcfa78956.png](/_resources/47defae234e513e12159614bcfa78956.png)

Lets go back to this PowerShell base64 command and decode this base64 string.

![785a6799f5a955eb2b11e45fc4c69e52.png](/_resources/785a6799f5a955eb2b11e45fc4c69e52.png)

Which we can see that its a command used to find all files with "password" in it inside User directory (which we already found from previous question.)
<details>
  <summary>Answer</summary>
<pre><code>findstr /S /R /N "^password" C:\Users\*.*</code></pre>
</details>

>Q8) The Attacker, to access other Internal systems with valid credentials, created an Instance in the cloud. Find it's private IP Address. (Format: Private IP Address) 

![6c9bbd422a40da21faa7ecd9f170a173.png](/_resources/6c9bbd422a40da21faa7ecd9f170a173.png)

I reduced my scope by filter start time so I would only get relevant log after all the activities we discovered so far. 

![c786f795674e4ab0a5d900b11bc638fb.png](/_resources/c786f795674e4ab0a5d900b11bc638fb.png)

This time we have to query for CloudTrail log with "[RunInstances](https://docs.aws.amazon.com/systems-manager/latest/userguide/automation-action-runinstance.html)" API then we can see that there is only RunInstances 1 event on this CloudTrail log. 

![d98660a5d4979d8a5b468bb8a7bc1e36.png](/_resources/d98660a5d4979d8a5b468bb8a7bc1e36.png)

Then we can get private IP address of this instance right here.

<details>
  <summary>Answer</summary>
<pre><code>10.0.1.126</code></pre>
</details>

>Q9) Which host did the attacker log in using the recently compromised account? (Format: Host)

![95fae76c7f32576527ee0e29651dd4ac.png](/_resources/95fae76c7f32576527ee0e29651dd4ac.png)

We know the user that was targeted by ASREP Roasting attack so we could query for Event ID 4624 like this `source = * pika.boo EventCode=4624 10.0.1.126 | sort UtcTime` which we can see that this user only logged on on this host only.
<details>
  <summary>Answer</summary>
<pre><code>MACHINE-1</code></pre>
</details>

>Q10) The attacker re-ran the previously found obfuscated command and then moved to a Linux system. Find the username, IP, and protocol used for access. (Format: Protocol, user, IP)

![34a503208cff70ce06617d6b62b11d50.png](/_resources/34a503208cff70ce06617d6b62b11d50.png)

While I searched though sysmon event ID 1, I found this ssh command attempted to access 10.0.1.113 as user john.
<details>
  <summary>Answer</summary>
<pre><code>SSH, john, 10.0.1.113</code></pre>
</details>

>Q11) A file was downloaded from the connected system. What was the file name? (Format: Filename.Extension)

![eacdd8bdac70d65d6393954ebf7a5c40.png](/_resources/eacdd8bdac70d65d6393954ebf7a5c40.png)

I used an IP address found from previous question to query which revealed that the threat actor used PowerShell IWR and bitsadmin to download this particular file hosted on Linux system.
<details>
  <summary>Answer</summary>
<pre><code>l0lDump.txt</code></pre>
</details>

>Q12) Another large obfuscated command was executed. What activity was performed? (Reference from MITRE Tactic) (Format: Activity Name (As Per MITRE Tactic))

![4bce3f7d3d05ad08a8513d91dd2f2c13.png](/_resources/4bce3f7d3d05ad08a8513d91dd2f2c13.png)

When talking about obfuscated command on Windows, the first thing that came up on top of my head is  PowerShell base64 command so I started hunting for it which I found this very long PowerShell base64 command right here. 

![9d115613f47b49f3becbe1d92d3df44a.png](/_resources/9d115613f47b49f3becbe1d92d3df44a.png)

Decode it then we can see that it will send several things to pastebin API that mean this is "Exfiltration" tactic.
<details>
  <summary>Answer</summary>
<pre><code>Exfiltration</code></pre>
</details>

>Q13) What web service was used for this activity? Also, provide the API key found. (Format: WebService Name, API)

![cbe98505df8c9a8f009fc22e558ada5c.png](/_resources/cbe98505df8c9a8f009fc22e558ada5c.png)
<details>
  <summary>Answer</summary>
<pre><code>pastebin, vfkaoc1w08ELOSUoYf4npiz2KaY0Irsp</code></pre>
</details>

>Q14) How did the environment disappear from the cloud? (Identify the API used) (Format: API)

![f206bd2ae3339c5f4dd1072bd6b3dafd.png](/_resources/f206bd2ae3339c5f4dd1072bd6b3dafd.png)

The API that was used for this is [TerminateInstances](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_TerminateInstances.html).
<details>
  <summary>Answer</summary>
<pre><code>TerminateInstances</code></pre>
</details>

>Q15) How many instances were disappeared? (Format: Integer)

![998f48dadc8e77a577470918384a3eeb.png](/_resources/998f48dadc8e77a577470918384a3eeb.png)

Take a look inside this event then we could see there are total of 6 instances were terminated by this activity.
<details>
  <summary>Answer</summary>
<pre><code>6</code></pre>
</details>

>Q16) A user from Machine-1 reported seeing a message in a blue box before the instances disappeared. What was the message? (Message will be inside quotes) (Format: Message)

![88f1b7705f7f2e6e472efa155a411131.png](/_resources/88f1b7705f7f2e6e472efa155a411131.png)

After searching for another PowerShell process for a while then I finally found this command which is the one that we will need to decode.

![08c393bd489a4c193abb4d471b5dc8a3.png](/_resources/08c393bd489a4c193abb4d471b5dc8a3.png)

There we got a message left for us too "HAPPY HALLOWEEN!"

<details>
  <summary>Answer</summary>
<pre><code>Kaboom!! Happy Halloween</code></pre>
</details>

![d045167d06c0832d9d4891aba5a911e8.png](/_resources/d045167d06c0832d9d4891aba5a911e8.png)
https://blueteamlabs.online/achievement/share/52929/240
* * *