# [LetsDefend - Disclose The Agent](https://app.letsdefend.io/challenge/disclose-the-agent)
Created: 16/01/2024 09:34
Last Updated: 25/01/2024 13:07
* * *
<div align=center>

**Disclose The Agent**
![8d446a4e6126b56bfef10fdb927326f5.png](../../_resources/8d446a4e6126b56bfef10fdb927326f5.png)
</div>

We reached the data of an agent leaking information. You have to disclose the agent.

Log file: https://files-ld.s3.us-east-2.amazonaws.com/smtpchallenge.zip Pass: 321

Note: pcap file found public resources.
* * *
## Start Investigation
We got a pcap file to work with so let's roll!
<div align=center>

![cc2c7f945ee1a20251146602e2ea1e39.png](../../_resources/cc2c7f945ee1a20251146602e2ea1e39.png)
First thing I checked is the Protocol Hierarchy Statistics and there are a lot of SMTP packets were captured and there are some of Syslog, NetBIOS, SMB, and ARP Protocol as well.

![9805245ae370e1d087e0d37bfd2eb718.png](../../_resources/9805245ae370e1d087e0d37bfd2eb718.png)
SMTP conversation caught my eyes right away when I examined this pcap file, I saw login credential and some emails.

![0df3db051716c83d0a5a304a96da3c44.png](../../_resources/0df3db051716c83d0a5a304a96da3c44.png)
Follow the TCP stream we can see the message of the email.
</div>

Look like Ann wrote this email as we seen in From: `"Ann Dercover" <sneakyg33k@aol.com>`

And the recipient is `sec558@gmail.com`

She's talking about Lunch, let's find out if there is another email were captured
<div align=center>

![c897fc0b68e247c939d3d02640c7dd1b.png](../../_resources/c897fc0b68e247c939d3d02640c7dd1b.png)
There it is an email from Ann to `mistersecretx@aol.com`

![33d0445f63ed898ef62bf6a204f404b6.png](../../_resources/33d0445f63ed898ef62bf6a204f404b6.png)
Look like they're planning to go to a date, so this mistersecretx is the Ann's secret boyfriend.

![3e2acc41473ea13f3f55925813168d12.png](../../_resources/3e2acc41473ea13f3f55925813168d12.png)
An attachment was also sent with this email.

![9caa35458cd3c0806ed46cb347a45532.png](../../_resources/9caa35458cd3c0806ed46cb347a45532.png)
I used NetworkMiner to extract the attachment

![55d90f8cac407e41468bfae243bbc76a.png](../../_resources/55d90f8cac407e41468bfae243bbc76a.png)
An attachment is a picture of location they decided to meet up, It's in Mexico
</div>

There are nothing more to be dig up so let's answer the questions

* * *
> What is the email address of Ann's secret boyfriend?
```
mistersecretx@aol.com
```

> What is Ann's email password?

<div align=center>

![1c1864692c4ff2c5fcff820036c40c39.png](../../_resources/1c1864692c4ff2c5fcff820036c40c39.png)
</div>

```
558r00lz
```


> What is the name of the file that Ann sent to his secret lover?
```
secretrendezvous.docx
```

> In what country will Ann meet with her secret lover?
```
Mexico
```

> What is the MD5 value of the attachment Ann sent?
```
9e423e11db88f01bbff81172839e1923
```
<div align=center>

![6746acb89959d9efd9676755554f8aed.png](../../_resources/6746acb89959d9efd9676755554f8aed.png)
</div>

* * *
## Summary
2 emails was captured in SMTP communication, first email content is about telling a friend that Ann can't do lunch next week because She was heading out of towns and the second email told us that out of town Ann was heading to is in Mexico and Ann was going there with her secret boyfriend that she sent out a location with an email attachment.

* No Badge for this challenge
* * *