# [HackTheBox Sherlocks - OpSalwarKameez24-4: Salsa-Dance](https://app.hackthebox.com/sherlocks/OpSalwarKameez24-4:%20Salsa-Dance)
Created: 03/11/2024 17:20
Last Updated: 08/12/2024 00:25
* * *
![abc413ae9aeb848d646db767d2576ae7.png](..//resources/abc413ae9aeb848d646db767d2576ae7.png)
**Scenario:**
After gaining elevated privileges on the victim machine, the Incident Response team has been assigned the task of analyzing whether the attacker has carried out any lateral movement or collected confidential data within the network, as unusual activity has been detected related to one of the cloud storage accounts.

* * *
>Task 1: What time (UTC) did the threat actor retrieve details about the domain controller using a native Windows tool?

We got Windows artefacts collected by [KAPE](https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape) and Linux artefacts collected by [CatScale](https://github.com/WithSecureLabs/LinuxCatScale) so lets dig into Windows artifacts first. 

![7ca42431eac968a67227e07203981c52.png](..//resources/7ca42431eac968a67227e07203981c52.png)

Then I noticed that `NLTEST.EXE` which is Windows built-in tool that can get a list of domain controllers so lets use `PECmd.exe` to retrieve 
execution timestamp of this executable. 

![10ecc29704daf86738cd50983f2281c1.png](..//resources/10ecc29704daf86738cd50983f2281c1.png)

After parsed prefetch folder, we will get 2 csv files then we can use Output Timeline file to see execution timeline and also execution time of `nltest.exe`

We can also see that PowerShell is likely to be the process that executed `nltest` and all the rest.

```
2024-10-24 06:27:29
```

>Task 2: To what directory on the compromised system did the threat actor download the tools used for reconnaissance?

![7b2e0de49e48f9fe33e8fe4df891f784.png](..//resources/7b2e0de49e48f9fe33e8fe4df891f784.png)

From prefetch output timeline, we can see that `bitsadmin.exe` was executed which is another popular Windows LOLBin that can be used to download files into system. (Which also the answer of Task 3)

![6f59aeb67671efef63497cc339686681.png](..//resources/6f59aeb67671efef63497cc339686681.png)

We can find Windows event log related to BitsAdmin right here.

![d2b10cc6207bbe140008d15401759276.png](..//resources/d2b10cc6207bbe140008d15401759276.png)

After parsed event log with `EvtxECmd.exe`, I opened output file in Timeline Explorer and find event related to BITS transfer job which we can see `netscan_portable.zip` was downloaded using BITS Jobs

![d980c05599cdb7b50844388dc4f04eee.png](..//resources/d980c05599cdb7b50844388dc4f04eee.png)

We will have to take a look at details of this event to get download path of this file.

```
C:\Windows\INF
```

>Task 3: Which legitimate Windows program did the threat actor use to download the initial file?
```
BITSADMIN.EXE
```

>Task 4: What is the MITRE ATT&CK Technique ID associated with the method used by the threat actor in Question #3?

![a4dd1df244d2e3eb3453b8bcc79724a8.png](..//resources/a4dd1df244d2e3eb3453b8bcc79724a8.png)

We know that the threat actor use BITS jobs to download file which match [this](https://attack.mitre.org/techniques/T1197/) technique on MITRE ATT&CK framework

```
T1197
```

>Task 5: The threat actor used a program to identify the credentials stored on the victim machine. What was the original filename of this program before it was renamed?

![e15427daf2b677b455830a1c7d2332cb.png](..//resources/e15427daf2b677b455830a1c7d2332cb.png)

Go back to prefetch timeline, we can see that `netscan.exe` was executed after downloaded so lets continue to dig a little bit more until we found unfamiliar binary.

![ffef27a78c389594457374f292147611.png](..//resources/ffef27a78c389594457374f292147611.png)

Then I noticed that `WINSYSVIEW.EXE` was executed from the same directory netscan tool was downloaded so lets find hash of this binary from **Amcache**.

![165dc06383d777d8a6380c1fa4f766cd.png](..//resources/165dc06383d777d8a6380c1fa4f766cd.png)

Now lets parse Amcache which stores SHA1 of executed binary with `amcacheparser.exe`.

![5c84d40584fa43435518c022136e2bed.png](..//resources/5c84d40584fa43435518c022136e2bed.png)

We will get the hash of this binary right here which is also the answer of Task 6

![04540701ddccb9f852645d62a145f9cc.png](..//resources/04540701ddccb9f852645d62a145f9cc.png)

Search this hash on VirusTotal, we can see that this binary is actually [CredentialsFileView](https://www.nirsoft.net/utils/credentials_file_view.html) from NirSoft that can be used to displays the passwords and other data stored inside Credentials files of Windows.

```
CredentialsFileView
```

>Task 6: What is the SHA1 hash of the file in Question #5?
```
5463f4140efd005a7bafa6fa0fa759bcfcf7da4a
```

>Task 7: At what time (UTC) did the threat actor rename the program in Question #5?

![941dbfe9ddb3ed2b1ddb2724feddb322.png](..//resources/941dbfe9ddb3ed2b1ddb2724feddb322.png)

When talking about renaming file, the artifact that would come to mind is UsnJournal (`$J`) then we will use `MFTECmd.exe` to parse it.

![25780315043e4d27efcde730dddb90b4.png](..//resources/25780315043e4d27efcde730dddb90b4.png)

Filter for "CredentialFileView" which we can see that it was renamed at this time after it was created on this system.

```
2024-10-24 06:35:24
```

>Task 8: What is the name of the compromised account used by the threat actor to connect to the database server?

![bfe1db07eab62b06df08895752bf9ff5.png](..//resources/bfe1db07eab62b06df08895752bf9ff5.png)

Its time to analyze artifacts collected by CatScale.

![c49ef5b6f9f9ef75ca33657f274919d2.png](..//resources/c49ef5b6f9f9ef75ca33657f274919d2.png)

We can go to "Logs" directory to read the output of `lastlog` command which show user that was connected to the database server and the source IP address (Answer of Task 9), we can alse see the login timestamp which also matched the timeframe of this incident so we can confirm that "sdb-aroy" is the compromised user of this database server.

```
sdb-aroy
```

>Task 9: What is the source IP address used by the threat actor to connect to the database server?
```
10.10.2.55
```

>Task 10: What database command did the threat actor initially enter that resulted in an error?

![34d152ea246847161ec7e344fc205f4c.png](..//resources/34d152ea246847161ec7e344fc205f4c.png)

Next, I extracted var-log tar gz file so we can analyze logs from database server.

![b598811bb883f4a14894d85b64a44935.png](..//resources/b598811bb883f4a14894d85b64a44935.png)

The database presents on this server is PostgreSQL which we will have to analyze `postgresql-12-main.log` right here.

![e434c35eb50f7e9efc0b52dc65368471.png](..//resources/e434c35eb50f7e9efc0b52dc65368471.png)

Then we can see that after threat actor logged in into this server, the threat actor used 2 wildcard queries to retrieve data from database but due to low privilege on this account which result in error for permission denied.

```
SELECT * FROM accounts;
```

>Task 11: What is the full command used by the threat actor to gain elevated access?

![e6b12ad9b295e6edd56a41545534d2b8.png](..//resources/e6b12ad9b295e6edd56a41545534d2b8.png)

Its time to take a look at `.psql_history` of compromised account.

![70d22290a8c0492b6a6c23bc3595b4b7.png](..//resources/70d22290a8c0492b6a6c23bc3595b4b7.png)

We can see that the threat actor use this query to make "sdb-aroy" user a SUPERUSER which will make the threat actor be able to query data which result in error from previous task.

```
COPY (SELECT '') TO PROGRAM 'psql -U postgres -c ''ALTER USER "sdb-aroy" WITH SUPERUSER;''';
```

>Task 12: What tool was used by the threat actor to export the database?

![5737f0da41c0c3976e2d4ede67f94728.png](..//resources/5737f0da41c0c3976e2d4ede67f94728.png)

Then after made "sdb-aroy" a SUPERUSER, the threat actor create another user as SUPERUSER then dump database using `ps_dump` then uploaded it to S3 bucket (Task13)

```
pg_dump
```

>Task 13: What is the complete target URL used by the threat actor for exfiltration?

![3cbc84f584af532eac8f6558e352c066.png](..//resources/3cbc84f584af532eac8f6558e352c066.png)

We can also see this command from `.bash_history` and then after exfiltrated sql dump file, the threat actor removed dumped sql file then edited `.bashrc` file so we will have to take a look at this file on next task.

```
https://festival-of-files.s3.amazonaws.com/atm.sql
```

>Task 14: What public IP addresses were used by the threat actor for persistence? Sort smallest initial octet to largest.

![0dc7e25eb3b4a00d4e11c0859f603a15.png](..//resources/0dc7e25eb3b4a00d4e11c0859f603a15.png)

After taking a look at `.bash_rc` file, we can see that the threat actor edited this file for persistence that will establish reverse shell connection to this IP address with netcat every time this user login.

![28cd6dcc8e5b4f83941baf26d8b808f2.png](..//resources/28cd6dcc8e5b4f83941baf26d8b808f2.png)

We found persistence on Database server then lets go back to Windows which we can see that schedule task was executed.

![561af15e773a538e505d7fe6d2381e10.png](..//resources/561af15e773a538e505d7fe6d2381e10.png)

Then After navigated to Tasks folder, I noticed this task is very suspicious so it might be the persistence task created by threat actor.

![bd75364fcbafb5de31f018e3404616c3.png](..//resources/bd75364fcbafb5de31f018e3404616c3.png)

Sure enough! it is another netcat command for persistence.

```
3.224.124.130, 34.234.202.16
```

>Task 15: At what time (UTC) did the victim's Windows machine connect to the Domain Controller?

![4f71876bb16a50bdacde7761690a7c5c.png](..//resources/4f71876bb16a50bdacde7761690a7c5c.png)

I made an hypothesis that the threat actor might use RDP for remote connecting to Domain Controller then we could use this Windows event log that logged RDP client activities that connect to other remote client.

![a5758a1aa4fdffb1e6a3887b1ee4fa13.png](..//resources/a5758a1aa4fdffb1e6a3887b1ee4fa13.png)

Parse it with `EvtxECmd.exe` then we can see that the connection was established around 07:07:45 then disconnecting around 07:34:40 which we can use these timestamp to calculate duration of this session for the next task.

```
2024-10-24 07:07:45
```

>Task 16: After accessing the Domain Controller, how long did the threat actor’s session last (in seconds)?

![e8c0df65c54a651027579de374f8f966.png](..//resources/e8c0df65c54a651027579de374f8f966.png)

We can grab both timestamp and let AI do the work, then we will have duration of this sessions in seconds like this

```
1615
```

![5dc3da0bd3b0b65ffbd17e87f862694d.png](..//resources/5dc3da0bd3b0b65ffbd17e87f862694d.png)
https://labs.hackthebox.com/achievement/sherlock/1438364/793
* * *
