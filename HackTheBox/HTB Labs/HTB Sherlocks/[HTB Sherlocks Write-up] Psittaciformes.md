# [HackTheBox Sherlocks - Psittaciformes](https://app.hackthebox.com/sherlocks/Psittaciformes)
![8647ce797f41cda9d29b9e2d682e7b23.png](/resources/8647ce797f41cda9d29b9e2d682e7b23.png)
**Scenario:**
Forela carry out penetration testing of their internal networks utilising an internal team within their security department. The security team have notes from tests in addition to company critical credentials. It seems their host may have been compromised. Please verify how this occurred using the retrospective collection provided.

* * *
>Task 1: What is the name of the repository utilized by the Pen Tester within Forela that resulted in the compromise of his host?

![1e7c28c93c38e65545db8b54c10a314f.png](/resources/1e7c28c93c38e65545db8b54c10a314f.png)

We got artifact collected with catscale as our evidence on this sherlock and that mean we are investigating Linux artfiacts.

![ec4b4e7942a0d3d06909c9d4098a9640.png](/resources/ec4b4e7942a0d3d06909c9d4098a9640.png)

When talking about Linux artficats for UEBA, bash history is the most valuable artifacts so I checked `User_Files/hidden-user-home-dir-list.txt` which contains list of user hidden files that were collected with catscale and then we can see that it collected bash history of "johnspire" and "root" user so we will dig into the bash history of "johnspire" first before digging into "root" (if the user using sudo to change user to root then we should do that)

![a1a1bbe2b71d7f5eda611acd787184f8.png](/resources/a1a1bbe2b71d7f5eda611acd787184f8.png)

We can extract the collected files with `tar -xvf hidden-user-home-dir.tar.gz`, and now we are ready for the investigation.

![a19d346cb6560cff0233d08be77e2491.png](/resources/a19d346cb6560cff0233d08be77e2491.png)

The bash history reveals the activity of this user, starting with starting the SSH service, running `nmap` on 10.129.228.158, and then using `nikto` before launching the Metasploit console via `msfconsole`. Afterwards, the user changed the password for “johnspire” and cloned the “autoenum” repository from GitHub. After successfully cloning the repository, the user executed `bash.sh` with 10.0.0.10 as an argument, followed by `sudo`, suggesting that the script might require root privileges to run. Therefore, we want to dig into this repository first before doing anything else.

![e415b28f0c2cfaa3ba1150b13bea1857.png](/resources/e415b28f0c2cfaa3ba1150b13bea1857.png)
![34cf7690f77168bc2d20ef7f21687333.png](/resources/34cf7690f77168bc2d20ef7f21687333.png)

After taking a look at the script from the [GitHub repository](https://github.com/pttemplates/autoenum/blob/main/enum.sh), we can see that the `do_wget_and_run` function performs actions that an enumeration script is not supposed to do — it downloads a ZIP file hosted on Dropbox, extracts it with a hard-coded password into the `/tmp` directory, executes it, and sets a cron job for persistence so that the file runs at every reboot. So this “autoenum” repository is the root cause of the compromise.

```
autoenum
```

>Task 2: What is the name of the malicious function within the script ran by the Pen Tester?
```
do_wget_and_run
```

>Task 3: What is the password of the zip file downloaded within the malicious function?

![4d2b5253e35c507132d15e40932ac681.png](/resources/4d2b5253e35c507132d15e40932ac681.png)

The password is hard-coded in the script, split into `part1` and `part2` variables, but in the end, they’re concatenated and decoded with `base64 -d`. We can do the same to get the password for this ZIP file right here.

```
superhacker
```

>Task 4: What is the full URL of the file downloaded by the attacker?

![47e3339dd93108d139bb3e8f031a8670.png](/resources/47e3339dd93108d139bb3e8f031a8670.png)

The full URL used to download the ZIP file is also separated into two variables, `f1` and `f2`, so we can simply do what the script does and combine them to get the full URL like this.

```
https://www.dropbox.com/scl/fi/uw8oxug0jydibnorjvyl2/blob.zip?rlkey=zmbys0idnbab9qnl45xhqn257&st=v22geon6&dl=1
```

>Task 5: When did the attacker finally take out the real comments for the malicious function?

![dcdb1f7f1fb9f6fbb0ae7f52715c8a44.png](/resources/dcdb1f7f1fb9f6fbb0ae7f52715c8a44.png)

From the question, it’s suggested that this script was not malicious at first, so we need to look into the Git history. For that, I will first clone the repository.

![957c31927205ad713b102bdab1427c38.png](/resources/957c31927205ad713b102bdab1427c38.png)

Then I used `git log` to see git commit history and we can see that there are quite a lot to look into but we still gonna have to look into each of them by using `git show` follow by commit ID

![f12749ca595fd3f43ebd729561059e84.png](/resources/f12749ca595fd3f43ebd729561059e84.png)

Then we will eventually look into commit 7d203152c5a3a56af3d57eb1faca67a3ec54135f that was committed at 2024-12-23 22:27:58 has introduced the final part of this malicious function by removing various comments from the `do_wget_and_run` function.

```
2024-12-23 22:27:58
```

>Task 6: The attacker changed the URL to download the file, what was it before the change?

![fb5a6ba23a57535515f2e5516efb603b.png](/resources/fb5a6ba23a57535515f2e5516efb603b.png)

On the commit 5d88bee8918d514a206fec91be72899544cdd37b, we can see the URL was changed on this commit.

```
https://www.dropbox.com/scl/fi/wu0lhwixtk2ap4nnbvv4a/blob.zip?rlkey=gmt8m9e7bd02obueh9q3voi5q&st=em7ud3pb&dl=1
```

>Task 7: What is the MITRE technique ID utilized by the attacker to persist?

![ee36cae2c5a196dea5677a75da9ff09c.png](/resources/ee36cae2c5a196dea5677a75da9ff09c.png)

As we can see, after the blob `file` is extracted from the ZIP to `/tmp` and executed, a cron job is also created to run it at every reboot. The MITRE technique that aligns with this is obviously [T1053.003 : Scheduled Task/Job: Cron](https://attack.mitre.org/techniques/T1053/003/). But the main problem with this malware is that it’s located in the /tmp directory, which gets cleared every reboot, so the cron job might not work as intended.

```
T1053.003
```

>Task 8: What is the name of the technique relevant to the binary the attacker runs?

![62985af66f754ed004e64d14a0adeadc.png](/resources/62985af66f754ed004e64d14a0adeadc.png)

Knowing the full path of this file, I ran `grep -r "/tmp/blob" ./*` to check for its existence in the CatScale collected artifacts. I found two records in the full timeline file indicating the creation timestamp of this file as well as its owner. From the bash history, we saw the user executed the script with sudo privileges, so the malware was extracted and run as root. I also obtained the hash of this file because, being a binary with execution permissions, CatScale logged its hash inside `Misc/hostname-YYYYMMDD-HHMM-exec-perm-files.txt`.

![89cb2fe61038690e02105ca42c3fc970.png](/resources/89cb2fe61038690e02105ca42c3fc970.png)

Using file hash to seach on [VirusTotal](https://www.virustotal.com/gui/file/b0e1ae6d73d656b203514f498b59cbcf29f067edf6fbd3803a3de7d21960848d/detection) which reveal that this file is a cryptominer which have to hijack resouce to mine cryptocurrency and that align with [T1496 : Resource Hijacking](https://attack.mitre.org/techniques/T1496/) technique from MITRE ATT&CK. and now we are done with this sherlock!

```
T1496
```

![15e854f7fc49aaf6627b8d4b2b626c87.png](/resources/15e854f7fc49aaf6627b8d4b2b626c87.png)
https://labs.hackthebox.com/achievement/sherlock/1438364/764
* * *