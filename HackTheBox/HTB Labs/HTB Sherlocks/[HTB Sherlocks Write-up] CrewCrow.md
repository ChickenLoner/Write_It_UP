# [HackTheBox Sherlocks - CrewCrow](https://app.hackthebox.com/sherlocks/CrewCrow)
![6ebe37a68e57300c75d581cbcaf6a1c3.png](/resources/6ebe37a68e57300c75d581cbcaf6a1c3.png)
## Scenario
The Cyber Crime Investigation Unit (CCIU) has been tracking a famous cybercriminal organization known as "CrewCrow" for several years. The group is responsible for numerous high-profile cyber-attacks, targeting financial institutions, government agencies, and private corporations worldwide. The elusive leader of CrewCrow, known by the alias "Nefarious," is a master hacker, who has managed to evade the authorities for years. In a major breakthrough, CCIU intercepted communications indicating that Nefarious was planning a significant cyber-attack. Acting swiftly, the unit launched a coordinated operation, to arrest CrewCrow members and seize their equipment. During the raid, agents confiscated several devices, including Nefarious's personal computer.As the top digital forensics analyst in the country, you have been tasked with analyzing the disk image of Nefarious's computer. Your objective is to uncover critical information that could provide insights into CrewCrow's operations, reveal the details of their planned attack, and ultimately bring Nefarious to justice.

* * *

![065c0d9488da54c3863540053a192229.png](/resources/065c0d9488da54c3863540053a192229.png)

Lets see all the evidences we have first and from the 2 csv files at the most surface level, we can assume that the creator of this sherlock collected evidence via KAPE.

![a5edfb59925af4473eecbc68f0d5f2aa.png](/resources/a5edfb59925af4473eecbc68f0d5f2aa.png)

By using `tree` command, we can see that we have 1 user beside default and public user which is "Nefarious" and from the scenario, we gonna conduct some user behaviour analysis (UEBA) of this so-called crimical.

One thing I noticed from this command is "Operations" folder on the documents folder of "Neferious" user so we might have to take a look at it during the investigation.

>Task 1: Identify the conferencing application used by CrewCrow members for their communications.

![498757d9c8f193d4940c9c2e982c09be.png](/resources/498757d9c8f193d4940c9c2e982c09be.png)

To get the list of program executed by this user, I used Registry Explorer to parse `NTUSER.dat` file and then go to UserAssist key which I discovered Zoom Installation binary was executed at 2024-07-16 05:31:16 and then the actual Zoom Video Conference program was used at 2024-07-16 09:01:39 for 9 minutes and 56 seconds so this is how this user communicate with other members.

![f40bfd3735efa0ae9b5ed9192d8c96f1.png](/resources/f40bfd3735efa0ae9b5ed9192d8c96f1.png)

There is a text file on the desktop as well which telling us that this group used Zoom for their main way of communication

```
Zoom
```

>Task 2: Determine the last time Nefarious used the conferencing application.

![39ff6074d3fa944df85abef9aed70228.png](/resources/39ff6074d3fa944df85abef9aed70228.png)

I tried to submit the last executed timestamp from UserAssist key but it was not correct so I used PECmd from EZTools to parse prefetch folders, maybe we will find something different there. (`.\PECmd.exe -d C:\Users\chicken\Desktop\Samples\HackTheBox\CrewCrow\C\Windows\prefetch --csv output`)

![1cb0e5ba84e6168580b591793d0d79ee.png](/resources/1cb0e5ba84e6168580b591793d0d79ee.png)

Then we can open the timeline output of PEmd result and filter for zoom binary then we can see that there are paired of `zoom.exe` was executed in short period of time which make the latter one is the correct answer of this question.

```
2024-07-16 09:02:02
```

>Task 3: Where is the conferencing application's data stored?

![c395312ef0ce8cd944a232a596bff477.png](/resources/c395312ef0ce8cd944a232a596bff477.png)

To understand how Zoom meeting store application and how to decrypt zoom database file, I recommeneded reading the [this blog](https://infosecwriteups.com/decrypting-zoom-team-chat-forensic-analysis-of-encrypted-chat-databases-394d5c471e60) post but to put it simply, Zoom storing file on `C:\Users\%USERNAME%\AppData\Roaming\Zoom\data` including encrypted database which we will need to decrypt it to beat this sherlock.

![61ec8991a17f406ea0f0a9db3f48406b.png](/resources/61ec8991a17f406ea0f0a9db3f48406b.png)

We can now confirm that this folder were copied during evidence acquisition so we can proceed to review the existing of them by taking a look.

![cffb56a118a00953e1853f066f42bad3.png](/resources/cffb56a118a00953e1853f066f42bad3.png)

Now after confirmed all files needed for investigations are here then we can answer and continue with the next question.

```
C:\Users\Nefarious\AppData\Roaming\Zoom\data
```

>Task 4: Which Windows data protection service is used to secure the conferencing application's database files?

![02bd01df86ff0aab80b8c06380d6019e.png](/resources/02bd01df86ff0aab80b8c06380d6019e.png)

According to this blog post, the zoom database files are protected with Windows Data Protection API (DPAPI) with key derivation function page size of 1024 and key derivation function (KDF) iteration of 4000 and this will come in handy when we actually get a key and open database file.

```
DPAPI
```

>Task 5: Determine the sign-in option used by Nefarious.

![40f2a4c2d2f987abd69140344cc5f376.png](/resources/40f2a4c2d2f987abd69140344cc5f376.png)

There are so many options to sign in to Zoom including SSO, Apple, Google, Facebook and Microsoft and Password.

![47fde24164fbe184bc35e505c0d6d2e3.png](/resources/47fde24164fbe184bc35e505c0d6d2e3.png)

We can answer this after obtained a key to unlock zoom database file which we can see that there is no information regarding of other platform so this user might sign in via Password.

```
Password
```

>Task 6: Retrieve the password used by Nefarious

![eb8056ed1ba9078aa4c423ce0a5d4249.png](/resources/eb8056ed1ba9078aa4c423ce0a5d4249.png)

Now lets finally get password of "Nefarious" user which is required for decryption zoom database and the first thing we could do beside dumping NTLM hash from registry hives is the DPAPI master key which we have it located at `C\Users\Nefarious\AppData\Roaming\Microsoft\Protect`



![f311fb82ea877f867f8872fff4613e65.png](/resources/f311fb82ea877f867f8872fff4613e65.png)

And inside a folder named after user's SID is a master key file `28bbab34-d06e-4372-a633-d924fbab301b`

Now we have both requirement for [DPAPImk2john](https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py) which should installed by default after installing John-The-Ripper.

First requirement is Nefarious user's SID and that is "S-1-5-21-3675116117-3467334887-929386110-1001", second requirement is master key file

![83a9ae6e4b42d47f1e03a86debb9f267.png](/resources/83a9ae6e4b42d47f1e03a86debb9f267.png)

Now we can proceed with `DPAPImk2john --sid="S-1-5-21-3675116117-3467334887-929386110-1001" --masterkey="28bbab34-d06e-4372-a633-d924fbab301b" --context="local" > hash.txt` command to generate hash to crack with John-The-Ripper but since DPAPImk2john is a python script then we need to install pycryptodome first.

![d2258c31571f0fabf0ff4b23c028de1d.png](/resources/d2258c31571f0fabf0ff4b23c028de1d.png)

Then after installed pycryptodome in python virtual environment, we should be able to get hash from master key like this so its time to crack!

![95af550d17b87f203c22b4bfc746439e.png](/resources/95af550d17b87f203c22b4bfc746439e.png)

To speed up the process, I count the asterisk on the answer format which is 15 character length which I filtered only password with this length from rockyou wordlist with the following command -`grep -E '^.{15}$' /usr/share/wordlists/rockyou.txt > rock15you.txt` then we will have total of 161029 which will save us sooooooo much time to bruteforce it.

![fce781240ff34d52edc924b2026e1a79.png](/resources/fce781240ff34d52edc924b2026e1a79.png)

Now after bruteforcing with new wordlist (`john --wordlist=/tmp/rock15you.txt hash.txt`), we will have `ohsonefarious92` as the password of "Nefarous" user.

```
ohsonefarious92
```

>Task 7: Find the key derivation function iterations used in the encryption process of the conferencing application's database.

![02bd01df86ff0aab80b8c06380d6019e.png](/resources/02bd01df86ff0aab80b8c06380d6019e.png)

As we already know that , the zoom database files are protected with Windows Data Protection API (DPAPI) with key derivation function page size of 1024 and key derivation function (KDF) iteration of 4000, and since we already get plaintext password of user then we should be able to decrypt master key and `win_osencrypt_key`.

```
4000
```

>Task 8: Find the key derivation function page size used in the encryption process.
```
1024
```

>Task 9: Identify Nefarious email address.

![fcbe1da18a6081dd604aa62f08a87413.png](/resources/fcbe1da18a6081dd604aa62f08a87413.png)

Now we can use `mimikatz` to get decrypted master key file with the following command `dpapi::masterkey /in:28bbab34-d06e-4372-a633-d924fbab301b /sid:S-1-5-21-3675116117-3467334887-929386110-1001 /password:ohsonefarious92 /protected`

![2e84e5509aea747e1120db7ff15af19d.png](/resources/2e84e5509aea747e1120db7ff15af19d.png)

Now we can use the master key value we got to decrypt `win_osencrypt_key` from `Zoom.us.ini`, Lets get the encrypted key from  file and remove ZWOSKEY prefix.

```
AQAAANCMnd8BFdERjHoAwE/Cl+sBAAAANKu7KG7QckOmM9kk+6swGwAAAAACAAAAAAAQZgAAAAEAACAAAADJx9AI6i9CEvRYhIK10gayvm5YyrBN9LxAjHylMKgQ0QAAAAAOgAAAAAIAACAAAAC2EfbilZ5wE8mRW0xeUP0IcyQCufOYKa7MbOFXLSdvBzAAAAB94pzf6DE7fRhpJ2tbIsw3ZtYaDKlb3ncvT16Jlwj44rMGIbIYWZtMBVbRV1U8PwNAAAAARwtW+e31mKSZeh4igd735aC1hB4J/8Ye93i0IhDeXBMFbAMWWBwLz77OuZa8spLkcKfYpGQF63fXVvJkxjmnpA==
```

![5817201b0da9d425cc68cddcbdbc9571.png](/resources/5817201b0da9d425cc68cddcbdbc9571.png)

Mimikatz only accept raw DPAPI blob so we can either use cyberchef to decode base64 and save to a file or using the following PowerShell command to save raw content to a file.

Decode base64 DPAPI blob to raw file
1. `$base64String = Get-Content -Path "keyblob.txt" -Raw`
2. `$bytes = [System.Convert]::FromBase64String($base64String)`
3. `Set-Content -Path "keyblob_decoded.bin" -Value $bytes -Encoding Byte`

![ea8a38277d2a15ee0bda2bdb1038a3c0.png](/resources/ea8a38277d2a15ee0bda2bdb1038a3c0.png)

Now we can use mimikatz to decrypt main key with master key with the following command `dpapi::blob /masterkey:b759020c3e3a1c15a2d1863d50ee4b27cbf13552cd51f286e68a3c52f70a52086ce301e9cabbbeed8442c4279f679c94cd9e605e5a79f00b4922c80af7a26382 /in:"keyblob_decoded.bin" /out:key.txt` which reveals `W2k+02GzBVeZKJhXsnRIqNrtrWVUBAvs0gLNe52zXKw=` as the `main_key`

![7abc6c42a742cfbeaf22bdc6a39a80c7.png](/resources/7abc6c42a742cfbeaf22bdc6a39a80c7.png)

Now we can use DB Browser for SQLCipher to open `zoomus.enc.db` file with the following obtain
- Password : `W2k+02GzBVeZKJhXsnRIqNrtrWVUBAvs0gLNe52zXKw=`
- Page Size : 1024
- KDF Iterations : 4000

![0639fc13a25b3ae0cd24287a8adaea21.png](/resources/0639fc13a25b3ae0cd24287a8adaea21.png)

After successfully opened encrypted database, we can proceed to look at `zoom_user_account_enc` table to get an information about logged in user including email address right here.

```
nefarious92@outlook.com
```

>Task 10: What is the Meeting ID?

![41238d2544e47491b512527b2b4b7bb1.png](/resources/41238d2544e47491b512527b2b4b7bb1.png)

For this question, I used the following [write-up](https://cellebrite.com/en/part-1-ctf-2022-write-up-marshas-pc/) to understand how to get saved meeting ID, the relavant part of this write-up about Zoom is Question 11.

![7768b8056414954ff6889d9a795001a1.png](/resources/7768b8056414954ff6889d9a795001a1.png)

Zoom saved meeting ID within the database file as well in the `zoom_kv` table and if we filtered for a keyword like "saved" or "meetingid" then we should be able to see the encrypted data of last meeting that included meeting ID as well.

This data was encrypted using AES CBC mode with SHA256 of user's SID as a key and IV is derived from SHA256 of the key.

So now we have 
- Encrypted data : `RNpZaXfokRphhecoO6sHn9U02wtiPGaxi8UuhoAMGM2MEe175kZQQ2d7/Bk6WjUc4bz5EFCFpvrwYy/KTd56mA==`
- Key : SHA256 of "S-1-5-21-3675116117-3467334887-929386110-1001" -> `7a032d50cd9ec8df491713057b4273234da2689b309106d2362093ae9f4bec21`

So we need an IV but I tried to manually get IV myself with CyberChef but it does not a valid IV, but luckily for us that the write-up also included a simply python script to generate both key and IV for us as well so we only need to change SID and then execute it to get both key and IV.

```python
import Crypto.Hash.SHA256
import hashlib

sid = b"S-1-5-21-3675116117-3467334887-929386110-1001"
key = hashlib.sha256(sid).digest()
iv = hashlib.sha256(key).digest()[:0x10]

print(" ".join(format(n, 'x') for n in key))

print(" ".join(format(n, 'x') for n in iv))
```

![1e0a34d3127519bcd6a99e8c7a4d1ce0.png](/resources/1e0a34d3127519bcd6a99e8c7a4d1ce0.png)

Now we have an IV (`f7 50 fe 8b 35 1b fe 78 60 a2 af 16 73 c6 9e 8`).

![99e773cee15828a5bc5229c4d215ee63.png](/resources/99e773cee15828a5bc5229c4d215ee63.png)

We can simply use CyberChef to decrypt the data and now we will have Meeting ID of the last zoom meeting right here.

```
86233834426
```

>Task 11: Retrieve the password used to encrypt the plan PDF file from the meeting chat.

![7510b700f9c5795c8392d0fccd8da8d5.png](/resources/7510b700f9c5795c8392d0fccd8da8d5.png)

To be able to read the meeting chat, we need to use open `zoommeeting.enc.db` file with all the same options from main database file and then go to `zoon_conf_chat_gen2_enc` table, now we can see that there are 2 people on this zoom meeting talking to each other and even sent file with password via Zoom chat as well.

```
EOztYmVeUxp6TmV
```

>Task 12: Discover the location from which the upcoming cyber-attack will be launched.

![ac721a1e76536d7e5879748e6c0508ad.png](/resources/ac721a1e76536d7e5879748e6c0508ad.png)

Located on the desktop, there are 2 folders inside "Operations" folder and the one we are looking for is in "Pending" folder.

![26ce3bc6cb4ab031cb22b4a5262c66f7.png](/resources/26ce3bc6cb4ab031cb22b4a5262c66f7.png)

There is a pdf file that was sent via Zoom right here.

![1aac4715cfe4afcfd0f31e5628dd0738.png](/resources/1aac4715cfe4afcfd0f31e5628dd0738.png)

Open pdf file and put password we got from zoom meeting chat.

![464b54876d364ff6cde72df51cf45b34.png](/resources/464b54876d364ff6cde72df51cf45b34.png)

Then we can finally get the location of upcoming attack that is in white right there.

```
Eastern Europe
```

https://labs.hackthebox.com/achievement/sherlock/1438364/900
* * *
