# [CyberDefenders - Jailbroken](https://cyberdefenders.org/blueteam-ctf-challenges/jailbroken/)
## Table of Contents

- [Scenario](#scenario)
- [Questions](#questions)

* * *
## Scenario
Jailbroken is an iPad case investigation that exposes different aspects of IOS systems where you can evaluate your DFIR skills against an OS you usually encounter in today's case investigations as a security blue team member.

**Category**: Endpoint Forensics

**Tools**:
- [iLEAPP](https://github.com/abrignoni/iLEAPP)
- [Autopsy](https://www.sleuthkit.org/autopsy/)
- [mac_apt](https://github.com/ydkhatri/mac_apt)
- [SqliteDB Browser](https://sqlitebrowser.org/)
* * *
## Questions
> Q1: What is the IOS version of this device?

![9254ee28bb7cc9087e5f694f9ceb754c.png](/resources/9254ee28bb7cc9087e5f694f9ceb754c.png)

To make our life easier, we will have to use [iLEAPP](https://github.com/abrignoni/iLEAPP)(iOS Logs, Events, And Plists Parser) to grab some keys information for us

![f9968c4f1ee3de9d405dc713206e0d80.png](/resources/f9968c4f1ee3de9d405dc713206e0d80.png)

Which including Device details of this device  

```
9.3.5
```

> Q2: Who is using the iPad? Include their first and last name. (Two words)

![0ff16009ef9009212c89bc27142e38b8.png](/resources/0ff16009ef9009212c89bc27142e38b8.png)

On "Account Data", we can see the username that was used on this device which indicates user's first and last name 

![21d1c22a0598cced838a6d7279c05c2e.png](/resources/21d1c22a0598cced838a6d7279c05c2e.png)

Then we can confirm this by open "Calendar List"

```
Tim Apple
```

> Q3: When was the last time this device was 100% charged? Format: 01/01/2000 01:01:01 PM

![d04ce6be9c222383f97575971fd66480.png](/resources/d04ce6be9c222383f97575971fd66480.png)

There are sevaral iOS forensics cheetsheet online that might be helpful for this investigation and from this [Medium blog](https://medium.com/@mpotisambo8/ios-forensics-cheat-sheet-a121c74ef42d) we can see that we can get an information about Battery Level from `CurrentPowerLog.PLSQL`

![175ff9a433f0f5d1c9d4ab9e2a8877d5.png](/resources/175ff9a433f0f5d1c9d4ab9e2a8877d5.png)

Which could be located in `\Jailbroken\private\var\containers\Shared\SystemGroup\4212B332-3DD8-449B-81B8-DBB62BCD3423\Library\BatteryLife`

![8589103ac3ba2750908b7659c134ebb0.png](/resources/8589103ac3ba2750908b7659c134ebb0.png)

After open this file with DB Browser for SQLite, go to `PLBatteryAgent_EventBackward_Battery` table then go to the last row which we will see that this is the last time this device was 100% charged but we will have to convert UNIX timestamp to UTC first

![1178348b485c78110dd5cd2d5a3d7fa4.png](/resources/1178348b485c78110dd5cd2d5a3d7fa4.png)

We can easily do this by using https://www.epochconverter.com/

```
04/15/2020 06:40:31 PM
```

> Q4: What is the title of the webpage that was viewed the most? (Three words)

![2aa0087bdd3d508a9e12a49e41dd05ab.png](/resources/2aa0087bdd3d508a9e12a49e41dd05ab.png)

From the same cheatsheet, we will have to find one of these files to determine which webpage was visited the most

![d22746f6be772a6102b9d56a9e5bc904.png](/resources/d22746f6be772a6102b9d56a9e5bc904.png)

First, lets find history file with `Get-ChildItem -Path "Z:\CD_35-jailbroken\Jailbroken\private\var\mobile\Containers\Data\Application" -Recurse -Filter "History.db" -ErrorAction SilentlyContinue` then we can see that it was located in `\Jailbroken\private\var\mobile\Containers\Data\Application\FB1B2A1C-AC19-406F-BEEC-EC048BF504EA\Library\Safari` 

![d269c26ebf47a0e35b04b1e64fcca3b4.png](/resources/d269c26ebf47a0e35b04b1e64fcca3b4.png)

Using DB Browser of SQLite to open this file and open `history_visits` table which we will see that this google search was visited the most

```
kirby with legs
```

> Q5: What is the title of the first podcast that was downloaded?

![37d6f0ace9b04d31064142644a046ae4.png](/resources/37d6f0ace9b04d31064142644a046ae4.png)

After some googling with "iOS podcast forensics", It landed me with https://salt4n6.com/tag/podcasts/ and now we know which file we are after 

![428c1a186dca1bdb58a0b6e3ce2761a3.png](/resources/428c1a186dca1bdb58a0b6e3ce2761a3.png)

So lets use `Get-ChildItem -Path "Z:\CD_35-jailbroken\Jailbroken\private\var\" -Recurse -Filter "MTLibrary.sqlite" -ErrorAction SilentlyContinue` to find where this file is located and it returns with `\Jailbroken\private\var\mobile\Containers\Shared\AppGroup\80179E24-1812-4B5F-8063-AECFC3773A7A\Documents`

![7944a19d22ed1ab700662e593cb2b6b1.png](/resources/7944a19d22ed1ab700662e593cb2b6b1.png)

Using DB Browser for SQLite, and go to `ZMTEPISODE` table and then we will see there is a column for download time which is `ZDOWNLOADDATE` so we can sort it to see how many podcasts were downloaded and when

We will eventually see that only 2 podcasts were downloaded and here is the timestamp of the first podcast that was downloaded

![1d4f5b35b5d1ec08cd1b333f63228aac.png](/resources/1d4f5b35b5d1ec08cd1b333f63228aac.png)

Scroll right for the title of this podcast to obtain an answer

```
WHERE ARE WE?
```

> Q6: What is the name of the WiFi network this device connected to? (Two words)

![a8d81a04cd854c78f2d4cb9e03a45776.png](/resources/a8d81a04cd854c78f2d4cb9e03a45776.png)

Back to iLEAPP report, go to "WIFI Connections" and here we can choose either of these reports to obtain this answer 

```
black lab
```

> Q7: What is the name of the skin/color scheme used for the game emulator? This should be a filename.

![5fa4e3555cb440d65784c02912adf5cc.png](/resources/5fa4e3555cb440d65784c02912adf5cc.png)

From history file, we can see that user searched for iOs jailbreak through and then download gameboy emulator and 2 games after that and here we can see which game emulator that was downloaded

![c33d0fecfac440aadf3a57694c7db787.png](/resources/c33d0fecfac440aadf3a57694c7db787.png)

Go to Application State DB report on iLEAPP to find installed location for this app

![1b4f395577a1647b4e433315d51b32c9.png](/resources/1b4f395577a1647b4e433315d51b32c9.png)

We will have to dig a little bit of GBA4iOS skin and from this [tutorials](http://www.gba4iosapp.com/tutorials/), we can see that it has to be either `.gbaskin` or `.gbcskin`

![0d0e6f4afec1e62ebf35b7087a8bbd94.png](/resources/0d0e6f4afec1e62ebf35b7087a8bbd94.png)

We got both here but the answer of this question is the one with `.gbaskin` extension

```
Default.gbaskin
```

> Q8: How long did the News App run in the background?

![7d200881a884559480e1a4bebd3db0e3.png](/resources/7d200881a884559480e1a4bebd3db0e3.png)

We will have to go back to `CurrentPowerlog.PLSQL` file and then go to `PLAppTimeService_Aggregate_AppRunTime` which stores information about runtime of each applications including news

```
197.810275
```

> Q9: What was the first app download from AppStore? (Two words)

![8497f084a552a624c9151e20a862d0d7.png](/resources/8497f084a552a624c9151e20a862d0d7.png)

Go back to "Apps - itunes Metadata" report from iLEAPP then we can see that there are 2 apps that were downloaded from AppStore, first is Cookie Run and second is Pokemon Quest

```
Cookie Run
```

> Q10: What app was used to jailbreak this device? 

![d601c625e8dc74bf4f79841672c933f9.png](/resources/d601c625e8dc74bf4f79841672c933f9.png)

We will have to find jailbreak app for this iOS version and lucky for us that this [website](https://idevicecentral.com/jailbreak-tools/ios-jailbreak-tools/) already collects most of jailbreaking apps for each iOS version

![25cbf383715ed8ffbf383621c2918cc6.png](/resources/25cbf383715ed8ffbf383621c2918cc6.png)

We have 3 candidates but as soon as I decompressed zip file to investigated, BitDefender already spolling me which one of them was installed on this device

![9432965059ca26a3393247242f5293ca.png](/resources/9432965059ca26a3393247242f5293ca.png)

To solve this as it was intented, we will have to find it in "Application State DB" report in iLEAPP 

```
Phoenix
```

> Q11: How many applications were installed from the app store?

![acd47ddcc3cc2935ca0aaaf90b88273e.png](/resources/acd47ddcc3cc2935ca0aaaf90b88273e.png)
```
2
```

> Q12: How many save states were made for the emulator game that was most recently obtained?

![423d32eb06e694781062be3853f0c2f6.png](/resources/423d32eb06e694781062be3853f0c2f6.png)

We already know that there are 2 games that were downloaded and installed on this device

![198248127cfdd95cc64f4d801153e7d3.png](/resources/198248127cfdd95cc64f4d801153e7d3.png)

We will have to use `Get-ChildItem -Path "Z:\CD_35-jailbroken\Jailbroken\private\var\" -Recurse -Filter "*.gba" -ErrorAction SilentlyContinue` to find where the location of them (`.gba` is a Game Boy Advance ROM file. It's an exact copy of a GBA video game) which will lead us to `\Jailbroken\private\var\mobile\Documents`

![734b5b44622784356e92731455823ded.png](/resources/734b5b44622784356e92731455823ded.png)

Going inside this folder then we can see there is a `Save States` folder here and as we can expected that it should have both save states for both game 

![523b5e7f12c3d0f2e86fbea9a4b44673.png](/resources/523b5e7f12c3d0f2e86fbea9a4b44673.png)

But each game and only 1 save state, we didn't have to account which game was installed last anymore

```
1
```

> Q13: What language is the user trying to learn?

![781c4936850715521c7b6c1b322612f1.png](/resources/781c4936850715521c7b6c1b322612f1.png)

From the podcast artifact we investigated, we can see that user also listened to Duolingo podcasts 

![90bd34d68b67fd3a5c75aec955169e45.png](/resources/90bd34d68b67fd3a5c75aec955169e45.png)

Put any of them inside language detection tool then we will come to the same conclusion

```
Spanish
```

> Q14: The user was reading a book in real life but used their IPad to record the page that they had left off on. What number was it?

![9f231e43a6264daf2149b2761ec3ce89.png](/resources/9f231e43a6264daf2149b2761ec3ce89.png)

I did some googling for a folder that stores recording videos and this [reddit user generously](https://www.reddit.com/r/computerforensics/comments/mm5qpz/apple_iphone_directory_accessibility/) telling us that we will have to go to `\private\var\mobile\Media\DKIM\10XAPPLE`

![9c1f3efb848f81ed53a0555508d7fb4b.png](/resources/9c1f3efb848f81ed53a0555508d7fb4b.png)

Close enough, we have `100APPLE` folder that have 1 recording video inside

![5d49793a3d1f3b2121f2981a0b3c38b4.png](/resources/5d49793a3d1f3b2121f2981a0b3c38b4.png)

User turned so many pages but eventually stopped at page 85 which is the answer of this question

```
85
```

> Q15: If you found me, what should I buy? 

I wanted to find all files that contains string "buy" but it took too long so I checked for hint which telling me that we need to find for any notes

![fa40e7c4e4535097d23384bd282d62ee.png](/resources/fa40e7c4e4535097d23384bd282d62ee.png)

Lets find where note database is located with `Get-ChildItem -Path "Z:\CD_35-jailbroken\Jailbroken\private\var\" -Recurse -Filter "NoteStore.sqlite" -ErrorAction SilentlyContinue` which will lead us to `\Jailbroken\private\var\mobile\Containers\Shared\AppGroup\4466A521-8AF9-4E09-800B-C3203BB70E0E`

![4612fb5046e7bd22ed961c4d4d380f23.png](/resources/4612fb5046e7bd22ed961c4d4d380f23.png)

For this artifact, we could not use DB Browser for SQLite to read notes but we will have to use [mac_apt](https://github.com/ydkhatri/mac_apt) with NOTES plugin like this `.\mac_apt_artifact_only.exe -i "Z:\CD_35-jailbroken\Jailbroken\private\var\mobile\Containers\Shared\AppGroup\4466A521-8AF9-4E09-800B-C3203BB70E0E\NoteStore.sqlite" -c NOTES -o "Z:\CD_35-jailbroken\"`

![d9609b75cdf995c932fb2b545a3788f4.png](/resources/d9609b75cdf995c932fb2b545a3788f4.png)

Go to output folder and open `Notes.csv`, then we can see that "we" should buy Crash Bandicoot game for PS4

```
Crash Bandicoot Nitro-Fueled Racing
```

> Q16: There was an SMS app on this device's dock. Provide the name in bundle format: com.provider.appname

![07fbb1b96217dfeba6117784ace1c2aa.png](/resources/07fbb1b96217dfeba6117784ace1c2aa.png)

Go to "Application State DB" report from iLEAPP then find for SMS app then we will eventually find the name in bundle format 

```
com.apple.MobileSMS
```

> Q17: A reminder was made to get something, what was it?

![1b08e05470008919431439b7a0037b65.png](/resources/1b08e05470008919431439b7a0037b65.png)

There are two main things that people use for reminders: Notes and Calendar. However, we already parsed Notes and found nothing, and the "Calendar List" report did not give us anything either.

![f6b0981235a1de435562452b3fe66034.png](/resources/f6b0981235a1de435562452b3fe66034.png)

We have to browse Calendar database directly which located in `\Jailbroken\private\var\mobile\Library\Calendar` and after open this database, go to `CalendarItem` then we will see 2 reminders here

```
milk
```

https://cyberdefenders.org/blueteam-ctf-challenges/achievements/Chicken_0248/jailbroken/

* * *
