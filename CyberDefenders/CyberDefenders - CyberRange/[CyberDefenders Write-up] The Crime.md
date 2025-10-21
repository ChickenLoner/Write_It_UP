# [CyberDefenders - The Crime](https://cyberdefenders.org/blueteam-ctf-challenges/the-crime/)
Created: 28/05/2024 18:04
Last Updated: 31/05/2024 21:01
* * *
>Category: Endpoint Forensics
>Tags: Android, ALEAPP, sqlitebrowser
* * *
**Scenario**:
We're currently in the midst of a murder investigation, and we've obtained the victim's phone as a key piece of evidence. After conducting interviews with witnesses and those in the victim's inner circle, your objective is to meticulously analyze the information we've gathered and diligently trace the evidence to piece together the sequence of events leading up to the incident.

**Tools**:
- [ALEAPP](https://github.com/abrignoni/ALEAPP) 
- [sqlitebrowser](https://sqlitebrowser.org/dl/)

**Resources**:
[Android-Forensics-References](https://github.com/RealityNet/Android-Forensics-References)
* * *
## Questions
> Q1: Based on the accounts of the witnesses and individuals close to the victim, it has become clear that the victim was interested in trading. This has led him to invest all of his money and acquire debt. Can you identify which trading application the victim primarily used on his phone?

![42a5f37df5773525924a2862674c270d.png](../../_resources/42a5f37df5773525924a2862674c270d.png)
๊Using [ALEAPP](https://github.com/abrignoni/ALEAPP) will make life easier, specify folder that we just extracted from zip file and output folder then click process
![199794b4a4e8fb1dbb89d881efd8ad6a.png](../../_resources/199794b4a4e8fb1dbb89d881efd8ad6a.png)
After a while, open report once it finished and go to Installed Apps then you will see that this phone only has 1 trading app
![5c27c09e13bd764388562f6e98b39490.png](../../_resources/5c27c09e13bd764388562f6e98b39490.png)
Which is Olymp Trade
```
Olymp Trade
```

> Q2: According to the testimony of the victim's best friend, he said, "While we were together, my friend got several calls he avoided. He said he owed the caller a lot of money but couldn't repay now". How much does the victim owe this person?

![0df5a81118313378f7f9585053c11e27.png](../../_resources/0df5a81118313378f7f9585053c11e27.png)
If sevaral calls were avoided then the debt owner often go to SMS message and after examined SMS message, look like victim owned someone large amount of money
```
250000
```

> Q3: What is the name of the person to whom the victim owes money?

![3d93dde883d5b13cfdae6dd80d840629.png](../../_resources/3d93dde883d5b13cfdae6dd80d840629.png)
We got debt owner number so we can use this to find his name in Contacts
![fd4e3c890ea8238f7e438656955a92e7.png](../../_resources/fd4e3c890ea8238f7e438656955a92e7.png)
```
Shady Wahab
```

> Q4: Based on the statement from the victim's family, they said that on September 20, 2023, he departed from his residence without informing anyone of his destination. Where was the victim located at that moment?

![2d46fd81a6e50735b96e2aa075e31f1e.png](../../_resources/2d46fd81a6e50735b96e2aa075e31f1e.png)
I checked Recent Activity then I found that victim used Google Maps which also has Snapsnot image too
![5f9808d4ca4b611b9a9cfaa235317f97.png](../../_resources/5f9808d4ca4b611b9a9cfaa235317f97.png)
We can see that victim was stayed inside this hotel
```
The Nile Ritz-Carlton
```

> Q5: The detective continued his investigation by questioning the hotel lobby. She informed him that the victim had reserved the room for 10 days and had a flight scheduled thereafter. The investigator believes that the victim may have stored his ticket information on his phone. Look for where the victim intended to travel.

![414bd7373c611941388337fada24f64f.png](../../_resources/414bd7373c611941388337fada24f64f.png)
ALEAPP result didn't get me any result so I went to media folder and just as I guessed, it was saved under Download folder
![895a11b71ef50cc983678f2a60613e94.png](../../_resources/895a11b71ef50cc983678f2a60613e94.png)
Victim intented to travel in Las Vegas
```
Las Vegas
```

> Q6: After examining the victim's Discord conversations, we discovered he had arranged to meet a friend at a specific location. Can you determine where this meeting was supposed to occur?

![ca802ba099f0b3196dc6f99fa01c1f76.png](../../_resources/ca802ba099f0b3196dc6f99fa01c1f76.png)
Go back to ALEAPP, it caught discord chats for us and look like victim had an appointment in The Mob Museum
```
The Mob Museum
```

![58747bdb6837a8cfed60d75741493827.png](../../_resources/58747bdb6837a8cfed60d75741493827.png)
* * *