# [CyberDefenders - Eli](https://cyberdefenders.org/blueteam-ctf-challenges/eli/)
## Table of Contents

  - [Scenario](#scenario)
  - [Questions](#questions)
- [Find all "Downloads" directories](#find-all-downloads-directories)
- [Iterate over each "Downloads" directory and list its contents](#iterate-over-each-downloads-directory-and-list-its-contents)

* * *
## Scenario
As a soc analyst, analyze the artifacts and answer the questions.

**Category**: Endpoint Forensics

**Tools**:
1. [CyberChef](https://gchq.github.io/CyberChef/)
2. [DCode](https://www.digital-detective.net/dcode/)
3. [DB Browser for SQLite](https://sqlitebrowser.org/)
4. [Unfurl](https://github.com/obsidianforensics/unfurl)
5. [CLEAPP](https://github.com/markmckinnon/cLeapp)
6. [RLEAPP](https://github.com/abrignoni/RLEAPP)

**Resources**:
1. Hindsight from Ryan Benson: https://github.com/obsidianforensics/hindsight
2. Chromebook Data Locations: https://www.magnetforensics.com/blog/chromebook-data-locations/
3. Taking a Byte out of Chromebook Analysis: https://www.magnetforensics.com/resources/taking-a-byte-of-chromebook-analysis-mvs-may-5/
4. Ross Donnelly on Google Takeout Location Data: https://dfir.pubpub.org/pub/d39u7lg1/release/1
5. Takeout Locations: https://www.magnetforensics.com/resources/targeted-locations-quick-reference-guide-for-android-and-google-takeouts/
6. Takeout Data: https://www.magnetforensics.com/resources/exploring-the-data-available-from-google-takeout-webinar-sep-22-oct-6/
* * *
## Questions
> Q1: The folder to store all your data in - How many files are in Eli's downloads directory?

![b98d789b71626f388d64ad6801eafa24.png](/resources/b98d789b71626f388d64ad6801eafa24.png)

I've never touched chromebook before so I didn't know how their data structure look like, so I did some google search and found that it should be Downloads folder somewhere under user folder

```
# Find all "Downloads" directories
$downloadsDirs = Get-ChildItem -Path C:\ -Recurse -Directory -Filter *Downloads*

# Iterate over each "Downloads" directory and list its contents
foreach ($dir in $downloadsDirs) {
    Write-Output "Contents of directory: $($dir.FullName)"
    Get-ChildItem -Path $dir.FullName
    Write-Output ""
}
```

So I used this powershell script to recursively find all files inside all "Downloads" folders 

![3eb4c97c785b7dd332c16b7529f1a03f.png](/resources/3eb4c97c785b7dd332c16b7529f1a03f.png)

Which we will see that under `\2021 CTF - Chromebook\decrypted\mount\user\Downloads` folder, there are 6 files while the rest of Downloads folders doesn't have anything inside of them

![bd2b8e8c73dfaaed8cd6f0447497f6c8.png](/resources/bd2b8e8c73dfaaed8cd6f0447497f6c8.png)

```
6
```

> Q2: Smile for the camera - What is the MD5 hash of the user's profile photo?

![d1a7294d516e1ba3b93421509edf9c59.png](/resources/d1a7294d516e1ba3b93421509edf9c59.png)

After determined user, directory then I found an avatar image inside `\2021 CTF - Chromebook\decrypted\mount\user\Accounts\Avatar Images` folder

```
5ddd4fe0041839deb0a4b0252002127b
```

> Q3: Road Trip! - What city was Eli's destination in?

![6fdb232dbdfe0a0b5c9d0b6ef1fd2134.png](/resources/6fdb232dbdfe0a0b5c9d0b6ef1fd2134.png)

Inside user's Downloads folder, we can see an image taken from google maps 

![522a2046d076fa826faa4867bc590aa5.png](/resources/522a2046d076fa826faa4867bc590aa5.png)

which indicates user was going to Chick-fill-a in Plattsburgh city

```
Plattsburgh
```

> Q4: Promise Me - How many promises does Wickr make?

![c4a3567868179db70070e393c7175b2f.png](/resources/c4a3567868179db70070e393c7175b2f.png)

There is a pdf file inside user's Downloads folder that writing about Customer Security Promises

![ce2e2dc4dbf164f1eaa0c400efaa4277.png](/resources/ce2e2dc4dbf164f1eaa0c400efaa4277.png)

Open this file and scroll down for a bit then we can see there are 9 promises 

```
9
```

> Q5: Key-ty Cat - What are the last five characters of the key for the Tabby Cat extension?

![21625653e87138491c961f34ab8977ac.png](/resources/21625653e87138491c961f34ab8977ac.png)

There are so much extensions inside user's Extensions folder

![59bc425d0795c6afbcd3b06d700cd4b5.png](/resources/59bc425d0795c6afbcd3b06d700cd4b5.png)

So I used `Get-ChildItem -Path "Z:\2021 CTF - Chromebook\decrypted\mount\user\Extensions" -Recurse -File | Select-String -Pattern "Tabby Cat" | Select-Object -ExpandProperty Path -Unique` to find all the file that has strings "Tabby Cat" which eventually gave us path to `manifest.json` of this extension

![9558723c4bb6a4563889d51688967008.png](/resources/9558723c4bb6a4563889d51688967008.png)

![2cf14252f6545c450241ba89b3c240c4.png](/resources/2cf14252f6545c450241ba89b3c240c4.png)

Lets open it and get the last five characters of the key to answer this question 

```
DAQAB
```

> Q6: Time to jam out - How many songs does Eli have downloaded?

![1684dc3c2ef3b48d1276c963bb0923a1.png](/resources/1684dc3c2ef3b48d1276c963bb0923a1.png)

There is Music folder inside `\2021 CTF - Chromebook\decrypted\mount\user\MyFiles\`, which have 2 mp3 files inside of it

```
2
```

> Q7: Autofill, roll out - Which word was Autofilled the most?

![565cff5bfdf754d4a1355dd3f63b568d.png](/resources/565cff5bfdf754d4a1355dd3f63b568d.png)

I used [cLEAPP](https://github.com/markmckinnon/cLeapp) (Chrome Logs Events and Protobuf Parser) which is a tool that can help us automated some process for a little bit 

![0d3b02538f532eb97595d8be89a522e2.png](/resources/0d3b02538f532eb97595d8be89a522e2.png)

Go to Chromebook Autofill then you can see that email field was filled the most

Alternatively, you can use DBbrowser for SQLite to open `Web Data` sqlite database from user home folder

```
email
```

> Q8: Dress for success - What is this bird's image's logical size in bytes?

![28d266b89f2823ad3954d6aa98d2c518.png](/resources/28d266b89f2823ad3954d6aa98d2c518.png)

If you remember little linux penguin inside download folder, then you can navigate there and display logical size of this image 

![19c7e75321aa0f385f525ef9ccbf98ba.png](/resources/19c7e75321aa0f385f525ef9ccbf98ba.png)

```
46,791
```

> Q9: Repeat customer - What was Eli's top visited site?

![d4d755501410c9bf596224e6047e5d0f.png](/resources/d4d755501410c9bf596224e6047e5d0f.png)

by using [hindsight](https://github.com/obsidianforensics/hindsight), you will eventually get the answer by sorting most visit sites but  its not google doc 

```
protonmail.com
```

> Q10: Vroom Vroom, What is the name of the car-related theme?

![7aa08df51c646f4a70d3da132a4fbf74.png](/resources/7aa08df51c646f4a70d3da132a4fbf74.png)

Go to Installed Extensions sheet and you will see there is only one extension that related to the car 

```
Lamborghini Cherry
```

> Q11: You got mail - How many emails were received from notification@service.tiktok.com?

![573f966f4ae70d94f79d9cb8aabd6904.png](/resources/573f966f4ae70d94f79d9cb8aabd6904.png)

I searched for a file that contains the string "tiktok"  inside and the file that caught my eye and made me want to look into it first is `\2021 CTF - Takeout\Takeout\Mail\All mail Including Spam and Trash.mbox`

![a10899876b33ec64dac7173a4a969454.png](/resources/a10899876b33ec64dac7173a4a969454.png)

![11f5b8aedbbfdcfdb6523a3a861b39ee.png](/resources/11f5b8aedbbfdcfdb6523a3a861b39ee.png)

We can use thunderbird to open this but to make things easier, I'll just open this file using VScode and filter for "From: "Tiktok" <notification@service.tiktok.com>""

```
6
```

> Q12: Hungry for directions - Where did the user request directions to on Mar 4, 2021, at 4:15:18 AM EDT

![b7d7f750351ed84eea5c78d1ecec7cb9.png](/resources/b7d7f750351ed84eea5c78d1ecec7cb9.png)

We know that user was going to Chick-fill-A but time doesn't add up so I searched for this specific time and found it was in `\2021 CTF - Takeout\Takeout\My Activity\Maps\MyActivity.html`

![f18018d0fec99409cda43ff7d2e12d9d.png](/resources/f18018d0fec99409cda43ff7d2e12d9d.png)

After researching what is Takeout folder, now it make sense why we found this information here

```
Chick-fil-A
```

> Q13: Who defines essential? - What was searched on Mar 4, 2021, at 4:09:35 AM EDT

![a9d68f86edd348da402926aaada9fe62.png](/resources/a9d68f86edd348da402926aaada9fe62.png)

It is in `\2021 CTF - Takeout\Takeout\My Activity\Search\MyActivity.html`

![d6961a66abc7ff18db752624d50d8011.png](/resources/d6961a66abc7ff18db752624d50d8011.png)

```
is travelling to get chicken essential travel
```

> Q14: I got three subscribers, and counting - How many YouTube channels is the user subscribed to?

![e9181af532bfd3a99b7db517679bf337.png](/resources/e9181af532bfd3a99b7db517679bf337.png)

There is a `subscriptions.json` inside `\2021 CTF - Takeout\Takeout\YouTube and YouTube Music\` folder

![d2b2f67adedb644fd18d05ef4e2eef67.png](/resources/d2b2f67adedb644fd18d05ef4e2eef67.png)

There is no data inside of it which mean this user does not subscribe to anyone on youtube

```
0
```

> Q15: Time flies when you're watching YT - What date was the first YouTube video the user watched uploaded?

![a04826aad67b3563faa059e3556a11e7.png](/resources/a04826aad67b3563faa059e3556a11e7.png)

The answer lying in `\2021 CTF - Takeout\Takeout\My Activity\YouTube` folder

![f40c17e38fcf086cdeafaf43b2264365.png](/resources/f40c17e38fcf086cdeafaf43b2264365.png)

Scroll down to the last record which is the oldest one/first one that was recorded, follow this link then you will find the first youtube video that user watched 

![fdefb53e6aaed15051dbae3409a834c9.png](/resources/fdefb53e6aaed15051dbae3409a834c9.png)

My timezone is UTC+7 so I have to subtract a day out of this

```
27/01/2021
```

> Q16: How much? - What is the price of the belt?

![62b2d5bd30c19858e3f4dd9cf7ad529a.png](/resources/62b2d5bd30c19858e3f4dd9cf7ad529a.png)

Result from searching for a "belt" string lead us to Chrome browsing history 

![98b4789aac6832c77990ac5f75ad0994.png](/resources/98b4789aac6832c77990ac5f75ad0994.png)

We can see that user accessed a shop for leather belt

![d592e221cd5ac3d4013471a4d78ffee4.png](/resources/d592e221cd5ac3d4013471a4d78ffee4.png)

But it is out of stock and the price could not be find anymore 

![30b032077037381c6ac0e317c78c4071.png](/resources/30b032077037381c6ac0e317c78c4071.png)

I couldn't search for this belt on web archive too

![fd8095865318a4adb58b4cc93f9fd3fb.png](/resources/fd8095865318a4adb58b4cc93f9fd3fb.png)

Inspecting web page does not give me anything either

So I had to read other write-up for this one and turn out that I was using the right url on wayback machine and the url that was archive is https://web.archive.org/web/20210122000112/https://www.vineyardvines.com/mens-belts/pebbled-leather-belt/1B001191.html?dwvar_1B001191_color=202&cgid=mens-accessories

![87f4cba3fc70eea8a9a5d75da5561c7c.png](/resources/87f4cba3fc70eea8a9a5d75da5561c7c.png)

```
98.5
```

https://cyberdefenders.org/blueteam-ctf-challenges/achievements/Chicken_0248/eli/

* * *
