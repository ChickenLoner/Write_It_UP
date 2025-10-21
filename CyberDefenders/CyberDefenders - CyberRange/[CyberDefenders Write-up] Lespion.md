# [CyberDefenders - Lespion](https://cyberdefenders.org/blueteam-ctf-challenges/lespion/) 
Created: 28/02/2024 15:36
Last Updated: 28/02/2024 09:07
* * *
>Category: Threat Intel
>Tags: BloodHound, Github, Mimikatz, OSINT, T1496, T1071, T1078
* * *
You, as a soc analyst, have been tasked by a client whose network was compromised and brought offline to investigate the incident and determine the attacker's identity.

Incident responders and digital forensic investigators are currently on the scene and have conducted a preliminary investigation. Their findings show that the attack originated from a single user account, probably, an insider.

Investigate the incident, find the insider, and uncover the attack actions.

**Tools**
- [Google Maps](https://www.google.com/maps)
- [Google Image search](https://www.google.com/imghp)
- [sherlock](https://github.com/sherlock-project/sherlock)
* * *
## Questions
> Q1: File -> Github.txt: What is the API key the insider added to his GitHub repositories?

We're provided with these 3 files, 1 text file, 1 jpeg file and 1 png file
![44325ea22fa5780eb05348ff7676a589.png](../../_resources/44325ea22fa5780eb05348ff7676a589-1.png)
The content of text file is a URL
![0fc7188d18f308d041ba410e22aa8248.png](../../_resources/0fc7188d18f308d041ba410e22aa8248-1.png)
It is a github repo of the EMarseille99 user 
![875feea30700ba61cd0f4fca67c5922c.png](../../_resources/875feea30700ba61cd0f4fca67c5922c-1.png)
Most of the repo were forked but there is one project that this user had created which is [Project-Build---Custom-Login-Page](https://github.com/EMarseille99/Project-Build---Custom-Login-Page)
![3a46a60731bca07239a79d8eafd45d4d.png](../../_resources/3a46a60731bca07239a79d8eafd45d4d-1.png)
![be9d8be086591982b62a8cfd373400a4.png](../../_resources/be9d8be086591982b62a8cfd373400a4-1.png)

Nothing special about `fsociety.js`, its just a logo from the infamous Mr Robot series
![a81eab6001dd06c902cc1aff3c967680.png](../../_resources/a81eab6001dd06c902cc1aff3c967680-1.png)

But on the other hand, There is an API key paremeter was set at the first line of `Login Page.js`
![2b0098dbccee1d111d18aea2d23b533f.png](../../_resources/2b0098dbccee1d111d18aea2d23b533f-1.png)

```
aJFRaLHjMXvYZgLPwiJkroYLGRkNBW
```

> Q2: File -> Github.txt: What is the plaintext password the insider added to his GitHub repositories?

Scroll to line 46~59, I found user credentials.
![541079eedde829692f6723648cf37ebc.png](../../_resources/541079eedde829692f6723648cf37ebc-1.png)
Decode the password with cyberchef
![c1916bba638f1f54a8ed7ec650cabccc.png](../../_resources/c1916bba638f1f54a8ed7ec650cabccc-1.png)
```
PicassoBaguette99
```

> Q3: File -> Github.txt: What cryptocurrency mining tool did the insider use?

I couldn't find anything about the mining tool on the [Project-Build---Custom-Login-Page](https://github.com/EMarseille99/Project-Build---Custom-Login-Page) repo so I went to search for other repos, Most of them are cybersecurity tools that widely used but there is one repo that says something about Crypto which is [xmrig](https://github.com/EMarseille99/xmrig)
![288f5150cc3ea355362fd80ca5d01594.png](../../_resources/288f5150cc3ea355362fd80ca5d01594-1.png)
After reading the `README.md`, It is confirmed that this is the crypto mining tool that we're searching for
![0012ee4031ac0760074f0617e23d7178.png](../../_resources/0012ee4031ac0760074f0617e23d7178-1.png)
```
xmrig
```

> Q4: What university did the insider go to? 

I used the email to search on google and found Linkedin profile that belongs to this user
![80dbdc19c07d808f055e5d282ba09068.png](../../_resources/80dbdc19c07d808f055e5d282ba09068-1.png)
![7904a8ee7dc3d38b93ed55e34276e450.png](../../_resources/7904a8ee7dc3d38b93ed55e34276e450-1.png)
And in the Linkedin there is an education section that list the university this user went to
![c9e4a9322236378cf27e06ecc765d332.png](../../_resources/c9e4a9322236378cf27e06ecc765d332-1.png)

```
Sorbonne
```

> Q5: What gaming website the insider had an account on?

Its time to use [sherlock](https://github.com/sherlock-project/sherlock) to hunt down the social media accounts but all of them couldn't be answered
![774d12f43dcc8cab0275d3cd0e52fe01.png](../../_resources/774d12f43dcc8cab0275d3cd0e52fe01-1.png)
So I went to other tool like [Namechk](https://namechk.com/)
![b5de20078bc807dfd712072831f9e40f.png](../../_resources/b5de20078bc807dfd712072831f9e40f-1.png)
And there it is! This username exists on Steam
![4c5e0330567053bd6b2a951c9e2c8e0d.png](../../_resources/4c5e0330567053bd6b2a951c9e2c8e0d-1.png)
![b0eb65e1a231de0b0ef64da3a3b60910.png](../../_resources/b0eb65e1a231de0b0ef64da3a3b60910-1.png)
```
steam
```

> Q6: What is the link to the insider Instagram profile?

Just searching by username, The first link should be it
![746658e4ae483ce5e8220ffe0221eb28.png](../../_resources/746658e4ae483ce5e8220ffe0221eb28-1.png)
![321618eb8f73ec3777e2893d05a3bcb4.png](../../_resources/321618eb8f73ec3777e2893d05a3bcb4-1.png)
```
https://www.instagram.com/emarseille99/
```

> Q7: Where did the insider go on the holiday? (Country only)

![28e5f683e52af4eb1cb43fa220b74d84.png](../../_resources/28e5f683e52af4eb1cb43fa220b74d84-1.png)
On the Instagram, This picture was posted with a holiday caption so This might be the place so I used Google Lens to search where it is

And the result is Marina Bay Sands in Singapore
![abd998eb0d2867e491ee7eaefc9c2d5a.png](../../_resources/abd998eb0d2867e491ee7eaefc9c2d5a-1.png)
```
Singapore
```

> Q8: Where is the insider family live? (City only)

On her Instragram, there are 2 pictures that the insider mentioned her family
![07e57d511483aa3f12454467c8ed37aa.png](../../_resources/07e57d511483aa3f12454467c8ed37aa-1.png)
![d62584a7ba75238e3c41a2f03c2e92f3.png](../../_resources/d62584a7ba75238e3c41a2f03c2e92f3-1.png)
I assumed that the second image is easier to search online so I used that 

The result says it's Burj Khalifa, It might be the highest tower that appeared on the image and It is located in Dubai
![7c53e2a85280a76c122f45f7b3db8548.png](../../_resources/7c53e2a85280a76c122f45f7b3db8548-1.png)
```
Dubai
```

> Q9: File -> office.jpg: You have been provided with a picture of the building in which the company has an office. Which city is the company located in?

Here is the image and I uploaded it for the Google Image Search to find the answer for me
![b042dc4cfc3805c6c6d37030d135fdd1.png](../../_resources/b042dc4cfc3805c6c6d37030d135fdd1-1.png)
And it says Birmingham New Street, on the office.jpg also showed the Grand Central and Odeon cinema
![a233ae2cf8a6b8e30d9ab3778c0dab4b.png](../../_resources/a233ae2cf8a6b8e30d9ab3778c0dab4b-1.png)
So both building confirmed the search result.
![1f772851f8bc3f9a0f2230bc3511c57c.png](../../_resources/1f772851f8bc3f9a0f2230bc3511c57c-1.png)

```
Birmingham
```

> Q10: File -> Webcam.png: With the intel, you have provided, our ground surveillance unit is now overlooking the person of interest suspected address. They saw them leaving their apartment and followed them to the airport. Their plane took off and has landed in another country. Our intelligence team spotted the target with this IP camera. Which state is this camera in?

This is Webcam.jpg, by taking a look you can see it's from a webcam according to filename and this picture was taken from EarthCam platform
![4ba202593a66736dc7cba09c44bfbc16.png](../../_resources/4ba202593a66736dc7cba09c44bfbc16-1.png)
Before I go to EarthCam to find this camera, I searched on Google Image first and found that this place is a University of Notre Dame

And There It is, same view confirmed now we need to know the state of this university
![fe7e0d0f44759f096ce699ecfffaf22e.png](../../_resources/fe7e0d0f44759f096ce699ecfffaf22e-1.png)
Indiana it is
![5253085b01ead368261a4241cacf1321.png](../../_resources/5253085b01ead368261a4241cacf1321-1.png)

```
Indiana
```

![718647f618d6237452180364af952c4f.png](../../_resources/718647f618d6237452180364af952c4f.png)
* * *