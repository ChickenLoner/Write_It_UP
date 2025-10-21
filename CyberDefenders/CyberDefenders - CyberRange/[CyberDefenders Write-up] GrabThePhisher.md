# [CyberDefenders - GrabThePhisher](https://cyberdefenders.org/blueteam-ctf-challenges/grabthephisher/)
Created: 27/02/2024 16:02
Last Updated: 27/02/2024 16:25
* * *
>Category: Threat Intel
>Tags: kit, osint, phishing, threat intel, T1567, T1016, T1566.003
* * *
**Scenario**:
An attacker compromised a server and impersonated https://pancakeswap.finance/, a decentralized exchange native to BNB Chain, to host a phishing kit at https://apankewk.soup.xyz/mainpage.php. The attacker set it as an open directory with the file name "pankewk.zip". 

Provided the phishing kit, you as a soc analyst are requested to analyze it and do your threat intel homework.
* * *
## Questions
> Q1: Which wallet is used for asking the seed phrase?

Here are the directory of the kit after decompressed 
![0e03e9d8fc117e5c560fd6e3f6983fed.png](../../_resources/0e03e9d8fc117e5c560fd6e3f6983fed.png)
There is a metamask which should be the answer of this question
```
metamask
```

For those who wonders what's Metamask?
There you go
![c04975e4f5ad3fb3155a188e90f1b839.png](../../_resources/c04975e4f5ad3fb3155a188e90f1b839.png)

> Q2: What is the file name that has the code for the phishing kit?

![a0851403d61765a4eb535a8ea9852fb8.png](../../_resources/a0851403d61765a4eb535a8ea9852fb8.png)
Inside the metamask folder, there is a php file 
```
metamask.php
```

> Q3: In which language was the kit written?

![0551d07efb9eeb76b7ff855b75178e3b.png](../../_resources/0551d07efb9eeb76b7ff855b75178e3b.png)
Its a php script to retrieve geolocation data based on the user IP address then extract Country, City out of it then it construct a message then send it to Telegram Bot using API 

After that it also log data it receive from a form to `/log/log.txt` by appending it 

```
php
```

> Q4: What service does the kit use to retrieve the victim's machine information?

![b9c264a1c5bf32fbe1a4b80de2f2edca.png](../../_resources/b9c264a1c5bf32fbe1a4b80de2f2edca.png)
```
sypex geo
```

> Q5: How many seed phrases were already collected?

For those who doesn't know what is the Wallet Seed Phase, here the explaination
![1944ebbcaa0bc8a96fdbe31b9f84133a.png](../../_resources/1944ebbcaa0bc8a96fdbe31b9f84133a.png)
I went to where the log where created and then opened it
![cab4bca61530f2dd5219d6ecdd0f60cf.png](../../_resources/cab4bca61530f2dd5219d6ecdd0f60cf.png)
Looking at the content it seems like a wallet seed phases

```
3
```

> Q6: Write down the seed phrase of the most recent phishing incident?

Since the log were written by appending the recent one must be the lastest
```
father also recycle embody balance concert mechanic believe owner pair muffin hockey
```

> Q7: Which medium had been used for credential dumping?

By looking at the code, the telegram it is
![58e14e41143dad1c40f903af8988fdad.png](../../_resources/58e14e41143dad1c40f903af8988fdad.png)
```
telegram
```

> Q8: What is the token for the channel?

![a9b0358b83aa2aaaad7f3a107b819805.png](../../_resources/a9b0358b83aa2aaaad7f3a107b819805.png)
```
5457463144:AAG8t4k7e2ew3tTi0IBShcWbSia0Irvxm10
```

> Q9: What is the chat ID of the phisher's 
channel?

![8db8522e257ee6213b308d1b782e7566.png](../../_resources/8db8522e257ee6213b308d1b782e7566.png)
```
5442785564
```

> Q10: What are the allies of the phish kit developer?

There is a comment on this script and there is a name too
![26444d99cdadb056695f3226c9ea3c73.png](../../_resources/26444d99cdadb056695f3226c9ea3c73.png)
```
j1j1b1s@m3r0
```

> Q11: What is the full name of the Phish Actor?

Since it's a Telegram API then I started reading [documentation](https://core.telegram.org/bots/api#available-methods) to interact with this API
And I found this getChat method that can retrieve information about the user
![af2843e6b68490998c65960571f4a035.png](../../_resources/af2843e6b68490998c65960571f4a035.png)
So I used this command
`wget https://api.telegram.org/bot5457463144:AAG8t4k7e2ew3tTi0IBShcWbSia0Irvxm10/getChat?chat_id=5442785564` on the cmd and got the answer
![b4a20c2f90512f98eb34f72c843e3925.png](../../_resources/b4a20c2f90512f98eb34f72c843e3925.png)
```
Marcus Aurelius
```

> Q12: What is the username of the Phish Actor? 

![bcb191b9783a674f9c8f78b007cfc7b1.png](../../_resources/bcb191b9783a674f9c8f78b007cfc7b1.png)
```
pumpkinboii
```

![66e1647b340aae50c0a9613b53120797.png](../../_resources/66e1647b340aae50c0a9613b53120797.png)
* * *