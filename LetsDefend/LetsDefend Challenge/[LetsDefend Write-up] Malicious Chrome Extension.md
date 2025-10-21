# [LetsDefend - Malicious Chrome Extension](https://app.letsdefend.io/challenge/malicious-chrome-extension)
Created: 25/04/2024 10:32
Last Updated: 30/11/2024 18:28
* * *
<div align=center>

**Malicious Chrome Extension**
![c965eb038a72dfecc10c0a3a595f0c2e.png](../../_resources/c965eb038a72dfecc10c0a3a595f0c2e.png)
</div>
The victim found out their private info was out there for everyone to see, and things got worse – the bad guys got into their money stuff, social media, and personal emails. We got an image of his machine so you can tell us what happened.

**File Location:** `/root/Desktop/ChallengeFile/Extension.7z`
* * *
## Start Investigation
> What is the ID of the malicious extension?

![5ac5d4791b35b4db9e8097a5440c980c.png](../../_resources/5ac5d4791b35b4db9e8097a5440c980c.png)
After extracted sample 7z file and after taking a look at folder structure ,this is `Users` folders which copied from Windows system.
![8789ef7aea75069553b73148c35dd806.png](../../_resources/8789ef7aea75069553b73148c35dd806.png)
Inside `Administrator` user, this system got 2 browsers which are Chrome and Edge but based on Challenge name that pretty clear about Chrome Extension so I went to `/Users/Administrator/AppData/Local/Google/Chrome/User Data/Default/Extensions` which is where extensions are stored
![30c5b024f972ebf3baf210c5454e4751.png](../../_resources/30c5b024f972ebf3baf210c5454e4751.png)
We can see that there are 8 extensions was installed on this user's browser and to make it quick, i'll search all extensions to [Chrome-Stats](https://chrome-stats.com/) instead of reading all `manifest.json` of all extensions and my reason is if any Chrome extension was flagged as malicious by Google, it will be removed from Web Store immediately
![a88a139088f78707254711aa8673a21e.png](../../_resources/a88a139088f78707254711aa8673a21e.png)
Then I found this `mmnbenehknklpbendgmgngeaignppnbe` extension id to be very suspicious since it was removed from Chrome Web Store so I have to do research on this one
![adb9aaaaa9280614e02104dbf9a1becd.png](../../_resources/adb9aaaaa9280614e02104dbf9a1becd.png)
[My first search result](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/malicious-cookie-stuffing-chrome-extensions-with-1-4-million-users/) is the one that confirmed that this extension is malicious and its the one we're looking for
![6c4ab0f5a07ff7d710921f0cf2c755f5.png](../../_resources/6c4ab0f5a07ff7d710921f0cf2c755f5.png)
There are 5 extensions that were used to conduct this malicious activity, and one of them was installed on Administrator Chrome's browser
```
mmnbenehknklpbendgmgngeaignppnbe
```

> What is the name of the malicious extension?

![bbc33337a5a5b1b0f9c12be00ff814cb.png](../../_resources/bbc33337a5a5b1b0f9c12be00ff814cb.png)
Go to `/_locales/en/`, there is a file that store a name of this extension since a name from `manifest.json` couldn't be used as an answer
![bd8c9fad4dde345cd0799e44e563e7be.png](../../_resources/bd8c9fad4dde345cd0799e44e563e7be.png)
```
Netflix Party Official
```

> How many people were affected by this extension?

![4438d9ad703749f38501b5df3d35a2b9.png](../../_resources/4438d9ad703749f38501b5df3d35a2b9.png)
Based on McAfree blog, 800k user installed this extension
```
800,000
```

> What is the attacker's domain name?

According to McAfree's blog, these extensions are tracking user browsing activity and send to extension creator then it can insert code into eCommence site that user visited which is modifying cookie of those eCommence site so "authors receive affiliate payment for any items purchased".    
![0b03a3163262985522367420b19c065e.png](../../_resources/0b03a3163262985522367420b19c065e.png)
Here is the port of `e` varible declaration, its different from infected system we got so we have to read `b0.js` ourselves
![a1ea7ecb44a5edbb6aba70e6c462ca5f.png](../../_resources/a1ea7ecb44a5edbb6aba70e6c462ca5f.png)
```
a1l4m.000webhostapp.com
```

> What is the full URL the attacker uses to exfiltrate the data?

![9050c72ad2e5ca9b5eaeeabd0c4779a4.png](../../_resources/9050c72ad2e5ca9b5eaeeabd0c4779a4.png)
to send any data that was being tracked, this extension need to use HTTP POST method which I also found that `url` variable was consist of `e` variable and other string which is a directory of C2 
```
https://a1l4m.000webhostapp.com/chrome/TrackData/
```

> What is the function name responsible for getting the victim's location?

![56aaabe922f29036ee4853b01a4ab778.png](../../_resources/56aaabe922f29036ee4853b01a4ab778.png)
According to blog, this extension also collected user location
![7e063738f9775eaa00d3474315ab5d2b.png](../../_resources/7e063738f9775eaa00d3474315ab5d2b.png)
Which is presented inside `b0.js` file, an attacker used `ip-api.com` to get user location which will responsed back in JSON
```
get_location
```

> What is the variable name that is responsible for storing the zip code of the victim?

![87b894e7762c6fdac9a79a755e8044eb.png](../../_resources/87b894e7762c6fdac9a79a755e8044eb.png)
you can see that zip code will be assigned to `zip` variable
```
zip
```

* * *
## Summary

This challenge goal is to make us dig into Google Chrome Extension and find the suspicious extension by any means whatever you read `manifest.json`, reading js code or doing online research then we can also used that search result to guide us to the rest of challenge.

This challenge also reminds us user that knowledge of JavaScript can be useful when it comes to any investigation like this.
<div align=center>

![907fd8484e55413707b5a6986a94af64.png](../../_resources/907fd8484e55413707b5a6986a94af64.png)
https://app.letsdefend.io/my-rewards/detail/118e150f513f4dd8b15df809aacae018
</div>

* * *
