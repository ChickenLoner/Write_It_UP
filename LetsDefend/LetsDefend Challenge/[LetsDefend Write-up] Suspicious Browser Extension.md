# [LetsDefend - Suspicious Browser Extension](https://app.letsdefend.io/challenge/suspicious-browser-extension)
Created: 25/04/2024 21:28
Last Updated: 07/06/2024 08:28
* * *
<div align=center>

**Suspicious Browser Extension**
![ec079e0680ab54bd70245349b61b8ac6.png](/_resources/ec079e0680ab54bd70245349b61b8ac6.png)
</div>
A person working in the accounting department wanted to add a browser extension, but it was deleted from his device because it was perceived as harmful by AVs.

Can you analyze the situation by analyzing this suspicious browser extension? We are waiting for information from you.

File link: [~~Download~~](https://files-ld.s3.us-east-2.amazonaws.com/FinanceEYEfeeder.zip) /root/Desktop/ChallengeFiles/FinanceEYEfeeder.crx ~~Password: infected~~
NOTE: Do not open in your local environment. It is a malicious file.
This challenge prepared by [@DXploiter](https://twitter.com/DXploiter)

* * *
## Start Investigation
> Which browser supports this extension?

![743e0ae2c8af2cd9f03861189bca38bb.png](/_resources/743e0ae2c8af2cd9f03861189bca38bb.png)
We got a crx file which is a typical file extension for browser extension 
![95c4790725ee3c5bcd34f8d20afc3edd.png](/_resources/95c4790725ee3c5bcd34f8d20afc3edd.png)
Then I did some research on how to analyse this file without installing it and found this [website](https://fileinfo.com/extension/crx) explaination is very useful
![18c3ea0b30da0d40025b8ac50c823f95.png](/_resources/18c3ea0b30da0d40025b8ac50c823f95.png)
And according to information provided on this website, we know now that crx file can be unzip
![b49eb6a700469b7a68ac65b7fc220bb4.png](/_resources/b49eb6a700469b7a68ac65b7fc220bb4.png)
There is it, crx file is designed for Google Chrome so answer of this question is Google Chrome obviously
```
Google Chrome
```

> What is the name of the main file which contains metadata?

![57627edae35803fb8ff200b14b96d6b4.png](/_resources/57627edae35803fb8ff200b14b96d6b4.png)
I knew the answer is `manifest.json` but I also did some research on why it has to be this file and my search result made it crystal clear to me
```
manifest.json
```

> How many js files are there? (Answer should be numerical)

![83466bf1ffef7fad76c84f431307d3a9.png](/_resources/83466bf1ffef7fad76c84f431307d3a9.png)
There are 2 js files here
```
2
```

> Go to crxcavator.io and check if this browser extension has already been analyzed by searching its name. Is it known to the community? (Yes/No)

![d608e2a93d21638fa1bba6eb9f4954a5.png](/_resources/d608e2a93d21638fa1bba6eb9f4954a5.png)
Checking extension name from `manifest.json`
![54d58aec5b716714122f72a4b8ef5217.png](/_resources/54d58aec5b716714122f72a4b8ef5217.png)
Then search on crxcavator.io which found none which mean the answer is No
```
No
```

> Download and install ExtAnalysis. Is the author of the extension known? (Yes/No)

Here is the [ExtAnalysis repository](https://github.com/Tuhinshubhra/ExtAnalysis), you can install with git and pip3 or using docker 
![da2aeb099694a412f367fa09bd6ccd10.png](/_resources/da2aeb099694a412f367fa09bd6ccd10.png)
ExtAnalysis is a framework that can be used to analyze malicious browser extensions so it made sense why this challenge told us to get one
![fca5302ea088a8a5f54b44a9e7abb085.png](/_resources/fca5302ea088a8a5f54b44a9e7abb085.png)
I installed this framework using git and pip3
![a640dba2aa81329d10cdb6d745d7ba92.png](/_resources/a640dba2aa81329d10cdb6d745d7ba92.png)
Look like I missed 1 package but if you have the same problem just use pip to install them
![7b1ea0c9b738ac6209efd2bed357b16c.png](/_resources/7b1ea0c9b738ac6209efd2bed357b16c.png)
Then after all requirements are met, executed python file then ExtAnalysis will be hosted at port 13337 on localhost
![ebe3e2747ee7633fffee892f2e6ccee8.png](/_resources/ebe3e2747ee7633fffee892f2e6ccee8.png)
Go to UPLOAD EXTENSION to upload crx file
![bcd758c3ba524049dbf88e7161848a04.png](/_resources/bcd758c3ba524049dbf88e7161848a04.png)
On BASIC INFO, look like Author is unknown so the answer of this question is No
```
No
```

> Often there are URLs and domains in malicious extensions. Using ExtAnlaylsis, check the ‘URLs and Domains’ tab How many URLs & Domains are listed? (Answer should be numerical)

![45bbfe74c9f9652a9ecb025722159e87.png](/_resources/45bbfe74c9f9652a9ecb025722159e87.png)
We got 2 domains here
```
2
```

> Find the piece of code that uses an evasion technique. Analyse it, what type of systems is it attempting to evade?

![516131e3ccb94c417a9f6e630b332d5d.png](/_resources/516131e3ccb94c417a9f6e630b332d5d.png)
Open `ThankYou.html` with your preferred text editor which you can see that if statement is checking for virtual machine and once any of them is detected, it will write something on web browser console and terminate chrome.exe process
```
virtual machine
```

> If this type of system is detected what function is triggered in its response?

![87b54d75d7596b48d913b7e0fcda5c74.png](/_resources/87b54d75d7596b48d913b7e0fcda5c74.png)
```
chrome.processes.terminate(0)
```

> What keyword in a user visited URL will trigger the if condition statement in the code?

![c1c536545198e8d02350f6d6ad09d9e6.png](/_resources/c1c536545198e8d02350f6d6ad09d9e6.png)
Go to `content.js`, you can see that it was obfuscated but one thing for sure is the first line is to assigned an array to a variable 
![8d7af9c341d201856a918b4ed30572e0.png](/_resources/8d7af9c341d201856a918b4ed30572e0.png)
This if condition might be the one that check for a keyword so lets grab each hex characters from an array to decode 
![e81f3e5746e2927ddf79d507e91d0185.png](/_resources/e81f3e5746e2927ddf79d507e91d0185.png)
![8905fe9039a3dd3ea16da373d2ebfe4c.png](/_resources/8905fe9039a3dd3ea16da373d2ebfe4c.png)
Look like it check for any url that has `login.aspx` inside of it

![2648cc8553a68cfeeb24ae6028207956.png](/_resources/2648cc8553a68cfeeb24ae6028207956.png)

To make life easier I found this https://obf-io.deobfuscate.io/ website to be very useful to de-obfuscate js code 
![6708373bf8f3b8dbd48413643cfda019.png](/_resources/6708373bf8f3b8dbd48413643cfda019.png)
It's time to deobfuscate and analyze this js script
![2ed6ba8cb89d35ef42aa2ad6fb248cf4.png](/_resources/2ed6ba8cb89d35ef42aa2ad6fb248cf4.png)
In conclusion, this script is a keylogger
```
login
```

> Based on the analysis of the content.js, what type of malware is this?

![fd34ddb2d1fc0f6925a1478792f2943e.png](/_resources/fd34ddb2d1fc0f6925a1478792f2943e.png)
![46973b530be0270187572fea72fdab71.png](/_resources/46973b530be0270187572fea72fdab71.png)
`window.onkeydown` is a property that used to capture any keystroke so the only malware type that do this thing is a keylogger malware
```
keylogger
```

> Which domain/URL will data be sent to?

![ada779e745f8e92cc8e7ff9ab9c3ebc7.png](/_resources/ada779e745f8e92cc8e7ff9ab9c3ebc7.png)
Now open `background.js` to grab an url which we couldn't find on `content.js`
![1bab56193df19cbe21cc2b428ca498ca.png](/_resources/1bab56193df19cbe21cc2b428ca498ca.png)
Put it in [deobfuscator](https://obf-io.deobfuscate.io/ ) we finally obtained a C2
```
https://google-analytics-cm.com/analytics-3032344.txt
```

> As a remediation measure, what type of credential would you recommend all affected users to reset immediately?

Keylogger designed to grab username along with password from infected host so the only one that can be reseted is password.
```
password
```

* * *
## Summary

This challenge will teach user how to investigate suspicious crx file which you will learn
- crx file can be unzip
- `manifest.json` contains metadata of any chrome-based extension
- crxcavator.io and ExtAnalysis can be used to analyze browser extension
- how to de-obfuscate JS code or find a good de-obfuscator to do that for you
- How can a JS can detected virtual machine and end a process
- How keylogger are written in JS
- How to remediation against credential that already stolen

Overall it is a great challenge for a beginner.
<div align=center>

![7f09f3deaaefcf50cb13104e30b5b48c.png](/_resources/7f09f3deaaefcf50cb13104e30b5b48c.png)
https://app.letsdefend.io/my-rewards/detail/3b1cbc9246e04f1b8489635f226ab131
</div>

* * *
