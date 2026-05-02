# [Blue Team Labs Online - Take a LAP](https://blueteamlabs.online/home/investigation/take-a-lap-98e1466885)

![d5fad17f7e0ec05584a434dbe42f9cb3.png](/resources/d5fad17f7e0ec05584a434dbe42f9cb3.png)

The Track and Field Company has recently implemented a new program to help with their password rotation.

>Digital Forensics

>**Tags**: FTK Imager AD Explorer
* * *
**Scenario**
The Track and Field Company has recently implemented a new program to help with their password rotation. One of the administrators is disgruntled that he was not chosen to help with this responsibility, and has been looking at information he should not have access to. Can you do some forensics work to gather information on the current employees, the company's security policies, as well as the actions of this unhappy admin?
* * *
## Environment Awareness
### Evidence & Tools Discovery

![807172b64dcdb4096e6bb61ecc74bfb7.png](/resources/807172b64dcdb4096e6bb61ecc74bfb7.png)

We only have 1 disk images and 3 tools provided so we have to open this image file with FTK Imager then try to find AD snapshot to open in AD Explorer. 

Scenario telling us that one of the administrators is disgruntled so we could expect AD snapshot (`.dat`) from one of user.
***
## Investigation Submission
>Q1) What is the hostname of the machine? (Format: String)

![5e041ee9a3c2e11568ab8cc2ce275bf6.png](/resources/5e041ee9a3c2e11568ab8cc2ce275bf6.png)

First thing I noticed is `ntds-dump` folder, which suddenly raise the red flag right here but we did not have a tool nor any objective to export them but its still a bad practice to leave ntds dump like that since any one could dump all credentials store in `ntds.dit` and use pass-the-hash attack to access machine within AD. 

![275ab31031591174154273a4f47c285c.png](/resources/275ab31031591174154273a4f47c285c.png)

First thing I found is user "krbeth.admin" has group policy backup and report on his desktop and luckily for us that we could use these files to answer Q1 and Q2

![81cad56f455fea5e177938a9ee6278aa.png](/resources/81cad56f455fea5e177938a9ee6278aa.png)

Pick one of them then you should be able to obtain both Q1 and Q2 answers in this format.

<details>
  <summary>Answer</summary>
<pre><code>WIN-ALN64CF5HR5</code></pre>
</details>

>Q2) What is the forest root domain name? (Format: prefix.name.suffix)
<details>
  <summary>Answer</summary>
<pre><code>lab.btlo.com</code></pre>
</details>

>Q3) Name all the non-default Organizational Units (OUs) that a domain administrator created. List the OUs in alphabetical order (Format: name, name, ...) 

![0317e33967efa928a4570c072c3f9a30.png](/resources/0317e33967efa928a4570c072c3f9a30.png)

group policy report won't get us OU so I moved to "Administrator" which I finally found AD Snapshot that could be loaded with AD Explorer

![226b2b0fcdc1a11a0a3f1572ae79744f.png](/resources/226b2b0fcdc1a11a0a3f1572ae79744f.png)

So lets export and load this in AD Explorer.

![21471779d6fb7b5e9ac31467ed4fc36c.png](/resources/21471779d6fb7b5e9ac31467ed4fc36c.png)

Then after we loaded AD Snapshot, we could expend "DC=lab,DC=BTLO,DC=com" domain component since this is only one we need to investigate and to identify which OU is not built-in OU, then we can take a look at built-in OU to find creation timestamp of this OU and that mean any OUs that is not has this timestamp are created OU.

![156bfb4c13281db785182fc697453b43.png](/resources/156bfb4c13281db785182fc697453b43.png)

After taking a look at each OUs, we will have these 4 that were created by a domain administrator.

<details>
  <summary>Answer</summary>
<pre><code>Administrators, Employees, Servers, Workstations</code></pre>
</details>

>Q4) Which Active Directory attribute contains a range of flags to define the properties of a user object? (Format: String)

![bbb1a99fc866693b253aa4776130410c.png](/resources/bbb1a99fc866693b253aa4776130410c.png)

This attribute is ["userAccountControl"](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties) and we need to use this Microsoft documentation for Q5 and Q6
<details>
  <summary>Answer</summary>
<pre><code>userAccountControl</code></pre>
</details>

>Q5) Which employee has their password set to not expire, and what is the value (in hex) of the attribute that dictates this? (Format: displayName, 0xXXXXX)

![8df55be2e2139d248ca40dd1ebba03b3.png](/resources/8df55be2e2139d248ca40dd1ebba03b3.png)

Read the Microsoft documentation then you can see that "userAccountControl" attribute has to have value over 65535 (in demical) for do not expire password.

![6546ca51f9c9fe3c8c754343286a29bc.png](/resources/6546ca51f9c9fe3c8c754343286a29bc.png)

And the only user that have userAccountControl value over 65535 is Kyla which has 66048

![322ea8740bc24f4f2e212b6a9d3a2432.png](/resources/322ea8740bc24f4f2e212b6a9d3a2432.png)

We don't have to calculate demical to hex since AD explorer can display these value in hex.

![580d1b756bec5dc0ae4f2dc566ba5b39.png](/resources/580d1b756bec5dc0ae4f2dc566ba5b39.png)

For those who have a question why 0x10200? because Kyla user is a normal account so this CN already have 0x0200 since created then when we added 0x10000 for password never expire then it would sum up to 0x10200

<details>
  <summary>Answer</summary>
<pre><code>Kyla Cornell, 0x10200</code></pre>
</details>

>Q6) Which user has their account disabled, and what is the value (in hex) of the attribute that dictates this? (Format: displayName, 0xXXX)

![c3c4784f5da4fd666c8b96b6b47988fd.png](/resources/c3c4784f5da4fd666c8b96b6b47988fd.png)

Take a look at the documentation again then we will have to add 0x0002 to 0x00200 which will make 0x202 so the user with this userAccountControl is the one we are looking for

![b35352a6ff553a93b8ae214a129e4a4e.png](/resources/b35352a6ff553a93b8ae214a129e4a4e.png)

There you go!

<details>
  <summary>Answer</summary>
<pre><code>Regina Kirk, 0x202</code></pre>
</details>

>Q7) What is the Common Name of the user whose username does not match the convention firstname.lastname? (Format: Full Name)

![77085caf280c34d0071705a09344e89c.png](/resources/77085caf280c34d0071705a09344e89c.png)

We already got the naming convention of this company which is fullname.lastname@lab.BTLO.com and the only user that does not match this is Royce which did not use full lastname.

<details>
  <summary>Answer</summary>
<pre><code>Royce Nixon</code></pre>
</details>

>Q8) What are the Display Names of the two Group Policy Objects (GPOs) that were created by a domain administrator? List the GPOs in alphabetical order (Format: displayName1, displayName2)

![5af2cbc7faf491779bf4e4a9c274b59a.png](/resources/5af2cbc7faf491779bf4e4a9c274b59a.png)

For this one, we have to expend "CN=System" and "CN=Policies" which we will find 2 familiar CNs that we found in "Administrator" and "krbeth.admin" Desktop so lets get names of these policies and move to the next question.

![35583f165dc1d8f3d1f311d5382d4ddd.png](/resources/35583f165dc1d8f3d1f311d5382d4ddd.png)
<details>
  <summary>Answer</summary>
<pre><code>LAPSSettings, PasswordEnforcement</code></pre>
</details>

>Q9) What are the names of the policy settings being enabled in the first GPO? (Format: rule1, rule2, rule3)

![349a8db600f7839868974e041d0f82fe.png](/resources/349a8db600f7839868974e041d0f82fe.png)

Lets go back to FTK Imager then we could see that "krbeth.admin" is the one created "LAPSSettings" policy.

![edbf098fa9dc95f831635cf493f2638b.png](/resources/edbf098fa9dc95f831635cf493f2638b.png)

Next, we will have to read the content of `gpreport.xml` to get all 3 rules on this policy. 

<details>
  <summary>Answer</summary>
<pre><code>Enable local admin password management, Name of administrator account to manage, Password Settings</code></pre>
</details>

>Q10) What are the Maximum Password Age, Minimum Password Age, Minimum Password Length, and Password History Size in the second GPO? (Format: value1, value2, value3, value4)

![043f7abd113293d76daa346a13cd1db2.png](/resources/043f7abd113293d76daa346a13cd1db2.png)

Its time for "Administrator"'s' policy, read `gpreport.xml` of this policy to get the answer of this question.

<details>
  <summary>Answer</summary>
<pre><code>71, 37, 14, 12</code></pre>
</details>

>Q11) What is the name of the Microsoft program that allows for regular rotation of local administrator passwords? (Format: XXXX)

![ac7c1548da3827690eb2def13127240f.png](/resources/ac7c1548da3827690eb2def13127240f.png)

Microsoft has a feature that can manage local administrator password which is called LAPS or Local Administrator Password Solution.

<details>
  <summary>Answer</summary>
<pre><code>LAPS</code></pre>
</details>

>Q12) What is the name of the Allowed Principals whose members are allowed to view the passwords from the previous question? (Format: String)

![9caa2c01ec17a42a69a64af0a6cb223e.png](/resources/9caa2c01ec17a42a69a64af0a6cb223e.png)

I didn't find this on AD Explorer but on FTK imager which pointing at PowerShell command history of this user responsible for editing the policy.

![9df282624d9cbfdc1b7ccc5612c5fffd.png](/resources/9df282624d9cbfdc1b7ccc5612c5fffd.png)

Then we will see that this user make "LAPSViewers" principals to view LAPS passwords from "Workstations" and "Servers" so we obtained this AD snapshot from "Administrator" which mean we could be able to view LAPS password from these 2 OUs too.

<details>
  <summary>Answer</summary>
<pre><code>LAPSViewers</code></pre>
</details>

>Q13) What is the Common Name of the administrator who is not in the group from the previous question? (Format: Full Name)

![128fc0d436cf7e7bc436680afb447be2.png](/resources/128fc0d436cf7e7bc436680afb447be2.png)

Take a look at LAPSViewers group right here then we should be able to see the only administrator that is not in this group.

<details>
  <summary>Answer</summary>
<pre><code>William Turnstiles</code></pre>
</details>

>Q14) What account and group did the administrator from the previous question determine are the Extended Rights Holders for the Workstations OU? (Format: account, group1, group2)

![4d967aab614893a406d35a4003191383.png](/resources/4d967aab614893a406d35a4003191383.png)

I went back to FTK Imager and found PowerShell history command which indicated that this user piped his Extended Rights Holders for Workstations OU to a file right here.

![f52fe69edcfcfc43051da2a0da363c98.png](/resources/f52fe69edcfcfc43051da2a0da363c98.png)

Read content of that file to get the answer of this question.

<details>
  <summary>Answer</summary>
<pre><code>NT AUTHORITY\SYSTEM, LAB\Domain Admins, LAB\LAPSViewers</code></pre>
</details>

>Q15) What are the local administrator passwords for the company’s workstations? (Format: password1, password2)

![5bf8c7d233529c706a2459f7c5933c0c.png](/resources/5bf8c7d233529c706a2459f7c5933c0c.png)

We already know that we could view LAPS passwords of Workstations and Servers OUs so lets grab them.

![809c8d878e0944a9004e48c5aecc1088.png](/resources/809c8d878e0944a9004e48c5aecc1088.png)
<details>
  <summary>Answer</summary>
<pre><code>-Tn*N}Q&%/_a#>L, DxTX.@)D[):w-#$</code></pre>
</details>

>Q16) LAPS does not store a password’s expiration time in a normal date format. Looking at the company’s servers, what are the first six digits of the default timestamp LAPS uses to show when these local administrator passwords will expire? (Format: XXXXXX)

![e9951fe9ff32cdb772a1a1b1be69b2e6.png](/resources/e9951fe9ff32cdb772a1a1b1be69b2e6.png)

For this one, I asked ChatGPT for help since AD Explorer does not show File Time Format.

![0bc509ff9bd683fb2dc32f60226b6b52.png](/resources/0bc509ff9bd683fb2dc32f60226b6b52.png)

So lets grab this timestamp.

![0235432382c0fdcf9a42b5be75794a59.png](/resources/0235432382c0fdcf9a42b5be75794a59.png)

And convert it to Windows File Time and copy first 6 digits to answer this question.

<details>
  <summary>Answer</summary>
<pre><code>133716</code></pre>
</details>

![5e66ed2b5895dc5f5e8e21d9c14fd38a.png](/resources/5e66ed2b5895dc5f5e8e21d9c14fd38a.png)
https://blueteamlabs.online/achievement/share/52929/192
* * *