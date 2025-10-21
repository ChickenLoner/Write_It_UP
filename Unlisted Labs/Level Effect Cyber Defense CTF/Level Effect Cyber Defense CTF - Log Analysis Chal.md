# Level Effect Cyber Defense CTF Write-up - Log Analysis Challenges (6/6 completeness)
[toc]
***
*NOTE*: This challenge I heavily relied on [Ultimate IT Security Windows Security Log Events Encyclopedia](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/) so I would love to share this wonderful resource to my readers here!
***
## Name that event 1 (100 points)
![9f0a5d9d8503e04ab0785071deafbd84.png](../../_resources/9f0a5d9d8503e04ab0785071deafbd84.png)
I failed to log on. What event ID am I?
***
![36e2c30c561d9bf4efee82e489e5e2d3.png](../../_resources/36e2c30c561d9bf4efee82e489e5e2d3.png)

Easy one. we can just search for "failed" on encyclopedia then we will see that when an account failed to log on, Windows will log this as EventID 4625

```
4625
```
***
## Name that event 2 (100 points)
![6e41a97c5e593e71b9de72112271e3dd.png](../../_resources/6e41a97c5e593e71b9de72112271e3dd.png)
I am newly scheduled. What event ID am I?
***
![6042403830d783985b1b22a3ad8d3f13.png](../../_resources/6042403830d783985b1b22a3ad8d3f13.png)

From this clue, we know that its related to Schedule task and "newly" mean that it just created so Windows will log this as EventID 4698

```
4698
```
***
## Name that event 3 (100 points)
![af48c369a211c8708fcaf9de542ac6bb.png](../../_resources/af48c369a211c8708fcaf9de542ac6bb.png)
I'm up and off to work. What event ID am I?
***
![28adeb35b6840447a3bda45b9960489f.png](../../_resources/28adeb35b6840447a3bda45b9960489f.png)

I was a little bit struggle on this one, at first I thought it might be Event ID 4608 (Windows is starting up) but there is another EventID that came across my mind which is new process started / created and turns out, it was the right answer

```
4688
```
***
## Name that event 4 (100 points)
![5dd0da9682ff74f6dfdc752d392d5883.png](../../_resources/5dd0da9682ff74f6dfdc752d392d5883.png)
I can't remember a thing. What event ID am I?
***
![ecc6f90b8a70bcc5e1f83b8e0eb52ff1.png](../../_resources/ecc6f90b8a70bcc5e1f83b8e0eb52ff1.png)

Can not remember a thing? possible something was cleared

```
1102
```
***
## whoami (100 points)
![e232157079178661c5d2dd74f27acba6.png](../../_resources/e232157079178661c5d2dd74f27acba6.png)
What tactic was the attacker employing based on this command history? (1 word)
***
![945c3788fceae4a7b88a3cccfb2660a8.png](../../_resources/945c3788fceae4a7b88a3cccfb2660a8.png)

After reviewing these commands, we can see that an attacker tried to gain information as much as possible on targeted system and this tactic called Discovery according to MITRE ATT&CK

```
Discovery
```
***
## In the system (150 points)
![ffc31aaf84a002e4dee46203db849e8d.png](../../_resources/ffc31aaf84a002e4dee46203db849e8d.png)
An analyst noticed some suspicious account activity on a workstation. We think the device may be compromised – can you look into this?

[log_chall.evtx](https://leveleffectcda.ctfd.io/files/1c5f28a4c20c7d14afa7a4a95b85746f/log_chall.evtx?token=eyJ1c2VyX2lkIjoxNTE0LCJ0ZWFtX2lkIjpudWxsLCJmaWxlX2lkIjozNX0.ZpP19w.y5J7aZCyHVNtSBfms9uM63IrqTM)
***
![99d0df28900536e3baa4ec6f2db99911.png](../../_resources/99d0df28900536e3baa4ec6f2db99911.png)

After opened this event log, we can see that there are a lot of EventID 4624 (	An account was successfully logged on)

We will have to find any suspicious Account Name on this event log to get a flag, because... well, a flag is in an Account Name as you can see

```
leveleffect{10gg3d}
```
***
![f638b6b3c90842f8b99dac165df45766.png](../../_resources/f638b6b3c90842f8b99dac165df45766.png)
***