---
layout:            post
title:             "Investigating Microsoft Quick Assist"
menutitle:         "Microsoft Quick Assist"
category:          DFIR
author:            BSmith
tags:              DFIR, Windows, Remote Access, IncidentResponse
---

Quick Assist is Microsoft's native remote access solution for tunneling a desktop connection across the internet. It enables a user to troubleshoot printer issues for family members from the comfort of their home. 

It's also potentially of great value to attackers. And it ain't exactly easy to monitor or investigate.

## How does it work?

Quick Assist is enabled by default on all standard Windows deployments. Feel free to read that again. 
To use it, the remote party (**client** for our purposes-- the one who will be viewing/controlling the other device) opens quickassist.exe from her device. She clicks "Help someone," logs in with an arbitrary Microsoft account, and is given a 6-character code to provide to the target. This target (**server** here-- the one whose device will be viewed/controlled) enters the 6-character code, clicks allow, and the screen is shared. From there, the client can request full control of the device.

<p float="center">
  <img src="/media/img/QuickAssist1/QuickAssistLanding1.PNG" width="46%" />
  <img src="/media/img/QuickAssist1/QuickAssistLanding2.PNG" width="46%" />
</p>

## External threat scenario

Consider two social engineering scenarios:

Scenario 1: A stranger claiming to be with your help desk rings your user and tells her that there's a security issue with her device. To fix it, the stranger asks your user to download ultraviewer.exe, then read off the newly generated ID and password before clicking to allow access. 

In this case, I think we can hope that our user is wise enough for this to appear suspicious. She's being asked to download something from an external domain (which our AV engine gets a crack at), then give the adversary whatever she needs to begin a session.

Scenario 2: A stranger-- also claiming to be from IT-- rings your user and gives the same line about a security issue. But this time, our stranger claims that the user won't need to download anything, because IT has already placed the requisite program on her device. Instead, all she has to do is press Windows+CTRL+Q. From there, our stranger reads off a six digit code to be entered by the user, and a session is underway. 

With this second scenario, the attacker has undermined quite a few elements that could cause suspicion, and has a shot at gaining access to the device using what amounts to a LOLBAS RAT. She can pop open a Powershell window, download cradle a second stage, and be off to the races. 

## This does something bold! (h2)

And then we can keep on truckin'

## Does python work? (h2)

Text text text text

```python
import pty;
pty.spawn("/bin/bash")
```

#### Yeah but what about a picture? (h4)
<figure>
   <img src="{{ "/assets/bliss.jpg" | absolute_url }}" />
   <figcaption>A nice field</figcaption>
</figure>

