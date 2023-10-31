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

<img src="/media/img/QuickAssist1/QuickAssistLanding1.PNG" width="300"> <img src="/media/img/QuickAssist1/QuickAssistLanding2.PNG" width="300">

<div id="image-table" alight="center">
    <table>
	    <tr>
    	    <td style="padding:10px">
        	    <img src="/media/img/QuickAssist1/QuickAssistLanding1.PNG" width="300"/>
      	    </td>
            <td style="padding:10px">
            	<img src="/media/img/QuickAssist1/QuickAssistLanding2.PNG" width="300"/>
            </td>
        </tr>
    </table>
</div>

The TL;DR on Quick Assist is that it uses HTTPS over Microsoft domains to establish an RDP session between hosts. It's described in better detail [by Microsoft](https://learn.microsoft.com/en-us/windows/client-management/client-tools/quick-assist). 

![](/media/img/QuickAssist1/quickassistflow.png)

## External threat scenario

Consider two social engineering scenarios:

Scenario 1: A stranger claiming to be with your help desk rings your user and tells her that there's a security issue with her device. To fix it, the stranger asks your user to download ultraviewer.exe, then read off the newly generated ID and password before clicking to allow access. 

In this case, I think we can hope that our user is wise enough for this to appear suspicious. She's being asked to download something from an external domain (which our AV engine gets a crack at), then give the adversary whatever she needs to begin a session.

Scenario 2: A stranger-- also claiming to be from IT-- rings your user and gives the same line about a security issue. But this time, our stranger claims that the user won't need to download anything, because IT has already placed the requisite program on her device. Instead, all she has to do is press Windows+CTRL+Q. From there, our stranger reads off a six digit code to be entered by the user, and a session is underway. 

With this second scenario, the attacker has undermined quite a few elements that could cause suspicion, and has a shot at gaining access to the device using what amounts to a LOLBAS RAT. She can pop open a Powershell window, download cradle a second stage, and be off to the races. 

If you're social engineering for access with any other tool, why?

## Challenges for Monitoring, Detecting, and Investigating

Quick Assist presents a slew of problems for those who have a need to keep an eye on it. 

First of all, it's hard spot a connection in network logs. When quickassist.exe is launched, it immediately loads multiple msedgewebview2 processes and resolves remoteassistance.support.services.microsoft.com to load the landing screen shown above. So not every Quick Assist launch-- or even every DNS request by Quick Assist-- is indicative of a sharing session. Plus, session creation does not involve the creation of any new child processes, or even additional module loads. Even the call to the Win32 screenshot API is performed on initial launch.

You're also probably not even logging the DNS activity associated with a connection at the host level. The widely-used SwiftOnSecurity configuration for Sysmon saves storage by suppressing logging for some extremely well-traveled domains, among which is every subdomain of microsoft.com. This means that the entire infrastructure used for session establishment is suppressed.

![](/media/img/QuickAssist1/SysmonConfig.PNG)

If asked to pick something that would not create event logs, this would not have been my choice. But there's no event log created by this tool to reflect any stage of session establishment, remote control, or session termination. Application/services logs do contain a Remote Assistance/Operational evtx events, but these seem to be related to components of the legacy Remote Assistance tool. Events there that pertain to Remote Assistance COM server do not correspond with Quick Assist usage. 

Finally, a network layer block to lock down usage of this tool isn't straightforward. It's all in Microsoft IP space. Moreover, the DNS requests used to set up a session return a series of CNAME records before finally resolving an IP. That means outside of sinkholing specific requests, a host-side control is the best option.

## Investigating

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

