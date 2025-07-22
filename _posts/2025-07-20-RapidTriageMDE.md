---
layout:            post
title:             "Rapid Triage of Compromised Device Using MDE"
menutitle:         "Rapid MDE Triage"
category:          DFIR
author:            BSmith
tags:              DFIR, Windows, EDR, IncidentResponse
---

When a device is compromised with malware, a quick triage is essential as a springboard for completing the work of scoping and containment. While a full forensic review and thorough analysis of logs and network telemetry are required, Microsoft's EDR gives a great starting point to begin gathering important answers.

This is a quick post with some observations on useful KQL logic for MDE Advanced Hunting to use in a compromise scenario. The idea is to rapidly assess what a given malicious (or maliciously-used) binary did in a given period of time.

## Lateral movement check

Check for what other network connections were made by a malware sample. This can be useful to identify lateral movement via SSH, SMB, RDP, etc., and can be done either by looking at an executable image or by pivoting on known C2 URLs.

Executable image:
```
//Take the module of a known bad DLL to look up what specific process/instance loaded it
DeviceImageLoadEvents 
| where SHA1 == "<hash of malicious DLL>"
| project DeviceName, InitiatingProcessUniqueId
//Look up that specific process in network events
| join DeviceNetworkEvents on InitiatingProcessUniqueId, DeviceName
//Optionally, remove HTTP/S 
| where not (RemotePort in (80, 443, 8080))
```

Known C2 domains:
```
//Take the specific process that communicated with a known-bad C2 domain and 
DeviceNetworkEvents 
| where RemoteUrl in ("<evildomain.com>", "<definitelyC2.net>", "<badguys.xyz>")
| project DeviceName, InitiatingProcessUniqueId
//Join back to network events to ask "what are ALL of the URLs logged by that process?"
| join DeviceNetworkEvents on InitiatingProcessUniqueId, DeviceName
//Optionally, remove HTTP/S 
| where not (RemotePort in (80, 443, 8080))
```

## Files accessed/modified/created

```
//Take the module of a known bad DLL to look up what specific process/instance loaded it
DeviceImageLoadEvents 
| where SHA1 == "<hash of malicious DLL>"
| project DeviceName, InitiatingProcessUniqueId
//Join to file events to see its activity
| join DeviceFileEvents on DeviceName, InitiatingProcessUniqueId
//Optionally, focus on the read events
| where ActionType contains "Accessed" 
```

## Hunt for other potential domains of interest

This one is courtesy of my guy Glass (https://jon.glass) and inspired a lot of thinking. It takes the resolved IP(s) of known malicious domains and checks for other traffic to those IP addresses. This is quite useful if an adversary has re-used a component of its infrastructure and ends up wih multiple malicious samples phoning out to the same IP via different FQDNs. 

```
//Pull the remote IP of known malicious domains from network traffic
DeviceNetworkEvents
| where RemoteUrl in ("<evildomain.com>", "<definitelyC2.net>", "<badguys.xyz>")
| project RemoteIp
//Join back on network events to check for domains that have a matching IP
| join DeviceNetworkEvents on RemoteIp
```
## A word on InitiatingProcessUniqueID

As of the time of this writing, the InitiatingProcessUniqueID field in MDE is not actually globally unique. In fact, it's not particularly close, and collisions happen frequently (clearly factors like the device's DNS name aren't part of whatever seed value is used to generate that identifier). I haven't seen  