---
title: "Certified Red Team Lead (CRTL) Review -- Struggle and Joy Certification"
author: x4sh3s
date: 2023-12-06 0:32:00 +0100
categories: [Defense Evasion, Certifications Review]
tags: [C2, EDR, Process_Injection, windows ]
image:
  path: /commons/redcat.png
  width: 730
  height: 380
  alt: 
---

In this post, i'll be reviewing CRTL certification, my learning and exam experience with some tips and resources.

## Introduction

After successfully obtaining my CRTO certification on July 4, I immediately purchased the next course in line, CRTL (CRTO II). I wasn't fully prepared for it, but I bought it anyway to push myself to study. I was eager to enhance my red teaming skills, particularly on the research side, making CRTL the logical next step.
![Amsi Bypass](/commons/CRTL.png)

## Background

As mentioned, I already have my CRTO and a background in red teaming and malware development from internships, work, and personal projects. This background played a crucial role in passing the exam, as CRTL doesn't cover basics, especially AD attacks, lateral movements, and using Cobalt Strike C2.

If pursuing this certification without the previous one, ensure comfort with Cobalt Strike and CRTO's contents, listed here, focusing on Kerberos attacks, lateral movements, domain reconnaissance, and privilege escalation.

## Content

CRTL-2 focuses more on the research side of red teaming, involving advanced tooling development and evading defenses. The objectives, as stated on the site, include:

- Building secure on-premise C2 infrastructure using public cloud redirectors and HTTPS.
- Going deeper into C++ and C# programming with Windows APIs.
- Writing custom tooling for offensive actions like process injection, PPID spoofing, and command line spoofing.
- Cleaning up memory indicators of Cobalt Strike's Beacon and leveraging in-memory obfuscation.
- Strategies for enumerating, identifying, and exploiting weaknesses in Attack Surface Reduction and Windows Defender Application Control technologies.
- Bypassing AV and EDR agents through circumventing ETW, userland hooking, and kernel callbacks.
- The CRTL-2 course is divided into eight chapters:

1. C2 Infrastructure
1. Windows APIs
1. Process Injection
1. Defense Evasion
1. Attack Surface Reduction
1. Windows Defender Application Control
1. Protected Processes
1. EDR Evasion

The first chapter describes building a secure C2 infrastructure using SSH tunneling, Apache redirection rules, and custom C2 malleable profiles.

The Windows APIs and Process Injection chapters discuss how these APIs are used in C++ and C# to perform various actions, including process injections using different techniques such as APC Injection and section mapping.

The subsequent chapters explain bypassing defense solutions like EDR, ASR, and WDAC, covering manual and Cobalt Strike provided features.

## Exam

The exam was challenging yet enjoyable, with a substantial sense of accomplishment after finding each flag. One downside was a particular flag, which I believe was unfair considering the certification's name, prerequisites, and course content. i was really stuck for more than 5h wandering what should i do ..?

![Amsi Bypass](/commons/mrrobot.gif)

Despite some flags being difficult, the overall experience was fun. The exam took 25 hours out of the allotted 72, providing a lot of time without excessive stress.
![CRTL's Badge](/commons/flags.png)

Few days after i've submited all the flags, i received this email:
![CRTL's Badge](/commons/BADGE.png)

## Tips

Here are some tips that helped me during the exam:

- Master the course's prerequisites
- Take notes during studying
- Practice before the exam
- Take long breaks during the exam.
- Have a look at the resources and the tools.

## Tools & Resources

Here are some useful resources and tools to be comfortable with before taking the exam:

- [Certified Pre-Owned](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
- [Malleable C2 Profiles](https://github.com/BC-SECURITY/Malleable-C2-Profiles)
- [Ultimate WDAC Bypass List](https://github.com/bohops/UltimateWDACBypassList)
- [Cheat Sheets](https://github.com/HarmJ0y/CheatSheets)
- [A Tale of EDR Bypass Methods](https://s3cur3th1ssh1t.github.io/A-tale-of-EDR-bypass-methods/)
- [Payloads All The Things - Active Directory Attack](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md)

### Tools

- Rubeus
- Certify
- Powerview
- ADSearch
- Cobalt Strike

## Conclusion

As mentioned, the exam was challenging but provided a valuable learning experience. Like any course, it has its pros and cons:

### Cons

- Poor exam environment: slow, lagging, copy-paste issues.
- Limited content; could be more enriched, especially regarding Windows API and process injection techniques.
- Some important notes essential for passing the exam were missing.

### Pros

- Good content.
- Fair pricing.
- Straight-to-the-point explanations.
- Sufficient exam time.

## What's Next?

I still want to focus more on red teaming, especially malware development and red team infrastructure. Although unsure about the next certification, I might focus on personal research, delving deeper into advanced techniques and exploring kernel mode and rootkit development.
