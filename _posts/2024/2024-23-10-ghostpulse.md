---
layout: post
title: Campaign Analysis - GhostPulse
date: 23-10-2024
categories: [Emerging Threats, Malware]
tag: [Malware, Emerging Threats]
---

![Banner ghostpulse](assets/images/blogs/ghostpulse/Banner-ghostpulse.png)

On the 27th October 2024, [Elastic Security Labs](https://www.elastic.co/security-labs/ghostpulse-haunts-victims-using-defense-evasion-bag-o-tricks#stage-2) followed a campaign to compromise users with signed [MSIX](https://learn.microsoft.com/en-us/windows/msix/overview) application packages to gain initial access. The campaign leverages a stealthy loader that Elastic has named GHOSTPULSE, which decrypts and loads a final payload capable of evading detection. In October 2024, [Elastic Security Labs]() posted an update to this campaign, where the GhostPulse loader hides inside a `.png` image using stegonography, eventually demploying itself and loading the **Lumma InfoStealer**

In this post, I will be covering this campaign from the beginning and right up to October 2024, analysing the malware samples as I go, and providing context on the technical aspects that allows these novel techniques to work.