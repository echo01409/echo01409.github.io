---
layout: post
title:  Return of the Phemedrone Stealer - Part One
date: 2025-06-20
categories: [Malware, Loader, DotNet]
tag: [Malware, Loader, DotNet]
---

<img src="assets/images/blogs/Phenedrome/Phen-Banner-part1.png" alt="Phen Banner" width="800" height="500">


## Overview

A few days ago, I was scrolling X (formally Twitter) where I follow other people in the cyber community, and came across [a post](https://twitter.com/1ZRR4H/status/1933245219748581862) about a threat actor impersonating the AnyDesk website to socially engineer victims into downloading malware. [AnyDesk](https://anydesk.com/en) is a remote mangement and monitoring (RMM) tool that has platform-independant remote access solutions that IT support can use to service users in their organisations. Over the years, we've seen many of these malvertising type attacks and service impoeronation attacks to trick victims.

Although I've analysed the full infection chain at this point, for this Part 1 blog, I decided to follow the first half of the infection chain - that being a `.NET` loader used to download, stage, and execute the Phemedrone Stealer.

{: .prompt-warning }
> **WARNING:** At the time of writing, `hxxps://anydeske[.]icu` is still up and is run by threat actors. Unless you **ACTUALLY** know what you're doing, don't browse to it - particularly because you run the risk of malicious JavaScript code being run in the browser and you're details being logged by the web server.

## Execution Flow

TL;DR, this is what's going on with the loader:

* Loader is dropped onto the victim machine through phishing, malvertising, or through the malicious AnyDesk website `"anydeske[.]icu"`
* The loader runs and the URL bytes are decrypted
* A handle is opened to the URL `"hxxps://anydeske[.]icu/download/enstall[.]exe"`, where `enstall.exe` is downloaded, remaned to `saturn.exe`, and saved into `%TEMP%`
* The loader then sets Microsoft Defender exclusion paths for `C:\ProgramData` and `$env:TEMP`
* The loader runs `saturn.exe` (Phenodrone Stealer)

## Stage 1 - The fake website

As mentioned in the Overview section, the campaign begins with a fake AnyDesk website that the victim is tricked into visiting. This could either be by pushing the fake site in Google Ads, or impersonating internal IT support and pushing the link through a phishing email. 

<img src="assets/images/blogs/Phenedrome/fake-anydesk.jpeg" alt="fake anydesk website clone" width="500" height="500">

The image above shows the fake website, and below is the real one:

<img src="assets/images/blogs/Phenedrome/real-anydesk.png" alt="fake anydesk website clone" width="500" height="500">

Both look very similar, minus a few small UI differences like the dark mode option. The fake website is being hosted at `anydeske[.]icu`. This domain gets used by the loader, which we'll discuss next.


## Stage 2 - The Loader

The original [twitter post](https://twitter.com/1ZRR4H/status/1933245219748581862) outlines that the fake AnyDesk website is used to download the loader, though, through analysis I found a slightly different use for the fake website by the loader. The loader itself is written in `.NET` and is deployed to preapre the victim machine for the download and running of the Phemedrone Stealer - we'll discuss exactly how the loader works here.

Below is the `Main()` function of the loader, and the first thing I noticed was the Cyrillic language, specifically Russian. The table below shows the Russian and the translations:

| Russian                                   | English  |
|----------                                 |----------|
| Инициализация...                          | Initialisation...                 |
| Выполняется предварительная подготовка... | Performing Pre-Initialisation...  |
| Произошла ошибка:                         | An error occured: Message         |

With the above in mind, let's break down the `Main()` function itself:

<img src="assets/images/blogs/Phenedrome/loader-main.png" alt="main function for the loader" width="500" height="500">

Firstly, we have a variable called `encryptedURL` that contains a number of bytes:

```cs
byte[] encryptedUrl = new byte[]
    {
        107, 168, 189, 208, 201, 153, 233, 71, 150, 99,
        5, 7, 97, 187, 176, 72, 190, 206, 253, 64,
        195, 158, 160, 195, 109, 201, 93, 226, 202, 120,
        242, 117, 77, 16, 14, 191, 111, 7, 148, 128,
        172, 102, 124, 158, 66, 109, 238, 166, 104, 29,
        42, 97, 175, 124, 45, 235, 27, 37, 86, 121,
        192, 132, 167, 18
    };
```

The list of decimal values above is an AES-encrypted byte array that contains a URL. The first 16 bytes act as the initialization vector (IV), and the rest are the ciphertext. A 256-bit decryption key is derived using `PBKDF2` with the hardcoded password `"FoxMalder3301"`, a salt of `"SaltValueForUrlDecryption"`, `10,000` iterations, and SHA1 as the hash function. The AES cipher runs in `CBC` mode to decrypt the ciphertext using the derived key and IV. After decryption, the result is unpadded using `PKCS7` padding rules to recover the original plaintext string, which is the final URL used by the malware.

I've written a Python script that automates the decryption process below, you'd just need to pass the bytes, password, and salt to it:


```python
import re
import hashlib
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA1 

url_data = """
0x6B, 0xA8, 0xBD, 0xD0, 0xC9, 0x99, 0xE9, 0x47, 0x96, 0x63,
0x05, 0x07, 0x61, 0xBB, 0xB0, 0x48, 0xBE, 0xCE, 0xFD, 0x40,
0xC3, 0x9E, 0xA0, 0xC3, 0x6D, 0xC9, 0x5D, 0xE2, 0xCA, 0x78,
0xF2, 0x75, 0x4D, 0x10, 0x0E, 0xBF, 0x6F, 0x07, 0x94, 0x80,
0xAC, 0x66, 0x7C, 0x9E, 0x42, 0x6D, 0xEE, 0xA6, 0x68, 0x1D,
0x2A, 0x61, 0xAF, 0x7C, 0x2D, 0xEB, 0x1B, 0x25, 0x56, 0x79,
0xC0, 0x84, 0xA7, 0x12
"""
def remove_pkcs7_padding(data):
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Invalid PKCS7 padding")
    return data[:-pad_len]

url_hex_values = re.findall(r'0x([0-9A-Fa-f]{2})', url_data)
url_bytes = bytes.fromhex("".join(url_hex_values))

password = b"FoxMalder3301"
salt = b"SaltValueForUrlDecryption"
key = PBKDF2(password, salt, dkLen=32, count=10000, hmac_hash_module=SHA1)

iv = url_bytes[:16]
ciphertext = url_bytes[16:]

cipher = AES.new(key, AES.MODE_CBC, iv)
plaintext_padded = cipher.decrypt(ciphertext)
plaintext = remove_pkcs7_padding(plaintext_padded)

print("[-] Derived AES-256 Key:", key.hex().upper())
print("[-] Decrypted URL:", plaintext.decode("utf-8"))
```

The output I got from the script is below:

<img src="assets/images/blogs/Phenedrome/load-extract-output.png" alt="location of salt and iteration count" width="800" height="800">

In terms of how I found this inofmraiton in the loader, the password `"FoxMalder3301"` was in the `Main()` function, and the salt `"SaltValueForUrlDecryption"` was hardcoded in the `GenerateSecureKey` method, the iteration count was specificed right after the salt string:


<img src="assets/images/blogs/Phenedrome/salt-location.png" alt="location of salt and iteration count" width="800" height="800">


The information outlined above can also be obtained dynamically by running the program in an isolated environment and setting breakpoints at the resolution of each instruction - below is the decrypted domain and a directory location:

<img src="assets/images/blogs/Phenedrome/domain-and-location.png" alt="domain and install directory" width="800" height="800">

Specifcially, the loader contacts the domain, downloads an executable file called `"enstall.exe"` [(VirusTotal)](https://www.virustotal.com/gui/file/29c5fe838dbcf78b8e6c77c60cd8a2e6c19515b6cd986e11d3b3e4af5fe61c73/detection), remanes it to `"saturn.exe"`, and saves it to `C:\Users\Username\AppData\Local\Temp`. `"enstall.exe"` is the actual Phemedrone Stealer which will be covered in the next section, but before it's run, the loader has a few more tasks it does to ready the victim machine.

If the Stealer was run without checking and disabling security, there's a really good chance it would be stopped from running, considering its a couple of years old now and has been signitured - As such, the loader writes a Windows Defender exclusion path.

<img src="assets/images/blogs/Phenedrome/defender-exclusion.png" alt="defender exclusion path" width="800" height="800">

It starts by getting the first folder path it it's list, shown below, which resolves to `C:\ProgramData`.

```cs
string folderPath = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
```

Next, it builds the command componants:

```cs
string text2 = "Add-MpPreference";
string text3 = "-ExclusionPath";
```

Following this, it constructs the full exclusion command:

```cs
string text4 = "Add-MpPreference -ExclusionPath \"C:\\ProgramData\""
```

Underneath, there is a bytes block that, when decoded to it's ASCII equivalaent, resolves to `Add-MpPreference -ExclusionPath $env:TEMP`

```cs
byte[] array3 = {
  65, 100, 100, 45, 77, 112, 80, 114, 101, 102,
  101, 114, 101, 110, 99, 101, 32, 45, 69, 120,
  99, 108, 117, 115, 105, 111, 110, 80, 97, 116,
  104, 32, 36, 101, 110, 118, 58, 84, 69, 77,
  80
};
```

So, what you end up with is two exclusions:

```cs
Program.ExecutePowerShellCommand(text4);  // Excludes ProgramData (text4 is ProgramData)
Program.ExecutePowerShellCommand(text5);  // Excludes %TEMP% (text5 is temp)
```

Finally, the downloaded file `"saturn.exe"` (The Phemedrone Stealer) is executed.

<img src="assets/images/blogs/Phenedrome/loader-exe-run.png" alt="Run the stealer" width="800" height="800">

## Indicators of Compromise

| Indicator Type                            | Value  |
|----------                                 |----------|
| SHA256 hash                               | `b1edc65392305bb7062c86930baae32ead04731e9dbd806ab6a5c382e9e52e3f`|
| Second stage domain                       | `"hxxps://anydeske[.]icu/download/enstall[.]exe"`|
| Exclusion path string1                    | `"Add-MpPreference -ExclusionPath \"C:\\ProgramData\"`|
| Exclusion path string2                    | `string text2 = "Add-MpPreference";`|
| Exclusion path string3                    | `string text3 = "-ExclusionPath";`|





## Conclusion

Okay, that was Part One. As I was writing this, I decided to split the campaign off into two parts as there is quite allot here. The Loader has been pretty simple, with little to no obfuscation or defence evasion. I've not really placed any focus on detecting the loader, since it's really simple and threat actors will change their methods of loading malware very regularly. In Part Two though, I'll cover the Phemodrone Stealer itself, by reverse engineering it and highlighting it's core functionality.



























