# RustBird (Early Bird APC Injection in Rust)

<p align="left">
	<a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/made%20with-Rust-red"></a>
	<a href="#"><img src="https://img.shields.io/badge/platform-windows-blueviolet"></a>
</p>

![rustbird](https://static.wikia.nocookie.net/finalfantasy/images/9/90/Rust_Bird_from_FFIII_Pixel_Remaster_sprite.png)

## Overview
The technique known as "Early Bird APC Injection" is used to inject malicious code into the legitimate processes of a Windows operating system. This method inserts malicious code into a process during its early stages, often before the main routines of the process are activated. It also features enhanced antivirus evasion capabilities through the implementation of a Block DLL Policy, which prevents the loading of DLLs not signed by Microsoft, the use of Zw* functions from undocumented APIs in the Windows Kernel, and the utilization of DLL sideloading.

## Generate Payload using MSFvenom
```
msfvenom -p windows/x64/exec cmd="calc.exe" -f raw -o raw.bin
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 276 bytes
Saved as: raw.bin
```

## Payload Encryption
RC4 Encrypt Payload: https://github.com/c2pain/RC4_Encryptor

Example:
```
C:\Users\C2Pain\Desktop> rc4_encryptor.exe raw.bin
[+] Encrypted shellcode saved to: r-a-w-4.enc
```

## DLL Sideloading
Using Dism.exe as an example, it has been noted that it loads DismCore.dll.

To locate the exported functions, you can use: https://github.com/c2pain/RustGetExports

You can then include the exported functions to the lib.rs.
```
RustGetExports.exe C:\Windows\System32\Dism\DismCore.dll
DismCore.dll
DllCanUnloadNow
DllGetClassObject
DllRegisterServer
```

## Usage 
You need to compiled the binary and copy C:\Windows\System32\Dism.exe to the same directory to run:
```
cargo build --release
```

## AV/EDR Testing Result on x64 Windows 10/11
Test Date: 5 Oct 2024
| AV/EDR Product | Execute |
| ------ | ------ |
| Microsoft Defender | :white_check_mark: |
| Norton 360 Deluxe | :white_check_mark: |
| McAfee | :white_check_mark: |

## Screenshots
![spawn-calc](/screenshots/spawn-calc.png)

## Reference and Credits
[RustRedOps](https://github.com/joaoviictorti/RustRedOps) by @joaoviictorti

[Hijack Execution Flow: DLL Side-Loading](https://attack.mitre.org/techniques/T1574/002/)

[Final Fantasy Wiki - Enemies in Final Fantasy III](https://finalfantasy.fandom.com/wiki/Rust_Bird)

## Full Disclaimer
For educational purposes only. Any actions and or activities related to the material contained within this repository is solely your responsibility. The misuse of the tools in this repo could result in criminal charges being brought against the persons in question. The author will not be held responsible in the event any criminal charges are brought against any individuals misusing the tools in this repository for mailicious ourposes or to break the law.
