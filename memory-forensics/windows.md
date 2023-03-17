# Windows Memory Forensics
## Verify Hashes before doing anything else!
```posh
Get-FileHash -Algorithm MD5 -Path path\to\memory\dump
```

## Volatility3

Windows Info	
```posh
#Includes x32/x64 determination, major and minor OS versions, and kdbg information
python vol.py -f “/path/to/file” windows.info
```

Process Information
```posh
#Volatility 3: Does not include a direct psxview equivalent. psxview shows hidden processes
vol.py -f “/path/to/file” windows.pslist
vol.py -f “/path/to/file” windows.psscan
vol.py -f “/path/to/file” windows.pstree
```

Dump Process by PID
```posh
#Volatility 3: Dumps exe and associated DLLs
python vol.py -f “/path/to/file” -o “/path/to/dir” windows.dumpfiles ‑‑pid <PID>
```

Dump Process Memory by PID
```posh
#Dumps memory associated with a particular PID
python vol.py -f “/path/to/file” -o “/path/to/dir” windows.memmap ‑‑dump ‑‑pid <PID>
```

Handles
```posh
#Volatility 3: PID, process, offset, handlevalue, type, grantedaccess, name
python vol.py -f “/path/to/file” windows.handles ‑‑pid <PID>
```

DLLs
```posh
#Volatility 3: PID, process, offset, handlevalue, type, grantedaccess, name
python vol.py -f “/path/to/file” windows.dlllist ‑‑pid <PID>
#ldrmodules, look for DLL's with FALSE, FALSE, FALSE
python vol.py -f “/path/to/file” windows.ldrmodules ‑‑pid <PID>
```

CMDLINE
```posh
#Volatility 3: PID, process name, args
python vol.py -f “/path/to/file” windows.cmdline
```

Network Information [^network]
[^network]:[Network Connection Timestamps in Memory](https://illusive.com/blog/threat-research-blog/why-and-how-to-extract-network-connection-timestamps-for-dfir-investigations/)
```posh
#Network connections associated with the memory dump
#netscan also includes a creation timestamp becuase it accesses the kernel pool, whereas netstat is usermode
vol.py -f “/path/to/file” windows.netscan
vol.py -f “/path/to/file” windows.netstat
```

Registry
```posh
#hivelist
vol.py -f “/path/to/file” windows.registry.hivescan
vol.py -f “/path/to/file” windows.registry.hivelist
#printkey
vol.py -f “/path/to/file” windows.registry.printkey
vol.py -f “/path/to/file” windows.registry.printkey ‑‑key “Software\Microsoft\Windows\CurrentVersion”
#hivedump is only available in volatility2, however, you may be able to extract registry hives using filedump with the offset
```

Files
```posh
#filescan
vol.py -f “/path/to/file” windows.filescan
#filedump
vol.py -f “/path/to/file” -o “/path/to/dir” windows.dumpfiles
vol.py -f “/path/to/file” -o “/path/to/dir” windows.dumpfiles ‑‑virtaddr <offset>
vol.py -f “/path/to/file” -o “/path/to/dir” windows.dumpfiles ‑‑physaddr <offset>
```

Malfind
```posh
#Volatility 3: PID, process name, process start, protection, commit charge, privatememory, file output, hexdump disassembly
vol.py -f “/path/to/file” windows.malfind
```

Yara
```posh
#yarascan
vol.py -f “/path/to/file” windows.vadyarascan ‑‑yara-rules <string>
vol.py -f “/path/to/file” windows.vadyarascan ‑‑yara-file “/path/to/file.yar”
vol.py -f “/path/to/file” yarascan.yarascan ‑‑yara-file “/path/to/file.yar”
```

## MemProcFS [^memprocfs]
[^memprocfs]:[MemProcFS Wiki](https://github.com/ufrisk/MemProcFS/wiki)

### .\forensic
Only works with -Forensic
MemProcFS forensics performs the batch oriented comprehensive analysis tasks
and outputs the result into a sqlite database and displays the result in the
forensic sub-directory. Analysis tasks include (but are not limited to):    
 - NTFS MFT scanning.                                                       
 - Timeline analysis of Processes, Registry, NTFS MFT, Plugins and more. 
### .\forensic\ntfs
The directory contains a best-effort reconstructed file system reconstructed from NTFS MFT entries located in physical memory. If the files are small enough contents may reside within the NTFS MFT and may be recoverable by opening the file.
### .\forensic\findevil
FindEvil locates signs of malware by analyzing select indicators of evil. FindEvil swiftly discovers certain code injection techniques commonly employed by malware while it is completely unaware of other not-yet implemented indicators.

FindEvil is work in progress. FindEvil will miss certain types of malware while quickly locating others. FindEvil only detects user-mode malware. FindEvil have false positives in its current implementation. FindEvil is only available on 64-bit Windows 11, 10 and 8.1.
### .\forensic\csv

The directory contains a comma separated (csv) files that may be used to import into Excel or Timeline Explorer. Timestamps are in UTC.

| File                      | Description                                   |
| ------------------------- | --------------------------------------------- |
| drivers.csv               | Kernel drivers.                               |
| handles.csv               | Handles related to all processes.             |
| modules.csv               | Loaded modules information.                   |
| process.csv               | Process information.                          |
| services.csv              | Services (user mode and kernel drivers).      |
| tasks.csv                 | Scheduled Tasks.                              |
| threads.csv               | Information about all threads on the system.  |
| timeline_all.csv          | Amalgamation of all timelines.                |
| timeline_kernelobject.csv | Kernel object manager objects.                |
| timeline_net.csv          | Network timeline.                             |
| timeline_ntfs.csv         | NTFS MFT timeline.                            |
| timeline_process.csv      | Process timeline.                             |
| timeline_registry.csv     | Registry timeline.                            |
| timeline_task.csv         | Scheduled Tasks timeline.                     |
| timeline_thread.csv       | Threading timeline.                           |
| timeline_web.csv          | Web timeline.                                 |
| unloaded_modules.csv      | Unloaded modules information.                 |

### .\misc\bitlocker
The bitlocker plugin is loosely based on the excellent [bitlocker volatility](https://github.com/breppo/Volatility-BitLocker) plugin. The MemProcFS plugin uses the same underlying technique of identifying potential bitlocker keys by pool tagging and other heuristics. The MemProcFS plugin also does some post-processing to increase output quality.

The bitlocker plugin works quite well on Windows 7 and Windows 10/11. Issues however exists on Windows 8 (and early Windows 10) versions where multiple keys may be recovered in error. At least one key should however most often be correct even on Windows 8 and early Windows 10 versions.

In order to mount a recovered bitlocker key it's recommended to use dislocker on a Linux system. Please use the recovered _.fvek_ key.
```bash
dislocker -k <recovered_key>.fvek /path/to/disk /path/to/dislocker          
mount /path/to/dislocker/dislocker-file /path/to/mount
```

### .\misc\web
The directory contains web browser related information such as browser history from supported web browsers.

| Supported Browser     |
| --------------------- |
| Google Chrome         |
| Microsoft Edge (new)  |
| Firefox               |

### .\registry\hive_files
Entire registry hives that can be processed by other tools like Registry Explorer or RegRipper

### .\sys
The directory contains directories and files displaying various system information.
The files in the **sys** directory are listed in the table below:
| File              | Description                                                             |
| ----------------- | ----------------------------------------------------------------------- |
| computername.txt  | Name of the computer                                                    |
| time-boot.txt     | Time of system boot                                                     |
| time-current.txt  | Time of system                                                          |
| timezone.txt      | TimeZone of system                                                      |
| unique-tag.txt    | MemProcFS derived ID for the current memory image                       |
| version.txt       | Operating system version on format: major.minor.build                   |
| version-major.txt | Operating system major version                                          |
| version-minor.txt | Operating system minor version                                          |
| version-build.txt | Operating system build number                                           |

### .\sys\net
Contains a listing of active TCP connections similar to netstat -ano
Does not give connection times like volatility

### .\sys\proc
The file proc.txt contains a per-pid tree view of the known processes in the system. The view includes all processes including terminated ones.

### .\sys\services
Contains information about services extracted from the service control manager (SCM)
The files in the **sys/services** directory are listed in the table below:
| File                           | Description                                               |
| ------------------------------ | --------------------------------------------------------- |
| __services.txt__               | Summary information about all services listed by ordinal. |
| by-id/[id]/registry/           | Service registry key.                                     |
| by-id/[id]/__svcinfo.txt__     | Detailed information about each service.                  |
| by-name/[name]/registry/       | Service registry key.                                     |
| by-name/[name]/__svcinfo.txt__ | Detailed information about each service.                  |

### .\sys\tasks
Contains information about scheduled tasks extracted from the registry.

### .\sys\users
information about the users on the system.
```
   # Username                         SID
-----------------------------------------
0000 SANSDFIR                         S-1-5-21-1552841522-3835366585-4197357653-1001
...
```
## MemProcFS-Analyzer
MemProcFS-Analyzer is a PowerShell script that mounts the memory file and then runs forensic tools against the mount in an automated fashion.

### AmcacheParser [^amcache]
[^amcache]:[AmcacheParser](https://thesecuritynoob.com/dfir-tools/dfir-tools-amcacheparser-what-is-it-how-to-use/)

Amcache.hve is a small registry hive that stores a wealth of information about recently run applications and programs, including full path, file timestamps, and file SHA1 hash value, it is commonly found at the following location: 
```C:\Windows\AppCompat\Programs\Amcache.hve```

### AppCompatCacheParser[^AppCompatCacheParser]
[^AppCompatCacheParser]:[AppCompatCacheParser](https://thesecuritynoob.com/dfir-tools/dfir-tools-amcacheparser-what-is-it-how-to-use-2/)

Shimcache, also known as AppCompatCache, is a component of the Application Compatibility Database, which was created by Microsoft and used by the Windows operating system to identify application compatibility issues. This helps developers troubleshoot legacy functions and contains data related to Windows features. It is used for quick search to decide whether modules need shimming for compatibility or not.

A Shim is a small library that transparently handles the applications interworking’s to provide support for older APIs in a newer environment or vice-versa. Shims allow backwards and forwards compatibility for applications on different software platforms.

The Registry Key related to this cache can be found and located as below.

```HKLM\SYSTEM\CurrentControlSet\Control\SessionManager\AppCompatCache\AppCompatCache```

### EvtxECmd
A Windows Event Log file parser that bypasses the Windows API.  There are a lot of advantages to a tool such as this; specifically by bypassing the API it doesn't succumb to the 'hiccups' that may occur as a result of files that weren't closed properly or for some other reason isn't formatted in a manner the API agrees with. This is especially important for memory forensics.

### IpInfo CLI
Takes all public IP addresses found in ``` .\sys\net ``` and generates GeoIP information on them

### lnk_parser
Yara is run against ``` .\forenisc\ntfs\ ``` to pull all .lnk files. lnk_parser then generates a CSV that contains the following items
- LNK Full Path
- LNK Modification Time
- LNK Access Time
- LNK Creation Time
- Target Full Path
- Working Directory
- Arguments
- Relative Path
- Icon Location
- Local Base Path
- Shortcut Key
- LNK Size
- MD5
- SHA1
- SHA256
- Entropy

It then uses this CSV to hunt for known suspicious/malicious lnk files. These include:
- ```C:\Google\AutoIt3.exe```
- ```C:\Windows\System32\cmd.exe```
- ```C:\Windows\System32\mshta.exe```
- ```C:\Windows\System32\msiexec.exe```
- ```C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe```
- ```C:\Windows\System32\rundll32.exe```
- ```C:\Windows\System32\schtasks.exe```
- ```C:\Windows\System32\wscript.exe```
- Long arguments (more than 50 characters)
- Long whitespace (more than 3 characters)
- LNK contains http:// or https://
- suspicious LNK file size
- Entropy > 6.5
