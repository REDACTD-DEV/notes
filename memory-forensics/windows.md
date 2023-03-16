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
```

CMDLINE
```posh
#Volatility 3: PID, process name, args
python vol.py -f “/path/to/file” windows.cmdline
```

Network Information [^network]
[^network]:[Why and How to Extract Network Connection Timestamps for DFIR Investigations](https://illusive.com/blog/threat-research-blog/why-and-how-to-extract-network-connection-timestamps-for-dfir-investigations/)
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
