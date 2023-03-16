# Windows Memory Forensics
## Volatility3
	### Windows Info
	```posh
	#Includes x32/x64 determination, major and minor OS versions, and kdbg information
	python vol.py -f “/path/to/file” windows.info
	```
	
	### Process Information
	```posh
	#Volatility 3: Does not include a direct psxview equivalent. psxview shows hidden processes
    vol.py -f “/path/to/file” windows.pslist
    vol.py -f “/path/to/file” windows.psscan
    vol.py -f “/path/to/file” windows.pstree
	```

    ### Dump Process by PID
	```posh
	#Volatility 3: Dumps exe and associated DLLs
	python vol.py -f “/path/to/file” -o “/path/to/dir” windows.dumpfiles ‑‑pid <PID>
	```

    ### Dump Process Memory by PID
	```posh
	#Dumps memory associated with a particular PID
	python vol.py -f “/path/to/file” -o “/path/to/dir” windows.memmap ‑‑dump ‑‑pid <PID>
    ```

    ### Handles
	```posh
	#Volatility 3: PID, process, offset, handlevalue, type, grantedaccess, name
	python vol.py -f “/path/to/file” windows.handles ‑‑pid <PID>
    ```

    ### DLLs
	```posh
	#Volatility 3: PID, process, offset, handlevalue, type, grantedaccess, name
	python vol.py -f “/path/to/file” windows.dlllist ‑‑pid <PID>
    ```
