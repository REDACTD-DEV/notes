Command             | Description
------------------- | -----------------------------------------
`uptime`            | Shows how long the system has been running
`df -h`             | Displays disk usage on all mounted disks
`free`              | View memory utilisation
`cat /proc/mounts`  | View mounts on live system
`ps aux`            | Process status of the OS and the currently running processes system and the PID
`lsof -p [pid]`     | Display more details on a particular process
`top`               | Display system resource usage and information about running processes
`netstat -antp`     | Show network connections and associated processes
`tcpdump`           | Capture and analyze network traffic
`arp -a`            | Displays the ARP table, which maps network addresses to physical addresses
`lsmod`             | Displays information about loaded kernel modules
`dmesg`             | Displays system boot messages and other kernel-related messages
`who`               | Displays information about users currently logged into the system
`uname -a`          | Displays system information such as the kernel version, OS version, and processor type
`ifconfig -a \|\| ip a`| Displays information about network interfaces and their configuration
`find /directory -type f -mtime -1 -print`| Finds files in a specified directory modified within the last day and displays their paths
