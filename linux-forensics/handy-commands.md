Create paths to known good binaries for analysis on live machines
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```

Mount EWF images to a SIFT/Kali machine for analysis
```bash
#install ewf-tools
sudo apt install ewf-tools
#mount ewf container
sudo mkdir /mnt/EWF-mount
sudo ewfmount IMAGE.E01 /mnt/EWF-mount/
cd /mnt/EWF-mount/
ls -lah
#mount image
sudo mkdir /mnt/image-mount
sudo mount /mnt/EWF-mount/ewf1 /mnt/image-mount -o ro,loop,show_sys_files,streams_interace=windows 
# cd /mnt/image-mount
# ls -lah 
```

Mount AFF images to a SIFT/Kali machine for analysis
```bash
# Install the AFFLIB tools
sudo apt-get install afflib-tools

# Create a directory for the mounted image file
sudo mkdir /mnt/fuse

# Mount the disk image file onto the directory using AFFUSE tool
sudo affuse ~/Desktop/Image\ Files/able_3.000 /mnt/fuse

# List the partition layout of the mounted disk image using MMLS tool
sudo mmls /mnt/fuse/able_3.000.raw

# Create directories for the loop devices to be mounted on
sudo mkdir -p /media/able/ext4_fs0
sudo mkdir -p /media/able/ext4_fs1
sudo mkdir -p /media/able/ext4_fs2

# Change the ownership of the mount point directories to the user 'kali'
sudo chown -R kali:kali /media/able

# Set up three loop devices for the disk image file at different offsets
# The '-f' option tells losetup to use the first available loop device
# The '-o' option specifies the offset in bytes where the loop device should start
sudo losetup -f -o $((2048*512)) /mnt/fuse/able_3.000.raw
losetup -a
sudo losetup -f -o $((104448*512)) /mnt/fuse/able_3.000.raw
losetup -a
sudo losetup -f -o $((571392*512)) /mnt/fuse/able_3.000.raw
losetup -a

# Mount the loop devices as ext4 filesystems on the directories created earlier
sudo mount /dev/loop0 /media/able/ext4_fs0
sudo mount /dev/loop1 /media/able/ext4_fs1
sudo mount /dev/loop2 /media/able/ext4_fs2
  
```

Pull Firefox history
```bash
sqlite3 places.sqlite "SELECT datetime(last_visit_date/1000000,'unixepoch','localtime'),url FROM moz_places"
```

SQL command that closely matches NirSoft BrowsingHistoryView
```sql
SELECT datetime(last_visit_date/1000000, 'unixepoch') AS VisitTime, -- Select the last visit date column in human-readable format and rename it as VisitTime
       url AS Url, -- Select the URL column and rename it as Url
       title AS Title, -- Select the title column and rename it as Title
       visit_count AS VisitCount -- Select the visit count column and rename it as VisitCount
FROM moz_places -- Select data from the moz_places table
ORDER BY last_visit_date ASC;
```
