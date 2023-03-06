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

Pull Firefox history
```bash
sqlite3 places.sqlite "SELECT datetime(last_visit_date/1000000,'unixepoch','localtime'),url FROM moz_places"
```
