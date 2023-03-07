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

Mount DD images to a SIFT/Kali machine for analysis
```bash
sudo apt-get install afflib-tools
sudo mkdir /mnt/fuse
sudo affuse ~/Desktop/Image\ Files/able_3.000 /mnt/fuse
sudo mmls /mnt/fuse/able_3.000.raw     
sudo mkdir -p /media/able/ext4_fs0      
sudo mkdir -p /media/able/ext4_fs1      
sudo mkdir -p /media/able/ext4_fs2      
sudo chown -R kali:kali /media/able 
sudo losetup -f -o $((2048*512)) /mnt/fuse/able_3.000.raw     
losetup -a
sudo losetup -f -o $((104448*512)) /mnt/fuse/able_3.000.raw   
losetup -a  
sudo losetup -f -o $((571392*512)) /mnt/fuse/able_3.000.raw    
losetup -a
sudo mount /dev/loop0 /media/able/ext4_fs0     
sudo mount /dev/loop1 /media/able/ext4_fs1     
sudo mount /dev/loop2 /media/able/ext4_fs2     
```

Pull Firefox history
```bash
sqlite3 places.sqlite "SELECT datetime(last_visit_date/1000000,'unixepoch','localtime'),url FROM moz_places"
```
