---  
share: true  
---  
  
### Extract the zip file  
```powershell  
'C:\Program Files\7-Zip\7z.exe' x .\Desktop\itunes.7z  
```  
  
### Convert manifest.plist to a hash that can be cracked with hashcat  
```powershell  
'perl' .\Downloads\itunes_backup2hashcat-master\itunes_backup2hashcat.pl C:\Users\User\Desktop\7888649912b394b6abbae8a5c94a45c312c9f316\Manifest.plist  
```  
```$itunes_backup$*10*6156796dfab06a60017beaed787d42477bd9bb1fa72d196f468a86e79fed2fe0dcb55bb2206b8001*10000*f034055dc86c9b1774a9e01d515b7b29b05f90b0*10000000*353941cce18704300d424e01ca215c6cb6488c6a```  
  
### Crack with hashcat  
```powershell  
'.\hashcat.exe' -m 14800 .\hashes.txt .\rockyou.txt  
```  
```rickastleyftw```  
  
### Decrypt into a new folder, ensures whichever tools you work with won't error out if they don't support encrypted backups  
```powershell  
'.\Downloads\iTunes_Backup_Reader.exe' -i .\Desktop\7888649912b394b6abbae8a5c94a45c312c9f316\ -o .\Desktop\decrypted -t db -d -p rickastleyftw  
```  
  
```  
  
  _ _____                   ___          _               ___             _  
 (_)_   _|  _ _ _  ___ ___ | _ ) __ _ __| |___  _ _ __  | _ \___ __ _ __| |___ _ _  
 | | | || || | ' \/ -_|_-< | _ \/ _` / _| / / || | '_ \ |   / -_) _` / _` / -_) '_|  
 |_| |_| \_,_|_||_\___/__/_|___/\__,_\__|_\_\_,_| .__/_|_|_\___\__,_\__,_\___|_|  
                        |___|                    |_| |___|  
  
  
Written by Jack Farley  
  
06-20 03:03 root         INFO     Starting to read backup at: .\Desktop\7888649912b394b6abbae8a5c94a45c312c9f316\  
06-20 03:03 root         INFO     Starting decryption of the Manifest.db  
06-20 03:03 root         INFO     Successfully decrypted Manifest.db!  
06-20 03:03 root         INFO     Program ended in: 6.929254770278931 seconds  
```  
  
### Parse with ILEAPP  
![[Pasted image 20230620132121.png]]  
  
### Flag 1 - Deleted message  
![[Pasted image 20230620132405.png]]  
  
### Flag 2 - Deleted Note  
Knowing the format of the flag search the report for the format  
```powershell  
findstr /s /i /m "cyberclub" *.*  
```  
  
```  
SMS & iMessage - Messages.html  
temp\Library\SMS\sms.db  
temp\NoteStore.sqlite  
_Timeline\tl.db  
_TSV Exports\SMS & iMessage - Messages.tsv  
```  
Configure https://github.com/threeplanetssoftware/apple_cloud_notes_parser as per the README and execute with ```rake```  
  
```  
C:/Ruby32-x64/bin/ruby.exe notes_cloud_ripper.rb --file NoteStore.sqlite  
  
Starting Apple Notes Parser at Tue Jun 20 03:50:54 2023  
Storing the results in ./output/2023_06_20-03_50_54  
  
Created a new AppleBackup from single file: NoteStore.sqlite  
Guessed Notes Version: 16  
Updated AppleNoteStore object with 3 AppleNotes in 2 folders belonging to 1 accounts.  
Adding the ZICNOTEDATA.ZPLAINTEXT and ZICNOTEDATA.ZDECOMPRESSEDDATA columns, this takes a few seconds  
  
Successfully finished at Tue Jun 20 03:50:54 2023  
```  
Opening the resulting JSON will show the flag  
![[Pasted image 20230620135732.png]]  
  
### Flag 3 - Deleted Photo  
The files in the iTunes backup are actually usable files, they've just been renamed to their SHA hash and missing extensions.  
  
Search the entire decrypted backup for the largest files  
```bash  
#!/bin/bash  
  
folder="."  # Specify the folder you want to search within  
count=20    # Number of largest files to display  
  
find "$folder" -type f -exec du -a {} + | sort -n -r | head -n "$count" | cut -f2- | xargs -I{} du -sh {}  
```  
  
Running file on the output files will show the ones that will be of interest and we can open them up with vlc  
  
![[Pasted image 20230620151153.png]]  
  
### Flag 4 - Music Metadata  
Finding all audio files can be done with the following script  
```bash  
for file in $(find "$folder" -type f);  
do     file "$file"     
done | grep -i audio  
```  
There is only one result  
```./Device_F2LWP4NSJCLF_DecryptedBackup/BACKUP/62/622afaa80743feab8ed131f7ac3842ab7477594f: Audio file with ID3 version 2.4.0, contains: MPEG ADTS, layer III, v1, 192 kbps, 44.1 kHz, Stereo ```  
  
Running exiftool against the file returns the flag:  
```  
ExifTool Version Number         : 12.57  
File Name                       : 622afaa80743feab8ed131f7ac3842ab7477594f  
Directory                       : ./Device_F2LWP4NSJCLF_DecryptedBackup/BACKUP/62  
File Size                       : 5.1 MB  
File Modification Date/Time     : 2023:06:20 00:48:23-04:00  
File Access Date/Time           : 2023:06:20 00:52:21-04:00  
File Inode Change Date/Time     : 2023:06:20 00:48:23-04:00  
File Permissions                : -rw-r--r--  
File Type                       : MP3  
File Type Extension             : mp3  
MIME Type                       : audio/mpeg  
MPEG Audio Version              : 1  
Audio Layer                     : 3  
Audio Bitrate                   : 192 kbps  
Sample Rate                     : 44100  
Channel Mode                    : Stereo  
MS Stereo                       : Off  
Intensity Stereo                : Off  
Copyright Flag                  : False  
Original Media                  : False  
Emphasis                        : None  
ID3 Size                        : 10466  
User Defined Text               : (compatible_brands) isommp42  
Encoder Settings                : Lavf58.29.100  
Title                           : Never Gonna Give You Up  
Artist                          : Rick Astley  
Comment                         : cyberclub{MusicMetadata}  
Duration                        : 0:03:32 (approx)  
```  
