FTP-Map
==========

Developer notes
================

* In this version (0.12) FTP-Map has support for downloading/uploading a single file from FTP Servers.
* The auto log function has been removed from version 0.12 (to use it run FTP-Map with -g)

<p> FTPMap should work on ( As far I know): </p>

* linux (Arch, Debian, Fedora etc..) 100%
* ARM (RaspberryPi, Android etc..). 100%
* BSD (FreeBSD, etc..) 100%
* Mac? (I didn't test)
* Windows (Cygwin?)


About
=====

Ftpmap scans remote FTP servers to indentify what software and what versions
they are running. It uses program-specific fingerprints to discover the name
of the software even when banners have been changed or removed, or when some
features have been disabled. FTP-Map will try to detect exploits by the  
FTP software/version.

![FtpMap09](https://pbs.twimg.com/media/CHZpCaoUEAAXCrZ.jpg)

Build
=====

    ./configure
    make
    sudo make install 

Usage
======


* Scan server:
    > ftpmap -s localhost -S -g

* Upload a file.
    > ftpmap -s localhost --user root --password root -U 'topsecretfile.txt'

* Download a file:
    > ftpmap -s localhost --user root --password root -d '/topsecretfile.txt'

* list files:
    > ftpmap -s localhost --user anonymous -p null -l '/'

* use --help for the full options.

Please send the fingerprint and the name of the software to hypsurus@mail.ru.
Another indication that can be displayed if login was successful is the FTP
PORT sequence prediction. If the difficulty is too low, it means that anyone
can steal your files and change their content, even without knowing your
password or sniffing your network.
There are very few known fingerprints yet, but submissions are welcome.

Obfuscating FTP servers
=======================


This software was written as a proof of concept that security through
obscurity doesn't work. Many system administrators think that hidding or
changing banners and messages in their server software can improve security.

Don't trust this. Script kiddies are just ignoring banners. If they read
that "XYZ FTP software has a vulnerability", they will try the exploit on
all FTP servers they will find, whatever software they are running. The same
thing goes for free and commercial vulnerability scanners. They are probing
exploits to find potential holes, and they just discard banners and messages.
On the other hand, removing software name and version is confusing for the
system administrator, who has no way to quickly check what's installed on his
servers.

If you want to sleep quietly, the best thing to do is to keep your systems
up to date : subscribe to mailing lists and apply vendor patches.

Get FTP-Map
=============
                git clone git://github.com/Hypsurus/ftpmap 

The END
=========
    
    Copyright 2015 (C) FTP-Map project developers.
    License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>.
