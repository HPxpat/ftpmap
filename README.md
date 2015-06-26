FTP-Map
==========

Ftpmap scans remote FTP servers to indentify what software and what versions
they are running. It uses program-specific fingerprints to discover the name
of the software even when banners have been changed or removed, or when some
features have been disabled. FTP-Map will try to detect exploits by the  
FTP software/version. and FTP-Map also contains tools for remote take-over.


![FtpMap09](https://pbs.twimg.com/media/CHZpCaoUEAAXCrZ.jpg)


Build
=====

    ./configure
    make
    sudo make install 

Usage
======

Using ftpmap is trivial, and the built-in help is self-explanatory :


Options:
        
        --scan, -S                 - Start FTP scan.
        --server, -s <host>        - The FTP server.
        --port, -P <port>          - The FTP port (default: 21).
        --user, -u <user>          - FTP user (default: anonymous).
        --password, -p <password>  - FTP password (default: NULL). 
        --execute, -x <cmd>        - Run command on the FTP server.
        --nofingerprint, -n        - Do not generate fingerprint.
        --login, -A                - Only login, print output and quit.\
        --force, -F                - Force to generate fingerprint.
        --output, -o <file>        - output file.
        --list, -L <path>          - Get list of files and folders on the FTP server.
        --delete <path>            - Delete files/folders on the server.
        --last-modified, -m <file> - Returns the last-modified time of the given file


Fuzzer Options:
	
        --fuzzer, -f               - Use the Fuzzer.
        --fuzzerlength,-b <length> - Buffer length to send. (default: 256)
        --fuzzer-nologin, -l       - Do not login.


General Options:

        --version, -v              - Show version information and quit.
        --help, -h                 - Show help and quit.

And...
======

please send the fingerprint and the name of the software to hypsurus@mail.ru.
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
