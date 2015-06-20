PiXiEServ is a simplified PXE server (network boot) that can be used **for home OS development and experimenting with boot-time environment**. Please note that **it is not a full featured PXE server** and so it cannot be used to boot a full blown OS like GNU/Linux or Windows.

![http://gynvael.coldwind.pl/img/pixiescreen.png](http://gynvael.coldwind.pl/img/pixiescreen.png)

**Newest version download**: [PiXiEServ-0.0.1.zip](http://code.google.com/p/pixieserv/downloads/detail?name=PiXiEServ-0.0.1.zip)

# When should I use and not use PiXiEServ #
PiXiEServ is a **simplified** PXE server - it doesn't support all the features of a full-blown PXE server. It just supports enough to assign an IP address to the requesting machine and provide it with a small binary payload to be booted. And nothing more.

So, you **can** use PiXiEServ for:
  * developing and testing a very small OS (up to 32KB) transmitted in one package
  * developing and testing any small payload that is supposed to run at boot time (access recovery bootkits, etc)

However, PiXiEServ **is not** the right choice if you want to:
  * start a full-blown OS through PXE or it's installer
  * test a small OS that downloads parts of itself from TFTP

In such cases it's best to set up a normal DHCP server and an TFTP server.

# Why should I use PXE for testing my very small OS #
... and not just put an image on a floppy disk (or create a floppy disk image)?

When testing on an emulator / virtual machine (like bochs, VirtualBox, VMWate, etc) it doesn't really make any difference. However, if you want to test your OS/payload on a real machine, it's highly unlikely that is has a floppy drive (they went out of fashion quite a while ago). So you're left with either creating a bootable CD (keep in mind that some modern laptops don't have a CD/DVD drive anymore), a bootable pendrive, writing the image directly on the hard disk or network boot. Of all these choices the network boot is the least troublesome - you just start the PXE server (or have it running all the time) and turn on your test machine, and that's it!

However, please note that a network boot requires a wired LAN connection (as far as I know). So if your machine support only WiFi you won't be able to use PXE.