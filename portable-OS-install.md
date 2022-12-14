# Scope
Create a portable OS that can be used for a variety of tasks, and most importantly be device agnostic. I should be able to run this on a beater laptop when travelling for basic use, and at home on better hardware.

## Hardware
Currently using a Sandisk 2TB USB 3.2 Gen 2 10Gb portable SSD. Fast enough to run an OS from, but includes USB for compatability with older devices.
If drive speed becomes an issue I will investigate a USB4 NVMe enclosure, as these should hit 40Gb/s on ThunderBolt capable machines while still being USB3 compatible.

## Software
Using linux with an EFI bootloader for the main OS.

## Linux install
Regular install of XFCE Manjaro, using the entire SSD. LUKS encrpytion turned on
qemu/kvm and virt-manager installed as per documentation on the [manjaro site](https://wiki.manjaro.org/index.php/Virt-manager)
This OS will have the bare minimum installed on it. The only time something should be installed is if it needs direct access to hardware such as:
- games that require GPU
- voice and video apps that need reliable sound
Since the entire install is running off the USB, its a good idea to disable USB autosuspend. This is done by adding a kernel parameter in the ```GRUB.cfg```

## Windows
Windows is installed as a kvm guest with the following options in virt manager:
- video set to QXL and vgamem increased to 65536MB
- storage driver set to virtIO
virtiO storage driver needs to be loaded at install, and spice guest tools need to be installed after Windows setup is complete.
Once system is up to date, it's shutdown, snapshotted and cloned for different Windows environments (work, forensics, devlab)
Same process will apply for Windows Server if that gets installed.

## nix
Nothing special about the nix installs, just install them, update them and add in the guest tools. Currently using:
- Kali
- REMnux
- pfSense

## MacOS
Followed the guide [on github](https://github.com/kholia/OSX-KVM) to setup and install MacOS Big Sur.
This is an extremely basic install only used for testing. No graphic acceleration so GUI is very slow.
