---
title: "Emulating Router Firmware Like a Pro: The Firmadyne Installation Guide"
# date: 2025-07-04 12:00:00 +0000  # Adjust to your actual date/time
categories: [Emulation, firmadyne]
tags: [firmware, firmadyne]

---


Firmadyne is an open-source toolkit designed for emulating and analyzing Linux-based embedded firmware, particularly for routers and IoT devices.

In this guide, I'll walk you through the complete installation and setup process for Firmadyne on an Ubuntu system.

I have 22.04.5 LTS (Jammy Jellyfish)


### Installation

First, update your package lists and install essential dependencies:

```bash
sudo apt-get update
sudo apt-get upgrade -y
sudo apt-get install -y build-essential libncurses5-dev zlib1g-dev busybox-static fakeroot git dmsetup kpartx netcat-openbsd nmap python3-psycopg2 snmp uml-utilities util-linux vlan libssl-dev libelf-dev qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils debootstrap python3 python3-pip
```

Clone the official Firmadyne repository from GitHub:

```bash
git clone --recursive https://github.com/firmadyne/firmadyne.git
cd firmadyne
```

Next, you need to install `binwalk`. Keep in mind, the `apt` version `binwalk` is causes some issue so better build it from source.

```bash
# Latest binwalk doesn't work
git clone --branch v2.3.4 --single-branch https://github.com/ReFirmLabs/binwalk.git

cd binwalk
sudo ./deps.sh  # Installs critical dependencies

# If you get error related to sasquatch then follow error-sasquatch or else continue
sudo python3 ./setup.py install
```

**Sasquatch Error**

If the error looks like this:

```txt
unsquashfs.c: In function ‘read_super’:
unsquashfs.c:1835:5: error: this ‘if’ clause does not guard... [-Werror=misleading-indentation]
 1835 |     if(swap)
      |     ^~
unsquashfs.c:1841:9: note: ...this statement, but the latter is misleadingly indented as if it were guarded by the ‘if’
 1841 |         read_fs_bytes(fd, SQUASHFS_START, sizeof(struct squashfs_super_block),
      |         ^~~~~~~~~~~~~
cc1: all warnings being treated as errors
make: *** [<builtin>: unsquashfs.o] Error 1
```

You need to install `sasquatch` separately.
Open the `deps.sh` and comment the function call to `install_sasquatch`.

```bash
# install_sasquatch
install_yaffshiv
install_jefferson
```

Now, follow these commands:

```bash
git clone --quiet --depth 1 --branch "master" https://github.com/devttys0/sasquatch
cd sasquatch 
sudo ./build.sh
```

Here, you might encounter the same error as before.

**Reference:**
[sasquatch error on StackOverflow](https://stackoverflow.com/questions/75034200/binwalks-sasquatch-file-build-sh-throws-2-errors-when-trying-to-run-it)

To fix this, rebuild using the following commands:

```bash
# From inside the sasquatch directory
wget https://raw.githubusercontent.com/devttys0/sasquatch/82da12efe97a37ddcd33dba53933bc96db4d7c69/patches/patch0.txt
mv patch0.txt patches
./build.sh
```

After that, you can run the `deps.sh` script for **binwalk** dependencies:

```bash
./deps.sh
```

If you see an error like this:

```txt
+ install_ubireader
+ git clone --quiet --depth 1 --branch master https://github.com/jrspruitt/ubi_reader
warning: Could not find remote branch master to clone.
fatal: Remote branch master not found in upstream origin
```

Simply update the `install_ubireader` function inside `deps.sh` like this:

```bash
function install_ubireader
{
    # git clone --quiet --depth 1 --branch "master" https://github.com/jrspruitt/ubi_reader
    # (cd ubi_reader && $SUDO $PYTHON setup.py install)
    # $SUDO rm -rf ubi_reader
    pip install --user ubi_reader
}
```

**Reference:** [ubi_reader install issue](https://github.com/attify/firmware-analysis-toolkit/issues/92#issuecomment-1643360224)

That’s it! Now when you run `./deps.sh`, everything should work without errors. 

**Database Configuration**

**Firmadyne** uses **PostgreSQL** to store information about analyzed firmware. Install and configure it as follows:

```bash
sudo apt-get install -y postgresql postgresql-client
sudo -u postgres createuser -P firmadyne # Set the password as 'firmadyne' when prompted

sudo -u postgres createdb -O firmadyne firmware

# Set up the database schema:
sudo -u postgres psql -d firmware < ./database/schema
```

**Install Additional Tools**

**Firmadyne** relies on several additional tools. Install them using the commands below:

```bash
# Download Firmadyne's pre-built binaries for all components:
sudo ./download.sh

# Install Python dependencies:
# Install 'python-magic' (ahupp’s fork)
sudo apt install -y libmagic1
sudo -H pip install git+https://github.com/ahupp/python-magic

# Install 'jefferson' (for JFFS2 extraction)
sudo -H pip install git+https://github.com/sviehb/jefferson

# Verify that jefferson installed correctly:
jefferson --help
```

**Configuration**

Now, edit the Firmadyne configuration file:

```bash
nano ./firmadyne.config
```

Update the following lines with your correct database password and paths:

```txt
# Uncomment and specify the full path to your FIRMADYNE repository:
# FIRMWARE_DIR=/home/yourusername/firmadyne
FIRMWARE_DIR=/home/fury/Desktop/IoTSec/firmadyne/ 

# specify full paths to other directories
BINARY_DIR=${FIRMWARE_DIR}/binaries/
TARBALL_DIR=${FIRMWARE_DIR}/images/
SCRATCH_DIR=${FIRMWARE_DIR}/scratch/
SCRIPT_DIR=${FIRMWARE_DIR}/scripts/
```

Now, everything is ready. Let’s start emulating the firmware.

You can download it from here:  
[Netgear WNAP320](https://www.downloads.netgear.com/files/GDC/WNAP320/WNAP320%20Firmware%20Version%202.0.3.zip)

After unzipping the `.zip` file, you’ll find a file named `WNAP320_V2.0.3_firmware.tar`.

Let’s extract it:

```bash
tar xvf WNAP320_V2.0.3_firmware.tar
vmlinux.gz.uImage
rootfs.squashfs
root_fs.md5
kernel.md5
```

The `rootfs.squashfs` file contains the filesystem.

I keep the `.zip` file inside the **Firmadyne** directory. Now, let’s pass the firmware to `extractor.py`.

### Extract Filesystem with Firmadyne


```bash
# ./sources/extractor/extractor.py [-h] [-sql  SQL] [-nf] [-nk] [-np] [-b BRAND] input [output]
./sources/extractor/extractor.py -b Netgear -sql 127.0.0.1 -np -nk "WNAP320_V2.0.3_firmware.tar" images
>> Database Image ID: 1
#...
# [REDACTED]
	>> Cleaning up /tmp/tmprthjxj2r...
>> Skipping: completed!
>> Cleaning up /tmp/tmpuhzo4pfj...
```

**Note:** If you get any errors, try running the command with `sudo`.

Next, we need to identify the architecture of firmware image `1` and store the result in the database’s `image` table.

```bash
./scripts/getArch.sh ./images/1.tar.gz
```

It detected the architecture as `mipseb`.

Now, load the filesystem contents of firmware `1` into the database, which will populate the `object` and `object_to_image` tables.

```bash
./scripts/tar2db.py -i 1 -f ./images/1.tar.gz
```

Create the QEMU disk image for the firmware:

```bash
sudo ./scripts/makeImage.sh 1
```

Now, infer the network configuration for firmware `1`. Kernel messages will be logged to `./scratch/1/qemu.initial.serial.log`.


```bash
./scripts/inferNetwork.sh 1

# [Output]
Querying database for architecture... Password for user firmadyne: 
mipseb
Running firmware 1: terminating after 60 secs...
qemu-system-mips: terminating on signal 2 from pid 44756 (timeout)
Inferring network...
Interfaces: [('brtrunk', '192.168.0.100')]
Done!
```

Now, let’s emulate firmware `1` with the inferred network configuration.
This will create a TAP device and modify the host’s network configuration.

```bash
./scratch/1/run.sh
```

The system should now be accessible over the network and ready for analysis.
Kernel messages will be mirrored to `./scratch/1/qemu.final.serial.log`.
The filesystem for firmware `1` can also be mounted and unmounted from `scratch/1/image` using:

```bash
./scripts/mount.sh 1
./scripts/umount.sh 1
```

The emulated router will have the IP address `192.168.0.100`.

You can run an `nmap` scan on it:

```bash
sudo nmap -sV 192.168.0.100
# OUTPUT
PORT    STATE SERVICE    VERSION
22/tcp  open  ssh        Dropbear sshd 0.51 (protocol 2.0)
80/tcp  open  http       lighttpd 1.4.18
443/tcp open  ssl/https?
MAC Address: 52:54:00:12:34:56 (QEMU virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Nice! We can see port `80` is open.
If you visit `http://192.168.0.100`, you’ll see the router’s admin page.

The default creds are `admin:password`

By default, the console will be automatically connected to your terminal.
You can also log in with `root` and `password`.

Note: `Ctrl-C` will be sent to the guest system. To stop the emulation, use the QEMU monitor with `Ctrl-a + x`.


### Exploiting a Known Vulnerability

While researching vulnerabilities, I found this:  
[Netgear WNAP320 Firmware Version 2.0.3 RCE](https://github.com/nobodyatall648/Netgear-WNAP320-Firmware-Version-2.0.3-RCE)

Let’s try it:

```bash
git clone https://github.com/nobodyatall648/Netgear-WNAP320-Firmware-Version-2.0.3-RCE
cd Netgear-WNAP320-Firmware-Version-2.0.3-RCE
python wnap320_v2_0_3_RCE.py 
Must specify the IP parameter
eg: python3 wnap320_v2_0_3.py <IP>
```

It asks for the IP address:

```bash
python wnap320_v2_0_3_RCE.py  192.168.0.100
Shell_CMD$ ls
BackupConfig.php
UserGuide.html
#...
Shell_CMD$ whoami
root
```

Success! We have obtained a root shell on the emulated router.

### Conclusion

This is how we can emulate router firmware using **Firmadyne**.

There’s also another project called **FirmAE**, which can emulate even more firmware images than Firmadyne. I’ll cover it in another post!

If you face any issues or errors, feel free to contact me!
