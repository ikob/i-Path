SIRENS for Linux Manual
					2010/08/31
					SOUM Corporation


--
1. Preparation

Note that the SIRENS for Linux package is developed Ubuntu 10.04
LTS Desktop. The following instruction is based on it.

 a) Install Ubuntu 10.04 LTS Desktop 64bit.

 b) Add below line to your /etc/apt/apt.conf.

    Acquire::http::No-Cache "True";

 c) Look up below lines from /etc/apt/sources.list, and un-comment
    out them.

    deb http://archive.canonical.com/ubuntu lucid partner
    deb-src http://archive.canonical.com/ubuntu lucid partner

 d) Install kernel development packages.

    $ sudo apt-get update
    $ sudo apt-get install fakeroot build-essential
    $ sudo apt-get install kexec-tools kernel-wedge makedumpfile
    $ sudo apt-get install kernel-package
    $ sudo apt-get build-dep linux
    $ sudo apt-get build-dep --no-install-recommends linux-image-$(uname -r)

 e) Install SNMP development packages.

    $ sudo apt-get install snmp libsnmp-dev

 f) Install libconfig packages.
    Download libconfig8 and libconfig8-dev from below URL, and
    install them by dpkg.

    https://launchpad.net/ubuntu/lucid/+package/libconfig8
    https://launchpad.net/ubuntu/lucid/+package/libconfig8-dev

    $ sudo dpkg -i libconfig8_1.3.2-2_amd64.deb 
    $ sudo dpkg -i libconfig8-dev_1.3.2-2_amd64.deb

 g) Install JDK(Sun Java SE6 JDK).

    $ sudo apt-get install sun-java6-jdk
    $ sudo update-java-alternatives -s java-6-sun

    If installation failed prematurely, set your TERM environment
    variable as "vt100", and try again.

 h) [optional] Set up network.
    If you want to set up network with static configuration,
    follow instructions below.

    $ sudo apt-get install sysv-rc-conf
    $ sudo sysv-rc-conf network-manager off

    Edit your /etc/network/interfaces.

    [sample]
    auto lo eth0 eth1
    iface lo inet loopback
    iface eth0 inet static
        address 192.168.1.1
        netmask 255.255.255.0
        post-up sysctl -w net.ipv4.ip_forward=1
    iface eth1 inet static
        address 192.168.2.1
        netmask 255.255.255.0

    Check and fix your /etc/resolv.conf, reboot.

 i) [optional] Upgrade your kernel.
    Download linux-image, linux-headers and linux-headers-generic
    from URL below, and install them by dpkg.

    http://kernel.ubuntu.com/~kernel-ppa/mainline/v2.6.33.5-lucid/

    $ sudo dpkg -i linux-image-2.6.33-02063305-generic_2.6.33-02063305_amd64.deb
    $ sudo dpkg -i linux-headers-2.6.33-02063305_2.6.33-02063305_all.deb
    $ sudo dpkg -i linux-headers-2.6.33-02063305-generic_2.6.33-02063305_amd64.deb

    Lookup below lines form your /etc/default/grub, comment out
    them, run update-grub and reboot.

    GRUB_HIDDEN_TIMEOUT=0
    GRUB_HIDDEN_TIMEOUT_QUIET=true

    $ sudo update-grub
    $ sudo reboot


--
2. Installation

2.1 SIRENS for Linux

    Follow instructions below. this installs LKM and header file.

    $ cd trunk/SIRENSLinux
    $ make
    $ sudo make install

    To load/unload LKM, run below command.

    $ sudo modprobe ip_sirens
    $ sudo rmmod ip_sirens

    You can pass optional parameter to LKM.

    sr_max_sk: Maximum number of tracking TCP socket
    sr_max_icmp: Maximum number of tracking ICMP echo
    sr_icmp_sirens_res: Enable SIRENS backword probe on ICMP

    To pass parameter to LKM, try below command.

    $ sudo modprobe sr_max_sk=100 sr_max_icmp=100

    You can see current parameter setting by below command.

    $ cat /sys/module/ip_sirens/parameters/sr_max_sk
    100
    $ cat /sys/module/ip_sirens/parameters/sr_max_icmp
    100
    $ cat /sys/module/ip_sirens/parameters/sr_icmp_sirens_res
    1

2.2 ping (SIRENS version)

    Follow instructions below. this installs /usr/local/bin/srping.

    $ cd trunk/ping
    $ make
    $ sudo make install

2.3 vifset

    Follow instructions below. this installs /usr/local/sbin/vifset.
    Note that you must provide your configuration file to vifset
    with "-c" option.

    $ cd trunk/vifset
    $ make -f Makefile.linux
    $ sudo make -f Makefile.linux install

2.4 iperf

    Follow instructions below.

    $ cd trunk/iperf-2.0.4
    $ ./configure --prefix=/usr/local/
    $ make
    $ sudo make install

2.5 SIRENSJNI

    Download java-getopt-1.0.13.jar from below URL, copy to
    trunk/SIRENSJNI/

    http://www.urbanophile.com/arenn/hacking/getopt/

    Run below commands.
    If your JDK isn't Sun Java SE6 JDK, fix your Makefile.linux.

    $ cd trunk/SIRENSJNI
    $ make -f Makefile.linux

    Above commands generates below files. You can deploy them
    into your CLASSPATH and LD_LIBRARY_PATH.

    SIRENSSocket-0.0.2-linux.jar
    libSIRENSImpl.so

2.6 pyperf

    Copy trunk/pyperf/pyperf.py to your favorite place.


--
3. Bugs.

* Can't follow dynamic generation/removal of NICs.

  SIRENS for Linux allocates per NIC storage on LKM loading,
  so it can't follow dynamic generation/removal of NICs.

  If New NIC appeared after LKM loading, invoking
  setsockopt(IPSIRENS_SRVAR), getsockopt(IPSIRENS_SRVAR) to the
  NIC may fail with EINVAL.

  If NIC has removed, detaching process may blocked until LKM
  unloading.

* Conflict with setsockopt(IP_OPTIONS) by user.

  SIRENS for Linux uses setsockopt(IP_OPTIONS) internally.
  you can't use your IP option with SIRENS.


Fin.
