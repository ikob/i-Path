SIRENS for FreeBSD Manual
					2012/01/04
					Katsushi Kobayashi


--
1. Preparation

Note that the SIRENS for FreeBSD package was develiopped on
FreeBSD 8.2. Also, this software was ported from
SIRENS for Linux package. 

 a) Install FreeBSD8.2 with Kernel-developpper option.

 b) Install additional packages as the followings:

    net-snmp
    libconfig

2.1 SIRENS for FreeBSD

    Follow instructions below. this installs LKM and header file.

    $ cd trunk/SIRENSLinux
    $ make -f Makefile.bsd
    $ su
    # make install

    To load/unload Lernel module, run below command on root

    # kldload ip_sirens.ko
    # kldunload ip_sirens.ko

2.2 ping (SIRENS version)

    Follow instructions below. this installs /usr/local/bin/srping.
    Note:  requires ip_output.c modification, add 1-line.

*** sys/netinet/ip_output.c.org	Thu Jan  5 16:57:41 2012
--- sys/netinet/ip_output.c	Thu Jan  5 19:31:08 2012
***************
*** 513,518 ****
--- 513,521 ----
  		goto done;
  
  	ip = mtod(m, struct ip *);
+ #if 1
+ 	hlen = ip->ip_hl << 2;
+ #endif
  
  	/* See if destination IP address was changed by packet filter. */
  	if (odst.s_addr != ip->ip_dst.s_addr) {


    $ cd trunk/ping
    $ make
    $ su
    # make install

2.3 vifset

    Follow instructions below. this installs /usr/local/sbin/vifset.
    Note that you must provide your configuration file to vifset
    with "-c" option.

    $ cd trunk/vifset
    $ make -f Makefile.bsd
    $ su
    # make -f Makefile.bsd install

2.4 iperf

    Follow instructions below.

    $ cd trunk/iperf-2.0.4
    $ ./configure --prefix=/usr/local/
    $ make
    $ su
    # make install

2.5 SIRENSJNI (optional)

    Note: not checked yet.

    Download java-getopt-1.0.13.jar from below URL, copy to
    trunk/SIRENSJNI/

    http://www.urbanophile.com/arenn/hacking/getopt/

    Run below commands.
    If your JDK isn't Sun Java SE6 JDK, fix your Makefile.linux.

    $ cd trunk/SIRENSJNI
    $ make -f Makefile.bsd

    Above commands generates below files. You can deploy them
    into your CLASSPATH and LD_LIBRARY_PATH.

    SIRENSSocket-0.0.2-linux.jar
    libSIRENSImpl.so

2.6 pyperf

    Copy trunk/pyperf/pyperf.py to your favorite place.


--
3. Bugs.

* Can't follow dynamic generation/removal of network interfaces, 
   e.g. NIC, VLAN.

  SIRENS for BSD allocates per network interface storage on loading
  kernel module, so it can't follow dynamic generation/removal of IFs' .
  If you would like to add IF, please unload SIRENS kernel module onece,
  and load it again.

* Conflict with setsockopt(IP_OPTIONS) by user.

  SIRENS for BSD uses setsockopt(IP_OPTIONS) internally.
  you can't use your IP option with SIRENS.


Fin.
