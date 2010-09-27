SIRENS for Linux ������
					2010/08/31
					���������̴


--
1. ��������

SIRENS for Linux �ϡ�Ubuntu 10.04 LTS Desktop 64bit �ǳ�ȯ��
���ư���ǧ��ԤäƤ��ޤ����ʲ��μ��˽��ä� Ubuntu �Ķ���
���ۤ��Ʋ�������

 a) Ubuntu 10.04 LTS Desktop 64bit �򥤥󥹥ȡ��뤷�ޤ���

 b) /etc/apt/apt.conf �˲����ιԤ��ɵ����ޤ���

    Acquire::http::No-Cache "True";

 c) /etc/apt/sources.list ���鲼���ιԤ�õ���������Ȥ򳰤�
    �ޤ���

    deb http://archive.canonical.com/ubuntu lucid partner
    deb-src http://archive.canonical.com/ubuntu lucid partner

 d) �����ͥ볫ȯ�Ķ��򥤥󥹥ȡ��뤷�ޤ���

    $ sudo apt-get update
    $ sudo apt-get install fakeroot build-essential
    $ sudo apt-get install kexec-tools kernel-wedge makedumpfile
    $ sudo apt-get install kernel-package
    $ sudo apt-get build-dep linux
    $ sudo apt-get build-dep --no-install-recommends linux-image-$(uname -r)

 e) SNMP �ѥå������򥤥󥹥ȡ��뤷�ޤ���

    $ sudo apt-get install snmp libsnmp-dev

 f) libconfig �ѥå������򥤥󥹥ȡ��뤷�ޤ���
    ������ URL ���� libconfig8 ����� libconfig8-dev ���������
    dpkg -i ��¹Ԥ��ޤ���

    https://launchpad.net/ubuntu/lucid/+package/libconfig8
    https://launchpad.net/ubuntu/lucid/+package/libconfig8-dev

    $ sudo dpkg -i libconfig8_1.3.2-2_amd64.deb 
    $ sudo dpkg -i libconfig8-dev_1.3.2-2_amd64.deb

 g) Java �Ķ�(Sun Java SE6 JDK)�򥤥󥹥ȡ��뤷�ޤ���

    $ sudo apt-get install sun-java6-jdk
    $ sudo update-java-alternatives -s java-6-sun

    apt-get ������Ǽ��Ԥ��Ƥ��ޤ���硢TERM �Ķ��ѿ��� "vt100"
    �����ꤷ�ƺƼ¹Ԥ��ƤߤƲ�������

 h) ɬ�פ˱����ƥͥåȥ�������Ĵ�����ޤ���
    ��Ū�˥ͥåȥ�����󥿡��ե�����������򤷤������ϡ�
    �ʲ��μ��Ǽ»ܤ��Ʋ�������

    $ sudo apt-get install sysv-rc-conf
    $ sudo sysv-rc-conf network-manager off

    /etc/network/interface �򲼵�����򻲹ͤ��Խ����ޤ���

    auto lo eth0 eth1
    iface lo inet loopback
    iface eth0 inet static
        address 192.168.1.1
        netmask 255.255.255.0
        post-up sysctl -w net.ipv4.ip_forward=1
    iface eth1 inet static
        address 192.168.2.1
        netmask 255.255.255.0

    /etc/resolv.conf ���ǧ�������������ä��齤�������Ƶ�ư
    ��Ԥ��ޤ���

 i) ɬ�פ˱����ƥ����ͥ�Υ��åץ��졼�ɤ�Ԥ��ޤ���
    ������ URL ���� linux-image, linux-headers,
    linux-headers-generic ���������dpkg -i ��¹Ԥ��ޤ���

    http://kernel.ubuntu.com/~kernel-ppa/mainline/v2.6.33.5-lucid/

    $ sudo dpkg -i linux-image-2.6.33-02063305-generic_2.6.33-02063305_amd64.deb
    $ sudo dpkg -i linux-headers-2.6.33-02063305_2.6.33-02063305_all.deb
    $ sudo dpkg -i linux-headers-2.6.33-02063305-generic_2.6.33-02063305_amd64.deb

    /etc/deafult/grub ���鲼���ιԤ�õ���������Ȥˤ��Ƥ���
    update-grub ��¹Ԥ����Ƶ�ư���ޤ���

    GRUB_HIDDEN_TIMEOUT=0
    GRUB_HIDDEN_TIMEOUT_QUIET=true

    $ sudo update-grub
    $ sudo reboot


--
2. SIRENS for Linux �Υ��󥹥ȡ���

2.1 SIRENS for Linux

    �ʲ��Υ��ޥ�ɤ�¹Ԥ��Ʋ��������إå��ե�����ȥ⥸�塼��
    �����󥹥ȡ��뤵��ޤ���

    $ cd trunk/SIRENSLinux
    $ make
    $ sudo make install

    �⥸�塼��Υ��ɤ���ӥ�����ɤ�Ԥ��ˤϡ��ʲ��Υ��ޥ�
    �ɤ�¹Ԥ��Ʋ�������

    $ sudo modprobe ip_sirens
    $ sudo rmmod ip_sirens

    �⥸�塼��ˤϰʲ��Υѥ�᡼�����Ϥ�������ǽ�Ǥ���

    sr_max_sk: Maximum number of tracking TCP socket
    sr_max_icmp: Maximum number of tracking ICMP echo
    sr_icmp_sirens_res: Enable SIRENS backword probe on ICMP

    �⥸�塼����Ϥ��ѥ�᡼������ꤹ����ϡ��ʲ��Τ褦��
    modprobe ��¹Ԥ��ޤ���

    $ sudo modprobe sr_max_sk=100 sr_max_icmp=100

    ���ߤΥѥ�᡼�����ǧ����ˤϡ��ʲ��Υ��ޥ�ɤ�¹Ԥ��Ʋ�
    ������

    $ cat /sys/module/ip_sirens/parameters/sr_max_sk
    100
    $ cat /sys/module/ip_sirens/parameters/sr_max_icmp
    100
    $ cat /sys/module/ip_sirens/parameters/sr_icmp_sirens_res
    1

2.2 SIRENS �� ping

    �ʲ��Υ��ޥ�ɤ�¹Ԥ��Ʋ�������/usr/local/bin/srping �˥�
    �󥹥ȡ��뤵��ޤ���

    $ cd trunk/ping
    $ make
    $ sudo make install

2.3 vifset

    �ʲ��Υ��ޥ�ɤ�¹Ԥ��Ʋ�������/usr/local/sbin/vifset �˥�
    �󥹥ȡ��뤵��ޤ���
    vifset ��¹Ԥ�����ˤϡ�"-c" ���ץ���������ե������
    ���ꤹ��ɬ�פ�����ޤ���

    $ cd trunk/vifset
    $ make -f Makefile.linux
    $ sudo make -f Makefile.linux install

2.4 iperf

    �ʲ��Υ��ޥ�ɤ�¹Ԥ��Ʋ�������

    $ cd trunk/iperf-2.0.4
    $ ./configure --prefix=/usr/local/
    $ make
    $ sudo make install

2.5 SIRENSJNI

    ������ URL ���� java-getopt-1.0.13.jar ���������
    trunk/SIRENSJNI �˥��ԡ����ޤ���

    http://www.urbanophile.com/arenn/hacking/getopt/

    �ʲ��Υ��ޥ�ɤ�¹Ԥ��Ʋ�������
    ���Ѥ��� Java �Ķ��� Sun Java SE6 �ǤϤʤ���硢Makefile.linux
    ��ʬ�δĶ��˹�碌��Ĵ������ɬ�פ�����ޤ���

    $ cd trunk/SIRENSJNI
    $ make -f Makefile.linux

    �嵭�Υ��ޥ�ɤ�¹Ԥ���ȡ��ʲ��Υե����뤬��������ޤ���
    ���줾�� CLASSPATH �� LD_LIBRARY_PATH ���ɲä��Ʋ�������

    SIRENSSocket-0.0.2-linux.jar
    libSIRENSImpl.so

2.6 pyperf

    ���󥹥ȡ���Ϥ���ޤ���
    trunk/pyperf/pyperf.py ��Ŭ���ʾ��˥��ԡ����ƻ��Ѥ��Ʋ�������


--
3. ���Τ�������

* �ͥåȥ�����󥿡��ե�������ưŪ���������б����Ƥ��ʤ���

  SIRENS for Linux �ϡ��⥸�塼��Υ��ɻ��ˡ��ͥåȥ������
  ���ե�������ɳ�դ� SRIFEntry ���Ѱդ��Ƥ��ޤ������Τ���ͥåȥ�
  �������󥿡��ե�������ưŪ�������ˤ��б����Ƥ��ޤ���

  �⥸�塼����ɸ�˽и������ͥåȥ�����󥿡��ե��������Ф�
  ��  setsockopt(IPSIRENS_SRVAR), getsockopt(IPSIRENS_SRVAR) ���
  �Ԥ���� EINVAL ���֤��ޤ���

  �⥸�塼����ɻ���¸�ߤ��Ƥ����ͥåȥ�����󥿡��ե�������
  ���Ǥ�����硢�⥸�塼��򥢥���ɤ���ޤǤϡ��ͥå������
  �����ե������Υǥ��å�����λ���ޤ���

* �桼���ץ���फ��� setsockopt(IP_OPTIONS) �Ⱦ��ͤ��롣

  SIRENS for Linux �ϡ�SIRENS header ��ѥ��åȤ��������뤿�����
  ��Ū�� setsockopt(IP_OPTIONS) �����ν�����ԤäƤ��ޤ���

  �桼���ץ���ब�ȼ��� setsockopt(IP_OPTIONS) ��¹Ԥ�����硢
  �տޤ����Ȥ����ư��ʤ���礬����ޤ���


�ʾ塣
