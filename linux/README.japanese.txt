SIRENS for Linux 説明書
					2010/08/31
					株式会社創夢


--
1. 事前設定

SIRENS for Linux は、Ubuntu 10.04 LTS Desktop 64bit で開発お
よび動作確認を行っています。以下の手順に従って Ubuntu 環境を
構築して下さい。

 a) Ubuntu 10.04 LTS Desktop 64bit をインストールします。

 b) /etc/apt/apt.conf に下記の行を追記します。

    Acquire::http::No-Cache "True";

 c) /etc/apt/sources.list から下記の行を探し、コメントを外し
    ます。

    deb http://archive.canonical.com/ubuntu lucid partner
    deb-src http://archive.canonical.com/ubuntu lucid partner

 d) カーネル開発環境をインストールします。

    $ sudo apt-get update
    $ sudo apt-get install fakeroot build-essential
    $ sudo apt-get install kexec-tools kernel-wedge makedumpfile
    $ sudo apt-get install kernel-package
    $ sudo apt-get build-dep linux
    $ sudo apt-get build-dep --no-install-recommends linux-image-$(uname -r)

 e) SNMP パッケージをインストールします。

    $ sudo apt-get install snmp libsnmp-dev

 f) libconfig パッケージをインストールします。
    下記の URL から libconfig8 および libconfig8-dev を取得し、
    dpkg -i を実行します。

    https://launchpad.net/ubuntu/lucid/+package/libconfig8
    https://launchpad.net/ubuntu/lucid/+package/libconfig8-dev

    $ sudo dpkg -i libconfig8_1.3.2-2_amd64.deb 
    $ sudo dpkg -i libconfig8-dev_1.3.2-2_amd64.deb

 g) Java 環境(Sun Java SE6 JDK)をインストールします。

    $ sudo apt-get install sun-java6-jdk
    $ sudo update-java-alternatives -s java-6-sun

    apt-get が途中で失敗してしまう場合、TERM 環境変数を "vt100"
    に設定して再実行してみて下さい。

 h) 必要に応じてネットワーク設定を調整します。
    静的にネットワークインターフェースの設定をしたい場合は、
    以下の手順で実施して下さい。

    $ sudo apt-get install sysv-rc-conf
    $ sudo sysv-rc-conf network-manager off

    /etc/network/interface を下記の例を参考に編集します。

    auto lo eth0 eth1
    iface lo inet loopback
    iface eth0 inet static
        address 192.168.1.1
        netmask 255.255.255.0
        post-up sysctl -w net.ipv4.ip_forward=1
    iface eth1 inet static
        address 192.168.2.1
        netmask 255.255.255.0

    /etc/resolv.conf を確認し、不備があったら修正し、再起動
    を行います。

 i) 必要に応じてカーネルのアップグレードを行います。
    下記の URL から linux-image, linux-headers,
    linux-headers-generic を取得し、dpkg -i を実行します。

    http://kernel.ubuntu.com/~kernel-ppa/mainline/v2.6.33.5-lucid/

    $ sudo dpkg -i linux-image-2.6.33-02063305-generic_2.6.33-02063305_amd64.deb
    $ sudo dpkg -i linux-headers-2.6.33-02063305_2.6.33-02063305_all.deb
    $ sudo dpkg -i linux-headers-2.6.33-02063305-generic_2.6.33-02063305_amd64.deb

    /etc/deafult/grub から下記の行を探し、コメントにしてから
    update-grub を実行し、再起動します。

    GRUB_HIDDEN_TIMEOUT=0
    GRUB_HIDDEN_TIMEOUT_QUIET=true

    $ sudo update-grub
    $ sudo reboot


--
2. SIRENS for Linux のインストール

2.1 SIRENS for Linux

    以下のコマンドを実行して下さい。ヘッダファイルとモジュール
    がインストールされます。

    $ cd trunk/SIRENSLinux
    $ make
    $ sudo make install

    モジュールのロードおよびアンロードを行うには、以下のコマン
    ドを実行して下さい。

    $ sudo modprobe ip_sirens
    $ sudo rmmod ip_sirens

    モジュールには以下のパラメータを渡す事が可能です。

    sr_max_sk: Maximum number of tracking TCP socket
    sr_max_icmp: Maximum number of tracking ICMP echo
    sr_icmp_sirens_res: Enable SIRENS backword probe on ICMP

    モジュールに渡すパラメータを指定する場合は、以下のように
    modprobe を実行します。

    $ sudo modprobe sr_max_sk=100 sr_max_icmp=100

    現在のパラメータを確認するには、以下のコマンドを実行して下
    さい。

    $ cat /sys/module/ip_sirens/parameters/sr_max_sk
    100
    $ cat /sys/module/ip_sirens/parameters/sr_max_icmp
    100
    $ cat /sys/module/ip_sirens/parameters/sr_icmp_sirens_res
    1

2.2 SIRENS 版 ping

    以下のコマンドを実行して下さい。/usr/local/bin/srping にイ
    ンストールされます。

    $ cd trunk/ping
    $ make
    $ sudo make install

2.3 vifset

    以下のコマンドを実行して下さい。/usr/local/sbin/vifset にイ
    ンストールされます。
    vifset を実行する場合には、"-c" オプションで設定ファイルを
    指定する必要があります。

    $ cd trunk/vifset
    $ make -f Makefile.linux
    $ sudo make -f Makefile.linux install

2.4 iperf

    以下のコマンドを実行して下さい。

    $ cd trunk/iperf-2.0.4
    $ ./configure --prefix=/usr/local/
    $ make
    $ sudo make install

2.5 SIRENSJNI

    下記の URL から java-getopt-1.0.13.jar を取得し、
    trunk/SIRENSJNI にコピーします。

    http://www.urbanophile.com/arenn/hacking/getopt/

    以下のコマンドを実行して下さい。
    使用する Java 環境が Sun Java SE6 ではない場合、Makefile.linux
    を自分の環境に合わせて調整する必要があります。

    $ cd trunk/SIRENSJNI
    $ make -f Makefile.linux

    上記のコマンドを実行すると、以下のファイルが生成されます。
    それぞれ CLASSPATH と LD_LIBRARY_PATH に追加して下さい。

    SIRENSSocket-0.0.2-linux.jar
    libSIRENSImpl.so

2.6 pyperf

    インストーラはありません。
    trunk/pyperf/pyperf.py を適当な場所にコピーして使用して下さい。


--
3. 既知の問題点

* ネットワークインターフェースの動的な増減に対応していない。

  SIRENS for Linux は、モジュールのロード時に、ネットワークインタ
  ーフェースに紐付く SRIFEntry を用意しています。そのためネットワ
  ークインターフェースの動的な増減には対応していません。

  モジュールロード後に出現したネットワークインターフェースに対し
  て  setsockopt(IPSIRENS_SRVAR), getsockopt(IPSIRENS_SRVAR) を実
  行すると EINVAL を返します。

  モジュールロード時に存在していたネットワークインターフェースが
  消滅した場合、モジュールをアンロードするまでは、ネッワークイン
  ターフェースのデタッチが完了しません。

* ユーザプログラムからの setsockopt(IP_OPTIONS) と衝突する。

  SIRENS for Linux は、SIRENS header をパケットに挿入するために内
  部的に setsockopt(IP_OPTIONS) 相当の処理を行っています。

  ユーザプログラムが独自に setsockopt(IP_OPTIONS) を実行した場合、
  意図したとおりに動作しない場合があります。


以上。
