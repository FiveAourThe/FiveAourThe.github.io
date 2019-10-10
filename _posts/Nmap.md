# Nmap

## Nmap基础

### Nmap简介

Nmap是一款开源的网络探测和网络扫描的工具，用来扫描网上电脑开放的网络连接端。确定哪些服务运行在哪些连接端，并且推断计算机运行哪个操作系统（fingerprinting）。

Nmap包含四项基本功能：

- 主机发现 (Host Discovery)
- 端口扫描 (Port Scanning)
- 版本侦测 (Version Detection)
- 操作系统侦测 (Operating System Detection)

### Nmap工作原理

![](D:\GitBook\paper\img\20190909092611.png)

### Nmap语法

固定格式如下：

`nmap 【选项|多选项|协】 【目标】`

#### 一次简单的扫描

`nmap 192.168.1.100`



### Nmap全面扫描

-A选项是Nmap的全面扫描，它可以全面扫描指定IP或域名的所有端口以及目标系统信息。

`nmap -A 192.168.1.100` 



### Nmap扫描指定网段

- `nmap 192.168.1.1-100`
- `nmap 192.168.1.1/24`



## Nmap主机发现

### Ping扫描

Ping扫描是只进行Ping，最后显示出在线主机。在默认情况下，Nmap会发送一个ICMP回声请求和一个TCP报文到目标端口。

`nmap -sP 192.168.1.1/24`

### 无Ping扫描

无Ping扫描用于防火墙禁止Ping的情况下，它能确定正在运行的计算机。这种扫描方式可以使Nmap穿透防火墙和避免被防火墙发现。

`nmap -P0 192.168.1.100`

### TCP SYN Ping扫描

该扫描模式会发送一个设置了SYN标志位的空TCP报文，默认目的端口为80。

`nmap -PS 192.168.1.100`

### TCP ACK Ping扫描

该扫描与TCP SYN Ping扫描非常类似，区别是设置TCP的标志位是ACK而不是SYN，使用这种方式扫描可以探测阻止SYN包或ICMP Echo请求的主机。

`nmap -PA 192.168.1.100`

也可以将-PA和-PS一起使用：

`nmap -PA -PS 192.168.1.100`



### UDP Ping扫描

该扫描方式是发送一个空的UDP报文到目标指定端口(默认端口40125)，如果主机响应则返回一个ICMP端口不可达错误，如果主机不是存活状态则返回各种ICMP错误信息。

`nmap -PU 192.168.1.100`



### ICMP Ping Types扫描

ICMP是Internet控制报文协议。它是TCP/IP协议族的一个子协议，用于在IP主机、路由器之间传递控制消息(网络通不通、主机是否可达、路由是否可用等)。该扫描模式，Nmap会发送一个ICMP type8报文到目标IP地址，从运行的主机得到一个Type0的报文。

- -PE选项
  - 向目标发送ICMP Echo 数据包来探测目标主机是否在线；
  - `nmap -PE 192.168.1.100`
- PP选项
  - ICMP时间戳Ping扫描，当防火墙不允许ICMP Echo请求，但配置不当可能会恢复ICMP时间缀请求
  - `nmap -PP 192.168.1.100`
- -PM选项
  - 进行ICMP掩码Ping扫描，会尝试用备选的ICMP等级Ping指定主机，有穿透防火墙的效果
  - `nmap -PM 192.168.1.100`

### ARP Ping 扫描

ARP(地址解析协议)，是根据IP地址获取物理地址的一个TCP/IP协议，其功能是：主机将ARP请求广播到网络上的所有主机，并接收返回消息，确定目标IP地址的物理地址，同时将IP地址和硬件地址(MAC地址)存入本机ARP缓存中，下次请求时直接查询ARP缓存；

ARP Ping扫描通常用于内网扫描，在本地局域网中防火墙不会禁止ARP请求；

`nmap -PR 192.168.1.100`



### 生成扫描列表

主机发现的退化形式，它仅仅列出网络上的每台主机，不发送任何报文到目标主机，默认会对主机进行反向域名解析以获取它们的名字；

`nmap -sL 192.168.1.100/24`，会生成该网段下所有主机的IP地址



### 禁止反向域名解析

- -n选项，禁止解析域名，nmap永远不会对目标IP地址做反向域名解析
  - `nmap -n -sL 192.168.1.100/24`
  - 如果单纯扫描一段IP，使用该选项可以大幅度减少目标主机的响应时间
- -R选项，反向解析域名，nmap永远对目标IP地址做反向域名解析
  - `nmap -R -sL 192.168.1.100/24`
  - 该选项多用于绑定域名的服务器主机上，便于我们了解目标的详细信息。如扫描一个C段时，我们更加清楚在哪一段IP上存在哪些网站



### 使用系统域名解析器

默认nmap通过直接发送查询到你主机上配置的域名服务器来解析域名，如果你希望使用系统自带的解析器，可以通过`--system-dns`选项：

`nmap --system-dns 192.168.1.2 192.168.1.100`



### 扫描IPv6地址

`nmap -6 xxxx:xxxx:xxxx:xxxx:xxxx`



### 路由跟踪

`nmap --traceroute -v www.baidu.com`



### SCTP INIT Ping扫描

SCTP(流控制传输协议)是IETF(因特网工程任务组)在2000年定义的一个传输层协议。SCTP INIT Ping扫描通过向目标发送INIT包，根据目标主机的相应判断目标主机是否存活。

`nmap -PY -v 192.168.1.100`



## Nmap探索网络

### 端口介绍

端口是指接口电路中的一些寄存器，这些寄存器分别用来存放数据信息、控制消息和状态信息，相应的端口分别称为数据端口、控制端口和状态端口。

电脑运行的系统程序，其实就像一个闭合的圆圈，但是电脑是为人服务的，他需要接受一些指令，并且要按照指令调整系统功能来工作，于是系统程序设计者，就把这个圆圈截成好多段，这些线段接口就叫端口（通俗讲是断口，就是中断），系统运行到这些端口时，一看端口是否打开或关闭，如果关闭，就是绳子接通了，系统往下运行，如果端口是打开的，系统就得到命令，有外部数据输入，接受外部数据并执行。



#### TCP端口

Transmission Control Protocol传输控制协议，TCP是一种面向连接（连接导向）的、可靠的、基于字节流的传输层（Transport layer）通信协议，由IETF的RFC 793说明（specified）。在简化的计算机网络OSI模型中，它完成第四层传输层所指定的功能，UDP是同一层内另一个重要的传输协议。

#### UDP端口 

UDP [1] :User Datagram Protocol用户数据报协议，UDP是OSI参考模型中一种无连接的传输层协议，提供面向事务的简单不可靠信息传送服务。UDP 协议基本上是IP协议与上层协议的接口。UDP协议适用端口分别运行在同一台设备上的多个应用程序。

#### 协议端口

如果把IP地址比作一间房子 ，端口就是出入这间房子的门。真正的房子只有几个门，但是一个IP地址的端口可以有65536（即：2^16）个之多！端口是通过端口号来标记的，端口号只有整数，范围是从0 到65535（2^16-1）。本地操作系统会给那些有需求的进程分配协议端口（protocol port，即我们常说的端口），每个协议端口由一个正整数标识，如：80，139，445，等等。当目的主机接收到数据包后，将根据报文首部的目的端口号，把数据发送到相应端口，而与此端口相对应的那个进程将会领取数据并等待下一组数据的到来。端口其实就是队，操作系统为各个进程分配了不同的队，数据包按照目的端口被推入相应的队中，等待被进程取用，在极特殊的情况下，这个队也是有可能溢出的，不过操作系统允许各进程指定和调整自己的队的大小。不光接受数据包的进程需要开启它自己的端口，发送数据包的进程也需要开启端口，这样，数据包中将会标识有源端口，以便接受方能顺利地回传数据包到这个端口。



### 端口扫描介绍

一个端口就是一个潜在的通信通道，也就是一个入侵通道。对目标计算机进行端口扫描，能得到许多有用的信息。通过扫描结果可以知道一台计算机上都提供了哪些服务，然后就可以通过所提供的这些服务的己知漏洞就可进行攻击。其原理是当一个主机向远端一个服务器的某一个端口提出建立一个连接的请求，如果对方有此项服务，就会应答，如果对方未安装此项服务时，即使你向相应的端口发出请求，对方仍无应答，利用这个原理，如果对所有熟知端口或自己选定的某个范围内的熟知端口分别建立连接，并记录下远端服务器所给予的应答，通过查看一记录就可以知道目标服务器上都安装了哪些服务，这就是端口扫描。



### Nmap6个端口状态

- Open
  - 对外开放状态
- Closed
  - 关闭状态
- Filtered
  - 被过滤状态
  - 当遇到防火墙或者路由器规则时，nmap报文就会过滤达到目标端口，这样Nmap无法判断目标端口是否开放
- Unfiltered
  - 未被过滤状态
  - 端口可以被访问，但是不能判断目标端口处于开放状态还是关闭状态
- Open|Filtered
  - 开放还是过滤状态，出现这种状态可以换一种扫描方式进一步确认端口开放情况
- Close|Filtered
  - 这种状态是Nmap不能确定端口是关闭还是被过滤。

### 时序选项

-T参数可以启用时序选项，Nmap有6种时序；

- -T0：非常慢的扫描，用于IDS逃避
- -T1：缓慢的扫描，用于IDS逃避
- -T2：降低速度以降低对宽带的消耗
- -T3：默认选项，根据目标的翻译自动调整时间
- -T4：快速扫描，需要在很好的网络环境下进行，请求可能会淹没目标
- -T5：极速扫描，以牺牲准确度来提升扫描速度

-T选项单一使用并不会有很好的效果，配合-F选项可以很大程度的提高扫描速度和效果。

`nmap -F -T4 192.168.1.100`

### 常用扫描方式

- -p选项
  - 可以指定一个你想要扫描的端口号，也可以是指定一个端口范围；
  - 如果想扫TCP端口又想扫UDP端口，可以在端口号前加上"T:"或"U:"，分别代表TCP协议和UDP协议；

- -r选项
  - 使用该选项不会对端口进行随机顺序扫描，默认nmap是随机顺序扫描端口的。
- --top-ports选项
  - 扫描概率高的1000个TCP端口，保存在nmap-services中
- --port-ratio选项
  - 通过nmap官方调查的端口开放概率，扫描指定一定概率以上的端口，具体范围在nmap-services中

-sU、-sT、-sS选项分别代表







### TCP SYN扫描

这种扫描方式，速度快，也相对比较隐蔽，因为它并不会建立TCP连接；它也被称为半开放扫描，当目标主机端口为关闭状态，Nmap的检测方法是发送一个SYN包请求连接，如果收到RST包则说明目标主机端口关闭，如果端口是开放的，发送一个SYN包，目标主机接收请求后会相应一个SYN/ACK包，nmap收到目标主机响应后，向目标发送一个RST代替ACK包，连接结束。

`nmap -sS 192.168.1.100`



### TCP连接扫描

该扫描时用于SYN扫描不能使用的时候，它是TCP连接扫描，会建立TCP连接。Nmap检测方法：Nmap发送一个SYN包请求，如果收到RST包则说明目标端口关闭，如果目标主机响应的是SYN+ACK包，Nmap就会像目标主机发送ACK包，确认连接，说明端口是开放的。

`nmap -sT 192.168.1.100`



### UDP扫描

UDP扫描是非常慢的，很多安全人员忽略了这些端口。UDP端口通过发送UDP数据包到目标主机并等待响应，如果目标主机返回ICMP不可达说明端口是关闭的，如果得到正确的响应说明端口是开放的。

`nmap -sU 192.168.1.100`



### TCP Null、FIN、Xmas隐蔽扫描

- Null扫描是通过发送非常规的TCP通信数据包对计算机进行探测，Null扫描不会标记任何数据包，若目标主机的对应端口是关闭的，会响应一个RST数据包，若目标端口是开放的则不会响应任何信息。

  - `nmap -sN 192.168.1.100`

- FIN扫描可以穿透防火墙，TCPP FIN扫描不需要完成TCP握手，nmap向目标端口发送一个FIN包，如果收到目标响应RST包，说明端口是开放的，如果没有收到目标的RST包则说明目标端口是关闭的。

  - `nmap -sF 192.168.1.100`

- Xmas扫描，数据包的FIN、PSH、URG标记位置打开(标志为1)，根据RFC793规定如果目标主机端口是开放的则会响应一个RST标记包。

  - `nmap -sX 192.168.1.100`


### TCP ACK扫描

TCP ACK扫描有一个致命的缺点，它不能确定端口是开放的还是被过滤的。

nmap检测方法：向目标主机端口发送一个只有设置ACK标志位的TCP数据，当扫描未过滤的系统时，open和close端口都会返回RST报文；当Nmap把它们标记为nufiltered，意思是ACK报文不能达，但不能确定端口状态时open还是closed。不响应的端口或者发送特定的ICMP错误消息的端口都会被标记为filterd。

`nmap -sA 192.168.1.100`



### TCP 窗口扫描

扫描方式与ACK扫描方式的原理几乎一样，它通过返回的RST报文的TCP窗口域判断目标端口是否开放。比如开放端口用正数表示，关闭端口用0表示。这种扫描方式扫描结果是很可能不准确的，如果100个端口只有2个事关闭的，那么这2个也很有可能是开放的。

`nmap -sW 192.168.1.100`



### TCP Maimon扫描

这种扫描技术和3种隐蔽扫描完全一样；

`nmap -sM 10.20.40.95`



### 自定义TCP扫描

自定义扫描是Nmap高级用法，这种扫描可以通过指定任意的TCP标志位进行扫描。`--scanflags`选项可以是数字标记值，如9(PSH和FIN)，也可以是字符名(URG、ACK、PSH、RST、SYN、FIN)的组合。

`nmap -sT --scanflags SYNURG 192.168.1.100`



### 空闲扫描

空闲扫描也是Nmap的高级用法，允许进行端口完全欺骗扫描。可以使攻击者能够不使用自己的IP向目标主机发送数据包，它可以利用不活跃的讲师主机反弹给攻击者一个旁道信道，从而进行端口扫描。

`nmap -sI www.eavl.com:80 192.168.1.100`



### IP协议扫描

IP协议扫描会确定目标端口的协议类型，这并不是一种严格的端口扫描方式，它不是扫描TCP、UDP端口号，而是IP协议号。

`nmap -sO 192.168.1.100`



## 指纹识别与探测



### 版本探测

`nmap -sV 192.168.1.100`

探测版本和操作系统：

`nmap -sV -A 192.168.1.100`

### 设置扫描强度

可以设置的值使1——9之间的值，默认强度是7，值越高识别的越准确，但是会牺牲扫描时间。

`nmap -sV --version-intensity 9 192.168.1.100`

### 轻量级扫描

轻量级扫描是--version-intensity 2的快捷命令

`nmap -sV --version-light 192.168.1.100`

### 重量级扫描

重量级扫描是--version-intensity 9的快捷命令

`nmap -sV --version-all 192.168.1.100`

### 获取详细的版本信息

`nmap -sV --version-trace 192.168.1.100`

### RPC扫描

RPC扫描对所有对发现开放的TCP/UDP端口执行SunRPC程序NULL命令，确定是否为RPC端口，如何是RPC端口，则返回程序和版本号。

`nmap -sS -sR 192.168.1.100`

### 操作系统探测

`nmap -O  192.168.1.100`

### 推测并识别系统

`nmap -O --osscan-guess 192.168.1.100`



## 定时任务

### 调整并行扫描组的大小

调整并行扫描组大小有两个选项，分别是--min-hostgroup与--max-hostgroup。nmap默认最初最小为5。

`nmap --max-hostgroup 10 192.168.1.100`

### 调整探测报文的并行度

调整探测报文的并行度有两个选项，分别是--min-parallelism和--max-parallelism。--min-parallelism大于1可以在网络或主机不好的情况下更好的扫描，但会影响结果的准确度。--max-parallelism设置为1，可以防止nmap对同一主机同一时间发送多次报文。

`nmap --min-parallelism 100 192.168.1.100`

### 调整探测报文的超时时间

调整探测报文的超时时间选项有3个，--min-rtt-timeout、--max-rtt-timeout、--initial-timeout。这些选项都是以毫秒为单位的，设置时需要加上ms单位。

`nmap --min-rtt-timeout 500ms 192.168.1.100`

### 放弃缓慢的主机目标

在扫描过多主机时可能会遇到带宽等原因导致扫描速度变慢，使用--host-timeout选项可以放弃缓慢的目标主机，来加快扫描速度。--host-timeout单位是毫秒，设置时需要加上ms单位。

`nmap --host-timeout 100ms 192.168.1.100`

### 调整报文适合时间间隔

调整报文合适时间间隔有2个选项，--scan-delay和--max-scan-delay。他们可以控制nmap对一个或多个主机发送探测报文的等待时间。

`nmap --scan-delay 1s 192.168.1.100`



## 防火墙/IDS逃逸技术

### 防火墙和IDS

网络防火墙是一个位于计算机和它所连接的网络之间的软件。流入流出计算机的所有网络通信都要经过网络防火墙，网络防火墙对流经它的网络流量进行过滤，过滤掉部分攻击流量。网络防火墙还可以控制端口的流出通信。

IDS是入侵检测系统，专业上讲就是依照一定的安全策略，通过软、硬件，对网络、系统的运行状况进行监视，尽可能发现各种攻击企图、攻击行为或者攻击结果，以保证网络系统资源的机密性、完整性和可用性。

### 报文分段

使用-f选项，nmap会在IP头后会将包分为8个字节或者更小。

`nmap -f 192.168.1.100`

### 指定偏移大小

MTU偏移量必须是8的倍数，MTU是设定TCP/IP协议传输数据报时的最大传输单元。

`nmap --mtu 24 192.168.1.100`

### IP欺骗

通过IP欺骗会让主机误以为是在利用诱饵进行扫描，从而忽略这次扫描。RND可以随机生成多个IP地址。需要注意的是诱饵主机必须处于工作状态，否则会导致目标主机SYN洪水攻击。

`nmap -D RND:11 192.168.1.100`

### 源地址欺骗

就是空闲扫描。

### 源端口欺骗

防火墙可能会根据端口选择是否信任数据流，管理员可能会认为这些端口不会有攻击发生。

`nmap --source-port 53 192.168.1.100`

### 指定发包长度

一般，TCP包是40个字节，ICMP Echo包是28个字节。通过--data-length选项在原来的报文基础上附加随机数据达到规避防火墙的效果。

对目标主机发送30个字节大小的数据包：

`nmap --data-length 30 192.168.1.100`

### 目标主机随机排序

使用--randomize-hosts对目标主机的顺序进行随机的排序。

`nmap --randomize-hosts 192.168.1.1-100`

### Mac地址欺骗

指定一个Mac地址，起到欺骗管理员的效果。--spoof-mac选项有3个参数，0表示随机生成一个MAC地址，MAC Address表示用户指定一个MAC地址，Vendor Name表示指定厂商生成一个MAC地址。

`nmap --spoof-mac 0 192.168.1.100`



## 信息搜集

### IP信息搜集

获取目标域名的IP地址和所在地：

`nmap --script ip-geolocation-* www.baidu.com`

### Whois查询

Whois通常使用TCP协议43端口。

`map --script whois-domain  www.baidu.com`

### 旁站查询/IP反查

`nmap --script hostmap-ip2hosts www.baidu.com`

### DNS信息搜集

DNS使用TCP和UDP的53端口。

`nmap --script dns-brute www.baidu.com`

### 检索系统信息

`nmap -p 445 --script membase-http-info 192.168.1.100`

### 检查后台打印机服务漏洞

`nmap -p --script smb-security-mode 192.168.1.100`

### 系统漏洞扫描

`nmap -p 445 --script smb-check-vulns 192.168.1.100`

### 扫描Web漏洞

#### 检查XSS漏洞

`nmap -p 80 --script http-stored-xss www.baidu.com`

#### 检查SQL注入

`nmap -p 80 --script http-sql-injection www.baidu.com`









## 数据库渗透测试



### 获取所有数据库

当我们已知目标Mysql的账号和密码，就可以通过以下命令获取所有数据库：

`nmap -p 3306 --script mysql-databases --script-args= mysqluser=root,root 10.20.40.95`



### 获取Mysql变量

通过以下命令获取目标Mysql变量：

`nmap -p 3306 --script mysql-variables 10.20.40.95`



### 审计Mysql密码

使用以下命令检查目标Mysql服务是否为空密码/root/匿名登录：

`nmap -p 3306 --script=mysql-empty-password 10.20.40.95`

#### 暴力破解

使用mysql-brute脚本可以检查Mysql弱口令：

`nmap -p 3306 --script=mysql-brute 10.20.40.96`

支持自定义账号密码：

`nmap -p 3306 --script=mysql-brute userdb=/root/user.txt passdb=/root/passwd.txt 10.20.40.96`



### 审计Mysql安全配置

`nmap -p 3306 --script mysql-audit --script-args "mysql-audit.username='root',mysql-audit.password='root',mysql-audit.filename='nselib/data/mysql-cis.audit'"`



### 审计Oracle密码

`nmap --script oracle-brute -p 1521 --script-args oracle-brute.sid=username 10.20.40.96`

该脚本也支持自定义字典：

`nmap --script oracle-brute -p 1521 --script-args oracle-brute.sid=username --script-args userdb=/root/user.txt,passdb=/root/passwd.txt 10.20.40.96`



### 审计Mssql密码

#### 检查空密码

`nmap -p 1433 --script ms-sql-empty-password 10.20.40.96`

#### 暴力破解

`nmap -p 1433 --script ms-sql-brute --script-args userdb=/root/user.txt,passdb=/root/pass.txt 10.20.40.96`



### 获取Mssql数据库数据

`nmap -p 1433 ms-sql-tables --script-args mssql.username=sa,mssql.Password=sa 10.20.40.96`



### Mssql执行系统命令

`nmap -p 1433 --script ms-sql-xp-cmdshell --script-args mssql.username=sa,mysql.password=sa,ms-sql-xp-cmdshell.cmd="whoami" 10.20.40.96`



### 审计Postgresql密码

`nmap -p 5432 --script pgsql-brute 10.20.40.96`



## Nmap在渗透测试中的应用

### 审计HTTP身份验证

`nmap --script http-brute -p 80 10.20.40.95`

### 审计FTP服务器

检测匿名用户：

`nmap --script ftp-anon 10.20.40.95`

默认字典爆破：

`nmap --script ftp-brute -p 21 10.20.40.95`

自定义爆破字典：

`nmap --script ftp-brute --script-args userdb=/root/user.txt,passwd=/root/passwd.txt -p 21 10.20.40.95`



### WordPress程序口令破解

枚举用户名：

`nmap --script http-wordpress-users -p 80 10.20.40.95`

默认字典暴力破解：

`nmap --script http-wordpress-brute -p 80 10.20.40.95`

自定义字典暴力破解：

`nmap --script http-wordpress-brute --script-args userdb=/root/user.txt,passdb=/root/passwd.txt --script-args http-wordpress-brute.thread=10 -p 80 10.20.40.95 `



### Joomla程序口令破解

默认字典暴力破解：

`nmap -p 80 --script http=joomla-brute 10.20.40.96`

自定义字典暴力破解：

`nmap -p 80 --script http-joomla-brute --script-args userdb=/root/user.txt,passdb=/root/passwd.txt,http-joomla-brute.threads=10 10.20.40.96`

### 邮件服务器口令

`nmap -p 110 --script pop3-brute 10.20.40.96`

### SMB口令破解

`nmap --script smb-brute -p 445 10.20.40.95`

自定义字典破解：

`nmap --script smb-brute --script-args userdb=/root/user.txt,passdb=/root/passwd.txt -p 445 10.20.40.95`



### 审计VNC服务器

`nmap --script vnc-brute -p 5900 10.20.40.95`

自定义字典破解：

`nmap --script vnc-brute --script-args userdb=/root/user.txt,passdb=/root/passwd.txt -p 5900 10.20.40.95`

### 审计SMTP服务器

`nmap -p 25 --script smtp-enum-users smtp.qq.com`



### 检测Stuxnet蠕虫

`nmap --script stuxnet-detect -p 445 10.20.40.95`

### SNMP安全审计

SNMP 是专门设计用于在 IP 网络管理网络节点（服务器、工作站、路由器、交换机及HUBS等）的一种标准协议，它是一种应用层协议。 SNMP 使网络管理员能够管理网络效能，发现并解决网络问题以及规划网络增长。通过 SNMP 接收随机消息（及事件报告）网络管理系统获知网络出现问题。

#### 获取目标主机网络连接状态

`nmap -sU -p 161 --script=snmp-netstat 10.20.40.96`

#### 获取目标主机系统进程

`nmap -sU -p 161 --script=snmp-processes 10.20.40.96`

#### 获取Windows服务器运行的服务

`nmap -sU -p 161 --script=snmp-win32-services 10.20.40.96`

#### SNMP口令破解

`nmap -sU -p 161 --script snmp-brute 10.20.40.96`



## Zenmap

zenmap是一个开放源代码的网络探测和安全审核的工具，它是nmap安全扫描工具的图形界面前端，它可以支持跨平台。使用zenmap工具可以快速地扫描大型网络或单个主机的信息。



### Zenmap扫描模板

- Intense scan 
  - 标准扫描
- Intense scan plus UDP
  - UDP扫描
- Intense scan, all TCP ports
  - 扫描所有端口
- Intense scan, no ping
  - 无Ping扫描
- Ping scan
  - Ping扫描
- Quick scan
  - 快速扫描
- Quick scan plus
  - 探测服务版本和端口扫描
- Quick traceroute
  - 追踪路由节点
- Regular scan
  - 自定义模板
- Slow comprehensive scan
  - 全面扫描

#### 自定义模板

快捷键Ctrl+P



## Nmap技巧

### 发送以太网数据包

在数据链路层发送报文：

`nmap --send-eth 10.20.40.96`

### 网络层发送

在网络层发送报文：

`nmap --send-ip 10.20.40.96`

### 假定拥有所有权

`nmap --privileged 10.20.40.96`

### 在交互模式中启动

`nmap --interactive`

### 查看Nmap版本号

`nmap -V`

### 设置调试级别

级别：1~9

`nmap -d 1 10.20.40.96`

### 跟踪发送报文/调试

`nmap --packet-trace 10.20.40.96`

### 列举接口和路由

`nmap --iflist www.baidu.com`



### 指定网络接口

`nmap -e eth0 10.20.40.96`

### 继续中断扫描

`nmap -oG 1.txt -v 10.20.40.96`

继续扫描：

`nmap --resume 1.txt`

### Nmap分布式扫描

#### Dnmap框架

服务器接收命令并发送至客户端进行Nmap安全扫描，扫描完毕后客户端返回扫描结果。

### 编写Nse脚本



### 探测防火墙

`nmap --script firewalk --traceroute 10.20.40.96`

### VMWare认证破解

`nmap -p 902 --script vmauthd-brute 10.20.40.96`



## Nmap保存与输出

### 标准保存

`nmap -F -oN test.txt 10.20.40.96`

保存的内容和打印的内荣一致

### XML保存

`nmap -oX test.xml 10.20.40.96`



### 133t保存

`nmap -oS test.txt 10.20.40.96`

### 

### Grep保存

`nmap -oG test.txt 10.20.40.96`



### 保存为所有格式

`nmap -oA test 10.20.40.96`



