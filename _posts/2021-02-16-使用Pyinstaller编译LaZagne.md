---
layout:     post
title:      使用Pyinstaller编译LaZagne
subtitle:   使用Pyinstaller编译LaZagne
date:       2021-02-16
author:     木已成舟
header-img: img/post-bg-rwd.jpg
catalog: 	 true
tags:
    - 内网渗透
---

## 0x00 LaZagne介绍

LaZagne 是用于获取存储在本地计算机上的大量密码的开源应用程序。LaZagne 使用Python编写，有较好的跨平台性，因此分为Windows 版本、Linux 版本、Mac版本。

支持以下密码获取：

| Windows                              | Linux                                                        | Mac                                                          |                    |
| ------------------------------------ | ------------------------------------------------------------ | ------------------------------------------------------------ | ------------------ |
| Browsers                             | 7Star Amigo BlackHawk Brave Centbrowser Chedot Chrome Canary Chromium Coccoc Comodo Dragon Comodo IceDragon Cyberfox Elements Browser Epic Privacy Browser Firefox Google Chrome Icecat K-Meleon Kometa Opera Orbitum Sputnik Torch Uran Vivaldi | Brave Chromium Dissenter-Browser Google Chrome IceCat Firefox Opera SlimJet Vivaldi WaterFox | Chrome Firefox     |
| Chats                                | Pidgin Psi Skype                                             | Pidgin Psi                                                   |                    |
| Databases                            | DBVisualizer Postgresql Robomongo Squirrel SQLdevelopper     | DBVisualizer Squirrel SQLdevelopper                          |                    |
| Games                                | GalconFusion Kalypsomedia RogueTale Turba                    |                                                              |                    |
| Git                                  | Git for Windows                                              |                                                              |                    |
| Mails                                | Outlook Thunderbird                                          | Clawsmail Thunderbird                                        |                    |
| Maven                                | Maven Apache                                                 |                                                              |                    |
| Dumps from memory                    | Keepass Mimikatz method                                      | System Password                                              |                    |
| Multimedia                           | EyeCON                                                       |                                                              |                    |
| PHP                                  | Composer                                                     |                                                              |                    |
| SVN                                  | Tortoise                                                     |                                                              |                    |
| Sysadmin                             | Apache Directory Studio CoreFTP CyberDuck FileZilla FileZilla Server FTPNavigator OpenSSH OpenVPN KeePass Configuration Files (KeePass1, KeePass2) PuttyCM RDPManager VNC WinSCP Windows Subsystem for Linux | Apache Directory Studio AWS Docker Environnement variable FileZilla gFTP History files Shares SSH private keys KeePass Configuration Files (KeePassX, KeePass2) Grub |                    |
| Wifi                                 | Wireless Network                                             | Network Manager WPA Supplicant                               |                    |
| Internal mechanism passwords storage | Autologon MSCache Credential Files Credman DPAPI Hash Hashdump (LM/NT) LSA secret Vault Files | GNOME Keyring Kwallet Hashdump                               | Keychains Hashdump |



## 0x01 基础命令

需要在一个较高权限下运行。

1. 抓取所有支持软件的密码：`laZagne.exe all`
2. 抓取特定一类软件的密码：`laZagne.exe browsers`
3. 抓取特定一个软件的密码：`laZagne.exe browsers -firefox`
4. 把所有的密码写入一个文件：`laZagne.exe all -oN;laZagne.exe all -oA -output C:\Users\test\Desktop`
5. 安静模式（标准输出上不会打印任何内容）：`laZagne.exe all -quiet -oA`
6. 解密域凭据（要解密域凭据，可以通过指定用户 Windows 密码的方式来完成。）：`laZagne.exe all -password ZapataVive`



## 0x02 编译即免杀

为什么说编译即免杀呢？因为杀软记录的是LaZagne Releases版本里exe的md5。自己编译打包的话，exe的md5是新的，从文件md5层面可以绕过部分杀软。

一开始在物理机上编译屡屡遇到问题，为避免干扰，重新创建了一台虚拟机进行编译。

### 安装Python环境

安装Python3.8

![20210216113210](../../../../img/20210216113210.png)



### 安装pyinstaller

`python -m pip install pyinstaller`

![20210216113304](../../../../img/20210216113304.png)



### 下载LaZagne项目安装依赖

项目地址：https://github.com/AlessandroZ/LaZagne

解压LaZagne，进入目录安装依赖库，`pip install -r requirements.txt`。

![20210216113440](../../../../img/20210216113440.png)



### Pyinstaller打包编译

依赖安装完成后，进入Windows目录，执行命令：`pyinstaller --onefile -w lazagne.spec`，如果遇到找不到msvcr100.dll、msvcp100.dll文件的情况，请到有这两个文件的计算机上拷贝到过去。

下图是编译成功的图。

![20210216113732](../../../../img/20210216113732.png)

### 使用LaZagne

将lazagne.exe复制到物理机上运行，没有报错，可以获取到账号密码。

![20210216114033](../../../../img/20210216114033.png)

### 测试免杀效果

给虚拟机安装360卫士+360杀毒，并将病毒库升级至最新，尝试将自己打包编译的lazagne.exe给360杀毒查杀，提示没有威胁。

![20210216114203](../../../../img/20210216114203.png)



## 0x03 一些思考

1. 编译出来的LaZagne.exe体积比较大，为9.77 MB。网上查了下可以在XP环境下打包减少一点体积。
2. 修改以及扩展LaZagne可以参考Github项目的wiki(https://github.com/AlessandroZ/LaZagne/wiki)









