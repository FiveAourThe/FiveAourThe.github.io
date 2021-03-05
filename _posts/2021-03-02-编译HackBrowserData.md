---
layout:     post
title:      编译HackBrowserData
subtitle:   编译HackBrowserData
date:       2021-03-02
author:     木已成舟
header-img: img/post-bg-rwd.jpg
catalog: 	 true
tags:
    - 内网渗透
---

### HackBrowser的优势

1. 当LaZagne没有抓到密码时，HackBrowser可以抓到
2. 跨平台性，支持Linux、Windows、MacOS
3. go语言，有一定的免杀性



### 编译环境准备

- Golang下载：https://dl.google.com/go/go1.15.8.windows-amd64.msi
- HackBrowserData源码下载：https://github.com/moonD4rk/HackBrowserData
- gcc环境下载并添加到Path中：https://sourceforge.net/projects/mingw-w64/files/

注意：这里有个坑点，一开始我下载的是Golang1.16版本的，编译就会报错，之后卸载换了1.15.8就可以编译：

![20210302100342](../../../../img/20210302100342.png)

### 编译

编译命令：

```
go get -v -t -d ./...
go build
```

如果出现以下错误，请先换源再试：

![20210302095104](../../../../img/20210302095104.png)

换国内源的命令：

```
go env -w GO111MODULE=on
go env -w GOPROXY=https://goproxy.cn,direct
```

继续执行编译命令，成功编译。

![20210302095345](../../../../img/20210302095345.png)



### 使用方法

在有杀毒软件的环境下运行以下命令，可以过静态和动态查杀，导出密码后，才被杀了。

`.\hack-browser-data.exe -b all -f json --dir results -cc`

![20210302095553](../../../../img/20210302095553.png)

![20210302095626](../../../../img/20210302095626.png)



### 一些思考

1. 编译体积：go语言编译的体积还是比较大的，约为16.5 MB，想要压缩体积的话，可以考虑使用UPX压缩 
2. 有一定的免杀性：工具抓到密码后，杀毒软件才会查杀该文件



