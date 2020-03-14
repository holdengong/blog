---
title: "使用Hugo搭建个人博客"
date: 2020-03-14T14:42:38+08:00
draft: false
---
## 下载Hugo

> https://github.com/gohugoio/hugo/releases

笔者是Windows系统，下载hugo_0.67.0_Windows-64bit.zip，解压到本地后，将路径加入到环境变量。

## 创建站点
首先创建一个git仓库  
拉取到本地  
如文件夹名为blog  
```
cd blog
hugo new site .
```

## 编写正文
hugo new hello-world.md

## 下载主题
```
cd theme 
git clone https://github.com/spf13/hyde.git
```

## 调试
```
hugo server --theme=hyde --buildDrafts
```
然后浏览器打开 http://localhost1313 可以查看效果

## 发布
发布前将hello-world.md的draft字段修改为true, https://holdengong.com/
为你网站的域名
```
hugo --theme=hyde -b https://holdengong.com/
```
执行完后会发现生成了public文件夹及内容

## 部署
### 云服务器可以使用腾讯云的学生版  
> https://cloud.tencent.com/act/campus?fromSource=gwzcw.2432501.2432501.2432501&utm_medium=cpc&utm_id=gwzcw.2432501.2432501.2432501
### 安装宝塔面板linux管理工具 
> https://www.bt.cn/
### 安装git
```
yum -y install git
```
拉取git仓库, e.g.仓库目录为/git/blog
### 宝塔新建站点
e.g.站点根路由为/www/wwwroot/www.holdengong.com

### 定时发布
利用linux的定时任务做一个简单的定时发布  
在宝塔面板新建定时任务,每1小时执行linux脚本
```
cd /git/blog
git pull
cp -rf /git/blog/public/. /www/wwwroot/www.holdengong.com/
```
后面会利用github的钩子来实现推送后自动发布

## 成功
部署成功。  
接下来只需要在本地content文件夹撰写日志, 然后编译
```
hugo --theme=hyde -b https://holdengong.com/
```
完成后推送到git仓库, 每小时会自动发布。


