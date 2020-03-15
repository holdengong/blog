---
title: "构建个人博客-2-使用Webhook自动发布"
date: 2020-03-14T21:15:28+08:00
draft: false
---
## 概述
上篇介绍了怎么利用hugo搭建个人博客。  有一个地方还是有点不方便，就是git push之后需要等半个小时才能发布。  
所以我想利用github的webhook实现每次推送自动发布。  

## github设置钩子
所谓的webhook,就是钩子,就是github搞事情的时候就会通知你。所以你需要准备一个接口接收github的post请求。 这里我设置为接收json格式数据，仅push时通知。
![image](https://fs.31huiyi.com/7f30d6fc-3768-40da-8866-730508edcff0.png)

## 编写接口
生产环境一般是使用Travis Ci或者Jenkins来实现类似功能，但这对于我来说有点重型了。所以自己写个接口简单实现下。
需求很简单，每当有代码推送的时候，拉取git并发布到blog部署目录。  

我这里使用.net core实现，代码十分简单，其实就一行，执行blog.sh脚本。  

再看下这个blog.sh脚本的内容，也很简单，首先拉取git内容，再拷贝到部署目录就行了。
```sh
#!/bin/bash
cd /git/blog
git pull
cp -rf /git/blog/public/. /www/wwwroot/www.holdengong.com/
```
这里有3个小坑要注意  
- 第一行的 #!/bin/bash 是必须的  
- 脚本必须是ANSI编码
- 需要执行命令 chmod +x blog.sh 是脚本可执行

## 完成
大功告成。接下来可以愉快的写日志了，写完只需要签入，自动发布，爽！  
> 这篇博客由系统自动发布

