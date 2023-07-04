---
title: Hexo+github搭建个人博客
date: 2023-07-02 21:23:30
tags: [搭建博客]
---

------

**使用Hexo + GitHub 搭建博客具有以下好处**

**1、简单易用：**Hexo是一个基于Node.js的静态网站生成器，它简化了博客搭建和部署的流程。通过Hexo，可以使用Markdown编写文章，并自动生成静态HTML页面。

**2、速度快：**Hexo生成的是纯静态页面，不需要在每次请求时重新运行服务器端代码，因此加载速度非常快。相比于动态网站，静态博客更能提供快速的访问体验。

**3、版本控制与备份：**使用Git将博客存储在GitHub上，不仅可以进行版本控制，跟踪每个文件的修改历史，还可以轻松地备份你的博客内容。如果遇到意外情况导致数据丢失，你可以从Git仓库中恢复之前的版本。

**4、托管于GitHub Pages：**GitHub Pages是由GitHub提供的免费静态网页托管服务。可以将Hexo生成的静态页面直接发布到GitHub Pages上，无需购买独立服务器或付费空间，这使得部署变得非常简便。

**5、高度可定制：**Hexo提供了众多主题和插件，能够自定义博客的外观和功能。可以根据自己的喜好选择合适的主题，并使用插件来增强博客的功能，如社交分享、评论系统等。		

本文提供在windows环境下搭建博客的详细介绍，包括**博客搭建、博客部署、博客书写**、**博客迁移**。

------



# 一、博客搭建

## 1.1 node.js安装下载

### 1.1.1 介绍

NOde.js是一个基于Chrome V8引擎的JavaScript运行时环境，允许开发者在服务器端使用JavaScript进行编程。它提供了一种极高效、可扩展的方式来构建网络应用程序。在博客搭建中，Node.js可以很方便地用于构建博客的API接口，这些接口可以提供给前端应用或其他第三方应用程序使用，可以实现文章的发布、评论的管理、用户认证等功能；除此之外，Node.js还可以用作静态文件服务器，提供博客中的静态资源（如图片、CSS、JavaScript文件）的快速传输，提高网站加载速度和性能。

### 1.1.2 下载

官网：https://nodejs.org/en/   

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/images/nodejs.png?x-oss-process=style/watermark" style="zoom:75%;" />

LTS是长期维护版，Current是长期使用版，下载LTS版本就可以了。

### 1.1.3 安装

直接点击下载的msi文件即可。

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/images/nodejs1.png?x-oss-process=style/watermark" style="zoom:75%;" />

直接一路无脑next就可以了，不放图了。

测试一下是否安装成功：在cmd窗口中输入：node -v 和 npm -v ，成功显示版本就可以了。 

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/images/nodejs2.png?x-oss-process=style/watermark"  />



## 1.2 Git安装下载

### 1.2.1 介绍

Git是一种分布式版本控制系统，用于跟踪、管理和协同开发项目的代码。将博客项目存储在Git仓库中，相当于进行了实时备份。如果发生意外情况，导致博客数据丢失或受损，可以轻松地从Git仓库中恢复到之前的版本。利用Git的分支机制，可以轻松管理不同环境的博客版本，通过配置自动化部署流程，可以根据项目的需要，将更新的博客内容快速发布到服务器上，实现持续集成和快速迭代。

### 1.2.2 下载

官网：https://git-scm.com/download/win 

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/images/Git.png?x-oss-process=style/watermark" style="zoom:75%;" />

点击第一行的Click here to download即可。

### 1.2.3 安装

直接点击下载好的exe文件就可以。

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/images/Git2.png?x-oss-process=style/watermark" style="zoom: 80%;" />

也是一路next就可以。

安装后验证，在cmd命令里输入git -v，正确显示版本就没问题。

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/images/Git3.png?x-oss-process=style/watermark" style="zoom:80%;" />

然后配置SSH key。配置SSH密钥对可以提供更强大的身份验证、加密通信和方便的登录方式。

打开**git bash**：

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/images/Git4.png?x-oss-process=style/watermark" style="zoom: 80%;" />

输入：

```bash
ssh-keygen -t rsa -C “yourEmail”  #your Email换成你的github账号的注册邮箱
```

多次**回车**后：

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/images/Git5.png?x-oss-process=style/watermark" style="zoom:80%;" />

然后在用户文件夹下，比如我的就是在 c盘-->用户-->wutong 下可以找到两个文件。一个是id_rsa，一个是id_rsa.pub。将id_rsa.pub用记事本打开，将里面的内容复制。也可以使用ls确认文件存在后，直接输入cat命令获取公钥：

```bash
cat id_rsa.pub
```

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/images/Git6.png?x-oss-process=style/watermark" style="zoom:80%;" />



然后进入你的github账户，点击头像，点击setting，进入个人设置。找到SSH and GPG keys -> New SSH key，将复制的ssh直接粘贴过去（什么都不用改），title可以随便填。

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/images/Git7.png?x-oss-process=style/watermark" style="zoom: 67%;" />

保存以后，使用如下命令测试是否链接成功：

```bash
ssh -T git@ginhub.com
```

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/images/Git8.png?x-oss-process=style/watermark" style="zoom:80%;" />

第一次链接会问你Are you sure，输入yes即可。如果链接不通，可以使用如下命令后，再进行测试。

```bash
ssh-agent -s #启动ssh代理

ssh-agent bash #ssh代理中运行bash,使其它命令使用代理

ssh-add ~/id_rsa #将私钥添加到代理中
```

配置用户名和eamil：

```bash
git config --global user.name "Your Name"

git config --global user.email "email@example.com"
```

## 1.3 hexo框架安装

### 1.3.1 介绍

Hexo是一个基于 Node.js 的静态博客生成器，可以快速创建和部署静态网站或博客。Hexo 具有方便的命令行界面，可以通过简单的命令生成静态的博客网页。且Hexo 支持各种主题和模板，可以选择使用现有的主题或自定义创建主题来定制博客的外观和样式。除此之外，Hexo 拥有强大的插件系统，提供了丰富的功能扩展选项。可以通过安装适用的插件来为你的博客添加额外的功能，比如评论系统、分析工具、社交媒体分享等。为了管理这些插件和主题，在搭建过程中需要使用npm和cnpm。npm 是 Node.js 的默认包管理器，而 cnpm 是中国淘宝镜像提供的加速服务。通过这两个工具，可以方便地安装、更新和删除所需的第三方插件和库。

### 1.3.2 安装

利用npm安装cnpm，在cmd里输入以下命令：

```bash
npm install -g cnpm --registry==https://registry.npm.taobao.org	
```

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/images/hexo1.png?x-oss-process=style/watermark" style="zoom:80%;" />

使用cnpm -v命令测试是否安装成功

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/images/hexo2.png?x-oss-process=style/watermark" style="zoom:80%;" />

利用cnpm安装hexo框架，在cmd里输入以下命令：

```bash
cnpm install -g hexo-cli
```

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/images/hexo3.png?x-oss-process=style/watermark" style="zoom:80%;" />

使用hexo -v 命令测试是否安装成功

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/images/hexo4.png?x-oss-process=style/watermark" style="zoom:80%;" />

### 1.3.3 初始化并启动服务

创建博客目录，比如D:\blogs，也可以创建在其它目录下。在该目录下，右键打开 git bash。输入 hexo init 初始化。

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/images/hexo5.png?x-oss-process=style/watermark" style="zoom:75%;" />

然后输入以下命令生成静态文件并启动服务：

```bash
	hexo generate

	hexo server
```

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/images/hexo6.png?x-oss-process=style/watermark" style="zoom:75%;" />

不要关闭服务，访问 http://localhost:4000/ 即可查看博客。

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/images/hexo7.png?x-oss-process=style/watermark" style="zoom: 50%;" />

------



# 二、博客部署

## 2.1  创建github个人仓库

登录github账号，点击头像，仓库在 your repositories中。

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/images/io1.png?x-oss-process=style/watermark" style="zoom: 50%;" />

点击new新建仓库，命名必须是  用户名.github.io。这个用户名是你的**github账户名**，比如我的账户名是wutong01304，那么仓库名就是wutong01304.github.io。刚开使没理解到位，用了图下的错误仓库名，然后最后的网址就404了。。。

还好仓库名可以修改，修改成正确的就好了。

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/images/io2.png?x-oss-process=style/watermark" style="zoom:75%;" />

域名可以绑定也可以不绑定，绑定的话，就去注册一个域名，然后在github pages项目根目录上新建一个CNAME文件，在CNAME文件上写入想绑定的域名，不需要带https和www。

## 2.2 安装hexo-deployer-git 的插件

在之前创建的博客目录下，也就是执行hexo init 初始化hexo的地方，在之前创建的博客目录下 安装hexo-deployer-git 插件，命令：

```bash
	cnpm install --save hexo-deployer-git
```

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/images/io3.png?x-oss-process=style/watermark" style="zoom:75%;" />

## 2.3 配置deploy

然后，配置deploy，将博客的代码和文件部署到服务器上。依然在之前创建的博客目录下，即D:\blogs ，找到_config.yml文件，找到末尾：

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/images/io4.png?x-oss-process=style/watermark" style="zoom:75%;" />

修改deploy，type为git，repo为刚才新建的个人仓库的地址，branch为master	

```yaml
deploy:
  type: git
  repo: git@github.com:username/username.github.io.git
  branch: master
```

修改后如下：

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/images/io5.png?x-oss-process=style/watermark" style="zoom:75%;" />



然后，依然在之前创建的博客目录下，即D:\blogs，输入

```bash
	hexo deploy
```

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/images/io6.png?x-oss-process=style/watermark" style="zoom:75%;" />

在deploy的时候，出现了git @github.com: Permission denied (publickey).报错，导致deploy失败。检查原因发现，是因为密钥问题，发现c盘用户下的id_rsa、id_rsa.pub、.gitconfig文件都在.ssh文件夹外面，这可能是之前多次配置ssh key问题。于是我把这些文件复制到.ssh文件内，然后就成功链接了。

上述图片中的warning可以不用管，也可以使用以下命令

```bash
	git config --global core.autocrlf true #提交时转换为LF，检出时转换为CRLF

	git config --global core.safecrlf false #允许提交包含混合换行符的文件
```

再次deploy就没有warning啦。

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/images/io7.png?x-oss-process=style/watermark" style="zoom:75%;" />

在浏览器中输入自己的域名 https://username.github.io/, 就可以访问啦。

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/images/io8.png?x-oss-process=style/watermark" style="zoom: 50%;" />

------

# 三、博客书写

## 3.1 新建博客

新建博客之后，在source/_posts 目录下会生成相关md文件，打开md文件就可以编辑了。

```bash
	hexo new "newblog" #新建博客
```

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/images/md1.png?x-oss-process=style/watermark" style="zoom:75%;" />

生成的md文件自带YAML front matter。我使用的是Typora来编辑markdown文件，官网：https://typoraio.cn/，当然，也可以用其它的编辑器。

```bash
	hexo clean #清除缓存

	hexo generate #生成静态文件

	hexo delopy #上传博客，默认不上传没有修改过的文件
```

## 3.2 上传md文件

也可以自己编写md文件，加上YAML front matter头就可以。

```yaml
title: name #文章页面上的显示名称

date: 2023-07-03 21:23:30 #文章生成时间，一般不改

tags: [tag1,tag2,tag3] #文章标签，可空，多标签请用数组格式
```

​		记得将写好的md文件放入source/_posts。然后也是一样的流程，hexo g和hexo s重新生成发布，再执行hexo d上传到github仓库就可以。这里hexo s是为了在本地预览博客，方便调试。

## 3.3 更换主题

hexo官网上有很多主题，可以选一个自己喜欢的： https://hexo.io/themes/ 。

点击主题的标题，就可以跳转到github页面，然后点击code获取主题的下载链接。

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/images/md2.png?x-oss-process=style/watermark" style="zoom:75%;" />

复制链接后，打开git bash，将其下载到本地。格式为 git clone URL themes/主题名

```bash
 git clone https://github.com/EvanNotFound/hexo-theme-redefine.git themes/redfine
```

然后修改_config.yml 文件，在里面找到theme: landscape改为theme: redefine。

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/images/md4.png?x-oss-process=style/watermark" style="zoom:75%;" />

找到url链接。将url修改为你的博客网址。

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/images/md5.png?x-oss-process=style/watermark" style="zoom:75%;" />

然后hexo g、hexo d 重新生成发布就可以啦。

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/images/md6.png?x-oss-process=style/watermark" style="zoom:75%;" />

最后刷新一下博客，就成功更换主题了：

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/images/md7.png?x-oss-process=style/watermark" style="zoom: 50%;" />



## 3.4 图片问题

图片存放在主机上，可能导致页面和图片加载速度较慢，而且更换主机后，博客中的图片可能因为文件夹位置错误导致加载失败，因此我们采用图云来解决这个问题。图云通常提供易于使用的管理界面和API，可以轻松地上传、删除和管理图片。此外，可以使用链接或嵌入代码将图片分享给他人，方便在博客中引用和展示。本文使用PicGo配置阿里云OSS

### 3.4.1、图床打造

阿里云官网：https://www.aliyun.com/ ，登录注册后，搜索对象存储OSS，点击立即购买。可以买40G，一年的，只要9块钱。

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/images/OSS1.png?x-oss-process=style/watermark" style="zoom:75%;" />

​		

支付完成后直接跳转到管理控制台。

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/images/OSS2.png?x-oss-process=style/watermark" style="zoom:75%;" />

点击左侧的Buket列表，创建Bucket。选择**标准存储**，**公共读**。

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/images/OSS3.png?x-oss-process=style/watermark" style="zoom: 50%;" />

创建完成后，就可以新建文件夹上传文件啦。

### 3.4.2 PicGo

PicGo是一款开源的图片上传工具，可以帮助用户快速上传本地图片到云存储，并生成可访问的链接。它支持多种云存储服务商，如腾讯云、阿里云等。

官网下载：https://github.com/Molunerfinn/PicGo/tags，下载之后安装。最好**不要安装beta测试版**，**不要安装在c盘**。安装完成后运行

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/images/OSS5.png?x-oss-process=style/watermark" style="zoom:75%;" />

点击图床设置，设置阿里云

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/images/OSS6.png?x-oss-process=style/watermark" style="zoom:75%;" />

前往阿里云获取相关信息。**点击头像-->点击AccessKey 管理-->创建 AccessKey**。验证以后，获得以下信息：

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/images/OSS7.png?x-oss-process=style/watermark" style="zoom:75%;" />

将信息填写到PicGo的KeyId和KeySecret。然后Bucket填写你创建的BucKet名字，存储区域就是设置的BucKet的地域（可以在历史访问路径-->概览-->访问端口里面找到）。存储路径就是在Bucket建立的目录路径。域名设置和网址后缀可以不用设置。域名最好不要设置，刚开始不懂，如下下图设置了之后，就出错了，图片加载不出来。

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/images/OSS8.png?x-oss-process=style/watermark" style="zoom: 67%;" />

填写完毕：

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/images/OSS9.png?x-oss-process=style/watermark" style="zoom:75%;" />

然后就可以上传图片了。上传完成后，会自动复制链接。然后点击PicGo的的设置，设置服务器。

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/images/OSS10.png?x-oss-process=style/watermark" style="zoom:75%;" />

点击Typora的偏好设置，设置上传选项如下：

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/images/OSS11.png?x-oss-process=style/watermark" style="zoom:75%;" />

这样每次插入图片的时候就会自动上传啦。可以点击 **验证图片上传选项**，检查下是否可以成功上传。**不要安在c盘，会因为没有权限无法启动PicGo。**

------



# 四、博客迁移

在使用Hexo进行部署时，hexo d命令会将Hexo生成的静态网页文件上传到GitHub或其他托管平台。这些静态网页文件是由Hexo编译生成的，用于展示最终的博客网站，它们不包含源文件（如Markdown文件）或其他Hexo框架的相关文件。部署过程中，Hexo会将生成的静态文件存储在项目根目录下的.deploy_git文件夹中。然后，hexo d命令会使用Git将该文件夹中的内容推送到远程仓库（例如GitHub上的仓库）。也就是说，一旦**换了电脑就没有办法更新博客了**。

因此，我们在仓库新增分支来备份配置文件和markdown源文件。

## 4.1 新建仓库分支

点开自己的仓库github.io，分支branch就在下图所示位置。

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/images/mig1.png?x-oss-process=style/watermark" style="zoom: 67%;" />

点击New branch新建一个名为hexo的分支。

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/images/mig2.png?x-oss-process=style/watermark" style="zoom: 67%;" />

在setting的General里，找到默认分支Default branch，然后将其改为hexo。点击update更新。

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/images/mig3.png?x-oss-process=style/watermark" style="zoom: 67%;" />

## 4.2 克隆分支

打开git bash，输入以下命令将其克隆到本地，因为默认分支已经设成了hexo，所以clone时只clone了hexo。

```bash
	git clone git@github.com:username/username.github.io.git
```

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/images/mig4.png?x-oss-process=style/watermark" style="zoom:75%;" />

把除了.git 文件夹外的所有文件都删掉。（.git文件被隐藏了，因此要打开  查看隐藏的文件）

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/images/mig5.png?x-oss-process=style/watermark" style="zoom:75%;" />

然后把之前我们写的博客源文件全部复制过来，即D:\blogs目录下的全部文件，除了.git 和 .deploy_git。如果之前克隆过theme中的主题文件，那么应该把主题文件中的.git文件夹删掉，因为git不能嵌套上传。

在克隆的io目录下，执行如下命令。（以后上传博客前，都要使用这些命令来更新分支）

```bash
	git add . #保存所有文件到暂存区
	git commit -m "add branch"  #提交变更,""中为注释
	git push #推送到github，这里默认分支已设置为hexo，所以修改的是hexo
```
<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/images/mig6.png?x-oss-process=style/watermark" style="zoom:75%;" />

执行成功后可以在github上看hexo分支下文件有没有上传上去，其中node_modules、public、db.json已经被忽略掉了，而这些文件不需要上传的，因为会在别的电脑上需要重新输入命令安装 。

hexo分支下就存放好了博客网站的配置文件和markdown源文件。

## 4.3 更换电脑

首先搭建环境，参考第一章的内容。**进行到第一章3.3节初始化**时，不进行hexo init的操作。（添加新的密钥原先的可以不用删除，这样两个电脑都可以更新博客了）

直接进行克隆：

```bash
	git clone git@github.com:username/username.github.io.git
```

然后进入到github.io文件夹，安装npm，然后重新生成静态文件并部署就可以了。

```bash
	npm install
	npm install hexo-deployer-git --save
	hexo g
	hexo d
```

------



# 感言：

*自己平常学习会记一些笔记和经验，但大多是在本地记给自己看的。最近回顾笔记，忽然有了把自己的笔记上传到网络上的想法，于是有了这篇搭建博客的博客。希望在若干年后，看到自己的博客，能够坚定初衷。*

*成长在路上。*

*感谢师兄给予我的帮助，师兄是一个非常优秀、值得我去学习的人，这篇博客也参考了他的经验：*https://frankcao3.github.io/2020/08/15/%E5%88%A9%E7%94%A8hexo+gitHub%E6%90%AD%E5%BB%BA%E4%B8%AA%E4%BA%BA%E5%8D%9A%E5%AE%A2/ 。
