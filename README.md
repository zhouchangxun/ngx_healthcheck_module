# ngx-healthcheck-module 
![loading](https://travis-ci.org/zhouchangxun/ngx_healthcheck_module.svg?branch=master)
- Health-checker for Nginx upstream servers
(support http upstream && stream upstream)  

> 该模块可以为Nginx提供主动式后端服务器健康检查的功能（同时支持四层和七层后端服务器的健康检测）。

Table of Contents
=================

* [Status](#status)
* [Description](#description)
* [Installation](#installation)
* [Usage](#usage)
* [Synopsis && Directive](#synopsis)
  * [healthcheck](#healthcheck)
  * [check](#check)
* [Bugs and Patches](#bugs-and-patches)
* [Author](#author)
* [Copyright and License](#copyright-and-license)
* [See Also](#see-also)

Status
======

This nginx module is still under development， you can help improve and it.

这个项目还在开发中完善中，欢迎贡献代码，或报告bug。一起使它变得更好。  
有意愿一起开发完善的同学或者有疑问的可以联系我：
- `QQ`:373882405
- `mail`: zhoucx@dtdream.com

Description
===========

当你使用nginx作为负载均衡器时，nginx原生只提供了基本的重试方式来保证访问到正常的后端服务器。  

相比之下，这个nginx第三方模块可以对后端服务器提供主动式的健康状态检测。  
它维护了一个后端服务器列表，保证新的请求直接发送到一个健康的后端服务器。

主要特性：
- 同时支持四层和七层后端服务器的健康检测
- 四层支持的检测类型：tcp / udp / http
- 七层支持的检测类型：http / fastcgi
- 提供一个统一的http状态查询接口，输出格式：html / json / csv

Installation
============

```
git clone https://github.com/nginx/nginx/nginx.git
git clone https://github.com/zhouchangxun/ngx_healthcheck_module.git

cd nginx/; 
git apply ../ngx_healthcheck_module/nginx-stable-1.12+.patch

./auto/configure --with-stream --add-module=../ngx_healthcheck_module/
make && make install
```

[Back to TOC](#table-of-contents)

Usage
=====

**nginx.conf example** 
```nginx
user  root;
worker_processes  1;
error_log  logs/error.log  info;
#pid        logs/nginx.pid;

events {
    worker_connections  1024;
}

http {
    server {
        listen 80;
        # status interface
        location /status {
            healthcheck_status json;
        }
        # http front
        location / { 
          proxy_pass http://http-cluster;
        }   
    }
    # as a backend server.
    server {
        listen 8080;
        location / {
          root html;
        }
    }
    
    upstream http-cluster {
        # simple round-robin
        server 127.0.0.1:8080;
        server 127.0.0.2:81;

        check interval=3000 rise=2 fall=5 timeout=5000 type=http;
        check_http_send "GET / HTTP/1.0\r\n\r\n";
        check_http_expect_alive http_2xx http_3xx;
    }
}

stream {
    upstream tcp-cluster {
        # simple round-robin
        server 127.0.0.1:22;
        server 192.168.0.2:22;
        check interval=3000 rise=2 fall=5 timeout=5000 default_down=true type=tcp;
    }
    server {
        listen 522;
        proxy_pass tcp-cluster;
    }
    
    upstream udp-cluster {
        # simple round-robin
        server 127.0.0.1:53;
        server 8.8.8.8:53;
        check interval=3000 rise=2 fall=5 timeout=5000 default_down=true type=udp;
    }
    server {
        listen 53;
        proxy_pass udp-cluster;
    }
    
}
```

**status interface**

One typical output is
``` python
root@changxun-PC:~/nginx-dev/ngx_healthcheck_module# curl localhost/status
{"servers": {
  "total": 6,
  "generation": 3,
  "http": [
    {"index": 0, "upstream": "http-cluster", "name": "127.0.0.1:8080", "status": "up", "rise": 119, "fall": 0, "type": "http", "port": 0},
    {"index": 1, "upstream": "http-cluster", "name": "127.0.0.2:81", "status": "down", "rise": 0, "fall": 120, "type": "http", "port": 0}
  ],
  "stream": [
    {"index": 0, "upstream": "tcp-cluster", "name": "127.0.0.1:22", "status": "up", "rise": 22, "fall": 0, "type": "tcp", "port": 0},
    {"index": 1, "upstream": "tcp-cluster", "name": "192.168.0.2:22", "status": "down", "rise": 0, "fall": 7, "type": "tcp", "port": 0},
    {"index": 2, "upstream": "udp-cluster", "name": "127.0.0.1:53", "status": "down", "rise": 0, "fall": 120, "type": "udp", "port": 0},
    {"index": 3, "upstream": "udp-cluster", "name": "8.8.8.8:53", "status": "up", "rise": 3, "fall": 0, "type": "udp", "port": 0}
  ]
}}
root@changxun-PC:~/nginx-dev/ngx_healthcheck_module# 
```

[Back to TOC](#table-of-contents)

Synopsis
========

check
-----

`Syntax`
> check interval=milliseconds [fall=count] [rise=count] [timeout=milliseconds] [default_down=true|false] [type=tcp|udp|http] [port=check_port]

`Default`: interval=30000 fall=5 rise=2 timeout=1000 default_down=true type=tcp

`Context`: http/upstream || stream/upstream

该指令可以打开后端服务器的健康检查功能。

`Detail`

- interval：向后端发送的健康检查包的间隔。
- fall(fall_count): 如果连续失败次数达到fall_count，服务器就被认为是down。
- rise(rise_count): 如果连续成功次数达到rise_count，服务器就被认为是up。
- timeout: 后端健康请求的超时时间。
- default_down: 设定初始时服务器的状态，如果是true，就说明默认是down的，如果是false，就是up的。
  默认值是true，也就是一开始服务器认为是不可用，要等健康检查包达到一定成功次数以后才会被认为是健康的。
- type：健康检查包的类型，现在支持以下多种类型
  - tcp：简单的tcp连接，如果连接成功，就说明后端正常。
  - udp：简单的发送udp报文，如果收到icmp error(主机或端口不可达)，就说明后端异常。(只有stream配置块中支持udp类型检查)
  - http：发送HTTP请求，通过后端的回复包的状态来判断后端是否存活。

- port: 指定后端服务器的检查端口。你可以指定不同于真实服务的后端服务器的端口，
比如后端提供的是443端口的应用，你可以去检查80端口的状态来判断后端健康状况。默认是0，表示跟后端server提供真实服务的端口一样。

A example as followed:
```nginx
stream {
    upstream tcp-cluster {
        # simple round-robin
        server 127.0.0.1:22;
        server 192.168.0.2:22;
        check interval=3000 rise=2 fall=5 timeout=5000 default_down=true type=tcp;
    }
    server {
        listen 522;
        proxy_pass tcp-cluster;
    }
    ...
}
```

healthcheck
-----------

`Syntax`: healthcheck_status [html|csv|json]

`Default`: healthcheck_status html

`Context`: http/server/location

A example as followed:
```nginx
http {
    server {
        listen 80;
        
        # status interface
        location /status {
            healthcheck_status;
        }
     ...
}
```

[Back to TOC](#table-of-contents)


Todo List
=========

- 增加测试用例
- 整理、优化代码
- 规范代码中的log输出

[Back to TOC](#table-of-contents)

Bugs and Patches
================

Please report bugs 

- create [GitHub Issue](http://github.com/zhouchangxun/ngx_healthcheck_module/issues),

or submit patches by

- new [Pull request](https://github.com/zhouchangxun/ngx_healthcheck_module/pull/new/master)

[Back to TOC](#table-of-contents)

Author
======

Chance Chou (周长勋) <changxunzhou@qq.com>.

[Back to TOC](#table-of-contents)

Copyright and License
=====================

The health check part is based on Yaoweibin's
    healthcheck module nginx_upstream_check_module
    (<http://github.com/yaoweibin/nginx_upstream_check_module>);
    
This module is licensed under the BSD license.

Copyright (C) 2017-, by Changxun Zhou <changxunzhou@qq.com>

Copyright (C) 2014 by Weibin Yao <yaoweibin@gmail.com>

All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

[Back to TOC](#table-of-contents)

See Also
========

* nginx: http://nginx.org

[Back to TOC](#table-of-contents)

