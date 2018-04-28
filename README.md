# ngx_healthcheck_module

support both http/stream upstream health check (tcp/udp/http),
and provide a http interface to get backend-server status"

该模块可以为Nginx提供主动式后端服务器健康检查的功能（检查类型支持 tcp/udp/http ）。

# build

## clone nginx code and this module code.
>git clone https://github.com/zhouchangxun/nginx/nginx.git

>git clone https://github.com/zhouchangxun/ngx_healthcheck_module.git

## apply patch to nginx source
> cd nginx/; git apply ../ngx_healthcheck_module/nginx-stable-1.12+.patch

## append option to enable this module
> ./auto/configure --with-stream --add-module=../ngx_healthcheck_module/

## build and install
>make && make install

# config examples

``` python
stream {
    upstream tcp-cluster {
        # simple round-robin
        server 192.168.0.1:22;
        server 192.168.0.2:22;
        check interval=3000 rise=2 fall=5 timeout=5000 default_down=true type=tcp;
    }
    upstream udp-cluster {
        # simple round-robin
        server 192.168.0.3:53;
        server 192.168.0.4:53;
        check interval=3000 rise=2 fall=5 timeout=5000 default_down=true type=udp;
    }
    upstream http-cluster {
        # simple round-robin
        server 192.168.0.5:80;
        server 192.168.0.6:80;
        check interval=3000 rise=2 fall=5 timeout=5000 type=http;
        check_keepalive_requests 100;
        check_http_send "HEAD / HTTP/1.1\r\nConnection: keep-alive\r\n\r\n";
        check_http_expect_alive http_2xx http_3xx;
    }
    server {
        listen 522;
        proxy_pass tcp-cluster;
    }
    server {
        listen 53;
        proxy_pass udp-cluster;
    }
    server {
        listen 8080;
        proxy_pass http-cluster;
    }
}

http {
    server {
        listen 80;
        location /status/http {
            check_status;
        }
        location /status/stream {
            l4check_status;
        }
    }
}
```
# directive

Syntax: 
> check interval=milliseconds [fall=count] [rise=count] [timeout=milliseconds] [default_down=true|false] [type=tcp|udp|http] [port=check_port]

Default: interval=30000 fall=5 rise=2 timeout=1000 default_down=true type=tcp

Context: http/upstream || stream/upstream

该指令可以打开后端服务器的健康检查功能。

## Detail description

interval：向后端发送的健康检查包的间隔。

fall(fall_count): 如果连续失败次数达到fall_count，服务器就被认为是down。

rise(rise_count): 如果连续成功次数达到rise_count，服务器就被认为是up。

timeout: 后端健康请求的超时时间。

default_down: 设定初始时服务器的状态，如果是true，就说明默认是down的，如果是false，就是up的。默认值是true，也就是一开始服务器认为是不可用，要等健康检查包达到一定成功次数以后才会被认为是健康的。

type：健康检查包的类型，现在支持以下多种类型

- tcp：简单的tcp连接，如果连接成功，就说明后端正常。
- udp：简单的发送udp报文，如果收到icmp error(主机或端口不可达)，就说明后端异常。(只有stream配置块中支持udp类型检查)
- http：发送HTTP请求，通过后端的回复包的状态来判断后端是否存活。

port: 指定后端服务器的检查端口。你可以指定不同于真实服务的后端服务器的端口，比如后端提供的是443端口的应用，你可以去检查80端口的状态来判断后端健康状况。默认是0，表示跟后端server提供真实服务的端口一样。

Syntax: check_keepalive_requests request_num

Default: 1

Context: http/upstream

该指令可以配置一个连接发送的请求数，其默认值为1，表示Nginx完成1次请求后即关闭连接。


Syntax: check_http_send http_packet

Default: "GET / HTTP/1.0\r\n\r\n"

Context: http/upstream

该指令可以配置http健康检查包发送的请求内容。为了减少传输数据量，推荐采用"HEAD"方法。

当采用长连接进行健康检查时，需在该指令中添加keep-alive请求头，如："HEAD / HTTP/1.1\r\nConnection: keep-alive\r\n\r\n"。
同时，在采用"GET"方法的情况下，请求uri的size不宜过大，确保可以在1个interval内传输完成，否则会被健康检查模块视为后端服务器或网络异常。


Syntax: check_http_expect_alive [ http_2xx | http_3xx | http_4xx | http_5xx ]

Default: http_2xx | http_3xx

Context: http/upstream

该指令指定HTTP回复的成功状态，默认认为2XX和3XX的状态是健康的。


*Syntax*: check_shm_size size

*Default*: 1M

*Contex*: http || stream

所有的后端服务器健康检查状态都存于共享内存中，该指令可以设置共享内存的大小。默认是1M，如果你有1千台以上的服务器并在配置的时候出现了错误，就可能需要扩大该内存的大小。

Syntax: check_status [html|csv|json]

Default: check_status html

Context: http/server/location

Syntax: l4check_status [html|csv|json]

Default: l4check_status html

Context: http/server/location

