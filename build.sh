#download
version=1.14.0
echo ============download nginx code.
cd ../ #/home/travis/build/zhouchangxun
wget http://nginx.org/download/nginx-$version.tar.gz
tar -zxf nginx-$version.tar.gz
pwd;ls
cd nginx-$version

echo ============apply patch
git apply ../ngx_healthcheck_module/nginx_healthcheck_for_nginx_1.14+.patch

#check dependency
dpkg -l |grep libpcre3-dev
dpkg -l|grep zlib1g-dev
dpkg -l|grep openssl
ls auto/
echo ===========begin build nginx
./configure --with-debug \
            --with-stream \
            --add-module=../ngx_healthcheck_module
make
sudo make install

echo ===========start nginx
sudo cp -f ../ngx_healthcheck_module/nginx.conf.example /usr/local/nginx/conf/nginx.conf
sudo ln -s /usr/local/nginx/sbin/nginx /usr/sbin/
sudo nginx -T
sudo nginx -t
sudo nginx &
#test
ps -ef | grep nginx
curl localhost
curl localhost/status

echo finish!
