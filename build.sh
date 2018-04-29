#download
version=1.14.0
cd /home/travis/build/zhouchangxun
wget http://nginx.org/download/nginx-$version.tar.gz
tar -zxvf nginx-$version.tar.gz
cd nginx-$version

#build
./auto/configure --with-debug \
            --with-stream \
            --add-module=../ngx_healthcheck_module
make
sudo make install

#start nginx
sudo /usr/local/nginx/sbin/nginx -c /usr/local/nginx/conf/nginx.conf
#show
ps -ef | grep nginx
echo execute finish
