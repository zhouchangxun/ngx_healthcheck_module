cd ../nginx;
./auto/configure --with-debug \
            --with-stream \
            --add-module=../ngx_healthcheck_module
make && make install
cd -
