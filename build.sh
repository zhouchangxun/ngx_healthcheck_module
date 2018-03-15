cd ../nginx.git;
./auto/configure --with-debug \
            --with-stream \
            --add-module=../ngx_healthcheck_module.git
make ;
#make install
cd -
