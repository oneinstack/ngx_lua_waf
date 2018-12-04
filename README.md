### ngx_lua_waf
ngx_lua_waf是一个基于lua-nginx-module的web应用防火墙, 支持验证码验证

### OneinStack启用ngx_lua_waf 
```
~/oneinstack/addons.sh
#install ngx_lua_waf
```
### 手工安装
```
cd /root/oneinstack/src
wget http://luajit.org/download/LuaJIT-2.1.0-beta3.tar.gz  #推荐2.1版本
wget https://github.com/openresty/lua-cjson/archive/2.1.0.6.tar.gz -o lua-cjson-2.1.0.6.tar.gz
git clone https://github.com/simpl/ngx_devel_kit.git
git clone https://github.com/openresty/lua-nginx-module.git
tar xzf LuaJIT-2.1.0-beta3.tar.gz
tar xzf lua-cjson-2.1.0.6.tar.gz
cd LuaJIT-2.1.0-beta3
make && make install
cd ../lua-cjson-2.1.0.6
sed -i 's@LUA_INCLUDE_DIR.*@LUA_INCLUDE_DIR \?=   \$(PREFIX)/include/luajit-2.1@' Makefile
make && make install
cd ..
export LUAJIT_LIB=/usr/local/lib
export LUAJIT_INC=/usr/local/include/luajit-2.1
sed -i "s@^nginx_modules_options=.*@nginx_modules_options='--with-ld-opt=-Wl,-rpath,/usr/local/lib --add-module=../lua-nginx-module --add-module=../ngx_devel_kit'@" options.conf
./install.sh --nginx_option 1

### 全局nginx新增waf
cat > /usr/local/nginx/conf/waf.conf << EOF
lua_shared_dict limit 20m;
lua_package_path "/usr/local/nginx/conf/waf/?.lua;;";
init_by_lua_file "/usr/local/nginx/conf/waf/init.lua";
access_by_lua_file "/usr/local/nginx/conf/waf/access.lua";
EOF

#vi /usr/local/nginx/conf/nginx.conf
#include vhost/*.conf;下一行新增，如下
include waf.conf;

### 单网站新增waf(推荐)
cat > /usr/local/nginx/conf/waf.conf << EOF
lua_shared_dict limit 20m;
lua_package_path "/usr/local/nginx/conf/waf/?.lua;;";
init_by_lua_file "/usr/local/nginx/conf/waf/init.lua";
EOF

#vi /usr/local/nginx/conf/vhost/www.example.com.conf
#location ~ [^/]\.php(/|$) {下一行新增，如下
access_by_lua_file "/usr/local/nginx/conf/waf/access.lua";
#注意：wordpress URL改成ngx.var.request_uri
 66         local ATTACK_URL = ngx.var.host .. ngx.var.uri
 67         -- local ATTACK_URL = ngx.var.host .. ngx.var.request_uri
#改成：
 66         -- local ATTACK_URL = ngx.var.host .. ngx.var.uri
 67         local ATTACK_URL = ngx.var.host .. ngx.var.request_uri
```

### Copyright
copy以下项目:<br />
https://github.com/loveshell/ngx_lua_waf<br />
https://github.com/unixhot/waf
