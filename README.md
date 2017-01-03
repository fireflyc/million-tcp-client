* 百万级TCP测试工具

参考《模拟百万级TCP并发》

mkdir -p build
cd build && cmake ..
make
然后执行
./tcp-client

程序依赖libpcap和libnet请自行安装依赖ubuntu是执行`apt-get install libpcap-dev libnet-dev`