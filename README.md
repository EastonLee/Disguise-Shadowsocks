2015-11-26
now, the fake http request header is only added before the first tcp segment from ssclient to ssserver
the fake http response header  is only added before the first tcp segment from ssserver to ssclient
it works on any vps now!

add disguise function against shadowsocks.

split tcp server and udp server on different ports to avoid censorship which gets smarter nowadays.

all tcp data will appear just like http request and responce.

2016-1-1
compatible with orginal shadowsocks