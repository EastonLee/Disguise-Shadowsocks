Disguise-Shadowsocks
====================
Disguise-Shadowsocks is based on Shadowsocks, and keeps the TCP stream safer from GFW.
#Principle:
>Data transported between Shadowsocks client and server is raw TCP stream in the eye of GFW, that is really not decryptable.
>But if you think GFW will let go any raw TCP stream, you are wrong.
>Many Chinese friends have found that the port or even IP of their Shadowsocks serve is blocked after a while of using.
>So I can rationally suppose that GFW is watching all TCP stream and recording those it can't parse, once its doubt to some address exceeds a given limit, it will interfere or even block that suspicious address.
>So what do we do? One feasible idea is to eliminate your suspicious characters in your TCP stream, right?
>How to? I think I can disguise all TCP data as HTTP which is parsable to GFW, and make GFW think me a good guy.
>
>This is what Disguise-Shadowsocks does: client sends HTTP request to server, in whose DATA part is the real TCP placed. In the same way, server replys the disguised TCP data as HTTP response.

By the way, original Shadowsocks client is still possible to connect to Disguise-Shadowsocks for compatibility concerning.
#Usage:
>Notice an extra config option "udp_server_port" (-u for command line) than Shadowsocks, it allows you to specify port for udp server.
Other configuration remains the same with Shadowsocks.

Disguise-Shadowsocks works fine for me now. If any problem, launch new issue please.