---
layout: page
title: "network"
---

# Wireshark
Website [here](https://www.wireshark.org/) & doc [here](https://www.wireshark.org/docs/wsug_html_chunked/index.html)

## Basic commands
- filter with a protocol:   `<protocol name>`
- filter with a word:   `<protocol name> contains <word>`
- filter with an (destination or source) ip:   `ip.addr == <address>`
- filter with a destination ip:   `ip.dst == <address>`
- filter with a source ip:   `id.src == <address>`
- filter with a port:   `<protocol name>.<port number>`
- filter with tcp analysis:   `tcp.analysis`
- filter with tcp flag analysis:   `tcp.analysis.flags`
- filter with http requests:   `http.request`
- filter with an http response status code:<br>`http.response.code == <response status code>`
- filter with a tcp flag:   `tcp.flags.<flag name> == <value>`
- or operator:   `||` (alternative `or`)
- and operator:   `&&` (alternative `and`)
- not operator:   `!` (alternative `not`)
- equal operator: `==` (alternative `eq`)
- example combination of rules (in this case remove arp, icmp and dns protocol):<br>`!(arp or icmp or dns)`
- filter with a (tcp/udp/tls/http) stream: right click on a packet  ==> follow  ==> stream<br>(equivalent of `<protocol name>.stream == <number>`)

## Useful links
- tcp flags [here](https://www.howtouselinux.com/post/tcp-flags)
- http(s) response status codes [here](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status)
