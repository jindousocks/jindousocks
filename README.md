jindousocks
===========

`jindousocks` is a proxy using SOCKS5 and TLS.

It works like `shadowsocks`, except that it transmits data between client and server in TLS,
while `shadowsocks` in its own private protocol.

It try to disguise the data as normal HTTPS connections to avoid being detected.

The data flow:

    +----+                 +--------+              +--------+         +-------------+
    | UA |<==SOCKS5(raw)==>| client |<==TLS(raw)==>| server |<==raw==>| target host |
    +----+                 +--------+              +--------+         +-------------+

where 'raw' can be FTP, HTTP, HTTPS, etc.


## usage

1. Download and build:

    $ go build

2. Run jindousocks server at where the target hosts can be reached:

    $ jindousocks server 'listen-address' 'certificate-file' 'key-file'

   Since the server pretends to be a HTTPS server, so the certificate and
   private key are needed. It's better that you have a real certificate.
   If you do not, make one by:

    $ openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem

3. Run jindousocks client at or around your computer:

    $ jindousocks client 'listen-address' 'server-address'

4. Point SOCKS5 proxy to the client listen-address in your UA(user agent),
   such as SwitchySharp extension in chrome.


## TODO

1. Authentication

2. Better disguise.
