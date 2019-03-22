/*
    +----+                 +--------+              +--------+         +-------------+
    | UA |<==SOCKS5(raw)==>| client |<==TLS(raw)==>| server |<==raw==>| target host |
    +----+                 +--------+              +--------+         +-------------+

    where 'raw' can be FTP, HTTP, HTTPS, etc.
*/

package main

import (
	"bytes"
	"strings"
	"os"
	"io"
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
)

var tlsConfig tls.Config
var serverAddr string

type connHandler func(net.Conn)

/* == jindousocks client == */
func clientHandler(c net.Conn) {
	defer c.Close()
	buffer := make([]byte, 1024)

	// socks5:hello
	SOCKS5_HELLO_REQUEST := []byte{5, 1, 0}
	SOCKS5_HELLO_REPLY := []byte{5, 0}
	readLen, err := c.Read(buffer)
	if err != nil {
		fmt.Println(err)
		return
	}
	buf := buffer[:readLen]
	if bytes.Compare(buf, SOCKS5_HELLO_REQUEST) != 0 {
		fmt.Println("invalid socks5 hello")
		return
	}
	_, err = c.Write(SOCKS5_HELLO_REPLY)
	if err != nil {
		fmt.Println(err)
		return
	}

	// socks5:connect
	SOCKS5_CONNECT_REQUEST := []byte{5, 1, 0}
	SOCKS5_CONNECT_REPLY := []byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	readLen, err = c.Read(buffer)
	if err != nil {
		fmt.Println(err)
		return
	}
	buf = buffer[:readLen]
	if bytes.Compare(buf[:3], SOCKS5_CONNECT_REQUEST) != 0 {
		fmt.Println("invalid socks5 connect")
		return
	}
	var addrStart, addrEnd int
	switch buf[3] {
	case 1:
		addrStart = 4
		addrEnd = 8
	case 3:
		addrStart = 5
		addrEnd = 5 + int(buf[4])
	default:
		fmt.Println("invalid socks5 address type")
		return
	}
	if readLen != addrEnd+2 {
		fmt.Println("invalid socks5 connect")
		return
	}
	addr := string(buf[addrStart:addrEnd])
	port := binary.BigEndian.Uint16(buf[addrEnd:])
	hostAddr := fmt.Sprintf("%s:%d", addr, port)
	fmt.Println("host: ", hostAddr)

	// connect to jindousocks server
	server, err := tls.Dial("tcp4", serverAddr, &tlsConfig)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer server.Close()

	// jindou control message
	// format: nonce(16), mac(16), hostAddr(len:variable)
	message := make([]byte, 33, 100)
	message[32] = byte(len(hostAddr))
	message = append(message, hostAddr...)

	_, err = server.Write(message)
	if err != nil {
		fmt.Println(err)
		return
	}

	readLen, err = server.Read(buffer) // TODO parse and check the reply
	fmt.Println("connect server: ", string(buffer[:readLen]))

	// socks5:connect reply
	_, err = c.Write(SOCKS5_CONNECT_REPLY)
	if err != nil {
		fmt.Println(err)
		return
	}

	duxAttach(c, server)
}

/* == jindousocks server == */
func serverHandler(c net.Conn) {
	defer c.Close()

	// jindow control message
	// format: nonce(16), mac(16), hostAddr(len:variable)
	buffer := make([]byte, 1024)
	readLen, err := c.Read(buffer)
	if err != nil {
		fmt.Println(err)
		return
	}
	if readLen < 33 { // TODO
		fmt.Println(err)
		return
	}
	buf := buffer[:readLen]

	// TODO check mac
	if buf[0] != 0 {
		fakeHttpForward(c, buf)
		return
	}

	addrLen := int(buf[32])
	if addrLen + 33 != readLen {
		fmt.Println("invalid length")
		return
	}
	hostAddr := string(buf[33:])
	fmt.Println("host:", hostAddr)

	// connect to remote host
	remote, err := net.Dial("tcp4", hostAddr)
	if err != nil {
		fmt.Println(err)
		return
	}

	defer remote.Close()

	c.Write([]byte("good")) // TODO

	// transmit
	duxAttach(c, remote)
}

func main() {
	usage := `invalid argument.
usage:
	jindousocks client 'listen-address' 'server-address'
	jindousocks server 'listen-address' 'certificate-file' 'key-file'
`

	argv := os.Args
	if len(argv) < 2 {
		fmt.Print(usage)
		return
	}

	var listener net.Listener
	var err error
	var handler connHandler

	switch argv[1] {
	case "client":
		if len(argv) != 4 {
			fmt.Print(usage)
			return
		}
		serverAddr = argv[3]
		if pi := strings.Index(serverAddr, ":"); pi == -1 {
			tlsConfig.ServerName = serverAddr
			serverAddr += ":443"
		} else {
			tlsConfig.ServerName = serverAddr[:pi]
		}
		tlsConfig.InsecureSkipVerify = true
		tlsConfig.ClientSessionCache = tls.NewLRUClientSessionCache(0)
		tlsConfig.NextProtos = []string{"h2", "http1.1"}

		handler = clientHandler
		listener, err = net.Listen("tcp4", argv[2])

	case "server":
		if len(argv) != 5 {
			fmt.Print(usage)
			return
		}
		cert, err := tls.LoadX509KeyPair(argv[3], argv[4])
		if err != nil {
			fmt.Println("invalid certificate: ", err)
			return
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
		tlsConfig.NextProtos = []string{"h2", "http1.1"}

		handler = serverHandler
		listener, err = tls.Listen("tcp", argv[2], &tlsConfig)

	default:
		fmt.Print(usage)
		return
	}

	if err != nil {
		fmt.Println(err)
		return
	}

	for {
		c, err := listener.Accept()
		if err != nil {
			fmt.Println(err)
			return
		}
		go handler(c)
	}
}


/* == utils == */
func singleForward(from, to io.ReadWriter) {
	buffer := make([]byte, 10240)
	for {
		readLen, err := from.Read(buffer);
		if err != nil {
			fmt.Println(err)
			return
		}
		writeLen, err := to.Write(buffer[:readLen])
		if err != nil {
			fmt.Println(err)
			return
		}
		if (writeLen != readLen) {
			fmt.Println("write not done")
			return
		}
	}
}
func duxAttach(a, b io.ReadWriter) {
	go singleForward(a, b)
	singleForward(b, a)
}

var HTTP_RESP_400 = `HTTP/1.1 400 Bad Request
Server: openresty/1.13.6.1
Content-Type: text/html
Content-Length: 179
Connection: close

<html>
<head><title>400 Bad Request</title></head>
<body bgcolor="white">
<center><h1>400 Bad Request</h1></center>
<hr><center>openresty/1.13.6.1</center>
</body>
</html>
`
var HTTP_RESP_404 = `HTTP/1.1 404 Not Found
Server: openresty/1.13.6.1
Content-Type: text/html
Content-Length: 175
Connection: keep-alive

<html>
<head><title>404 Not Found</title></head>
<body bgcolor="white">
<center><h1>404 Not Found</h1></center>
<hr><center>openresty/1.13.6.1</center>
</body>
</html>
`
func fakeHttpForward(c net.Conn, buf []byte) {
	// TODO: forward the connection to a real HTTP server.
	// Now we just return 400 or 404
	_, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(buf)))
	if err != nil {
		fmt.Println("!!! return HTTP 400")
		c.Write([]byte(HTTP_RESP_400))
		return
	}
	fmt.Println("!!! return HTTP 404")
	c.Write([]byte(HTTP_RESP_404))
}
