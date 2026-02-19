package main

import (
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"
)

func startTestServer(t *testing.T) (addr string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	srv := &Server{
		Timeout:     5 * time.Second,
		IdleTimeout: 5 * time.Second,
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go srv.handleConnection(conn)
		}
	}()

	return ln.Addr().String()
}

func startEchoServer(t *testing.T) (addr string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()

	return ln.Addr().String()
}

// socks5Handshake performs the SOCKS5 handshake (NO AUTH) on an existing connection.
func socks5Handshake(t *testing.T, conn net.Conn) {
	t.Helper()
	// Send: VER=5, NMETHODS=1, METHOD=0 (NO AUTH)
	_, err := conn.Write([]byte{0x05, 0x01, 0x00})
	if err != nil {
		t.Fatal(err)
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatal(err)
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		t.Fatalf("unexpected handshake response: %v", resp)
	}
}

// socks5Connect sends a CONNECT request with IPv4 address.
func socks5ConnectIPv4(t *testing.T, conn net.Conn, ip net.IP, port uint16) byte {
	t.Helper()
	req := []byte{0x05, 0x01, 0x00, atypIPv4}
	req = append(req, ip.To4()...)
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, port)
	req = append(req, portBuf...)
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}

	// Read reply header
	reply := make([]byte, 4)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatal(err)
	}

	// Skip BND.ADDR + BND.PORT
	switch reply[3] {
	case atypIPv4:
		discard := make([]byte, 4+2)
		io.ReadFull(conn, discard)
	case atypIPv6:
		discard := make([]byte, 16+2)
		io.ReadFull(conn, discard)
	}

	return reply[1] // REP
}

// socks5ConnectDomain sends a CONNECT request with domain name.
func socks5ConnectDomain(t *testing.T, conn net.Conn, domain string, port uint16) byte {
	t.Helper()
	req := []byte{0x05, 0x01, 0x00, atypDomainName, byte(len(domain))}
	req = append(req, []byte(domain)...)
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, port)
	req = append(req, portBuf...)
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}

	reply := make([]byte, 4)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatal(err)
	}

	switch reply[3] {
	case atypIPv4:
		discard := make([]byte, 4+2)
		io.ReadFull(conn, discard)
	case atypIPv6:
		discard := make([]byte, 16+2)
		io.ReadFull(conn, discard)
	}

	return reply[1]
}

func TestNegotiate_Success(t *testing.T) {
	proxyAddr := startTestServer(t)
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// VER=5, NMETHODS=1, METHOD=NO AUTH
	conn.Write([]byte{0x05, 0x01, 0x00})

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatal(err)
	}
	if resp[0] != 0x05 {
		t.Errorf("expected version 5, got %d", resp[0])
	}
	if resp[1] != 0x00 {
		t.Errorf("expected method 0 (NO AUTH), got %d", resp[1])
	}
}

func TestNegotiate_InvalidVersion(t *testing.T) {
	proxyAddr := startTestServer(t)
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Send SOCKS4 version
	conn.Write([]byte{0x04, 0x01, 0x00})

	// Server should close connection
	buf := make([]byte, 2)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = io.ReadFull(conn, buf)
	if err == nil {
		t.Error("expected error or EOF for invalid version")
	}
}

func TestNegotiate_NoAcceptableMethod(t *testing.T) {
	proxyAddr := startTestServer(t)
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// VER=5, NMETHODS=1, METHOD=0x02 (USERNAME/PASSWORD only)
	conn.Write([]byte{0x05, 0x01, 0x02})

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatal(err)
	}
	if resp[0] != 0x05 {
		t.Errorf("expected version 5, got %d", resp[0])
	}
	if resp[1] != 0xFF {
		t.Errorf("expected method 0xFF (NO ACCEPTABLE), got %d", resp[1])
	}
}

func TestConnect_DomainName(t *testing.T) {
	proxyAddr := startTestServer(t)
	echoAddr := startEchoServer(t)
	echoHost, echoPortStr, _ := net.SplitHostPort(echoAddr)
	_ = echoHost

	// Parse echo server port
	echoTCPAddr, _ := net.ResolveTCPAddr("tcp", echoAddr)

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	socks5Handshake(t, conn)
	rep := socks5ConnectDomain(t, conn, "127.0.0.1", uint16(echoTCPAddr.Port))
	if rep != repSuccess {
		t.Fatalf("expected success reply, got 0x%02x (echo port: %s)", rep, echoPortStr)
	}

	// Send data and verify echo
	msg := []byte("hello socks5")
	conn.Write(msg)

	buf := make([]byte, len(msg))
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != string(msg) {
		t.Errorf("expected %q, got %q", msg, buf)
	}
}

func TestConnect_IPv4(t *testing.T) {
	proxyAddr := startTestServer(t)
	echoAddr := startEchoServer(t)
	echoTCPAddr, _ := net.ResolveTCPAddr("tcp", echoAddr)

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	socks5Handshake(t, conn)
	rep := socks5ConnectIPv4(t, conn, net.ParseIP("127.0.0.1"), uint16(echoTCPAddr.Port))
	if rep != repSuccess {
		t.Fatalf("expected success reply, got 0x%02x", rep)
	}

	msg := []byte("hello ipv4")
	conn.Write(msg)

	buf := make([]byte, len(msg))
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != string(msg) {
		t.Errorf("expected %q, got %q", msg, buf)
	}
}

func TestConnect_UnsupportedCommand(t *testing.T) {
	proxyAddr := startTestServer(t)
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	socks5Handshake(t, conn)

	// Send BIND command (0x02) instead of CONNECT (0x01)
	req := []byte{0x05, 0x02, 0x00, atypIPv4, 127, 0, 0, 1, 0x00, 0x50}
	conn.Write(req)

	reply := make([]byte, 4)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != repCommandNotSupported {
		t.Errorf("expected reply 0x07 (command not supported), got 0x%02x", reply[1])
	}
}

func TestConnect_BlockMetadataIPv4(t *testing.T) {
	proxyAddr := startTestServerWithBlockMetadata(t)

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	socks5Handshake(t, conn)

	// Try to connect to metadata endpoint 169.254.169.254:80
	rep := socks5ConnectIPv4(t, conn, net.ParseIP("169.254.169.254"), 80)
	if rep != repConnectionNotAllowed {
		t.Errorf("expected reply 0x%02x (connection not allowed), got 0x%02x", repConnectionNotAllowed, rep)
	}
}

func TestConnect_BlockMetadataLinkLocal(t *testing.T) {
	proxyAddr := startTestServerWithBlockMetadata(t)

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	socks5Handshake(t, conn)

	// Any link-local address in 169.254.0.0/16 should be blocked
	rep := socks5ConnectIPv4(t, conn, net.ParseIP("169.254.1.1"), 80)
	if rep != repConnectionNotAllowed {
		t.Errorf("expected reply 0x%02x (connection not allowed), got 0x%02x", repConnectionNotAllowed, rep)
	}
}

func TestConnect_AllowNonMetadata(t *testing.T) {
	proxyAddr := startTestServerWithBlockMetadata(t)
	echoAddr := startEchoServer(t)
	echoTCPAddr, _ := net.ResolveTCPAddr("tcp", echoAddr)

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	socks5Handshake(t, conn)

	// 127.0.0.1 should still be allowed
	rep := socks5ConnectIPv4(t, conn, net.ParseIP("127.0.0.1"), uint16(echoTCPAddr.Port))
	if rep != repSuccess {
		t.Fatalf("expected success reply, got 0x%02x", rep)
	}
}

func startTestServerWithBlockMetadata(t *testing.T) (addr string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	srv := &Server{
		Timeout:       5 * time.Second,
		IdleTimeout:   5 * time.Second,
		BlockMetadata: true,
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go srv.handleConnection(conn)
		}
	}()

	return ln.Addr().String()
}

func startTestServerWithAuth(t *testing.T, username, password string) (addr string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	srv := &Server{
		Timeout:     5 * time.Second,
		IdleTimeout: 5 * time.Second,
		Username:    username,
		Password:    password,
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go srv.handleConnection(conn)
		}
	}()

	return ln.Addr().String()
}

// socks5HandshakeUserPass performs the SOCKS5 handshake with username/password auth.
func socks5HandshakeUserPass(t *testing.T, conn net.Conn, username, password string) {
	t.Helper()
	// Send: VER=5, NMETHODS=1, METHOD=0x02 (USERNAME/PASSWORD)
	_, err := conn.Write([]byte{0x05, 0x01, 0x02})
	if err != nil {
		t.Fatal(err)
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatal(err)
	}
	if resp[0] != 0x05 || resp[1] != 0x02 {
		t.Fatalf("unexpected handshake response: %v", resp)
	}

	// Validate RFC 1929 length limits
	if len(username) == 0 || len(username) > 255 {
		t.Fatalf("username length %d out of RFC 1929 range (1-255)", len(username))
	}
	if len(password) == 0 || len(password) > 255 {
		t.Fatalf("password length %d out of RFC 1929 range (1-255)", len(password))
	}

	// Send username/password subnegotiation
	auth := []byte{0x01, byte(len(username))}
	auth = append(auth, []byte(username)...)
	auth = append(auth, byte(len(password)))
	auth = append(auth, []byte(password)...)
	if _, err := conn.Write(auth); err != nil {
		t.Fatal(err)
	}

	authResp := make([]byte, 2)
	if _, err := io.ReadFull(conn, authResp); err != nil {
		t.Fatal(err)
	}
	if authResp[0] != 0x01 || authResp[1] != 0x00 {
		t.Fatalf("auth failed: %v", authResp)
	}
}

func TestAuth_Success(t *testing.T) {
	proxyAddr := startTestServerWithAuth(t, "user", "pass")
	echoAddr := startEchoServer(t)
	echoTCPAddr, _ := net.ResolveTCPAddr("tcp", echoAddr)

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	socks5HandshakeUserPass(t, conn, "user", "pass")
	rep := socks5ConnectIPv4(t, conn, net.ParseIP("127.0.0.1"), uint16(echoTCPAddr.Port))
	if rep != repSuccess {
		t.Fatalf("expected success reply, got 0x%02x", rep)
	}

	msg := []byte("hello auth")
	conn.Write(msg)

	buf := make([]byte, len(msg))
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != string(msg) {
		t.Errorf("expected %q, got %q", msg, buf)
	}
}

func TestAuth_WrongPassword(t *testing.T) {
	proxyAddr := startTestServerWithAuth(t, "user", "pass")

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Send: VER=5, NMETHODS=1, METHOD=0x02
	conn.Write([]byte{0x05, 0x01, 0x02})

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatal(err)
	}
	if resp[1] != 0x02 {
		t.Fatalf("expected method 0x02, got 0x%02x", resp[1])
	}

	// Send wrong password
	auth := []byte{0x01, 0x04}
	auth = append(auth, []byte("user")...)
	auth = append(auth, 0x05)
	auth = append(auth, []byte("wrong")...)
	conn.Write(auth)

	authResp := make([]byte, 2)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(conn, authResp); err != nil {
		t.Fatal(err)
	}
	if authResp[0] != 0x01 {
		t.Errorf("expected auth version 0x01, got 0x%02x", authResp[0])
	}
	if authResp[1] != 0x01 {
		t.Errorf("expected auth failure 0x01, got 0x%02x", authResp[1])
	}
}

func TestAuth_NoAuthMethodRejected(t *testing.T) {
	proxyAddr := startTestServerWithAuth(t, "user", "pass")

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Send: VER=5, NMETHODS=1, METHOD=0x00 (NO AUTH only)
	conn.Write([]byte{0x05, 0x01, 0x00})

	resp := make([]byte, 2)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatal(err)
	}
	if resp[0] != 0x05 {
		t.Errorf("expected version 5, got %d", resp[0])
	}
	if resp[1] != 0xFF {
		t.Errorf("expected method 0xFF (NO ACCEPTABLE), got 0x%02x", resp[1])
	}
}

func TestConnect_ConnectionRefused(t *testing.T) {
	proxyAddr := startTestServer(t)

	// Find a port that's not listening
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedAddr, _ := net.ResolveTCPAddr("tcp", ln.Addr().String())
	ln.Close() // Close immediately so port is not listening

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	socks5Handshake(t, conn)
	rep := socks5ConnectIPv4(t, conn, net.ParseIP("127.0.0.1"), uint16(closedAddr.Port))
	if rep == repSuccess {
		t.Error("expected error reply for closed port, got success")
	}
}
