package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"
)

const (
	socks5Version = 0x05

	authNone         = 0x00
	authNoAcceptable = 0xFF

	cmdConnect = 0x01

	atypIPv4       = 0x01
	atypDomainName = 0x03
	atypIPv6       = 0x04

	repSuccess              = 0x00
	repGeneralFailure       = 0x01
	repConnectionNotAllowed = 0x02
	repNetworkUnreachable   = 0x03
	repHostUnreachable      = 0x04
	repConnectionRefused    = 0x05
	repTTLExpired           = 0x06
	repCommandNotSupported  = 0x07
	repAddressNotSupported  = 0x08
)

// Server is a SOCKS5 proxy server.
type Server struct {
	Timeout       time.Duration
	IdleTimeout   time.Duration
	BlockMetadata bool
	Logger        *slog.Logger
}

func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()

	logger := s.Logger.With("remote", conn.RemoteAddr())

	conn.SetDeadline(time.Now().Add(s.Timeout))

	if err := s.negotiate(conn); err != nil {
		logger.Debug("negotiate failed", "error", err)
		return
	}

	s.handleConnect(conn, logger)
}

func (s *Server) negotiate(conn net.Conn) error {
	// Read VER, NMETHODS
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return fmt.Errorf("read header: %w", err)
	}

	if header[0] != socks5Version {
		return fmt.Errorf("unsupported version: %d", header[0])
	}

	nmethods := int(header[1])
	if nmethods == 0 {
		return fmt.Errorf("no methods")
	}

	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return fmt.Errorf("read methods: %w", err)
	}

	// Check for NO AUTH
	found := false
	for _, m := range methods {
		if m == authNone {
			found = true
			break
		}
	}

	if !found {
		conn.Write([]byte{socks5Version, authNoAcceptable})
		return fmt.Errorf("no acceptable auth method")
	}

	_, err := conn.Write([]byte{socks5Version, authNone})
	return err
}

func (s *Server) handleConnect(conn net.Conn, logger *slog.Logger) {
	// Read VER, CMD, RSV, ATYP
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		logger.Debug("read request header failed", "error", err)
		return
	}

	if header[0] != socks5Version {
		logger.Debug("unsupported version in request", "version", header[0])
		return
	}

	if header[1] != cmdConnect {
		s.sendReply(conn, repCommandNotSupported, nil)
		return
	}

	// Parse address
	addr, err := readAddress(conn, header[3])
	if err != nil {
		logger.Debug("read address failed", "error", err)
		s.sendReply(conn, repAddressNotSupported, nil)
		return
	}

	logger = logger.With("target", addr)

	// Validate destination address
	if s.BlockMetadata {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			logger.Debug("invalid address", "error", err)
			s.sendReply(conn, repConnectionNotAllowed, nil)
			return
		}

		if ip := net.ParseIP(host); ip != nil {
			if isBlockedIP(ip) {
				logger.Info("blocked connection to metadata endpoint", "target", addr)
				s.sendReply(conn, repConnectionNotAllowed, nil)
				return
			}
		} else {
			// Resolve domain name and check resolved IPs
			ips, err := net.LookupHost(host)
			if err != nil {
				logger.Debug("dns lookup failed", "error", err)
				s.sendReply(conn, repHostUnreachable, nil)
				return
			}
			for _, ipStr := range ips {
				if ip := net.ParseIP(ipStr); ip != nil && isBlockedIP(ip) {
					logger.Info("blocked connection to metadata endpoint (resolved)", "target", addr, "resolved", ipStr)
					s.sendReply(conn, repConnectionNotAllowed, nil)
					return
				}
			}
		}
	}

	logger.Info("connecting")

	// Dial target
	dialer := net.Dialer{Timeout: s.Timeout}
	target, err := dialer.Dial("tcp", addr)
	if err != nil {
		logger.Debug("dial failed", "error", err)
		s.sendReply(conn, errorToReply(err), nil)
		return
	}
	defer target.Close()

	// Send success reply with bound address
	bindAddr := target.LocalAddr().(*net.TCPAddr)
	s.sendReply(conn, repSuccess, bindAddr)

	// Clear deadlines before relay
	conn.SetDeadline(time.Time{})

	logger.Info("relaying")
	tx, rx := relay(conn, target, s.IdleTimeout)
	logger.Info("done", "tx", tx, "rx", rx)
}

func readAddress(r io.Reader, atyp byte) (string, error) {
	switch atyp {
	case atypIPv4:
		buf := make([]byte, 4+2) // IPv4 + port
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		ip := net.IP(buf[:4])
		port := binary.BigEndian.Uint16(buf[4:])
		return net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port)), nil

	case atypDomainName:
		// Read domain length
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(r, lenBuf); err != nil {
			return "", err
		}
		domainLen := int(lenBuf[0])
		buf := make([]byte, domainLen+2) // domain + port
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		domain := string(buf[:domainLen])
		port := binary.BigEndian.Uint16(buf[domainLen:])
		return net.JoinHostPort(domain, fmt.Sprintf("%d", port)), nil

	case atypIPv6:
		buf := make([]byte, 16+2) // IPv6 + port
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		ip := net.IP(buf[:16])
		port := binary.BigEndian.Uint16(buf[16:])
		return net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port)), nil

	default:
		return "", fmt.Errorf("unsupported address type: %d", atyp)
	}
}

func (s *Server) sendReply(conn net.Conn, rep byte, bindAddr *net.TCPAddr) {
	// +----+-----+-------+------+----------+----------+
	// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
	// +----+-----+-------+------+----------+----------+
	reply := []byte{socks5Version, rep, 0x00}

	if bindAddr != nil && bindAddr.IP.To4() != nil {
		reply = append(reply, atypIPv4)
		reply = append(reply, bindAddr.IP.To4()...)
		port := make([]byte, 2)
		binary.BigEndian.PutUint16(port, uint16(bindAddr.Port))
		reply = append(reply, port...)
	} else if bindAddr != nil && bindAddr.IP.To16() != nil {
		reply = append(reply, atypIPv6)
		reply = append(reply, bindAddr.IP.To16()...)
		port := make([]byte, 2)
		binary.BigEndian.PutUint16(port, uint16(bindAddr.Port))
		reply = append(reply, port...)
	} else {
		// Default: IPv4 0.0.0.0:0
		reply = append(reply, atypIPv4, 0, 0, 0, 0, 0, 0)
	}

	conn.Write(reply)
}

// metadataNet is the link-local subnet containing cloud metadata endpoints.
var metadataNet = func() *net.IPNet {
	_, n, _ := net.ParseCIDR("169.254.0.0/16")
	return n
}()

func isBlockedIP(ip net.IP) bool {
	return metadataNet.Contains(ip)
}

func errorToReply(err error) byte {
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if opErr.Op == "dial" {
			var dnsErr *net.DNSError
			if errors.As(err, &dnsErr) {
				return repHostUnreachable
			}
			// Check for connection refused
			if errors.Is(err, &net.AddrError{}) {
				return repHostUnreachable
			}
			// For other dial errors, try to distinguish
			return repConnectionRefused
		}
	}
	return repGeneralFailure
}
