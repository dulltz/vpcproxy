package main

import (
	"io"
	"net"
	"sync"
	"time"
)

func relay(client, target net.Conn, idleTimeout time.Duration) (tx, rx int64) {
	var wg sync.WaitGroup
	wg.Add(2)

	// client -> target
	go func() {
		defer wg.Done()
		tx = idleTimeoutCopy(target, client, idleTimeout)
		if tc, ok := target.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	// target -> client
	go func() {
		defer wg.Done()
		rx = idleTimeoutCopy(client, target, idleTimeout)
		if tc, ok := client.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	wg.Wait()
	return tx, rx
}

func idleTimeoutCopy(dst, src net.Conn, idleTimeout time.Duration) int64 {
	buf := make([]byte, 32*1024)
	var written int64
	for {
		src.SetReadDeadline(time.Now().Add(idleTimeout))
		n, readErr := src.Read(buf)
		if n > 0 {
			dst.SetWriteDeadline(time.Now().Add(idleTimeout))
			nw, writeErr := dst.Write(buf[:n])
			written += int64(nw)
			if writeErr != nil {
				break
			}
		}
		if readErr != nil {
			if readErr != io.EOF {
				// timeout or other error
			}
			break
		}
	}
	return written
}
