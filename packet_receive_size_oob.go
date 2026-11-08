//go:build darwin || linux || freebsd

package quic

func (c *oobConn) setReadPacketSize(size int) { c.receivePacketSize = size }
