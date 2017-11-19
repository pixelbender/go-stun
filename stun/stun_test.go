package stun

import (
	"net"
	"testing"
	"time"
)

func TestDiscoverConn(t *testing.T) {
	config := DefaultConfig
	config.RetransmissionTimeout = 300 * time.Millisecond
	config.TransactionTimeout = time.Second
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		t.Fatal(err)
	}

	addr, err := DiscoverConn("stun.l.google.com:19302", conn)
	if err != nil {
		t.Fatal(err)
	}

	if addr == nil {
		t.Fatal("addr not determined")
	}
}
