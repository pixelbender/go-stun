package stun

import (
	"net"
	"testing"
)

func TestDiscoverConn(t *testing.T) {
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
