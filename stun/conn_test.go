package stun

import (
	"testing"
	"time"
)

func TestDiscover(t *testing.T) {
	config := DefaultConfig
	config.RetransmissionTimeout = 300 * time.Millisecond
	config.TransactionTimeout = time.Second
	if testing.Verbose() {
		config.Logf = t.Logf
	} else {
		t.Parallel()
	}
	conn, addr, err := Discover("stun:stun.l.google.com:19302")
	if err != nil {
		t.Fatal(err)
		return
	}
	if conn == nil || addr == nil {
		t.Fail()
	}
	t.Logf("Local address: %v, Server reflexive address: %v", conn.LocalAddr(), addr)
}
