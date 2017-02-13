package stun

import (
	"testing"
)

func TestDiscover(t *testing.T) {
	if testing.Verbose() {
		DefaultConfig.Logf = t.Logf
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
