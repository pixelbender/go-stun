package stun

import (
	"log"
	"testing"
)

func TestGooglePublicDiscover(t *testing.T) {
	conn, err := Dial("udp", "stun.l.google.com:19302")
	if err != nil {
		t.Fatalf("dial error %v", err)
	}
	req := NewMessage(BindingRequest, nil)
	resp, err := conn.Exchange(req)
	if err != nil {
		t.Fatalf("exchange error %v", err)
	}
	if resp == nil {
		t.Fatalf("response error")
	}
	log.Printf("%#v", resp)
}
