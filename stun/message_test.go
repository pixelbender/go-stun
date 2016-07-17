package stun

import (
	"encoding/hex"
	"testing"
)

func TestMessageDecode(t *testing.T) {
	cases := []string{
		"000100002112a4425179754d624b4f71642f6d6f",
	}
	for _, it := range cases {
		b, err := hex.DecodeString(it)
		if err != nil {
			t.Fatalf("decode error %v", err)
		}
		m, err := DecodeMessage(b)
		if err != nil {
			t.Fatalf("read error %v", err)
		}
		if m == nil {
			t.Fatalf("read error")
		}
	}
}
