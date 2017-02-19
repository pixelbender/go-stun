package stun

import (
	"encoding/hex"
	"net"
	"testing"
)

// Test Vectors for STUN. RFC 5769.

var samples = []string{
	"000100582112a442b7e7a701bc34d686fa87dfae802200105354554e207465737420636c69656e74002400046e0001ff80290008932ff9b151263b36000600096576746a3a68367659202020000800149aeaa70cbfd8cb56781ef2b5b2d3f249c1b571a280280004e57a3bcf",
	"0101003c2112a442b7e7a701bc34d686fa87dfae8022000b7465737420766563746f7220002000080001a147e112a643000800142b91f599fd9e90c38c7489f92af9ba53f06be7d780280004c07d4c96",
	"010100482112a442b7e7a701bc34d686fa87dfae8022000b7465737420766563746f7220002000140002a1470113a9faa5d3f179bc25f4b5bed2b9d900080014a382954e4be67bf11784c97c8292c275bfe3ed4180280004c8fb0b4c",
	"000100602112a44278ad3433c6ad72c029da412e00060012e3839ee38388e383aae38383e382afe382b900000015001c662f2f3439396b39353464364f4c33346f4c394653547679363473410014000b6578616d706c652e6f72670000080014f67024656dd64a3e02b8e0712e85c9a28ca89666",
}

func BenchmarkDecode(b *testing.B) {
	data := make([][]byte, len(samples))
	for i, it := range samples {
		d, err := hex.DecodeString(it)
		if err != nil {
			b.Fatal(err)
		}
		data[i] = d
	}
	for n := 0; n < b.N; n++ {
		for _, d := range data {
			_, err := UnmarshalMessage(d)
			if err != nil {
				b.Fatal(err)
			}
		}
	}
}

func BenchmarkEncode(b *testing.B) {
	data := make([]*Message, len(samples))
	for i, it := range samples {
		d, err := hex.DecodeString(it)
		if err != nil {
			b.Fatal(err)
		}
		m, err := UnmarshalMessage(d)
		if err != nil {
			b.Fatal(err)
		}
		data[i] = m
	}
	d := getBuffer()
	for n := 0; n < b.N; n++ {
		for _, m := range data {
			d = m.Marshal(d[:0])
		}
	}
	putBuffer(d)
}

func BenchmarkBuffer(b *testing.B) {
	for n := 0; n < b.N; n++ {
		putBuffer(getBuffer())
	}
}

func TestIntegrity(t *testing.T) {
	key := []byte("VOkJxbRl1RmTxUk/WvJxBt")
	for _, it := range samples[:3] {
		d, err := hex.DecodeString(it)
		if err != nil {
			t.Fatal(err)
		}
		m, err := UnmarshalMessage(d)
		if err != nil {
			t.Fatal(err)
		}
		m.Set(MessageIntegrity(key))
		m, err = UnmarshalMessage(m.Marshal(nil))
		if err != nil {
			t.Fatal(err)
		}
		if !m.CheckIntegrity(key) {
			t.Error("integrity check failed")
		}
		if !m.CheckFingerprint() {
			t.Error("fingerprint check failed")
		}
	}
}

func TestVectorsSampleRequest(t *testing.T) {
	b, err := hex.DecodeString(samples[0])
	if err != nil {
		t.Fatal(err)
	}
	m, err := UnmarshalMessage(b)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("message", m)
	if !m.CheckIntegrity([]byte("VOkJxbRl1RmTxUk/WvJxBt")) {
		t.Error("integrity check failed")
	}
	if !m.CheckFingerprint() {
		t.Error("fingerprint check failed")
	}
	if m.Kind() != KindRequest || m.Method() != MethodBinding {
		t.Error("wrong message type:", m.Type)
	}
	if v := m.GetString(AttrSoftware); v != "STUN test client" {
		t.Error("wrong software:", v)
	}
	if v := m.GetString(AttrUsername); v != "evtj:h6vY" {
		t.Error("wrong username:", v)
	}
}

func TestVectorsSampleIPv4Response(t *testing.T) {
	b, err := hex.DecodeString(samples[1])
	if err != nil {
		t.Fatal(err)
	}
	m, err := UnmarshalMessage(b)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("message", m)
	if !m.CheckIntegrity([]byte("VOkJxbRl1RmTxUk/WvJxBt")) {
		t.Error("integrity check failed")
	}
	if !m.CheckFingerprint() {
		t.Error("fingerprint check failed")
	}
	if m.Kind() != KindResponse || m.Method() != MethodBinding {
		t.Error("wrong message type:", m.Type)
	}
	if v := m.GetString(AttrSoftware); v != "test vector" {
		t.Error("wrong software:", v)
	}
	addr := m.GetAddr("udp", AttrXorMappedAddress).(*net.UDPAddr)
	if addr == nil || !addr.IP.Equal(net.ParseIP("192.0.2.1")) || addr.Port != 32853 {
		t.Error("wrong address:", addr)
	}
}

func TestVectorsSampleIPv6Response(t *testing.T) {
	b, err := hex.DecodeString(samples[2])
	if err != nil {
		t.Fatal(err)
	}
	m, err := UnmarshalMessage(b)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("message", m)
	if !m.CheckIntegrity([]byte("VOkJxbRl1RmTxUk/WvJxBt")) {
		t.Error("integrity check failed")
	}
	if !m.CheckFingerprint() {
		t.Error("fingerprint check failed")
	}
	if m.Kind() != KindResponse || m.Method() != MethodBinding {
		t.Error("wrong message type:", m.Type)
	}
	if v := m.GetString(AttrSoftware); v != "test vector" {
		t.Error("wrong software:", v)
	}
	addr := m.GetAddr("udp", AttrXorMappedAddress).(*net.UDPAddr)
	if addr == nil || !addr.IP.Equal(net.ParseIP("2001:db8:1234:5678:11:2233:4455:6677")) || addr.Port != 32853 {
		t.Error("wrong address:", addr)
	}
}

func TestVectorsSampleLongTermAuth(t *testing.T) {
	b, err := hex.DecodeString(samples[3])
	if err != nil {
		t.Fatal(err)
	}
	m, err := UnmarshalMessage(b)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("message", m)
	sess := &Session{
		Realm: m.GetString(AttrRealm),
	}
	auth := LongTermAuthMethod(m.GetString(AttrUsername), "TheMatrIX")
	if err = auth(sess); err != nil {
		t.Error("auth error:", err)
	}
	if !m.CheckIntegrity(sess.Key) {
		t.Error("integrity check failed")
	}
	if m.Kind() != KindRequest || m.Method() != MethodBinding {
		t.Error("wrong message type:", m.Method)
	}
	if v := m.GetString(AttrNonce); v != "f//499k954d6OL34oL9FSTvy64sA" {
		t.Error("wrong nonce:", v)
	}
	if v := m.GetString(AttrRealm); v != "example.org" {
		t.Error("wrong realm:", v)
	}
}

func TestNewAttr(t *testing.T) {
	for typ := range attrNames {
		if newAttr(typ) == nil {
			t.Error("attribute is not created:", AttrName(typ))
		}
	}
}
