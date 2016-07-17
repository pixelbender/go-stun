package stun

import (
	"encoding/hex"
	"log"
	"testing"
)

func TestDiscoverGooglePublic(t *testing.T) {
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

// Test Vectors for STUN. RFC 5769.
const (
	testVectorsSampleRequest = "000100582112a442b7e7a701bc34d686fa87dfae802200105354554e207465737420636c69656e74002400046e0001ff80290008932ff9b151263b36000600096576746a3a68367659202020000800149aeaa70cbfd8cb56781ef2b5b2d3f249c1b571a280280004e57a3bcf"
	sampleIPv4Response       = "0101003c2112a442b7e7a701bc34d686fa87dfae8022000b7465737420766563746f7220002000080001a147e112a643000800142b91f599fd9e90c38c7489f92af9ba53f06be7d780280004c07d4c96"
	sampleIPv6Response       = "010100482112a442b7e7a701bc34d686fa87dfae8022000b7465737420766563746f7220002000140002a1470113a9faa5d3f179bc25f4b5bed2b9d900080014a382954e4be67bf11784c97c8292c275bfe3ed4180280004c8fb0b4c"
	sampleLongTermAuth       = "000100602112a44278ad3433c6ad72c029da412e00060012e3839ee38388e383aae38383e382afe382b900000015001c662f2f3439396b39353464364f4c33346f4c394653547679363473410014000b6578616d706c652e6f72670000080014f67024656dd64a3e02b8e0712e85c9a28ca89666"
)

func TestVectorsSampleRequest(t *testing.T) {
	msg, err := readMessageHex("000100582112a442b7e7a701bc34d686fa87dfae802200105354554e207465737420636c69656e74002400046e0001ff80290008932ff9b151263b36000600096576746a3a68367659202020000800149aeaa70cbfd8cb56781ef2b5b2d3f249c1b571a280280004e57a3bcf")
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	log.Printf("%#v", msg)
	if msg.Attributes.String(AttrSoftware) != "STUN test client" {
		t.Fatal("incorrect SOFTWARE attribute")
	}
	if msg.Attributes.String(AttrUsername) != "evtj:h6vY" {
		t.Fatal("incorrect USERNAME attribute")
	}
	mi := msg.Attributes[AttrMessageIntegrity].(*messageIntegrity)
	key := []byte("VOkJxbRl1RmTxUk/WvJxBt")
	if !mi.Check(key) {
		t.Fatal("incorrect MESSAGE-INTEGRITY attribute")
	}
}

func TestVectorsSampleLongTermAuth(t *testing.T) {
	msg, err := readMessageHex("000100602112a44278ad3433c6ad72c029da412e00060012e3839ee38388e383aae38383e382afe382b900000015001c662f2f3439396b39353464364f4c33346f4c394653547679363473410014000b6578616d706c652e6f72670000080014f67024656dd64a3e02b8e0712e85c9a28ca89666")
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	log.Printf("%#v", msg)

	username := msg.Attributes.Bytes(AttrUsername)
	realm := msg.Attributes.Bytes(AttrRealm)

	key := LongTermKey(username, realm, []byte("TheMatrIX"))

	mi := msg.Attributes[AttrMessageIntegrity].(*messageIntegrity)

	if !mi.Check(key) {
		t.Fatal("incorrect MESSAGE-INTEGRITY attribute")
	}
}

//
//func TestVectors(t *testing.T) {
//	msg, err := readMessage(sampleIPv4Response)
//	if err != nil {
//		t.Fatalf("decode error: %v", err)
//	}
//	log.Printf("%#v", msg)
//	if msg.String(AttrSoftware) != "test vector" {
//		t.Fatal("unexpected SOFTWARE attribute")
//	}
//	if msg.String(AttrUsername) != "evtj:h6vY" {
//		t.Fatal("unexpected USERNAME attribute")
//	}
//}

func readMessageHex(s string) (*Message, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return DecodeMessage(b)
}
