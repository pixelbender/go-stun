package ice

import (
	"net"
	"reflect"
	"testing"
)

func TestAgent(t *testing.T) {
	agent := &Agent{Component: 1}
	_, err := agent.Listen("udp4", "tcp4")
	if err != nil {
		t.Fatal(err)
	}
	_, err = agent.Listen("udp4", "tcp4")
	if err != nil {
		t.Fatal(err)
	}

	/*
		err = agent.Discover("stun:stun.l.google.com:19302", "", "")
		if err != nil {
			t.Fatal(err)
		}
		err = agent.Discover("stun:stun.l.google.com:19302", "", "")
		if err != nil {
			t.Fatal(err)
		}*/
}

func TestParseCandidate(t *testing.T) {
	t.Parallel()
	v := "candidate:2298457258 2 UDP 1686052606 192.168.0.10 40000 typ srflx raddr 172.16.0.1 rport 50000 generation 0"
	c := &Candidate{
		Foundation: "2298457258",
		Component:  2,
		Transport:  TransportUDP,
		Priority:   1686052606,
		Address: &Addr{
			IP:   net.ParseIP("192.168.0.10"),
			Port: 40000,
		},
		Type: TypeServerReflexive,
		BaseAddress: &Addr{
			IP:   net.ParseIP("172.16.0.1"),
			Port: 50000,
		},
		Params: map[string]string{
			"generation": "0",
		},
	}
	it, err := ParseCandidate(v)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(c, it) {
		t.Fatalf("found %+v expected %+v", it, c)
	}
	if it := c.Attribute().String(); it != v {
		t.Fatalf("found %+v expected %+v", it, v)
	}
}
