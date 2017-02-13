package stun

import (
	"net"
	"sync"
	"testing"
	"time"
)

var once sync.Once

func newDetector(t *testing.T) *Detector {
	config := DefaultConfig.clone()
	config.RetransmissionTimeout = 300 * time.Millisecond
	config.TransactionTimeout = time.Second
	if testing.Verbose() {
		config.Logf = t.Logf
	} else {
		t.Parallel()
	}
	once.Do(func() {
		srv := NewServer(nil)
		loop, _ := net.ResolveIPAddr("ip", "localhost")
		for _, it := range append(local, loop) {
			for _, port := range []string{"3478", "3479"} {
				go srv.ListenAndServe("udp", net.JoinHostPort(it.IP.String(), port))
			}
		}
		time.Sleep(time.Second)
	})
	c, err := Dial("stun:localhost", config)
	if err != nil {
		t.Fatal(err)
	}
	return NewDetector(c)
}

func TestHairpinning(t *testing.T) {
	d := newDetector(t)
	err := d.Hairpinning()
	if err != nil {
		t.Fatal(err)
	}
}

func TestFiltering(t *testing.T) {
	d := newDetector(t)
	v, err := d.Filtering()
	if err != nil {
		t.Fatal(err)
	}
	if v != EndpointIndependent {
		t.Errorf("Wrong filtering type: %v", v)
	}
}

func TestMapping(t *testing.T) {
	d := newDetector(t)
	v, err := d.Mapping()
	if err != nil {
		t.Fatal(err)
	}
	if v != EndpointIndependent {
		t.Errorf("Wrong mapping type: %v", v)
	}
}
