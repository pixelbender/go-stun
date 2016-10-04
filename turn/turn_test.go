package turn

import (
	"log"
	"testing"
)

func TestAllocate(t *testing.T) {
	conn, err := Allocate("turn:example.org", "webinar", "developer")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	conn.Dial()

	// conn.createPermission()

	log.Printf("Addr: %v", conn.RelayedAddr())
}
