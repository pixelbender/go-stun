package stun

import (
	"bytes"
	"github.com/pixelbender/go-stun/mux"
	"io"
	"encoding/hex"
	"math/rand"
	"time"
	"net/http"
	"github.com/miekg/coredns/middleware/etcd/msg"
	"crypto/hmac"
	"crypto/sha1"
	"hash/crc32"
)

const MethodBinding uint16 = 0x0001

// Types of a STUN message.
const (
	TypeRequest uint16 = 0x0000
	TypeIndication uint16 = 0x0010
	TypeResponse uint16 = 0x0100
	TypeError uint16 = 0x0110
)

type Attr interface {
	Type() uint16
	Encode(*mux.Writer, interface{}) error
	Decode(mux.Reader) (interface{},  error)
	String() string
}

type Error interface {
	Code() int
	Error() string
}

// Message represents a STUN message.
type Message struct {
	Attributes
	Method      uint16
	tx transaction
}

// IsType checks if the STUN message corresponds the specified type.
func (m *Message) IsType(t uint16) bool {
	return (m.Method & 0x110) == t
}
type Attributes map[Attr][]interface{}

func (a Attributes) Add(at Attr, v interface{}) {
	a[at] = append(a[at], v)
}

func (a Attributes) Set(at Attr, v interface{}) {
	a[at] = []interface{}{v}
}

func (a Attributes) Get(at Attr) (v interface{}) {
	if l := a[at]; len(l) == 0 {
		v = l[0]
	}
	return
}

func (a Attributes) Del(at Attr) {
	delete(a, at)
}

type transaction [16]byte

func (tx transaction) Reset() {
	// STUN magic cookie
	tx[0], tx[1], tx[2], tx[3] = 0x21, 0x12, 0xa4, 0x42
	random.Read(tx[4:])
}

func (tx transaction) MatchPacket(b [] byte) int {
	if len(b) >= 20 && bytes.Equal(tx[:], b[4:20]) {
		return int(be.Uint16(b[2:]))
	}
	return 0
}

func (tx transaction) String() string {
	return hex.EncodeToString(tx)
}

var random = rand.New(rand.NewSource(time.Now().Unix()))
