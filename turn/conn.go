package turn

import (
	"github.com/pixelbender/go-stun/stun"
	"time"
	"errors"
	"net"
	"sync/atomic"
	"github.com/pixelbender/go-stun/mux"
	"sync"
)

var errBadResponse = errors.New("turn: bad response")

var defaultLifetime = 10 * time.Minute

type Config struct {
	// GetAuthKey returns a key for a MESSAGE-INTEGRITY attribute generation and validation.
	// See stun.Config for details.
	GetAuthKey func(m *stun.Message) ([]byte, error)
	// Software is a value for SOFTWARE attribute.
	Software string
}

type Conn struct {
	stun.Conn

	config *Config
	transport uint8

	mu        sync.RWMutex
	channels  []*Channel
	conn      *stun.Conn
	deadline  time.Time
	addr      net.Addr
	seq       int32
}

// NewConn creates a TURN connection over the net.Conn with specified configuration.
// It starts reading goroutine
func NewConn(inner net.Conn, config *Config) *Conn {
	m := mux.NewTransport(inner)
	c := NewConnMux(m, config)
	go m.Serve()
	return c
}

func NewConnMux(m mux.Transport, config *Config) *Conn {
	c := &Conn{Conn: m, config: config}
	m.Handle(c.ServeMux)
	return c
}

func (c *Conn) Allocate(network string) (Allocation, error) {
	msg, err := c.RoundTrip(methodAllocate, stun.Attributes{
		attrRequestedTransport: c.transport,
		attrLifeTime: ttl,
		attrDontFragment: true,
	})
	if err != nil {
		return err
	}
	ttl, err = msg.GetDuration(attrLifeTime)
	if err != nil {
		return err
	}
	addr, err := msg.GetAddress(attrXorRelayedAddress)
	if err != nil {
		return err
	}
	c.deadline = time.Now().Add(ttl - time.Minute)
	c.addr = &net.UDPAddr{IP:addr.IP, Port:addr.Port}
	return nil
}


func (c *Conn) Dial(addr net.Addr) (ch *Channel, err error) {
	id := uint16(atomic.AddInt32(&c.seq, 1) + 0x4000)
	_, err = c.conn.RoundTrip(&stun.Message{
		Method: MethodChannelBind,
		Attributes: stun.Attributes{
			AttrXorPeerAddress: addr,
			AttrChannelNumber: id,
		},
	})
	if err != nil {
		return
	}
	ch = &Channel{id:id}
	c.mu.Lock()
	if c.channels == nil {
		c.channels = make(map[uint16]*Channel)
	}
	c.channels[id] = ch
	c.mu.Unlock()
	return
}


/*
	stun.NewConn(c, config.Config)

	m := mux.NewConn(inner, nil)
	m.Handle(m.ServeMux)
	stun.NewConnMux()

	c = &Conn{
		Conn: stun.NewConn(inner, config),
		transport: transportUDP,
	}
	c.Reader(c.decode)
	c.Handle(c.probe, c.Receive)
	err = c.allocate(defaultLifetime)
	return
*/

func (c *Conn) decode(r mux.Reader) error {

	return c.addr
}

func (c *Conn) RelayedAddr() net.Addr {
	return c.addr
}

/*
func (c *Conn) roundTrip(method uint8, attrs stun.Attributes) (*Message, error) {
	c.conn.RoundTrip(&stun.Message{
		Method: MethodAllocate,
		Attributes: stun.Attributes{
			AttrRequestedTransport: c.transport,
			AttrLifeTime: ttl,
			AttrDontFragment: true,
		},
	}
})
}*/



func (c *Conn) refresh() error {
	msg, err := c.roundTrip(methodRefresh, nil)
	if err != nil {
		return err
	}
	if v, ok := msg.Attributes[AttrLifeTime]; ok {
		c.deadline = time.Now().Add(v.(time.Duration) - time.Minute)
	} else {
		return errBadResponse
	}
	return nil
}

func (c *Conn) CreatePermission(addr net.Addr) (err error) {
	_, err = c.roundTrip(methodCreatePermission, stun.Attributes{
		AttrXorPeerAddress: addr,
	},
}

func (c *Conn) sendChannelData(id uint16, p mux.Packet) (int, error) {
	w := c.NewPacket()
	b := w.Next(4)
	l := w.Len()
	p.Encode(w)
	be.PutUint16(b, ch.id)
	be.PutUint16(b[2:], uint16(w.Len() - l))
	return w.Send()
}

func (c *Conn) Close() (err error) {
	err = c.allocate(0)
	return c.conn.Close()
}

func (p *dataPacket) Decode(w mux.Writer) error {
	b := w.Next(4)
	l := w.Len()
	p.packet.Encode(w)
	be.PutUint16(b, p.id)
	be.PutUint16(b[2:], uint16(w.Len() - l))
}

type Allocation struct {

}

type Channel struct {
	conn *Conn
	id    uint16
	input chan mux.Packet
	//dec []func(r mux.Reader) error
}

func newChannel(conn mux.Mux, id uint16) *Channel {
}

func (ch *Channel) NewPacket() (mux.Packet, error) {
	return newPacket(conn.NewPacket(), ch.id)
}

func (ch *Channel) Write(p []byte) (int, error) {
	p := ch.NewPacket()
	p.Write(p)
	return p.Send()
	make([]byte, 4 + len(b))

	return len(p), ch.WritePacket(rawBytes(p).marshal)
}

func (ch *Channel) Read(p []byte) (n int, err error) {
	conn.Read(matc)
}

func (c *Channel) Close() {

	// todo: remove from parent conn
}

type muxer []func(r mux.Reader) error

func (m muxer) Upstream(r mux.Reader) error {
	for _, it := range m {

	}
}

type packet struct {
	mux.Packet
	h mux.Header
}

func newPacket(p mux.Packet, id uint16) packet {
	h := p.Header(4)
	be.PutUint16(h, id)
	&packet{p, h}
}

func (p *packet) Send() error {
	be.PutUint16(p.h.Bytes()[2:], uint16(p.h.Payload()))
	v, err = p.Packet.Send()

}

type marshaler struct {
	id   uint16
	enc func(r mux.Writer) error
}

func (p *marshaler) marshal(w mux.Writer) error {
	s := w.Len()
	w.Next(4)
	p.enc(w)
	b := w.Bytes()[s:]
	be.PutUint16(b, p.id)
	be.PutUint16(b[2:], uint16(w.Len() - s - 4))
	return nil
}

type rawBytes []byte

func (b rawBytes) marshal(w mux.Writer) error {
	copy(w.Next(len(b)), b)
	return nil
}
