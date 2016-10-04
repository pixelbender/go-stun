package stun

import (
	"bytes"
	"time"
	"net"
)

type Client struct {
	Transport     RoundTripper
	CheckRedirect func(req *Message, addr *Addr) error
}

type RoundTripper interface {
	// RoundTrip executes a single STUN transaction, returning a response for the provided request.
	RoundTrip(*Message) (*Message, error)
}

// RoundTrip executes a single STUN transaction, returning a response for the provided request.
func (c *Conn) RoundTrip(req *Message) (res *Message, err error) {
	req.NewTransaction()

	ts := time.Now()
	_, retransmit := c.Conn.Conn.(net.PacketConn)
	rto := c.config.getRetransmissionTimeout()
	rtx := ts.Add(rto)
	deadline := ts.Add(c.config.getTransactionTimeout())

	for {
		err = c.WriteMessage(req)
		if err != nil {
			return
		}
		ts = time.Now()
		rtx = ts.Add(rto)
		select {
		case b, ok := <-tx.Read():
			if !ok {
				return nil, ErrCancelled
			}
			if !bytes.Equal(req.Transaction[:], res.Transaction[:]) {
				continue
			}

		// check transaction id

			if err == nil {
				return res
			}

			err = req.Attributes[AttrErrorCode].(ErrorCode)

			switch err {
			case ErrUnauthorized, ErrStaleNonce:
				tx.Attributes[AttrRealm] = res.Attributes[AttrRealm]
				tx.Attributes[AttrNonce] = res.Attributes[AttrNonce]
				//tx.Key, err = c.config.getAuthKey(a.Attributes)

				if err != nil {
					return
				}
			}

		//w.Reset()
			tx.Reset()
		case retransmit && <-time.After(rtx.Sub(ts)):
			rto <<= 1

		case <-time.After(deadline.Sub(ts)):
			return ErrTimeout
		}
	}
}

func (c *Conn) Discover() (net.Addr, error) {
	msg, err := c.RoundTrip(&Message{Method: methodBinding})
	if err != nil {
		return nil, err
	}
	if addr, ok := msg.Attributes[AttrXorMappedAddress]; ok {
		return addr.(*Addr), nil
	} else if addr, ok := msg.Attributes[AttrMappedAddress]; ok {
		return addr.(*Addr), nil
	}
}