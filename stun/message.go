package stun

import (
	"bytes"
	"fmt"
	"sort"
	"strconv"
)

const (
	KindRequest    uint16 = 0x0000
	KindIndication uint16 = 0x0010
	KindResponse   uint16 = 0x0100
	KindError      uint16 = 0x0110
)

// Attribute represents a STUN attribute.
type Attr interface {
	Type() uint16
	Marshal(p []byte) []byte
	Unmarshal(b []byte) error
}

// Message represents a STUN message.
type Message struct {
	Type        uint16
	Transaction []byte
	Attributes  []Attr
}

func (m *Message) Kind() uint16 {
	return m.Type & 0x110
}

func (m *Message) Method() uint16 {
	return m.Type &^ 0x110
}

func (m *Message) Add(attr Attr) {
	m.Attributes = append(m.Attributes, attr)
}

func (m *Message) Set(attr Attr) {
	m.Del(attr.Type())
	m.Add(attr)
}

func (m *Message) Get(typ uint16) (attr Attr) {
	for _, attr = range m.Attributes {
		if attr.Type() == typ {
			return
		}
	}
	return nil
}

func (m *Message) GetString(typ uint16) string {
	if str, ok := m.Get(typ).(fmt.Stringer); ok {
		return str.String()
	}
	return ""
}

func (m *Message) GetAddr(typ uint16) *Addr {
	if addr, ok := m.Get(typ).(*Addr); ok {
		return addr
	}
	return nil
}

func (m *Message) GetError() *Error {
	if err, ok := m.Get(AttrErrorCode).(*Error); ok {
		return err
	}
	return nil
}

func (m *Message) Del(typ uint16) {
	n := 0
	for _, a := range m.Attributes {
		if a.Type() != typ {
			m.Attributes[n] = a
			n++
		}
	}
	m.Attributes = m.Attributes[:n]
}

func (m *Message) Marshal(p []byte) []byte {
	pos := len(p)
	r, b := grow(p, 20)

	be.PutUint16(b, m.Type)
	copy(b[4:], m.Transaction)

	sort.Sort(byPosition(m.Attributes))
	for _, attr := range m.Attributes {
		r = m.marshalAttr(r, pos, attr)
	}

	be.PutUint16(r[pos+2:], uint16(len(r)-pos-20))
	return r
}

func (m *Message) marshalAttr(p []byte, pos int, attr Attr) []byte {
	h := len(p)
	r, b := grow(p, 4)
	be.PutUint16(b, attr.Type())

	switch v := attr.(type) {
	case *Addr:
		r = v.MarshalAddress(r, m.Transaction)
	case *MessageIntegrity:
		r = v.MarshalSum(r, pos)
	case *Fingerprint:
		r = v.MarshalSum(r, pos)
	default:
		r = attr.Marshal(r)
	}

	n := len(r) - h - 4
	be.PutUint16(r[h+2:], uint16(n))

	// Padding
	if pad := n & 3; pad != 0 {
		r, b = grow(r, 4-pad)
		for i := range b {
			b[i] = 0
		}
	}
	return r
}

func (m *Message) Unmarshal(b []byte) error {
	if len(b) < 20 {
		return ErrFormat
	}
	n := int(be.Uint16(b[2:])) + 20
	if len(b) < n {
		return ErrFormat
	}
	pos, p := 20, make([]byte, n)
	copy(p, b[:n])

	m.Type = be.Uint16(p)
	m.Transaction = p[4:20]
	for pos < len(p) {
		s, attr, err := m.unmarshalAttr(p, pos)
		if err != nil {
			return err
		}
		pos += s
		if attr != nil {
			m.Attributes = append(m.Attributes, attr)
		}
	}

	return nil
}

func (m *Message) unmarshalAttr(p []byte, pos int) (n int, attr Attr, err error) {
	b := p[pos:]
	if len(b) < 4 {
		err = ErrFormat
		return
	}
	typ := be.Uint16(b)
	attr, n = NewAttr(typ), int(be.Uint16(b[2:]))+4
	if len(b) < n {
		err = ErrFormat
		return
	}

	b = b[4:n]
	if attr != nil {
		switch v := attr.(type) {
		case *Addr:
			err = v.UnmarshalAddress(b, m.Transaction)
		case *MessageIntegrity:
			err = v.UnmarshalSum(b, p[:pos+n])
		case *Fingerprint:
			err = v.UnmarshalSum(b, p[:pos+n])
		default:
			err = attr.Unmarshal(b)
		}
	} else if typ < 0x8000 { // Comprehension-required attribute
		err = ErrUnknownAttr
	}
	if err != nil {
		err = &errAttribute{err, typ}
		return
	}

	// Padding
	if pad := n & 3; pad != 0 {
		n += 4 - pad
		if len(p) < pos+n {
			err = ErrFormat
		}
	}
	return
}

func (m *Message) CheckMessageIntegrity(key []byte) bool {
	if attr, ok := m.Get(AttrMessageIntegrity).(*MessageIntegrity); ok {
		return attr.Check(key)
	}
	return false
}

func (m *Message) CheckFingerprint() bool {
	if attr, ok := m.Get(AttrFingerprint).(*Fingerprint); ok {
		return attr.Check()
	}
	return false
}

func (m *Message) String() string {
	buf := &bytes.Buffer{}
	buf.WriteString(methodName(m.Method()))
	buf.WriteString(kindName(m.Kind()))
	buf.WriteByte('{')
	for i, attr := range m.Attributes {
		if i > 0 {
			buf.WriteString(", ")
		}
		buf.WriteString(AttrName(attr.Type()))
		switch v := attr.(type) {
		case Flag:
		case fmt.Stringer:
			buf.WriteString(": \"" + v.String() + "\"")
		default:
			buf.WriteString(fmt.Sprintf(": %v", attr))
		}
	}
	buf.WriteByte('}')
	return buf.String()
}

func methodName(m uint16) string {
	if r, ok := methodNames[m]; ok {
		return r
	}
	return "Method(0x" + strconv.FormatInt(int64(m), 16) + ")"
}

func kindName(k uint16) string {
	switch k {
	case KindRequest:
		return "Request"
	case KindIndication:
		return "Indication"
	case KindResponse:
		return "Response"
	case KindError:
		return "Error"
	}
	return "Kind(0x" + strconv.FormatInt(int64(k), 16) + ")"
}

func UnmarshalMessage(b []byte) (m *Message, err error) {
	m = &Message{}
	err = m.Unmarshal(b)
	return
}

type byPosition []Attr

func (s byPosition) Len() int {
	return len(s)
}

func (s byPosition) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (s byPosition) Less(i, j int) bool {
	a, b := s[i].Type(), s[j].Type()
	switch b {
	case a:
		return i < j
	case AttrMessageIntegrity:
		return a != AttrFingerprint
	case AttrFingerprint:
		return true
	default:
		return i < j
	}
}
