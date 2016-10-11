package stun

//func (c *Client) Discover() (net.Addr, error) {
//	msg, err := c.RoundTrip(&Message{Method: methodBinding})
//	if err != nil {
//		return nil, err
//	}
//	if addr, ok := msg.Attributes[AttrXorMappedAddress]; ok {
//		return addr.(*Addr), nil
//	} else if addr, ok := msg.Attributes[AttrMappedAddress]; ok {
//		return addr.(*Addr), nil
//	}
//}
