# go-stun

Go implementation of STUN, TURN and ICE Protocols

[![Build Status](https://travis-ci.org/pixelbender/go-stun.svg)](https://travis-ci.org/pixelbender/go-stun)
[![Coverage Status](https://coveralls.io/repos/github/pixelbender/go-stun/badge.svg?branch=master)](https://coveralls.io/github/pixelbender/go-stun?branch=master)
[![Go Report Card](https://goreportcard.com/badge/github.com/pixelbender/go-stun)](https://goreportcard.com/report/github.com/pixelbender/go-stun)
[![GoDoc](https://godoc.org/github.com/pixelbender/go-stun?status.svg)](https://godoc.org/github.com/pixelbender/go-stun)

## Features

- [x] STUN Encoder/Decoder
- [x] STUN Client/Server
- [x] STUN Authorization
- [x] STUN Transactions
- [x] STUN Multiplexing
- [ ] STUN Redirection
- [ ] NAT Behavior Discovery
- [x] ICE Messages
- [ ] ICE Agent
- [ ] ICE Gathering
- [ ] ICE Lite
- [x] TURN Messages
- [x] TURN Client
- [ ] TURN Server
- [ ] ...

## Installation

```sh
go get github.com/pixelbender/go-stun
```

## STUN: Server reflexive transport address discovery

```go
package main

import (
	"github.com/pixelbender/go-stun/stun"
	"fmt"
)

func main() {
    conn, addr, err := stun.Discover("stun:stun.l.google.com:19302")
	if err != nil {
    	fmt.Println(err)
    	return
    }
    defer conn.Close()
	fmt.Printf("Local address: %v, Server reflexive address: %v", conn.LocalAddr(), addr)
}
```

## TURN: Relayed transport address allocation

```go
package main

import (
	"github.com/pixelbender/go-stun/turn"
	"fmt"
)

func main() {
	conn, err := turn.Allocate("turn:username:password@example.org")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer conn.Close()
	fmt.Printf("Local address: %v, Relayed transport address: %v", conn.LocalAddr(), conn.RelayedAddr())
}
```

## Specifications

- [RFC 5389: STUN](https://tools.ietf.org/html/rfc5389)
- [RFC 5780: NAT Behavior Discovery Using STUN](https://tools.ietf.org/html/rfc5780)
- [RFC 7064: URI Scheme for STUN](https://tools.ietf.org/html/rfc7064)
- [RFC 5766: TURN: Relay Extensions to STUN](https://tools.ietf.org/html/rfc5766)
- [RFC 5245: ICE: A Protocol for NAT for Offer/Answer Protocols](https://tools.ietf.org/html/rfc5245)
- [RFC 6062: TURN Extensions for TCP Allocations](https://tools.ietf.org/html/rfc6062)
- [RFC 7065: TURN URI](https://tools.ietf.org/html/rfc7065)
- [RFC 6544: TCP Candidates with ICE](https://tools.ietf.org/html/rfc6544)
