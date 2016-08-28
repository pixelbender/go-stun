package turn

import (
	"github.com/pixelbender/go-stun/stun"
	"net"
	"time"
)

type Server struct {
	*stun.Server
	LifeTime time.Duration
}

func NewServer() *Server {
	srv := &Server{
		LifeTime: time.Second,
	}
	srv.Server = &stun.Server{
		Config: &stun.Config{
			GetAttributeCodec: GetAttributeCodec,
		},
		Handler: srv,
	}
	return srv
}

func (srv *Server) ServeSTUN(rw stun.ResponseWriter, r *stun.Message) {
	switch r.Method {
	case MethodAllocate:
		rw.WriteMessage(&stun.Message{
			Method: r.Method | stun.TypeResponse,
			Attributes: stun.Attributes{
				stun.AttrXorMappedAddress: rw.RemoteAddr(),
				AttrXorRelayedAddress:     &stun.Addr{IP: net.ParseIP("127.0.0.1"), Port: 1000},
				AttrLifeTime:              uint32(srv.LifeTime / time.Second),
			},
		})
	default:
		srv.Handler.ServeSTUN(rw, r)
	}
}
