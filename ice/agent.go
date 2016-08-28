package ice

import (
	"time"
)

// Agent represents an ICE agent.
type Agent struct {
	Username string
	Password string
	local    []*Candidate
	remote   []*Candidate
}

type Config struct {
	Server   []*Server
	Networks []string // "udp", "udp4", "udp6", "tcp", "tcp4" or "tcp6"
}

type Server struct {
	URI      string
	Username string
	Password string
}

var DefaultConfig = &Config{
//	Networks: []stirng{Transport: }
}

func Gather(config *Config) (*Agent, error) {
	if config == nil {
		config = DefaultConfig
	}
	queue := make(chan *Candidate, 10)
	local, err := NewLocalCandidates()
	if err != nil {
		return nil, err
	}
	for {
		select {
		case c, _ := <-queue:
			if c != nil {
				local = append(local, c)
			}
		case <-time.After(100 * time.Millisecond):
		}
	}
	return &Agent{local: local}, nil
}
