package rdp

import (
	"time"
)

func NewClient(newtork, host string, port int) (c Conn, err error) {
	c = &client{
		state: CLOSED,
	}
	return
}

var (
	ClientBufferSize    = 32
	ClientMaxPacketSize = 1024
	ClientTimeout       = time.Second * 10
	ClientPingInterval  = time.Second * 1
)

type client struct {
	active bool
	state  State

	in  chan []byte
	out chan []byte

	rvc chan Packet
	snd chan Packet
}

func (c *client) State() State {
	return c.state
}

func (c *client) Send(b []byte) (err error) {
	return nil
}

func (c *client) Close() {

}

func (c *client) run() {
	if c.active {
		return
	}

	c.active = true
	for c.active {

	}
}
