package rdp

type Conn interface {
	State() State
	Send(b []byte) (err error)
	Close()
}
