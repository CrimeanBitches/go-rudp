package rdp

// State is ...
type State byte

const (
	// CLOSED is ...
	CLOSED State = 0
	// LISTEN is ...
	LISTEN State = 1
	// SYNSENT is ...
	SYNSENT State = 2
	// SYNRCVD is ...
	SYNRCVD State = 4
	// OPEN is ...
	OPEN State = 8
	// CLOSEWAIT is ...
	CLOSEWAIT State = 16
)

var stateNames = map[State]string{
	CLOSED:    "CLOSED",
	LISTEN:    "LISTEN",
	SYNSENT:   "SYNSENT",
	SYNRCVD:   "SYNRCVD",
	OPEN:      "OPEN",
	CLOSEWAIT: "CLOSEWAIT",
}
