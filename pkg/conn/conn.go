/*
	Package conn handles sophonic connections to trisolan resources
*/
package conn

import (
	"math/rand"
	"time"
)

// SophonicConnection represents a connection to remote resource
type SophonicConnection struct {
}

// ConnectSophon establishes a sophonic connection to a remote resource and returns a
// SophonicConnection that can be used for communication
func ConnectSophon() *SophonicConnection {
	delay := rand.Intn(5)
	time.Sleep(time.Duration(delay) * time.Second)
	return &SophonicConnection{}
}

func init() {
	rand.Seed(time.Now().UnixNano())
}
