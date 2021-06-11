package conn

import "testing"

func TestConnectSophon(t *testing.T) {
	c := ConnectSophon()
	if c == nil {
		t.Error("Received nil SophonicConnection")
	}
}
